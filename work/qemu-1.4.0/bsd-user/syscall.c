/*
 *  BSD syscalls
 *
 *  Copyright (c) 2003 - 2008 Fabrice Bellard
 *  Copyright (c) 2012 - 2013 Stacey Son <sson@FreeBSD.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#if defined(__FreeBSD__)
#include <sys/param.h>
#endif

#if defined(__FreeBSD_version) && __FreeBSD_version < 900000
#define st_atim st_atimespec
#define st_ctim st_ctimespec
#define st_mtim st_mtimespec
#define st_birthtim st_birthtimespec
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <limits.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/event.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/socket.h>
#ifdef __FreeBSD__
#include <sys/regression.h>
#if defined(__FreeBSD_version) && __FreeBSD_version > 900000
#include <sys/procdesc.h>
#endif
#include <sys/ucontext.h>
#include <sys/thr.h>
#include <sys/rtprio.h>
#include <sys/umtx.h>
#include <sys/uuid.h>
#if defined(__FreeBSD_version) && __FreeBSD_version > 900000
#include <sys/_termios.h>
#else
#include <sys/termios.h>
#endif
#include <sys/ttycom.h>
#include <sys/filio.h>
#include <sys/reboot.h>
#include <sys/timex.h>
#define _ACL_PRIVATE
#include <sys/acl.h>
#include <sys/extattr.h>
#include <kenv.h>
#include <pthread.h>
#include <machine/atomic.h>
#endif
#include <sys/un.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/msg.h>
#include <utime.h>

#include <netinet/in.h>

#include "qemu.h"
#include "qemu-common.h"
#include "target_signal.h"
#ifdef __FreeBSD__
#include "freebsd/ttycom.h"
#include "freebsd/filio.h"
#endif

//#define DEBUG

static abi_ulong target_brk_start, target_brk_cur, target_brk_end;

static char *get_filename_from_fd(pid_t pid, int fd, char *filename, size_t len);

#ifdef __FreeBSD__
#include <sys/queue.h>
#include <sys/user.h>
#include <libprocstat.h>


/*
 * Get the filename for the given file descriptor.
 * Note that this may return NULL (fail) if no longer cached in the kernel.
 */
static char *
get_filename_from_fd(pid_t pid, int fd, char *filename, size_t len)
{
	unsigned int cnt;
	struct procstat *procstat = NULL;
	struct kinfo_proc *kipp = NULL;
	struct filestat_list *head = NULL;
	struct filestat *fst;
	char *ret = NULL;

#if defined(__FreeBSD_version) && __FreeBSD_version > 900000
	procstat = procstat_open_sysctl();
	if (NULL == procstat)
		goto out;

	kipp = procstat_getprocs(procstat, KERN_PROC_PID, pid, &cnt);
	if (NULL == kipp)
		goto out;

	head = procstat_getfiles(procstat, kipp, 0);
	if (NULL == head)
		goto out;

	STAILQ_FOREACH(fst, head, next) {
		if (fd == fst->fs_fd) {
			if (fst->fs_path != NULL) {
				(void)strlcpy(filename, fst->fs_path, len);
				ret = filename;
			}
			break;
		}
	}

out:
	if (head != NULL)
		procstat_freefiles(procstat, head);
	if (kipp != NULL)
		procstat_freeprocs(procstat, kipp);
	if (procstat != NULL)
		procstat_close(procstat);
#endif
	return (ret);
}

#else

static char *
get_filename_from_fd(pid_t pid, int fd, char *filename, size_t len)
{
	return (NULL);
}

#endif /* ! __FreeBSD__ */

static inline abi_long get_errno(abi_long ret)
{
    if (ret == -1)
        /* XXX need to translate host -> target errnos here */
        return -(errno);
    else
        return ret;
}

static inline int
host_to_target_errno(int err)
{
	/* XXX need to translate host errnos here */
	return (err);
}

#define target_to_host_bitmask(x, tbl) (x)

static inline int is_error(abi_long ret)
{
    return (abi_ulong)ret >= (abi_ulong)(-4096);
}

void target_set_brk(abi_ulong start_brk, abi_ulong cur_brk, abi_ulong end_brk)
{
    target_brk_start = HOST_PAGE_ALIGN(start_brk);
    target_brk_cur = cur_brk;
    target_brk_end = HOST_PAGE_ALIGN(end_brk);
}

/* do_obreak() must return target errnos. */
static abi_long do_obreak(abi_ulong new_brk)
{
    abi_long mapped_addr;
    abi_ulong new_alloc_size;

    return -TARGET_EINVAL;	// XXX Temporary disable obreak() until it can be properly fixed

    if (!new_brk)
        return 0;
    if (new_brk < target_brk_cur) {
        return -TARGET_EINVAL;
    }

    /* If the new brk is less than this, set it and we're done... */
    if (new_brk < target_brk_end) {
        target_brk_cur = new_brk;
        return 0;
    }

    /* We need to allocate more memory after the brk... */
    new_alloc_size = HOST_PAGE_ALIGN(new_brk - target_brk_end + 1);
    mapped_addr = get_errno(target_mmap(target_brk_end, new_alloc_size,
                                        PROT_READ|PROT_WRITE,
                                        MAP_ANON|MAP_FIXED|MAP_PRIVATE, -1, 0));

    if (!is_error(mapped_addr)) {
        target_brk_cur = new_brk;
	target_brk_end += new_alloc_size;
    } else {
        return mapped_addr;
    }

    return 0;
}

abi_long do_brk(abi_ulong new_brk)
{
    return do_obreak(new_brk);
}

#if defined(TARGET_I386)
static abi_long do_freebsd_sysarch(CPUX86State *env, int op, abi_ulong parms)
{
    abi_long ret = 0;
    abi_ulong val;
    int idx;

    switch(op) {
#ifdef TARGET_ABI32
    case TARGET_FREEBSD_I386_SET_GSBASE:
    case TARGET_FREEBSD_I386_SET_FSBASE:
        if (op == TARGET_FREEBSD_I386_SET_GSBASE)
#else
    case TARGET_FREEBSD_AMD64_SET_GSBASE:
    case TARGET_FREEBSD_AMD64_SET_FSBASE:
        if (op == TARGET_FREEBSD_AMD64_SET_GSBASE)
#endif
            idx = R_GS;
        else
            idx = R_FS;
        if (get_user(val, parms, abi_ulong))
            return -TARGET_EFAULT;
        cpu_x86_load_seg(env, idx, 0);
        env->segs[idx].base = val;
        break;
#ifdef TARGET_ABI32
    case TARGET_FREEBSD_I386_GET_GSBASE:
    case TARGET_FREEBSD_I386_GET_FSBASE:
        if (op == TARGET_FREEBSD_I386_GET_GSBASE)
#else
    case TARGET_FREEBSD_AMD64_GET_GSBASE:
    case TARGET_FREEBSD_AMD64_GET_FSBASE:
        if (op == TARGET_FREEBSD_AMD64_GET_GSBASE)
#endif
            idx = R_GS;
        else
            idx = R_FS;
        val = env->segs[idx].base;
        if (put_user(val, parms, abi_ulong))
            return -TARGET_EFAULT;
        break;
    /* XXX handle the others... */
    default:
        ret = -TARGET_EINVAL;
        break;
    }
    return ret;
}
#endif

#ifdef TARGET_SPARC
struct target_sparc_sigtramp_install_args {
	abi_ulong	sia_new;	/* address of sigtramp code */
	abi_ulong	sia_old;	/* user address to store old sigtramp addr */
};

abi_ulong sparc_user_sigtramp = 0;

static abi_long do_freebsd_sysarch(void *env, int op, abi_ulong parms)
{
    int ret = 0;
    abi_ulong val, old;
    /*
    struct target_sparc_sigtramp_install_args *target_sigtramp_args;
    */


    switch(op) {
    case TARGET_SPARC_SIGTRAMP_INSTALL:
	    {

#if 0
		    /* Sparc userland is giving us a new sigtramp code ptr. */
		    if (!(target_sigtramp_args = lock_user(VERIFY_WRITE, parms,
			sizeof(*target_sigtramp_args), 1))) {
			    ret = -TARGET_EFAULT;
		    } else {
			if (target_sigtramp_args->sia_old) {
				put_user_ual(sparc_user_sigtramp,
				    target_sigtramp_args->sia_old);
			}
			sparc_user_sigtramp = target_sigtramp_args->sia_new;
			unlock_user(target_sigtramp_args, parms, 0);

		    }
#endif
		    val = sparc_user_sigtramp;
		    if (get_user(sparc_user_sigtramp, parms, abi_ulong)) {
			    return (-TARGET_EFAULT);
		    }
		    parms += sizeof(abi_ulong);
		    if (get_user(old, parms, abi_ulong)) {
			    return (-TARGET_EFAULT);
		    }
		    if (old) {
			    if (put_user(val, old, abi_ulong)) {
				    return (-TARGET_EFAULT);
			    }
		    }
	    }
	    break;

    case TARGET_SPARC_UTRAP_INSTALL:
	    /* XXX not currently handled */
    default:
	    ret = -TARGET_EINVAL;
	    break;
    }

    return (ret);
}
#endif

#ifdef TARGET_ARM
static abi_long do_freebsd_sysarch(CPUARMState *env, int op, abi_ulong parms)
{
    int ret = 0;

    switch (op) {
    case TARGET_FREEBSD_ARM_SYNC_ICACHE:
    case TARGET_FREEBSD_ARM_DRAIN_WRITEBUF:
	break;

    case TARGET_FREEBSD_ARM_SET_TP:
        cpu_set_tls(env, parms);
	break;

    case TARGET_FREEBSD_ARM_GET_TP:
	/* XXX Need a cpu_get_tls() */
	if (put_user(env->cp15.c13_tls2, parms, abi_ulong))
		ret = -TARGET_EFAULT;
	break;

    default:
	ret = -TARGET_EINVAL;
	break;
    }

    return (ret);
}
#endif

#ifdef TARGET_MIPS
static abi_long do_freebsd_sysarch(CPUMIPSState *env, int op, abi_ulong parms)
{
	int ret = 0;

	switch(op) {
	case TARGET_MIPS_SET_TLS:
		cpu_set_tls(env, parms);
		break;

	case TARGET_MIPS_GET_TLS:
		/* XXX Need a cpu_get_tls() */
		if (put_user(env->tls_value, parms, abi_ulong))
			ret = -TARGET_EFAULT;
		break;
	default:
		ret = -TARGET_EINVAL;
		break;
	}

	return (ret);
}
#endif

#ifdef __FreeBSD__
extern int _getlogin(char *, int);

/*
 * XXX this uses the undocumented oidfmt interface to find the kind of
 * a requested sysctl, see /sys/kern/kern_sysctl.c:sysctl_sysctl_oidfmt()
 * (this is mostly copied from src/sbin/sysctl/sysctl.c)
 */
static int
oidfmt(int *oid, int len, char *fmt, uint32_t *kind)
{
    int qoid[CTL_MAXNAME+2];
    uint8_t buf[BUFSIZ];
    int i;
    size_t j;

    qoid[0] = 0;
    qoid[1] = 4;
    memcpy(qoid + 2, oid, len * sizeof(int));

    j = sizeof(buf);
    i = sysctl(qoid, len + 2, buf, &j, 0, 0);
    if (i)
        return i;

    if (kind)
        *kind = *(uint32_t *)buf;

    if (fmt)
        strcpy(fmt, (char *)(buf + sizeof(uint32_t)));
    return (0);
}

/*
 * try and convert sysctl return data for the target.
 * XXX doesn't handle CTLTYPE_OPAQUE and CTLTYPE_STRUCT.
 */
static int sysctl_oldcvt(void *holdp, size_t holdlen, uint32_t kind)
{
    switch (kind & CTLTYPE) {
    case CTLTYPE_INT:
    case CTLTYPE_UINT:
        *(uint32_t *)holdp = tswap32(*(uint32_t *)holdp);
        break;
#ifdef TARGET_ABI32
    case CTLTYPE_LONG:
    case CTLTYPE_ULONG:
        *(uint32_t *)holdp = tswap32(*(long *)holdp);
        break;
#else
    case CTLTYPE_LONG:
        *(uint64_t *)holdp = tswap64(*(long *)holdp);
    case CTLTYPE_ULONG:
        *(uint64_t *)holdp = tswap64(*(unsigned long *)holdp);
        break;
#endif
#if !defined(__FreeBSD_version) || __FreeBSD_version < 900031
    case CTLTYPE_QUAD:
#else
    case CTLTYPE_U64:
    case CTLTYPE_S64:
#endif
        *(uint64_t *)holdp = tswap64(*(uint64_t *)holdp);
        break;
    case CTLTYPE_STRING:
        break;
    default:
        /* XXX unhandled */
        return -1;
    }
    return 0;
}

/*
 * Convert the undocmented name2oid sysctl data for the target.
 */
static inline void
sysctl_name2oid(uint32_t *holdp, size_t holdlen)
{
	size_t i;

	for(i = 0; i < holdlen; i++)
		holdp[i] = tswap32(holdp[i]);
}

static inline void
sysctl_oidfmt(uint32_t *holdp)
{
	/* byte swap the kind */
	holdp[0] = tswap32(holdp[0]);
}

/* XXX this needs to be emulated on non-FreeBSD hosts... */
static abi_long do_freebsd_sysctl(abi_ulong namep, int32_t namelen, abi_ulong oldp,
                          abi_ulong oldlenp, abi_ulong newp, abi_ulong newlen)
{
    abi_long ret;
    void *hnamep, *holdp = NULL, *hnewp = NULL;
    size_t holdlen;
    abi_ulong oldlen = 0;
    int32_t *snamep = g_malloc(sizeof(int32_t) * namelen), *p, *q, i;
    uint32_t kind = 0;

    if (oldlenp)
        if (get_user_ual(oldlen, oldlenp))
		return -TARGET_EFAULT;
    if (!(hnamep = lock_user(VERIFY_READ, namep, namelen, 1)))
        return -TARGET_EFAULT;
    if (newp && !(hnewp = lock_user(VERIFY_READ, newp, newlen, 1)))
        return -TARGET_EFAULT;
    if (oldp && !(holdp = lock_user(VERIFY_WRITE, oldp, oldlen, 0)))
        return -TARGET_EFAULT;
    holdlen = oldlen;
    for (p = hnamep, q = snamep, i = 0; i < namelen; p++, i++)
       *q++ = tswap32(*p);
    oidfmt(snamep, namelen, NULL, &kind);

    /* Handle some arch/emulator dependent sysctl()'s here. */
    switch(snamep[0]) {
    case CTL_KERN:
	    switch(snamep[1]) {
	    case KERN_USRSTACK:
#if TARGET_USRSTACK != 0
		    (*(abi_ulong *)holdp) = tswapal(TARGET_USRSTACK);
		    holdlen = sizeof(abi_ulong);
		    ret = 0;
#else
		    ret = -TARGET_ENOENT;
#endif
		    goto out;

	    case KERN_PS_STRINGS:
#if defined(TARGET_PS_STRINGS)
		    (*(abi_ulong *)holdp) = tswapal(TARGET_PS_STRINGS);
		    holdlen = sizeof(abi_ulong);
		    ret = 0;
#else
		    ret = -TARGET_ENOENT;
#endif
		    goto out;

	    case KERN_PROC:
		    switch(snamep[2]) {
		    case KERN_PROC_PATHNAME:
			    holdlen = strlen(target_proc_pathname) + 1;
			    if (holdp) {
				    if (oldlen < holdlen) {
					    ret = -TARGET_EINVAL;
					    goto out;
				    }
				    strlcpy(holdp, target_proc_pathname,
					oldlen);
			    }
			    ret = 0;
			    goto out;

		    default:
			    break;
		    }
		    break;

	    default:
		    break;
	    }
            break;

    case CTL_HW:
	    switch(snamep[1]) {
	    case HW_MACHINE:
		strlcpy(holdp, TARGET_HW_MACHINE, oldlen);
		ret = 0;
		goto out;

	    case HW_MACHINE_ARCH:
		strlcpy(holdp, TARGET_HW_MACHINE_ARCH, oldlen);
		ret = 0;
		goto out;

	    default:
		break;
	    }

    default:
	    break;
    }

    ret = get_errno(sysctl(snamep, namelen, holdp, &holdlen, hnewp, newlen));
    if (!ret && (holdp != 0 && holdlen != 0)) {
	if (0 == snamep[0] && (3 == snamep[1] || 4 == snamep[1])) {
		if (3 == snamep[1]) {
			/* Handle the undocumented name2oid special case. */
			sysctl_name2oid(holdp, holdlen);
		} else {
			/* Handle oidfmt */
			sysctl_oidfmt(holdp);
		}
	} else {
		sysctl_oldcvt(holdp, holdlen, kind);
	}
    }
#ifdef DEBUG
    else {
	    printf("sysctl(mib[0]=%d, mib[1]=%d, mib[3]=%d...) returned %d\n",
		snamep[0], snamep[1], snamep[2], (int)ret);
    }
#endif

out:
    if (oldlenp)
	    put_user_ual(holdlen, oldlenp);
    unlock_user(hnamep, namep, 0);
    unlock_user(holdp, oldp, holdlen);
    if (hnewp)
        unlock_user(hnewp, newp, 0);
    g_free(snamep);
    return ret;
}
#endif

/* FIXME
 * lock_iovec()/unlock_iovec() have a return code of 0 for success where
 * other lock functions have a return code of 0 for failure.
 */
static abi_long lock_iovec(int type, struct iovec *vec, abi_ulong target_addr,
                           int count, int copy)
{
    struct target_iovec *target_vec;
    abi_ulong base;
    int i;

    target_vec = lock_user(VERIFY_READ, target_addr, count * sizeof(struct target_iovec), 1);
    if (!target_vec)
        return -TARGET_EFAULT;
    for(i = 0;i < count; i++) {
        base = tswapl(target_vec[i].iov_base);
        vec[i].iov_len = tswapl(target_vec[i].iov_len);
        if (vec[i].iov_len != 0) {
            vec[i].iov_base = lock_user(type, base, vec[i].iov_len, copy);
            /* Don't check lock_user return value. We must call writev even
               if a element has invalid base address. */
        } else {
            /* zero length pointer is ignored */
            vec[i].iov_base = NULL;
        }
    }
    unlock_user (target_vec, target_addr, 0);
    return 0;
}

static abi_long unlock_iovec(struct iovec *vec, abi_ulong target_addr,
                             int count, int copy)
{
    struct target_iovec *target_vec;
    abi_ulong base;
    int i;

    target_vec = lock_user(VERIFY_READ, target_addr, count * sizeof(struct target_iovec), 1);
    if (!target_vec)
        return -TARGET_EFAULT;
    for(i = 0;i < count; i++) {
        if (target_vec[i].iov_base) {
            base = tswapl(target_vec[i].iov_base);
            unlock_user(vec[i].iov_base, base, copy ? vec[i].iov_len : 0);
        }
    }
    unlock_user (target_vec, target_addr, 0);

    return 0;
}

static inline abi_long
target_to_host_ip_mreq(struct ip_mreqn *mreqn, abi_ulong target_addr,
    socklen_t len)
{
	struct target_ip_mreqn *target_smreqn;

	target_smreqn = lock_user(VERIFY_READ, target_addr, len, 1);
	if (!target_smreqn)
		return -TARGET_EFAULT;
	mreqn->imr_multiaddr.s_addr = target_smreqn->imr_multiaddr.s_addr;
	mreqn->imr_address.s_addr = target_smreqn->imr_address.s_addr;
	if (len == sizeof(struct target_ip_mreqn))
		mreqn->imr_ifindex = tswapal(target_smreqn->imr_ifindex);
	unlock_user(target_smreqn, target_addr, 0);

	return (0);
}

static inline abi_long
target_to_host_sockaddr(struct sockaddr *addr, abi_ulong target_addr,
    socklen_t len)
{
	const socklen_t unix_maxlen = sizeof (struct sockaddr_un);
	sa_family_t sa_family;
	struct target_sockaddr *target_saddr;

	target_saddr = lock_user(VERIFY_READ, target_addr, len, 1);
	if (!target_saddr)
		return -TARGET_EFAULT;

	sa_family = target_saddr->sa_family;

	/*
	 * Oops. The caller might send a incomplete sun_path; sun_path
	 * must be terminated by \0 (see the manual page), but unfortunately
	 * it is quite common to specify sockaddr_un length as
	 * "strlen(x->sun_path)" while it should be "strlen(...) + 1". We will
	 * fix that here if needed.
	 */
	if (target_saddr->sa_family == AF_UNIX) {
		if (len < unix_maxlen && len > 0) {
			char *cp = (char*)target_saddr;

			if ( cp[len-1] && !cp[len] )
				len++;
		}
		if (len > unix_maxlen)
			len = unix_maxlen;
	}

	memcpy(addr, target_saddr, len);
	addr->sa_family = sa_family;		/* type uint8_t */
	addr->sa_len = target_saddr->sa_len;	/* type uint8_t */
	unlock_user(target_saddr, target_addr, 0);

	return (0);
}

static inline abi_long
host_to_target_sockaddr(abi_ulong target_addr, struct sockaddr *addr,
    socklen_t len)
{
	struct target_sockaddr *target_saddr;

	target_saddr = lock_user(VERIFY_WRITE, target_addr, len, 0);
	if (!target_saddr)
		return (-TARGET_EFAULT);
	memcpy(target_saddr, addr, len);
	target_saddr->sa_family = addr->sa_family;	/* type uint8_t */
	target_saddr->sa_len = addr->sa_len;		/* type uint8_t */
	unlock_user(target_saddr, target_addr, len);

	return (0);
}

static inline abi_long
target_to_host_cmsg(struct msghdr *msgh, struct target_msghdr *target_msgh)
{
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(msgh);
	abi_long msg_controllen;
	abi_ulong target_cmsg_addr;
	struct target_cmsghdr *target_cmsg;
	socklen_t space = 0;


	msg_controllen = tswapal(target_msgh->msg_controllen);
	if (msg_controllen < sizeof (struct target_cmsghdr))
		goto the_end;
	target_cmsg_addr = tswapal(target_msgh->msg_control);
	target_cmsg = lock_user(VERIFY_READ, target_cmsg_addr,
	    msg_controllen, 1);
	if (!target_cmsg)
		return (-TARGET_EFAULT);
	while (cmsg && target_cmsg) {
		void *data = CMSG_DATA(cmsg);
		void *target_data = TARGET_CMSG_DATA(target_cmsg);
		int len = tswapal(target_cmsg->cmsg_len) -
		    TARGET_CMSG_ALIGN(sizeof (struct target_cmsghdr));
		space += CMSG_SPACE(len);
		if (space > msgh->msg_controllen) {
			space -= CMSG_SPACE(len);
			gemu_log("Host cmsg overflow\n");
			break;
		}
		cmsg->cmsg_level = tswap32(target_cmsg->cmsg_level);
		cmsg->cmsg_type = tswap32(target_cmsg->cmsg_type);
		cmsg->cmsg_len = CMSG_LEN(len);

		if (cmsg->cmsg_level != TARGET_SOL_SOCKET ||
		    cmsg->cmsg_type != SCM_RIGHTS) {
			gemu_log("Unsupported ancillary data: %d/%d\n",
			    cmsg->cmsg_level, cmsg->cmsg_type);
			memcpy(data, target_data, len);
		} else {
			int *fd = (int *)data;
			int *target_fd = (int *)target_data;
			int i, numfds = len / sizeof(int);

			for (i = 0; i < numfds; i++)
				fd[i] = tswap32(target_fd[i]);
		}
		cmsg = CMSG_NXTHDR(msgh, cmsg);
		target_cmsg = TARGET_CMSG_NXTHDR(target_msgh, target_cmsg);
	}
	unlock_user(target_cmsg, target_cmsg_addr, 0);

the_end:
	msgh->msg_controllen = space;
	return (0);
}

static inline abi_long
host_to_target_cmsg(struct target_msghdr *target_msgh, struct msghdr *msgh)
{
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(msgh);
	abi_long msg_controllen;
	abi_ulong target_cmsg_addr;
	struct target_cmsghdr *target_cmsg;
	socklen_t space = 0;

	msg_controllen = tswapal(target_msgh->msg_controllen);
	if (msg_controllen < sizeof (struct target_cmsghdr))
		goto the_end;
	target_cmsg_addr = tswapal(target_msgh->msg_control);
	target_cmsg = lock_user(VERIFY_WRITE, target_cmsg_addr,
	    msg_controllen, 0);
	if (!target_cmsg)
		return (-TARGET_EFAULT);
	while (cmsg && target_cmsg) {
		void *data = CMSG_DATA(cmsg);
		void *target_data = TARGET_CMSG_DATA(target_cmsg);
		int len = cmsg->cmsg_len - CMSG_ALIGN(sizeof (struct cmsghdr));

		space += TARGET_CMSG_SPACE(len);
		if (space > msg_controllen) {
			space -= TARGET_CMSG_SPACE(len);
			gemu_log("Target cmsg overflow\n");
			break;
		}
		target_cmsg->cmsg_level = tswap32(cmsg->cmsg_level);
		target_cmsg->cmsg_type = tswap32(cmsg->cmsg_type);
		target_cmsg->cmsg_len = tswapal(TARGET_CMSG_LEN(len));
		if ((cmsg->cmsg_level == TARGET_SOL_SOCKET) &&
		    (cmsg->cmsg_type == SCM_RIGHTS)) {
			int *fd = (int *)data;
			int *target_fd = (int *)target_data;
			int i, numfds = len / sizeof(int);
			for (i = 0; i < numfds; i++)
				target_fd[i] = tswap32(fd[i]);
		} else if ((cmsg->cmsg_level == TARGET_SOL_SOCKET) &&
		    (cmsg->cmsg_type == SO_TIMESTAMP) &&
		    (len == sizeof(struct timeval))) {
			/* copy struct timeval to target */
			struct timeval *tv = (struct timeval *)data;
			struct target_timeval *target_tv =
			    (struct target_timeval *)target_data;
			target_tv->tv_sec = tswapal(tv->tv_sec);
			target_tv->tv_usec = tswapal(tv->tv_usec);
		} else {
			gemu_log("Unsupported ancillary data: %d/%d\n",
			    cmsg->cmsg_level, cmsg->cmsg_type);
			memcpy(target_data, data, len);
		}
		cmsg = CMSG_NXTHDR(msgh, cmsg);
		target_cmsg = TARGET_CMSG_NXTHDR(target_msgh, target_cmsg);
	}
	unlock_user(target_cmsg, target_cmsg_addr, space);

the_end:
	target_msgh->msg_controllen = tswapal(space);
	return (0);
}

static inline rlim_t
target_to_host_rlim(abi_ulong target_rlim)
{
	abi_ulong target_rlim_swap;
	rlim_t result;

	target_rlim_swap = tswapal(target_rlim);
	if (target_rlim_swap == TARGET_RLIM_INFINITY)
		return (RLIM_INFINITY);

	result = target_rlim_swap;
	if (target_rlim_swap != (rlim_t)result)
		return (RLIM_INFINITY);

	return (result);
}

static inline abi_ulong
host_to_target_rlim(rlim_t rlim)
{
	abi_ulong target_rlim_swap;
	abi_ulong result;

	if (rlim == RLIM_INFINITY || rlim != (abi_long)rlim)
		target_rlim_swap = TARGET_RLIM_INFINITY;
	else
		target_rlim_swap = rlim;
	result = tswapal(target_rlim_swap);

	return (result);
}

static inline int
target_to_host_resource(int code)
{

	switch (code) {
	case TARGET_RLIMIT_AS:
		return RLIMIT_AS;

	case TARGET_RLIMIT_CORE:
		return RLIMIT_CORE;

	case TARGET_RLIMIT_CPU:
		return RLIMIT_CPU;

	case TARGET_RLIMIT_DATA:
		return RLIMIT_DATA;

	case TARGET_RLIMIT_FSIZE:
		return RLIMIT_FSIZE;

	case TARGET_RLIMIT_MEMLOCK:
		return RLIMIT_MEMLOCK;

	case TARGET_RLIMIT_NOFILE:
		return RLIMIT_NOFILE;

	case TARGET_RLIMIT_NPROC:
		return RLIMIT_NPROC;

	case TARGET_RLIMIT_RSS:
		return RLIMIT_RSS;

	case TARGET_RLIMIT_SBSIZE:
		return RLIMIT_SBSIZE;

	case TARGET_RLIMIT_STACK:
		return RLIMIT_STACK;

	case TARGET_RLIMIT_SWAP:
		return RLIMIT_SWAP;

	case TARGET_RLIMIT_NPTS:
		return RLIMIT_NPTS;

	default:
		return (code);
	}
}

static int
target_to_host_fcntl_cmd(int cmd)
{

	switch(cmd) {
	case TARGET_F_DUPFD:
		return F_DUPFD;

	case TARGET_F_DUP2FD:
		return F_DUP2FD;

	case TARGET_F_GETFD:
		return F_GETFD;

	case TARGET_F_SETFD:
		return F_SETFD;

	case TARGET_F_GETFL:
		return F_GETFL;

	case TARGET_F_SETFL:
		return F_SETFL;

	case TARGET_F_GETOWN:
		return F_GETOWN;

	case TARGET_F_SETOWN:
		return F_SETOWN;

	case TARGET_F_GETLK:
		return F_GETLK;

	case TARGET_F_SETLK:
		return F_SETLK;

	case TARGET_F_SETLKW:
		return F_SETLKW;

	case TARGET_F_READAHEAD:
		return F_READAHEAD;

	case TARGET_F_RDAHEAD:
		return F_RDAHEAD;

	default:
		return (cmd);
	}
}

static inline abi_long
host_to_target_rusage(abi_ulong target_addr, const struct rusage *rusage)
{
	struct target_rusage *target_rusage;

	if (!lock_user_struct(VERIFY_WRITE, target_rusage, target_addr, 0))
		return (-TARGET_EFAULT);
	target_rusage->ru_utime.tv_sec = tswapal(rusage->ru_utime.tv_sec);
	target_rusage->ru_utime.tv_usec = tswapal(rusage->ru_utime.tv_usec);
	target_rusage->ru_stime.tv_sec = tswapal(rusage->ru_stime.tv_sec);
	target_rusage->ru_stime.tv_usec = tswapal(rusage->ru_stime.tv_usec);
	target_rusage->ru_maxrss = tswapal(rusage->ru_maxrss);
	target_rusage->ru_ixrss = tswapal(rusage->ru_ixrss);
	target_rusage->ru_idrss = tswapal(rusage->ru_idrss);
	target_rusage->ru_isrss = tswapal(rusage->ru_isrss);
	target_rusage->ru_minflt = tswapal(rusage->ru_minflt);
	target_rusage->ru_majflt = tswapal(rusage->ru_majflt);
	target_rusage->ru_nswap = tswapal(rusage->ru_nswap);
	target_rusage->ru_inblock = tswapal(rusage->ru_inblock);
	target_rusage->ru_oublock = tswapal(rusage->ru_oublock);
	target_rusage->ru_msgsnd = tswapal(rusage->ru_msgsnd);
	target_rusage->ru_msgrcv = tswapal(rusage->ru_msgrcv);
	target_rusage->ru_nsignals = tswapal(rusage->ru_nsignals);
	target_rusage->ru_nvcsw = tswapal(rusage->ru_nvcsw);
	target_rusage->ru_nivcsw = tswapal(rusage->ru_nivcsw);
	unlock_user_struct(target_rusage, target_addr, 1);

	return (0);
}

/*
 * Map host to target signal numbers for the wait family of syscalls.
 * Assume all other status bits are the same.
 */
static int
host_to_target_waitstatus(int status)
{
	if (WIFSIGNALED(status)) {
		return (host_to_target_signal(WTERMSIG(status)) |
		    (status & ~0x7f));
	}
	if (WIFSTOPPED(status)) {
		return (host_to_target_signal(WSTOPSIG(status)) << 8) |
		    (status & 0xff);
	}
	return (status);
}

static inline abi_long
target_to_host_timeval(struct timeval *tv, abi_ulong target_tv_addr)
{
     struct target_freebsd_timeval *target_tv;

     if (!lock_user_struct(VERIFY_READ, target_tv, target_tv_addr, 0))
		return -TARGET_EFAULT;
   __get_user(tv->tv_sec, &target_tv->tv_sec);
   __get_user(tv->tv_usec, &target_tv->tv_usec);
     unlock_user_struct(target_tv, target_tv_addr, 1);
     return (0);
}

static inline abi_long
target_to_host_timex(struct timex *host_tx, abi_ulong target_tx_addr)
{
	struct target_timex *target_tx;

	if (!lock_user_struct(VERIFY_READ, target_tx, target_tx_addr, 0))
		return (-TARGET_EFAULT);
	__get_user(host_tx->modes, &target_tx->modes);
	__get_user(host_tx->offset, &target_tx->offset);
	__get_user(host_tx->freq, &target_tx->freq);
	__get_user(host_tx->maxerror, &target_tx->maxerror);
	__get_user(host_tx->esterror, &target_tx->esterror);
	__get_user(host_tx->status, &target_tx->status);
	__get_user(host_tx->constant, &target_tx->constant);
	__get_user(host_tx->precision, &target_tx->precision);
	__get_user(host_tx->ppsfreq, &target_tx->ppsfreq);
	__get_user(host_tx->jitter, &target_tx->jitter);
	__get_user(host_tx->shift, &target_tx->shift);
	__get_user(host_tx->stabil, &target_tx->stabil);
	__get_user(host_tx->jitcnt, &target_tx->jitcnt);
	__get_user(host_tx->calcnt, &target_tx->calcnt);
	__get_user(host_tx->errcnt, &target_tx->errcnt);
	__get_user(host_tx->stbcnt, &target_tx->stbcnt);
	unlock_user_struct(target_tx, target_tx_addr, 1);
	return (0);
}

static inline abi_long
target_to_host_timespec(struct timespec *ts, abi_ulong target_ts_addr)
{
     struct target_freebsd_timespec *target_ts;

     if (!lock_user_struct(VERIFY_READ, target_ts, target_ts_addr, 0))
		return -TARGET_EFAULT;
   __get_user(ts->tv_sec, &target_ts->tv_sec);
   __get_user(ts->tv_nsec, &target_ts->tv_nsec);
     unlock_user_struct(target_ts, target_ts_addr, 1);
     return (0);
}

static inline abi_long
host_to_target_timeval(struct timeval *tv, abi_ulong target_tv_addr)
{
     struct target_freebsd_timeval *target_tv;

     if (!lock_user_struct(VERIFY_WRITE, target_tv, target_tv_addr, 0))
		return -TARGET_EFAULT;
   __put_user(tv->tv_sec, &target_tv->tv_sec);
   __put_user(tv->tv_usec, &target_tv->tv_usec);
     unlock_user_struct(target_tv, target_tv_addr, 1);
     return (0);
}

static inline abi_long
host_to_target_timespec(abi_ulong target_ts_addr, struct timespec *ts)
{
     struct target_freebsd_timespec *target_ts;

     if (!lock_user_struct(VERIFY_WRITE, target_ts, target_ts_addr, 0))
		return -TARGET_EFAULT;
   __put_user(ts->tv_sec, &target_ts->tv_sec);
   __put_user(ts->tv_nsec, &target_ts->tv_nsec);
     unlock_user_struct(target_ts, target_ts_addr, 1);
     return (0);
}

static inline abi_long
host_to_target_ntptimeval(abi_ulong target_ntv_addr, struct ntptimeval *ntv)
{
	struct target_ntptimeval *target_ntv;

	if (!lock_user_struct(VERIFY_WRITE, target_ntv, target_ntv_addr, 0))
		return (-TARGET_EFAULT);
	__put_user(ntv->time.tv_sec, &target_ntv->time.tv_sec);
	__put_user(ntv->time.tv_nsec, &target_ntv->time.tv_nsec);
	__put_user(ntv->maxerror, &target_ntv->maxerror);
	__put_user(ntv->esterror, &target_ntv->esterror);
	__put_user(ntv->tai, &target_ntv->tai);
	__put_user(ntv->time_state, &target_ntv->time_state);
	return (0);
}

static inline abi_ulong
copy_from_user_fdset(fd_set *fds, abi_ulong target_fds_addr, int n)
{
	int i, nw, j, k;
	abi_ulong b, *target_fds;

	nw = (n + TARGET_ABI_BITS - 1) / TARGET_ABI_BITS;
	if (!(target_fds = lock_user(VERIFY_READ, target_fds_addr,
		    sizeof(abi_ulong) * nw, 1)))
		return (-TARGET_EFAULT);

	FD_ZERO(fds);
	k = 0;
	for (i = 0; i < nw; i++) {
		/* grab the abi_ulong */
		__get_user(b, &target_fds[i]);
		for (j = 0; j < TARGET_ABI_BITS; j++) {
			/* check the bit inside the abi_ulong */
			if ((b >> j) & 1)
				FD_SET(k, fds);
			k++;
		}
	}

	unlock_user(target_fds, target_fds_addr, 0);

	return (0);
}

static inline abi_ulong
copy_from_user_fdset_ptr(fd_set *fds, fd_set **fds_ptr,
    abi_ulong target_fds_addr, int n)
{
	if (target_fds_addr) {
		if (copy_from_user_fdset(fds, target_fds_addr, n))
			return (-TARGET_EFAULT);
		*fds_ptr = fds;
	} else {
		*fds_ptr = NULL;
	}
	return (0);
}

static inline abi_long
copy_to_user_fdset(abi_ulong target_fds_addr, const fd_set *fds, int n)
{
	int i, nw, j, k;
	abi_long v;
	abi_ulong *target_fds;

	nw = (n + TARGET_ABI_BITS - 1) / TARGET_ABI_BITS;
	if (!(target_fds = lock_user(VERIFY_WRITE, target_fds_addr,
		    sizeof(abi_ulong) * nw, 0)))
		return (-TARGET_EFAULT);

	k = 0;
	for (i = 0; i < nw; i++) {
		v = 0;
		for (j = 0; j < TARGET_ABI_BITS; j++) {
			v |= ((FD_ISSET(k, fds) != 0) << j);
			k++;
		}
		__put_user(v, &target_fds[i]);
	}

	unlock_user(target_fds, target_fds_addr, sizeof(abi_ulong) * nw);

	return (0);
}

#if TARGET_ABI_BITS == 32
static inline uint64_t
target_offset64(uint32_t word0, uint32_t word1)
{
#ifdef TARGET_WORDS_BIGENDIAN
	return ((uint64_t)word0 << 32) | word1;
#else
	return ((uint64_t)word1 << 32) | word0;
#endif
}
#else /* TARGET_ABI_BITS != 32 */
static inline uint64_t
target_offset64(uint64_t word0, uint64_t word1)
{
	return (word0);
}
#endif /* TARGET_ABI_BITS != 32 */

/* ARM EABI and MIPS expect 64bit types aligned even on pairs of registers */
#ifdef TARGET_ARM
static inline int
regpairs_aligned(void *cpu_env) {

	return ((((CPUARMState *)cpu_env)->eabi) == 1);
}
#elif defined(TARGET_MIPS) && TARGET_ABI_BITS == 32
static inline int
regpairs_aligned(void *cpu_env) { return 1; }
#else
static inline int
regpairs_aligned(void *cpu_env) { return 0; }
#endif

static inline abi_long
unimplemented(int num)
{

	qemu_log("qemu: Unsupported syscall: %d\n", num);
	return (-TARGET_ENOSYS);
}

/* do_bind() must return target values and target errnos. */
static abi_long
do_bind(int sockfd, abi_ulong target_addr, socklen_t addrlen)
{
	abi_long ret;
	void *addr;

	if ((int)addrlen < 0)
		return (-TARGET_EINVAL);

	addr = alloca(addrlen + 1);
	ret = target_to_host_sockaddr(addr, target_addr, addrlen);
	if (ret)
		return (ret);

	return get_errno(bind(sockfd, addr, addrlen));
}

/* do_connect() must return target values and target errnos. */
static abi_long
do_connect(int sockfd, abi_ulong target_addr, socklen_t addrlen)
{
	abi_long ret;
	void *addr;

	if ((int)addrlen < 0)
		return (-TARGET_EINVAL);

	addr = alloca(addrlen);

	ret = target_to_host_sockaddr(addr, target_addr, addrlen);

	if (ret)
		return (ret);

	return (get_errno(connect(sockfd, addr, addrlen)));
}

/* do_sendrecvmsg() must return target values and target errnos. */
static abi_long
do_sendrecvmsg(int fd, abi_ulong target_msg, int flags, int send)
{
	abi_long ret, len;
	struct target_msghdr *msgp;
	struct msghdr msg;
	int count;
	struct iovec *vec;
	abi_ulong target_vec;

	if (!lock_user_struct(send ? VERIFY_READ : VERIFY_WRITE, msgp,
		target_msg, send ? 1 : 0))
		return (-TARGET_EFAULT);
	if (msgp->msg_name) {
		msg.msg_namelen = tswap32(msgp->msg_namelen);
		msg.msg_name = alloca(msg.msg_namelen);
		ret = target_to_host_sockaddr(msg.msg_name,
		    tswapal(msgp->msg_name), msg.msg_namelen);

		if (ret) {
			unlock_user_struct(msgp, target_msg, send ? 0 : 1);
			return (ret);
		}
	} else {
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
	}
	msg.msg_controllen = 2 * tswapal(msgp->msg_controllen);
	msg.msg_control = alloca(msg.msg_controllen);
	msg.msg_flags = tswap32(msgp->msg_flags);

	count = tswapal(msgp->msg_iovlen);
	vec = alloca(count * sizeof(struct iovec));
	target_vec = tswapal(msgp->msg_iov);
	lock_iovec(send ? VERIFY_READ : VERIFY_WRITE, vec, target_vec, count,
	    send);
	msg.msg_iovlen = count;
	msg.msg_iov = vec;

	if (send) {
		ret = target_to_host_cmsg(&msg, msgp);
		if (0 == ret)
			ret = get_errno(sendmsg(fd, &msg, flags));
	} else {
		ret = get_errno(recvmsg(fd, &msg, flags));
		if (!is_error(ret)) {
			len = ret;
			ret = host_to_target_cmsg(msgp, &msg);
			if (!is_error(ret)) {
				msgp->msg_namelen = tswap32(msg.msg_namelen);
				if (msg.msg_name != NULL) {
					ret = host_to_target_sockaddr(
					    tswapal(msgp->msg_name),
					    msg.msg_name, msg.msg_namelen);
					if (ret)
						goto out;
				}
			}
			ret = len;
		}
	}
out:
	unlock_iovec(vec, target_vec, count, !send);
	unlock_user_struct(msgp, target_msg, send ? 0 : 1);
	return (ret);
}

/* do_accept() must return target values and target errnos. */
static abi_long
do_accept(int fd, abi_ulong target_addr, abi_ulong target_addrlen_addr)
{
	socklen_t addrlen;
	void *addr;
	abi_long ret;

	if (target_addr == 0)
		return get_errno(accept(fd, NULL, NULL));

	/* return EINVAL if addrlen pointer is invalid */
	if (get_user_u32(addrlen, target_addrlen_addr))
		return (-TARGET_EINVAL);

	if ((int)addrlen < 0)
		return (-TARGET_EINVAL);

	if (!access_ok(VERIFY_WRITE, target_addr, addrlen))
		return -TARGET_EINVAL;

	addr = alloca(addrlen);

	ret = get_errno(accept(fd, addr, &addrlen));
	if (!is_error(ret)) {
		host_to_target_sockaddr(target_addr, addr, addrlen);
		if (put_user_u32(addrlen, target_addrlen_addr))
			ret = (-TARGET_EFAULT);
	}
	return (ret);
}

/* do_getpeername() must return target values and target errnos. */
static abi_long
do_getpeername(int fd, abi_ulong target_addr, abi_ulong target_addrlen_addr)
{
	socklen_t addrlen;
	void *addr;
	abi_long ret;
	if (get_user_u32(addrlen, target_addrlen_addr))
		return (-TARGET_EFAULT);
	if ((int)addrlen < 0) {
		return (-TARGET_EINVAL);
	}
	if (!access_ok(VERIFY_WRITE, target_addr, addrlen))
		return (-TARGET_EFAULT);
	addr = alloca(addrlen);
	ret = get_errno(getpeername(fd, addr, &addrlen));
	if (!is_error(ret)) {
		host_to_target_sockaddr(target_addr, addr, addrlen);
		if (put_user_u32(addrlen, target_addrlen_addr))
			ret = (-TARGET_EFAULT);
	}
	return (ret);
}

/* do_getsockname() must return target values and target errnos. */
static abi_long
do_getsockname(int fd, abi_ulong target_addr, abi_ulong target_addrlen_addr)
{
	socklen_t addrlen;
	void *addr;
	abi_long ret;

	if (get_user_u32(addrlen, target_addrlen_addr))
		return (-TARGET_EFAULT);

	if ((int)addrlen < 0)
		return (-TARGET_EINVAL);

	if (!access_ok(VERIFY_WRITE, target_addr, addrlen))
		return (-TARGET_EFAULT);

	addr = alloca(addrlen);

	ret = get_errno(getsockname(fd, addr, &addrlen));
	if (!is_error(ret)) {
		host_to_target_sockaddr(target_addr, addr, addrlen);
		if (put_user_u32(addrlen, target_addrlen_addr))
			ret = (-TARGET_EFAULT);
	}
	return (ret);
}

/* do_socketpair() must return target values and target errnos. */
static abi_long
do_socketpair(int domain, int type, int protocol, abi_ulong target_tab_addr)
{
	int tab[2];
	abi_long ret;

	ret = get_errno(socketpair(domain, type, protocol, tab));
	if (!is_error(ret)) {
		if (put_user_s32(tab[0], target_tab_addr)
		    || put_user_s32(tab[1], target_tab_addr + sizeof(tab[0])))
			ret = (-TARGET_EFAULT);
	}
	return (ret);
}

/* do_sendto() must return target values and target errnos. */
static abi_long
do_sendto(int fd, abi_ulong msg, size_t len, int flags, abi_ulong target_addr,
    socklen_t addrlen)
{
	struct sockaddr *saddr;
	void *host_msg;
	abi_long ret;

	if ((int)addrlen < 0)
		return (-TARGET_EINVAL);
	host_msg = lock_user(VERIFY_READ, msg, len, 1);
	if (!host_msg)
		return (-TARGET_EFAULT);
	if (target_addr) {
		saddr = alloca(addrlen);
		ret = target_to_host_sockaddr(saddr, target_addr, addrlen);
		if (ret) {
			unlock_user(host_msg, msg, 0);
			return (ret);
		}
		ret = get_errno(sendto(fd, host_msg, len, flags, saddr,
			addrlen));
	} else {
		ret = get_errno(send(fd, host_msg, len, flags));
	}
	unlock_user(host_msg, msg, 0);
	return (ret);
}

/* do_recvfrom() must return target values and target errnos. */
static abi_long
do_recvfrom(int fd, abi_ulong msg, size_t len, int flags, abi_ulong target_addr,
    abi_ulong target_addrlen)
{
	socklen_t addrlen;
	struct sockaddr *saddr;
	void *host_msg;
	abi_long ret;

	host_msg = lock_user(VERIFY_WRITE, msg, len, 0);
	if (!host_msg)
		return (-TARGET_EFAULT);
	if (target_addr) {
		if (get_user_u32(addrlen, target_addrlen)) {
			ret = -TARGET_EFAULT;
			goto fail;
		}
		if ((int)addrlen < 0) {
			ret = (-TARGET_EINVAL);
			goto fail;
		}
		saddr = alloca(addrlen);
		ret = get_errno(recvfrom(fd, host_msg, len, flags, saddr,
			&addrlen));
	} else {
		saddr = NULL; /* To keep compiler quiet.  */
		ret = get_errno(qemu_recv(fd, host_msg, len, flags));
	}
	if (!is_error(ret)) {
		if (target_addr) {
			host_to_target_sockaddr(target_addr, saddr, addrlen);
			if (put_user_u32(addrlen, target_addrlen)) {
				ret = -TARGET_EFAULT;
				goto fail;
			}
		}
		unlock_user(host_msg, msg, len);
	} else {
fail:
		unlock_user(host_msg, msg, 0);
	}
	return (ret);
}

/* do_freebsd_select() must return target values and target errnos. */
static abi_long
do_freebsd_select(int n, abi_ulong rfd_addr, abi_ulong wfd_addr,
    abi_ulong efd_addr, abi_ulong target_tv_addr)
{
	fd_set rfds, wfds, efds;
	fd_set *rfds_ptr, *wfds_ptr, *efds_ptr;
	struct timeval tv, *tv_ptr;
	abi_long ret;

	if ((ret = copy_from_user_fdset_ptr(&rfds, &rfds_ptr, rfd_addr, n)) != 0)
		return (ret);
	if ((ret = copy_from_user_fdset_ptr(&wfds, &wfds_ptr, wfd_addr, n)) != 0)
		return (ret);
	if ((ret = copy_from_user_fdset_ptr(&efds, &efds_ptr, efd_addr, n)) != 0)
		return (ret);

	if (target_tv_addr) {
		if (target_to_host_timeval(&tv, target_tv_addr))
			return (-TARGET_EFAULT);
		tv_ptr = &tv;
	} else {
		tv_ptr = NULL;
	}

	ret = get_errno(select(n, rfds_ptr, wfds_ptr, efds_ptr, tv_ptr));

	if (!is_error(ret)) {
		if (rfd_addr && copy_to_user_fdset(rfd_addr, &rfds, n))
			return (-TARGET_EFAULT);
		if (wfd_addr && copy_to_user_fdset(wfd_addr, &wfds, n))
			return (-TARGET_EFAULT);
		if (efd_addr && copy_to_user_fdset(efd_addr, &efds, n))
			return (-TARGET_EFAULT);

		if (target_tv_addr &&
		    host_to_target_timeval(&tv, target_tv_addr))
			return (-TARGET_EFAULT);
	}

	return (ret);
}

/* do_freebsd_pselect() must return target values and target errnos. */
static abi_long
do_freebsd_pselect(int n, abi_ulong rfd_addr, abi_ulong wfd_addr,
    abi_ulong efd_addr, abi_ulong ts_addr, abi_ulong set_addr)
{
	fd_set rfds, wfds, efds;
	fd_set *rfds_ptr, *wfds_ptr, *efds_ptr;
	sigset_t set, *set_ptr;
	struct timespec ts, *ts_ptr;
	void *p;
	abi_long ret;

	ret = copy_from_user_fdset_ptr(&rfds, &rfds_ptr, rfd_addr, n);
	if (ret)
		return (ret);
	ret = copy_from_user_fdset_ptr(&wfds, &wfds_ptr, wfd_addr, n);
	if (ret)
		return (ret);
	ret = copy_from_user_fdset_ptr(&efds, &efds_ptr, efd_addr, n);
	if (ret)
		return (ret);

	/* Unlike select(), pselect() uses struct timespec instead of timeval */
	if (ts_addr) {
		if (target_to_host_timespec(&ts, ts_addr))
			return (-TARGET_EFAULT);
		ts_ptr = &ts;
	} else {
		ts_ptr = NULL;
	}

	if (set_addr) {
		if (!(p = lock_user(VERIFY_READ, set_addr,
			    sizeof(target_sigset_t), 1)))
			return (-TARGET_EFAULT);
		target_to_host_sigset(&set, p);
		unlock_user(p, set_addr, 0);
		set_ptr = &set;
	} else {
		set_ptr = NULL;
	}

	ret = get_errno(pselect(n, rfds_ptr, wfds_ptr, efds_ptr, ts_ptr,
		set_ptr));

	if (!is_error(ret)) {
		if (rfd_addr && copy_to_user_fdset(rfd_addr, &rfds, n))
			return (-TARGET_EFAULT);
		if (wfd_addr && copy_to_user_fdset(wfd_addr, &wfds, n))
			return (-TARGET_EFAULT);
		if (efd_addr && copy_to_user_fdset(efd_addr, &efds, n))
			return (-TARGET_EFAULT);

		if (ts_addr && host_to_target_timespec(ts_addr, &ts))
			return (-TARGET_EFAULT);
	}

	return (ret);
}

/* do_getsockopt() must return target values and target errnos. */
static abi_long
do_getsockopt(int sockfd, int level, int optname, abi_ulong optval_addr,
    abi_ulong optlen)
{
	abi_long ret;
	int len, val;
	socklen_t lv;

	switch(level) {
	case TARGET_SOL_SOCKET:
		level = SOL_SOCKET;
		switch (optname) {

		/* These don't just return a single integer */
		case TARGET_SO_LINGER:
		case TARGET_SO_RCVTIMEO:
		case TARGET_SO_SNDTIMEO:
		case TARGET_SO_ACCEPTFILTER:
			goto unimplemented;

		/* Options with 'int' argument.  */
		case TARGET_SO_DEBUG:
			optname = SO_DEBUG;
			goto int_case;

		case TARGET_SO_REUSEADDR:
			optname = SO_REUSEADDR;
			goto int_case;

		case TARGET_SO_REUSEPORT:
			optname = SO_REUSEPORT;
			goto int_case;

		case TARGET_SO_TYPE:
			optname = SO_TYPE;
			goto int_case;

		case TARGET_SO_ERROR:
			optname = SO_ERROR;
			goto int_case;

		case TARGET_SO_DONTROUTE:
			optname = SO_DONTROUTE;
			goto int_case;

		case TARGET_SO_BROADCAST:
			optname = SO_BROADCAST;
			goto int_case;

		case TARGET_SO_SNDBUF:
			optname = SO_SNDBUF;
			goto int_case;

		case TARGET_SO_RCVBUF:
			optname = SO_RCVBUF;
			goto int_case;

		case TARGET_SO_KEEPALIVE:
			optname = SO_KEEPALIVE;
			goto int_case;

		case TARGET_SO_OOBINLINE:
			optname = SO_OOBINLINE;
			goto int_case;

		case TARGET_SO_TIMESTAMP:
			optname = SO_TIMESTAMP;
			goto int_case;

		case TARGET_SO_RCVLOWAT:
			optname = SO_RCVLOWAT;
			goto int_case;

		case TARGET_SO_LISTENINCQLEN:
			optname = SO_LISTENINCQLEN;
			goto int_case;

		default:
int_case:
			if (get_user_u32(len, optlen))
				return (-TARGET_EFAULT);
			if (len < 0)
				return (-TARGET_EINVAL);
			lv = sizeof(lv);
			ret = get_errno(getsockopt(sockfd, level, optname,
				&val, &lv));
			if (ret < 0)
				return (ret);
			if (len > lv)
				len = lv;
			if (len == 4) {
				if (put_user_u32(val, optval_addr))
					return (-TARGET_EFAULT);
			} else {
				if (put_user_u8(val, optval_addr))
					return (-TARGET_EFAULT);
			}
			if (put_user_u32(len, optlen))
				return (-TARGET_EFAULT);
			break;

		}
		break;

	case IPPROTO_TCP:
		/* TCP options all take an 'int' value. */
		goto int_case;

	case IPPROTO_IP:
		switch(optname) {
		case IP_HDRINCL:
		case IP_TOS:
		case IP_TTL:
		case IP_RECVOPTS:
		case IP_RECVRETOPTS:
		case IP_RECVDSTADDR:

		case IP_RETOPTS:
#if defined(__FreeBSD_version) && __FreeBSD_version > 900000
		case IP_RECVTOS:
#endif
		case IP_MULTICAST_TTL:
		case IP_MULTICAST_LOOP:
		case IP_PORTRANGE:
		case IP_IPSEC_POLICY:
		case IP_FAITH:
		case IP_ONESBCAST:
		case IP_BINDANY:
			if (get_user_u32(len, optlen))
				return (-TARGET_EFAULT);
			if (len < 0)
				return (-TARGET_EINVAL);
			lv = sizeof(lv);
			ret = get_errno(getsockopt(sockfd, level, optname,
				&val, &lv));
			if (ret < 0)
				return (ret);
			if (len < sizeof(int) && len > 0 && val >= 0 &&
			    val < 255) {
				len = 1;
				if (put_user_u32(len, optlen)
				    || put_user_u8(val, optval_addr))
					return (-TARGET_EFAULT);
			} else {
				if (len > sizeof(int))
					len = sizeof(int);
				if (put_user_u32(len, optlen)
				    || put_user_u32(val, optval_addr))
					return (-TARGET_EFAULT);
			}
			break;

		default:
			goto unimplemented;
		}
		break;

	default:
unimplemented:
		gemu_log("getsockopt level=%d optname=%d not yet supported\n",
		    level, optname);
		ret = (-TARGET_EOPNOTSUPP);
		break;
	}
	return (ret);
}

/* do_setsockopt() must return target values and target errnos. */
static abi_long
do_setsockopt(int sockfd, int level, int optname, abi_ulong optval_addr,
    socklen_t optlen)
{
	abi_long ret;
	int val;
	struct ip_mreqn *ip_mreq;

	switch(level) {
	case IPPROTO_TCP:
		/* TCP options all take an 'int' value. */
		if (optlen < sizeof(uint32_t))
			return (-TARGET_EINVAL);

		if (get_user_u32(val, optval_addr))
			return (-TARGET_EFAULT);
		ret = get_errno(setsockopt(sockfd, level, optname, &val,
			sizeof(val)));
		break;

	case IPPROTO_IP:
		switch (optname) {
		case IP_HDRINCL:/* int; header is included with data */
		case IP_TOS:	/* int; IP type of service and preced. */
		case IP_TTL:	/* int; IP time to live */
		case IP_RECVOPTS: /* bool; receive all IP opts w/dgram */
		case IP_RECVRETOPTS: /* bool; receive IP opts for response */
		case IP_RECVDSTADDR: /* bool; receive IP dst addr w/dgram */
		case IP_MULTICAST_IF:/* u_char; set/get IP multicast i/f  */
		case IP_MULTICAST_TTL:/* u_char; set/get IP multicast ttl */
		case IP_MULTICAST_LOOP:/*u_char;set/get IP multicast loopback */
		case IP_PORTRANGE: /* int; range to choose for unspec port */
		case IP_RECVIF: /* bool; receive reception if w/dgram */
		case IP_IPSEC_POLICY:	/* int; set/get security policy */
		case IP_FAITH:	/* bool; accept FAITH'ed connections */
		case IP_RECVTTL: /* bool; receive reception TTL w/dgram */
			val = 0;
			if (optlen >= sizeof(uint32_t)) {
				if (get_user_u32(val, optval_addr))
					return (-TARGET_EFAULT);
			} else if (optlen >= 1) {
				if (get_user_u8(val, optval_addr))
					return (-TARGET_EFAULT);
			}
			ret = get_errno(setsockopt(sockfd, level, optname,
				&val, sizeof(val)));
			break;

		case IP_ADD_MEMBERSHIP: /*ip_mreq; add an IP group membership */
		case IP_DROP_MEMBERSHIP:/*ip_mreq; drop an IP group membership*/
			if (optlen < sizeof (struct target_ip_mreq) ||
			    optlen > sizeof (struct target_ip_mreqn))
				return (-TARGET_EINVAL);
			ip_mreq = (struct ip_mreqn *) alloca(optlen);
			target_to_host_ip_mreq(ip_mreq, optval_addr, optlen);
			ret = get_errno(setsockopt(sockfd, level, optname,
				ip_mreq, optlen));
			break;

		default:
			goto unimplemented;
		}
		break;


	case TARGET_SOL_SOCKET:
		switch (optname) {
		/* Options with 'int' argument.  */
		case TARGET_SO_DEBUG:
			optname = SO_DEBUG;
			break;

		case TARGET_SO_REUSEADDR:
			optname = SO_REUSEADDR;
			break;

		case TARGET_SO_REUSEPORT:
			optname = SO_REUSEADDR;
			break;

		case TARGET_SO_KEEPALIVE:
			optname = SO_KEEPALIVE;
			break;

		case TARGET_SO_DONTROUTE:
			optname = SO_DONTROUTE;
			break;

		case TARGET_SO_LINGER:
			optname = SO_LINGER;
			break;

		case TARGET_SO_BROADCAST:
			optname = SO_BROADCAST;
			break;

		case TARGET_SO_OOBINLINE:
			optname = SO_OOBINLINE;
			break;

		case TARGET_SO_SNDBUF:
			optname = SO_SNDBUF;
			break;

		case TARGET_SO_RCVBUF:
			optname = SO_RCVBUF;
			break;

		case TARGET_SO_SNDLOWAT:
			optname = SO_RCVLOWAT;
			break;

		case TARGET_SO_RCVLOWAT:
			optname = SO_RCVLOWAT;
			break;

		case TARGET_SO_SNDTIMEO:
			optname = SO_SNDTIMEO;
			break;

		case TARGET_SO_RCVTIMEO:
			optname = SO_RCVTIMEO;
			break;

		case TARGET_SO_ACCEPTFILTER:
			goto unimplemented;

		case TARGET_SO_NOSIGPIPE:
			optname = SO_NOSIGPIPE;
			break;

		case TARGET_SO_TIMESTAMP:
			optname = SO_TIMESTAMP;
			break;

		case TARGET_SO_BINTIME:
			optname = SO_BINTIME;
			break;

		case TARGET_SO_ERROR:
			optname = SO_ERROR;
			break;

		case TARGET_SO_SETFIB:
			optname = SO_ERROR;
			break;

#ifdef SO_USER_COOKIE
		case TARGET_SO_USER_COOKIE:
			optname = SO_USER_COOKIE;
			break;
#endif

		default:
			goto unimplemented;
		}
		if (optlen < sizeof(uint32_t))
			return (-TARGET_EINVAL);
		if (get_user_u32(val, optval_addr))
			return (-TARGET_EFAULT);
		ret = get_errno(setsockopt(sockfd, SOL_SOCKET, optname, &val,
			sizeof(val)));
		break;
	default:
unimplemented:
	gemu_log("Unsupported setsockopt level=%d optname=%d\n",
	    level, optname);
	ret = -TARGET_ENOPROTOOPT;
	}

	return (ret);
}

static inline abi_long
target_to_host_sembuf(struct sembuf *host_sembuf, abi_ulong target_addr,
    unsigned nsops)
{
	struct target_sembuf *target_sembuf;
	int i;

	target_sembuf = lock_user(VERIFY_READ, target_addr,
	    nsops * sizeof(struct target_sembuf), 1);
	if (!target_sembuf)
		return (-TARGET_EFAULT);

	for(i=0; i<nsops; i++) {
		__get_user(host_sembuf[i].sem_num, &target_sembuf[i].sem_num);
		__get_user(host_sembuf[i].sem_op, &target_sembuf[i].sem_op);
		__get_user(host_sembuf[i].sem_flg, &target_sembuf[i].sem_flg);
	}

	unlock_user(target_sembuf, target_addr, 0);

	return (0);
}

static inline abi_long
do_semop(int semid, abi_long ptr, unsigned nsops)
{
	struct sembuf sops[nsops];

	if (target_to_host_sembuf(sops, ptr, nsops))
		return (-TARGET_EFAULT);

	return semop(semid, sops, nsops);
}

static inline abi_long
target_to_host_semarray(int semid, unsigned short **host_array,
    abi_ulong target_addr)
{
	int nsems;
	unsigned short *array;
	union semun semun;
	struct semid_ds semid_ds;
	int i, ret;

	semun.buf = &semid_ds;
	ret = semctl(semid, 0, IPC_STAT, semun);
	if (ret == -1)
		return (get_errno(ret));
	nsems = semid_ds.sem_nsems;
	*host_array = (unsigned short *)malloc(nsems * sizeof(unsigned short));
	array = lock_user(VERIFY_READ, target_addr,
	    nsems*sizeof(unsigned short), 1);
	if (!array) {
		free(*host_array);
		return (-TARGET_EFAULT);
	}
	for(i=0; i<nsems; i++) {
		(*host_array)[i] = array[i];
	}
	unlock_user(array, target_addr, 0);

	return (0);
}

static inline abi_long
host_to_target_semarray(int semid, abi_ulong target_addr,
    unsigned short **host_array)
{
	int nsems;
	unsigned short *array;
	union semun semun;
	struct semid_ds semid_ds;
	int i, ret;

	semun.buf = &semid_ds;

	ret = semctl(semid, 0, IPC_STAT, semun);
	if (ret == -1) {
		free(*host_array);
		return get_errno(ret);
	}

	nsems = semid_ds.sem_nsems;
	array = (unsigned short *)lock_user(VERIFY_WRITE, target_addr,
	    nsems*sizeof(unsigned short), 0);
	 if (!array) {
		 free(*host_array);
		 return (-TARGET_EFAULT);
	 }

	 for(i=0; i<nsems; i++) {
		 array[i] = (*host_array)[i];
	 }
	 free(*host_array);
	 unlock_user(array, target_addr, 1);

	 return (0);
}

static inline abi_long
target_to_host_ipc_perm(struct ipc_perm *host_ip, abi_ulong target_addr)
{
	struct target_ipc_perm *target_ip;

	if (!lock_user_struct(VERIFY_READ, target_ip, target_addr, 1))
		return (-TARGET_EFAULT);
	host_ip->cuid = tswap32(target_ip->cuid);
	host_ip->cgid = tswap32(target_ip->cgid);
	host_ip->uid = tswap32(target_ip->uid);
	host_ip->gid = tswap32(target_ip->gid);
	host_ip->mode = tswap16(target_ip->mode);
	host_ip->seq = tswap16(target_ip->seq);
	host_ip->key = tswapal(target_ip->key);
	unlock_user_struct(target_ip, target_addr, 0);

	return (0);
}

static inline abi_long
host_to_target_ipc_perm(abi_ulong target_addr, struct ipc_perm *host_ip)
{
	struct target_ipc_perm *target_ip;

	if (!lock_user_struct(VERIFY_WRITE, target_ip, target_addr, 0))
		return (-TARGET_EFAULT);
	target_ip->cuid = tswap32(host_ip->cuid);
	target_ip->cgid = tswap32(host_ip->cgid);
	target_ip->uid = tswap32(host_ip->uid);
	target_ip->gid = tswap32(host_ip->gid);
	target_ip->mode = tswap16(host_ip->mode);
	target_ip->seq = tswap16(host_ip->seq);
	target_ip->key = tswapal(host_ip->key);
	unlock_user_struct(target_ip, target_addr, 1);
	return (0);
}

static inline abi_long
target_to_host_semid_ds(struct semid_ds *host_sd, abi_ulong target_addr)
{
	struct target_semid_ds *target_sd;

	if (!lock_user_struct(VERIFY_READ, target_sd, target_addr, 1))
		return (-TARGET_EFAULT);
	if (target_to_host_ipc_perm(&(host_sd->sem_perm), (target_addr +
		offsetof(struct target_semid_ds, sem_perm)) ))
		return (-TARGET_EFAULT);
	/* sem_base is not used by kernel for IPC_STAT/IPC_SET */
	/* host_sd->sem_base  = g2h(target_sd->sem_base); */
	host_sd->sem_nsems = tswap16(target_sd->sem_nsems);
	host_sd->sem_otime = tswapal(target_sd->sem_otime);
	host_sd->sem_ctime = tswapal(target_sd->sem_ctime);
	unlock_user_struct(target_sd, target_addr, 0);
	return (0);
}

static inline abi_long
host_to_target_semid_ds(abi_ulong target_addr, struct semid_ds *host_sd)
{
	struct target_semid_ds *target_sd;

	if (!lock_user_struct(VERIFY_WRITE, target_sd, target_addr, 0))
		return (-TARGET_EFAULT);
	if (host_to_target_ipc_perm((target_addr +
		offsetof(struct target_semid_ds, sem_perm)),
		&(host_sd->sem_perm)))
		return (-TARGET_EFAULT);
	/* sem_base is not used by kernel for IPC_STAT/IPC_SET */
	/* target_sd->sem_base = h2g((void *)host_sd->sem_base); */
	target_sd->sem_nsems = tswap16(host_sd->sem_nsems);
	target_sd->sem_otime = tswapal(host_sd->sem_otime);
	target_sd->sem_ctime = tswapal(host_sd->sem_ctime);
	unlock_user_struct(target_sd, target_addr, 1);

	return (0);
}

static inline abi_long
do_semctl(int semid, int semnum, int cmd, union target_semun target_su)
{
	union semun arg;
	struct semid_ds dsarg;
	unsigned short *array = NULL;
	abi_long ret = -TARGET_EINVAL;
	abi_long err;
	abi_ulong target_addr;

	cmd &= 0xff;

	switch( cmd ) {
	case GETVAL:
	case SETVAL:
		arg.val = tswap32(target_su.val);
		ret = get_errno(semctl(semid, semnum, cmd, arg));
		target_su.val = tswap32(arg.val);
		break;

	case GETALL:
	case SETALL:
		if (get_user_ual(target_addr, (abi_ulong)target_su.array))
			return (-TARGET_EFAULT);
		err = target_to_host_semarray(semid, &array, target_addr);
		if (err)
			return (err);
		arg.array = array;
		ret = get_errno(semctl(semid, semnum, cmd, arg));
		err = host_to_target_semarray(semid, target_addr, &array);
		if (err)
			return (err);
		break;

	case IPC_STAT:
	case IPC_SET:
		if (get_user_ual(target_addr, (abi_ulong)target_su.buf))
			return (-TARGET_EFAULT);
		err = target_to_host_semid_ds(&dsarg, target_addr);
		if (err)
			return (err);
		arg.buf = &dsarg;
		ret = get_errno(semctl(semid, semnum, cmd, arg));
		err = host_to_target_semid_ds(target_addr, &dsarg);
		if (err)
			return (err);
		break;

	case IPC_RMID:
	case GETPID:
	case GETNCNT:
	case GETZCNT:
		ret = get_errno(semctl(semid, semnum, cmd, NULL));
		break;

	default:
		ret = -TARGET_EINVAL;
		break;
	}
	return (ret);
}

#define N_SHM_REGIONS	32

static struct shm_regions {
	abi_long	start;
	abi_long	size;
} shm_regions[N_SHM_REGIONS];

static inline abi_ulong
do_shmat(int shmid, abi_ulong shmaddr, int shmflg)
{
	abi_long raddr;
	void *host_raddr;
	struct shmid_ds shm_info;
	int i,ret;

	/* Find out the length of the shared memory segment. */
	ret = get_errno(shmctl(shmid, IPC_STAT, &shm_info));
	if (is_error(ret)) {
		/* Can't get the length */
		return (ret);
	}

	mmap_lock();

	if (shmaddr) {
		host_raddr = shmat(shmid, (void *)g2h(shmaddr), shmflg);
	} else {
		abi_ulong mmap_start;

		mmap_start = mmap_find_vma(0, shm_info.shm_segsz);

		if (mmap_start == -1) {
			errno = ENOMEM;
			host_raddr = (void *)-1;
		} else {
			host_raddr = shmat(shmid, g2h(mmap_start),
			    shmflg /* | SHM_REMAP */);
		}
	}

	if (host_raddr == (void *)-1) {
		mmap_unlock();
		return get_errno((long)host_raddr);
	}
	raddr=h2g((unsigned long)host_raddr);

	page_set_flags(raddr, raddr + shm_info.shm_segsz,
	    PAGE_VALID | PAGE_READ | ((shmflg & SHM_RDONLY)? 0 : PAGE_WRITE));

	for (i = 0; i < N_SHM_REGIONS; i++) {
		if (shm_regions[i].start == 0) {
			shm_regions[i].start = raddr;
			shm_regions[i].size = shm_info.shm_segsz;
			break;
		}
	}

	mmap_unlock();
	return (raddr);
}

static inline abi_long
do_shmdt(abi_ulong shmaddr)
{
	int i;

	for (i = 0; i < N_SHM_REGIONS; ++i) {
		if (shm_regions[i].start == shmaddr) {
			shm_regions[i].start = 0;
			page_set_flags(shmaddr,
			    shmaddr + shm_regions[i].size, 0);
			break;
		}
	}

	return ( get_errno(shmdt(g2h(shmaddr))) );
}

static inline abi_long
target_to_host_shmid_ds(struct shmid_ds *host_sd, abi_ulong target_addr)
{
	struct target_shmid_ds *target_sd;

	if (!lock_user_struct(VERIFY_READ, target_sd, target_addr, 1))
		return (-TARGET_EFAULT);
	if (target_to_host_ipc_perm(&(host_sd->shm_perm), target_addr))
		return (-TARGET_EFAULT);
	__get_user(host_sd->shm_segsz, &target_sd->shm_segsz);
	__get_user(host_sd->shm_lpid, &target_sd->shm_lpid);
	__get_user(host_sd->shm_cpid, &target_sd->shm_cpid);
	__get_user(host_sd->shm_nattch, &target_sd->shm_nattch);
	__get_user(host_sd->shm_atime, &target_sd->shm_atime);
	__get_user(host_sd->shm_dtime, &target_sd->shm_dtime);
	__get_user(host_sd->shm_ctime, &target_sd->shm_ctime);
	unlock_user_struct(target_sd, target_addr, 0);
	return (0);
}

static inline abi_long
host_to_target_shmid_ds(abi_ulong target_addr, struct shmid_ds *host_sd)
{
	struct target_shmid_ds *target_sd;

	if (!lock_user_struct(VERIFY_WRITE, target_sd, target_addr, 0))
		return (-TARGET_EFAULT);
	if (host_to_target_ipc_perm(target_addr, &(host_sd->shm_perm)))
		return (-TARGET_EFAULT);
	__put_user(host_sd->shm_segsz, &target_sd->shm_segsz);
	__put_user(host_sd->shm_lpid, &target_sd->shm_lpid);
	__put_user(host_sd->shm_cpid, &target_sd->shm_cpid);
	__put_user(host_sd->shm_nattch, &target_sd->shm_nattch);
	__put_user(host_sd->shm_atime, &target_sd->shm_atime);
	__put_user(host_sd->shm_dtime, &target_sd->shm_dtime);
	__put_user(host_sd->shm_ctime, &target_sd->shm_ctime);
	unlock_user_struct(target_sd, target_addr, 1);
	return (0);
}

static inline abi_long
do_shmctl(int shmid, int cmd, abi_long buff)
{
	struct shmid_ds dsarg;
	abi_long ret = -TARGET_EINVAL;

	cmd &= 0xff;

	switch(cmd) {
	case IPC_STAT:
	case IPC_SET:
		if (target_to_host_shmid_ds(&dsarg, buff))
			return (-TARGET_EFAULT);
		ret = get_errno(shmctl(shmid, cmd, &dsarg));
		if (host_to_target_shmid_ds(buff, &dsarg))
			return (-TARGET_EFAULT);
		break;

	case IPC_RMID:
		ret = get_errno(shmctl(shmid, cmd, NULL));
		break;

	default:
		ret = -TARGET_EINVAL;
		break;
	}

	return (ret);
}

static inline abi_long
target_to_host_msqid_ds(struct msqid_ds *host_md, abi_ulong target_addr)
{
	struct target_msqid_ds *target_md;

	if (!lock_user_struct(VERIFY_READ, target_md, target_addr, 1))
		return (-TARGET_EFAULT);
	if (target_to_host_ipc_perm(&(host_md->msg_perm),target_addr))
		return (-TARGET_EFAULT);

	/* msg_first and msg_last are not used by IPC_SET/IPC_STAT in kernel. */
	host_md->msg_first = host_md->msg_last = NULL;

	host_md->msg_cbytes = tswapal(target_md->msg_cbytes);
	host_md->msg_qnum = tswapal(target_md->msg_qnum);
	host_md->msg_qbytes = tswapal(target_md->msg_qbytes);
	host_md->msg_lspid = tswapal(target_md->msg_lspid);
	host_md->msg_lrpid = tswapal(target_md->msg_lrpid);
	host_md->msg_stime = tswapal(target_md->msg_stime);
	host_md->msg_rtime = tswapal(target_md->msg_rtime);
	host_md->msg_ctime = tswapal(target_md->msg_ctime);
	unlock_user_struct(target_md, target_addr, 0);

	return (0);
}

static inline abi_long
host_to_target_msqid_ds(abi_ulong target_addr, struct msqid_ds *host_md)
{
	struct target_msqid_ds *target_md;

	if (!lock_user_struct(VERIFY_WRITE, target_md, target_addr, 0))
		return (-TARGET_EFAULT);
	if (host_to_target_ipc_perm(target_addr,&(host_md->msg_perm)))
		return (-TARGET_EFAULT);

	/* msg_first and msg_last are not used by IPC_SET/IPC_STAT in kernel. */
	target_md->msg_cbytes = tswapal(host_md->msg_cbytes);
	target_md->msg_qnum = tswapal(host_md->msg_qnum);
	target_md->msg_qbytes = tswapal(host_md->msg_qbytes);
	target_md->msg_lspid = tswapal(host_md->msg_lspid);
	target_md->msg_lrpid = tswapal(host_md->msg_lrpid);
	target_md->msg_stime = tswapal(host_md->msg_stime);
	target_md->msg_rtime = tswapal(host_md->msg_rtime);
	target_md->msg_ctime = tswapal(host_md->msg_ctime);
	unlock_user_struct(target_md, target_addr, 1);

	return (0);
}

static inline abi_long
do_msgctl(int msgid, int cmd, abi_long ptr)
{
	struct msqid_ds dsarg;
	abi_long ret = -TARGET_EINVAL;

	cmd &= 0xff;

	switch (cmd) {
	case IPC_STAT:
	case IPC_SET:
		if (target_to_host_msqid_ds(&dsarg,ptr))
			return -TARGET_EFAULT;
		ret = get_errno(msgctl(msgid, cmd, &dsarg));
		if (host_to_target_msqid_ds(ptr,&dsarg))
			return -TARGET_EFAULT;
		break;

	case IPC_RMID:
		ret = get_errno(msgctl(msgid, cmd, NULL));
		break;

	default:
		ret = -TARGET_EINVAL;
		break;
	}
	return (ret);
}

static inline abi_long
do_msgsnd(int msqid, abi_long msgp, unsigned int msgsz, int msgflg)
{
	struct target_msgbuf *target_mb;
	struct mymsg *host_mb;
	abi_long ret = 0;

	if (!lock_user_struct(VERIFY_READ, target_mb, msgp, 0))
		return (-TARGET_EFAULT);

	host_mb = malloc(msgsz+sizeof(long));
	host_mb->mtype = (abi_long) tswapal(target_mb->mtype);
	memcpy(host_mb->mtext, target_mb->mtext, msgsz);
	ret = get_errno(msgsnd(msqid, host_mb, msgsz, msgflg));
	free(host_mb);
	unlock_user_struct(target_mb, msgp, 0);

	return (ret);
}

static inline abi_long
do_msgrcv(int msqid, abi_long msgp, unsigned int msgsz, abi_long msgtyp,
    int msgflg)
{
	struct target_msgbuf *target_mb;
	char *target_mtext;
	struct mymsg *host_mb;
	abi_long ret = 0;

	if (!lock_user_struct(VERIFY_WRITE, target_mb, msgp, 0))
		return (-TARGET_EFAULT);

	host_mb = g_malloc(msgsz+sizeof(long));
	ret = get_errno(msgrcv(msqid, host_mb, msgsz, tswapal(msgtyp), msgflg));
	if (ret > 0) {
		abi_ulong target_mtext_addr = msgp + sizeof(abi_ulong);
		target_mtext = lock_user(VERIFY_WRITE, target_mtext_addr,
		    ret, 0);
		if (!target_mtext) {
			ret = -TARGET_EFAULT;
			goto end;
		}
		memcpy(target_mb->mtext, host_mb->mtext, ret);
		unlock_user(target_mtext, target_mtext_addr, ret);
	}
	target_mb->mtype = tswapal(host_mb->mtype);
end:
	if (target_mb)
		unlock_user_struct(target_mb, msgp, 1);
	g_free(host_mb);
	return (ret);
}

static void
set_second_rval(CPUArchState *env, abi_ulong retval2)
{
#if defined(TARGET_ALPHA)
	((CPUAlphaState *)env)->ir[IR_A4] = retval2;
#elif defined(TARGET_ARM)
	((CPUARMState *)env)->regs[1] = retval2;
#elif defined(TARGET_MIPS)
	((CPUMIPSState*)env)->active_tc.gpr[3] = retval2;
#elif defined(TARGET_SH4)
	((CPUSH4State*)env)->gregs[1] = retval2;
#elif defined(TARGET_X86_64) || defined(TARGET_I386)
	((CPUX86State*)env)->regs[R_EDX] = retval2;
#elif defined(TARGET_SPARC64) || defined(TARGET_SPARC)
	((CPUSPARCState*)env)->regwptr[1] = retval2;
#else
#warning Arch not supported for returning multiple values from syscall.
#endif
}

/*
 * do_fock() must return host values and target errnos (unlike most do_*()
 * functions.
 */
static int
do_fork(CPUArchState *env, int num, int flags, int *fdp)
{
	int ret, fd;
	abi_ulong child_flag = 0;

	fork_start();
	switch(num) {
	case TARGET_FREEBSD_NR_fork:
	case TARGET_FREEBSD_NR_vfork:
		ret = fork();
		break;

	case TARGET_FREEBSD_NR_rfork:
		ret = rfork(flags);
		break;

#if defined(__FreeBSD_version) && __FreeBSD_version > 900000
	case TARGET_FREEBSD_NR_pdfork:
		ret = pdfork(&fd, flags);
		break;
#endif

	default:
		ret = -TARGET_ENOSYS;
		break;
	}
	if (0 == ret) {
		/* Child */
		child_flag = 1;
		cpu_clone_regs(env, 0);
	} else {
		/* Parent */
		fork_end(0);
	}
	if (fdp != NULL)
		*fdp = fd;

	/*
	 * The fork() syscall sets a child flag in 2nd return value:
	 *   0 for parent process, 1 for child process
	 */
	set_second_rval(env, child_flag);

	return (ret);
}

#if defined(CONFIG_USE_NPTL)

#define NEW_STACK_SIZE	(0x40000)

static pthread_mutex_t new_thread_lock = PTHREAD_MUTEX_INITIALIZER;
typedef struct {
	CPUArchState *env;
	long parent_tid;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	pthread_t thread;
	sigset_t sigmask;
	struct target_thr_param param;
} new_thread_info_t;

static void *
new_thread_start(void *arg)
{
	new_thread_info_t *info = arg;
	CPUArchState *env;
	TaskState *ts;
	long tid;

	env = info->env;
	thread_env = env;
	fork_end(1);

	ts = (TaskState *)thread_env->opaque;
	(void)thr_self(&tid);
	task_settid(ts);

	/* copy out the TID info */
	if (info->param.child_tid)
		put_user(tid, info->param.child_tid, abi_long);
	if (info->param.parent_tid)
		put_user(info->parent_tid, info->param.parent_tid, abi_long);

	/* Set arch dependent registers to start thread. */
	thread_set_upcall(env, info->param.start_func, info->param.arg,
	    info->param.stack_base, info->param.stack_size);

	/* Enable signals */
	sigprocmask(SIG_SETMASK, &info->sigmask, NULL);
	/* Signal to the parent that we're ready. */
	pthread_mutex_lock(&info->mutex);
	pthread_cond_broadcast(&info->cond);
	pthread_mutex_unlock(&info->mutex);
	/* Wait until the parent has finished initializing the TLS state. */
	pthread_mutex_lock(&new_thread_lock);
	pthread_mutex_unlock(&new_thread_lock);

	cpu_loop(env);
	/* never exits */

	return (NULL);
}

static void
rtp_to_schedparam(const struct rtprio *rtp, int *policy, struct sched_param *param)
{

	switch(rtp->type) {
	case RTP_PRIO_REALTIME:
		*policy = SCHED_RR;
		param->sched_priority = RTP_PRIO_MAX - rtp->prio;
		break;

	case RTP_PRIO_FIFO:
		*policy = SCHED_FIFO;
		param->sched_priority = RTP_PRIO_MAX - rtp->prio;
		break;

	default:
		*policy = SCHED_OTHER;
		param->sched_priority = 0;
		break;
	}
}

static int
do_thr_create(CPUArchState *env, ucontext_t *ctx, long *id, int flags)
{

	return (unimplemented(TARGET_FREEBSD_NR_thr_create));
}

static int
do_thr_new(CPUArchState *env, abi_ulong target_param_addr, int32_t param_size)
{
	new_thread_info_t info;
	pthread_attr_t attr;
	TaskState *ts;
	CPUArchState *new_env;
	struct target_thr_param *target_param;
	abi_ulong target_rtp_addr;
	struct target_rtprio *target_rtp;
	struct rtprio *rtp_ptr, rtp;
	TaskState *parent_ts = (TaskState *)env->opaque;
	sigset_t sigmask;
	struct sched_param sched_param;
	int sched_policy;
	int ret = 0;

	memset(&info, 0, sizeof(info));

	if (!lock_user_struct(VERIFY_READ, target_param, target_param_addr, 1))
		return (-TARGET_EFAULT);
	info.param.start_func = tswapal(target_param->start_func);
	info.param.arg = tswapal(target_param->arg);
	info.param.stack_base = tswapal(target_param->stack_base);
	info.param.stack_size = tswapal(target_param->stack_size);
	info.param.tls_base = tswapal(target_param->tls_base);
	info.param.tls_size = tswapal(target_param->tls_size);
	info.param.child_tid = tswapal(target_param->child_tid);
	info.param.parent_tid = tswapal(target_param->parent_tid);
	info.param.flags = tswap32(target_param->flags);
	target_rtp_addr = info.param.rtp = tswapal(target_param->rtp);
	unlock_user(target_param, target_param_addr, 0);

	thr_self(&info.parent_tid);

	if (target_rtp_addr) {
		if (!lock_user_struct(VERIFY_READ, target_rtp, target_rtp_addr,
			1))
			return (-TARGET_EFAULT);
		rtp.type = tswap16(target_rtp->type);
		rtp.prio = tswap16(target_rtp->prio);
		unlock_user(target_rtp, target_rtp_addr, 0);
		rtp_ptr = &rtp;
	} else {
		rtp_ptr = NULL;
	}

	/* Create a new CPU instance. */
	fork_start();
	ts = g_malloc0(sizeof(TaskState));
	init_task_state(ts);
	new_env = cpu_copy(env);
#if defined(TARGET_I386) || defined(TARGET_SPARC) || defined(TARGET_PPC)
	cpu_reset(ENV_GET_CPU(new_env));
#endif

	/* init regs that differ from the parent thread. */
	cpu_clone_regs(new_env, info.param.stack_base);
	new_env->opaque = ts;
	ts->bprm = parent_ts->bprm;
	ts->info = parent_ts->info;

#if defined(TARGET_MIPS) || defined(TARGET_ARM)
	cpu_set_tls(env, info.param.tls_base);
#endif

	/* Grab a mutex so that thread setup appears atomic. */
	pthread_mutex_lock(&new_thread_lock);

	pthread_mutex_init(&info.mutex, NULL);
	pthread_mutex_lock(&info.mutex);
	pthread_cond_init(&info.cond, NULL);
	info.env = new_env;

	/* XXX return value needs to be checked... */
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, NEW_STACK_SIZE);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (rtp_ptr) {
		rtp_to_schedparam(&rtp, &sched_policy, &sched_param);
		pthread_attr_setschedpolicy(&attr, sched_policy);
		pthread_attr_setschedparam(&attr, &sched_param);
	}

	/*
	 * It is not safe to deliver signals until the child has finished
	 * initializing, so temporarily block all signals.
	 */
	sigfillset(&sigmask);
	sigprocmask(SIG_BLOCK, &sigmask, &info.sigmask);

	/* XXX return value needs to be checked... */
	ret = pthread_create(&info.thread, &attr, new_thread_start, &info);
	/* XXX Free new CPU state if thread creation fails. */

	fork_end(0);

	sigprocmask(SIG_SETMASK, &info.sigmask, NULL);
	pthread_attr_destroy(&attr);
	if (0 == ret) {
		/* Wait for the child to initialize. */
		pthread_cond_wait(&info.cond, &info.mutex);
	} else {
		/* pthread_create failed. */
	}

	pthread_mutex_unlock(&info.mutex);
	pthread_cond_destroy(&info.cond);
	pthread_mutex_destroy(&info.mutex);
	pthread_mutex_unlock(&new_thread_lock);

	return (ret);
}

static int
do_thr_self(long *id)
{

	return (get_errno(thr_self(id)));
}

static void
do_thr_exit(CPUArchState *cpu_env, abi_ulong tid_addr)
{

	if (first_cpu->next_cpu) {
		TaskState *ts;
		CPUArchState **lastp, *p;

		/*
		 * *XXX This probably breaks if a signal arrives.
		 * We should disable signals.
		 */
		cpu_list_lock();
		lastp = &first_cpu;
		p = first_cpu;
		while (p && p != (CPUArchState *)cpu_env) {
			lastp = &p->next_cpu;
			p = p->next_cpu;
		}
		/*
		 * if we didn't find the CPU for this thread then something
		 * is horribly wrong.
		 */
		if (!p)
			abort();
		/* Remove the CPU from the list. */
		*lastp = p->next_cpu;
		cpu_list_unlock();
		ts = ((CPUArchState *)cpu_env)->opaque;

		if (tid_addr) {
			/* Signal target userland that it can free the stack. */
			if (! put_user_sal(1, tid_addr))
				_umtx_op(g2h(tid_addr), UMTX_OP_WAKE, INT_MAX,
				    NULL, NULL);
		}

		thread_env = NULL;
		object_unref(OBJECT(ENV_GET_CPU(cpu_env)));
		g_free(ts);
		pthread_exit(NULL);
	}

	gdb_exit(cpu_env, 0);	/* XXX need to put in the correct exit status here? */
	_exit(0);
}

static int
do_thr_kill(long id, int sig)
{

	return (get_errno(thr_kill(id, sig)));
}

static int
do_thr_kill2(pid_t pid, long id, int sig)
{

	return (get_errno(thr_kill2(pid, id, sig)));
}

static int
do_thr_suspend(const struct timespec *timeout)
{

	return (get_errno(thr_suspend(timeout)));
}

static int
do_thr_wake(long tid)
{

	return (get_errno(thr_wake(tid)));
}

static int
do_thr_set_name(long tid, char *name)
{

	 return (get_errno(thr_set_name(tid, name)));
}


#else /* ! CONFIG_USE_NPTL */

static int
do_thr_create(CPUArchState *env, ucontext_t *ctx, long *id, int flags)
{
	return (unimplemented(TARGET_FREEBSD_NR_thr_create));
}

static int
do_thr_new(CPUArchState *env, abi_ulong target_param_addr, int32_t param_size)
{
	return (unimplemented(TARGET_FREEBSD_NR_thr_new));
}

static int
do_thr_self(long *tid)
{
	return (unimplemented(TARGET_FREEBSD_NR_thr_self));
}

static void
do_thr_exit(CPUArchState *cpu_env, abi_ulong state_addr)
{
}

static int
do_thr_kill(long tid, int sig)
{
	return (unimplemented(TARGET_FREEBSD_NR_thr_kill2));
}

static int
do_thr_kill2(pid_t pid, long tid, int sig)
{
	return (unimplemented(TARGET_FREEBSD_NR_thr_kill2));
}

static int
do_thr_suspend(const struct timespec *timeout)
{
	return (unimplemented(TARGET_FREEBSD_NR_thr_suspend));
}

static int
do_thr_wake(long tid)
{
	return (unimplemented(TARGET_FREEBSD_NR_thr_wake));
}

static int
do_thr_set_name(long tid, char *name)
{
	return (unimplemented(TARGET_FREEBSD_NR_thr_set_name));
}

#endif /* CONFIG_USE_NPTL */

static int
tcmpset_al(abi_ulong *addr, abi_ulong a, abi_ulong b)
{
	abi_ulong current = tswapal(a);
	abi_ulong new = tswapal(b);

#ifdef TARGET_ABI32
	return (atomic_cmpset_acq_32(addr, current, new));
#else
	return (atomic_cmpset_acq_64(addr, current, new));
#endif
}

static int
tcmpset_32(uint32_t *addr, uint32_t a, uint32_t b)
{
	uint32_t current = tswap32(a);
	uint32_t new = tswap32(b);

	return (atomic_cmpset_acq_32(addr, current, new));
}

static int
do_lock_umtx(abi_ulong target_addr, abi_long id, struct timespec *timeout)
{
	abi_long owner;
	int ret;

	/*
	 * XXX Note that memory at umtx_addr can change and so we need to be
	 * careful and check for faults.
	 */
	for (;;) {
		struct target_umtx *target_umtx;

		if (!lock_user_struct(VERIFY_WRITE, target_umtx, target_addr, 0))
			return (-TARGET_EFAULT);

		/* Check the simple uncontested case. */
		if (tcmpset_al(&target_umtx->u_owner,
				TARGET_UMTX_UNOWNED, id)) {
			unlock_user_struct(target_umtx, target_addr, 1);
			return (0);
		}

		/* Check to see if the lock is contested but free. */
		__get_user(owner, &target_umtx->u_owner);

		if (TARGET_UMTX_CONTESTED == owner) {
			if (tcmpset_al(&target_umtx->u_owner,
					TARGET_UMTX_CONTESTED,
					id | TARGET_UMTX_CONTESTED)) {
				unlock_user_struct(target_umtx, target_addr, 1);
				return (0);
			}

			/* We failed because it changed on us, restart. */
			unlock_user_struct(target_umtx, target_addr, 1);
			continue;
		}

		/* Set the contested bit and sleep. */
		do {
			__get_user(owner, &target_umtx->u_owner);
			if (owner & TARGET_UMTX_CONTESTED)
				break;
		} while (!tcmpset_al(&target_umtx->u_owner, owner,
			owner | TARGET_UMTX_CONTESTED));

		__get_user(owner, &target_umtx->u_owner);
		unlock_user_struct(target_umtx, target_addr, 1);

		/* Byte swap, if needed, to match what is stored in user mem. */
		owner = tswapal(owner);
#ifdef TARGET_ABI32
		ret = get_errno(_umtx_op(target_umtx, UMTX_OP_WAIT_UINT, owner,
			NULL, timeout));
#else
		ret = get_errno(_umtx_op(target_umtx, UMTX_OP_WAIT, owner,
			NULL, timeout));
#endif
		if (ret)
			return (ret);
	}
}

static int
do_unlock_umtx(abi_ulong target_addr, abi_ulong id)
{
	abi_ulong owner;
	struct target_umtx *target_umtx;

	if (!lock_user_struct(VERIFY_WRITE, target_umtx, target_addr, 0))
		return (-TARGET_EFAULT);

	__get_user(owner, &target_umtx->u_owner);
	if ((owner & ~TARGET_UMTX_CONTESTED) != id) {
		unlock_user_struct(target_umtx, target_addr, 1);
		return (-TARGET_EPERM);
	}

	/* Check the simple uncontested case. */
	if ((owner & ~TARGET_UMTX_CONTESTED) == 0)
		if (tcmpset_al(&target_umtx->u_owner, owner,
			TARGET_UMTX_UNOWNED)) {
			unlock_user_struct(target_umtx, target_addr, 1);
			return (0);
		}

	/* This is a contested lock. Unlock it. */
	__put_user(TARGET_UMTX_UNOWNED, &target_umtx->u_owner);
	unlock_user_struct(target_umtx, target_addr, 1);

	/* Wake up all those contesting it. */
	_umtx_op(target_umtx, UMTX_OP_WAKE, 0, 0, 0);

	return (0);
}

static int
do_lock_umutex(abi_ulong target_addr, uint32_t id, struct timespec *ts,
    int mode)
{
	uint32_t owner, flags;
	int ret = 0;

	for (;;) {
		struct target_umutex *target_umutex;

		if (!lock_user_struct(VERIFY_WRITE, target_umutex,
			target_addr, 0))
			return (-TARGET_EFAULT);

		__get_user(owner, &target_umutex->m_owner);

		if (TARGET_UMUTEX_WAIT == mode) {
			if (TARGET_UMUTEX_UNOWNED == owner ||
			    TARGET_UMUTEX_CONTESTED == owner)
				unlock_user_struct(target_umutex,
				    target_addr, 1);
				return (0);
		} else {
			if (tcmpset_32(&target_umutex->m_owner,
				TARGET_UMUTEX_UNOWNED, id)) {
				/* The acquired succeeded. */
				unlock_user_struct(target_umutex,
				    target_addr, 1);
				return (0);
			}

			/*
			 * If no one owns it but it is contested try to acquire
			 * it.
			 */
			if (TARGET_UMUTEX_CONTESTED == owner) {
				if (tcmpset_32(&target_umutex->m_owner,
					TARGET_UMUTEX_CONTESTED,
					id | TARGET_UMUTEX_CONTESTED)) {

					unlock_user_struct(target_umutex,
					    target_addr, 1);
					return (0);
				}

				/* The lock changed so restart. */
				unlock_user_struct(target_umutex,
				    target_addr, 1);
				continue;
			}
		}

		__get_user(flags, &target_umutex->m_flags);
		if ((flags & TARGET_UMUTEX_ERROR_CHECK) != 0 &&
		    (owner & ~TARGET_UMUTEX_CONTESTED) == id) {
			unlock_user_struct(target_umutex, target_addr, 1);
			return (-TARGET_EDEADLK);
		}

		if (TARGET_UMUTEX_TRY == mode) {
			unlock_user_struct(target_umutex, target_addr, 1);
			return (-TARGET_EBUSY);
		}

		/*
		 * If we caught a signal, we have retried and now
		 * exit immediately.
		 */
		if (ret) {
			unlock_user_struct(target_umutex, target_addr, 1);
			return (ret);
		}

		/* Set the contested bit and sleep. */
		if (!tcmpset_32(&target_umutex->m_owner, owner,
			owner | TARGET_UMUTEX_CONTESTED)) {
			unlock_user_struct(target_umutex, target_addr, 1);
			continue;
		}

		owner = owner | TARGET_UMUTEX_CONTESTED;
		unlock_user_struct(target_umutex, target_addr, 1);

		/* Byte swap, if needed, to match what is stored in user mem. */
		owner = tswap32(owner);
		ret = get_errno(_umtx_op(target_umutex, UMTX_OP_WAIT_UINT, owner,
			0, ts));
	}

	if (NULL == ts) {
		/*
		 * In the case of no timeout do a restart on this syscall,
		 * if interrupted.
		 */
		if (-TARGET_EINTR == ret)
			ret = -TARGET_ERESTART;
	}

	return (0);
}

static int
do_unlock_umutex(abi_ulong target_addr, uint32_t id)
{
	struct target_umutex *target_umutex;
	uint32_t owner;


	if (!lock_user_struct(VERIFY_WRITE, target_umutex, target_addr, 0))
		return (-TARGET_EFAULT);

	/* Make sure we own this mutex. */
	__get_user(owner, &target_umutex->m_owner);
	if ((owner & ~TARGET_UMUTEX_CONTESTED) != id) {
		unlock_user_struct(target_umutex, target_addr, 1);
		return (-TARGET_EPERM);
	}

	if ((owner & TARGET_UMUTEX_CONTESTED) == 0)
		if (tcmpset_32(&target_umutex->m_owner, owner,
			TARGET_UMTX_UNOWNED)) {
			unlock_user_struct(target_umutex, target_addr, 1);
			return (0);
		}

	/* This is a contested lock. Unlock it. */
	__put_user(TARGET_UMUTEX_UNOWNED, &target_umutex->m_owner);
	unlock_user_struct(target_umutex, target_addr, 1);

	/* And wake up all those contesting it. */
	return ( _umtx_op(g2h(target_addr), UMTX_OP_WAKE, 0, 0, 0));
}

/*
 * _cv_mutex is keeps other threads from doing a signal or broadcast until
 * the thread is actually asleep and ready.  This is a global mutex for all
 * condition vars so I am sure performance may be a problem if there are lots
 * of CVs.
 */
static struct umutex _cv_mutex = {0,0,{0,0},{0,0,0,0}};


/*
 * wflags CVWAIT_CHECK_UNPARKING, CVWAIT_ABSTIME, CVWAIT_CLOCKID
 */
static int
do_cv_wait(abi_ulong target_ucond_addr, abi_ulong target_umtx_addr,
    struct timespec *ts, int wflags)
{
	long tid;
	int ret;

	if (! access_ok(VERIFY_WRITE, target_ucond_addr,
		sizeof(struct target_ucond))) {

		return (-TARGET_EFAULT);
	}

	/* Check the clock ID if needed. */
	if ((wflags & TARGET_CVWAIT_CLOCKID) != 0) {
		struct target_ucond *target_ucond;
		uint32_t clockid;

		if (!lock_user_struct(VERIFY_WRITE, target_ucond,
			target_ucond_addr, 0))
			return (-TARGET_EFAULT);
		__get_user(clockid, &target_ucond->c_clockid);
		unlock_user_struct(target_ucond, target_ucond_addr, 1);
		if (clockid < CLOCK_REALTIME ||
		    clockid >= CLOCK_THREAD_CPUTIME_ID) {
			/* Only HW clock id will work. */
			return (-TARGET_EINVAL);
		}
	}

	thr_self(&tid);

	/* Lock the _cv_mutex so we can safely unlock the user mutex */
	_umtx_op(&_cv_mutex, UMTX_OP_MUTEX_LOCK, 0, NULL, NULL);

	/* unlock the user mutex */
	ret = do_unlock_umutex(target_umtx_addr, tid);
	if (ret) {
		_umtx_op(&_cv_mutex, UMTX_OP_MUTEX_UNLOCK, 0, NULL, NULL);
		return (ret);
	}

	/* UMTX_OP_CV_WAIT unlocks _cv_mutex */
	ret = get_errno(_umtx_op(g2h(target_ucond_addr), UMTX_OP_CV_WAIT,
		wflags, &_cv_mutex, ts));

	return (ret);
}

static int
do_cv_signal(abi_ulong target_ucond_addr)
{
	int ret;

	if (! access_ok(VERIFY_WRITE, target_ucond_addr,
		sizeof(struct target_ucond)))
		return (-TARGET_EFAULT);

	/* Lock the _cv_mutex to prevent a race in do_cv_wait(). */
	_umtx_op(&_cv_mutex, UMTX_OP_MUTEX_LOCK, 0, NULL, NULL);
	ret = get_errno(_umtx_op(g2h(target_ucond_addr), UMTX_OP_CV_SIGNAL, 0,
		NULL, NULL));
	_umtx_op(&_cv_mutex, UMTX_OP_MUTEX_UNLOCK, 0, NULL, NULL);

	return (ret);
}

static int
do_cv_broadcast(abi_ulong target_ucond_addr)
{
	int ret;

	if (! access_ok(VERIFY_WRITE, target_ucond_addr,
		sizeof(struct target_ucond)))
		return (-TARGET_EFAULT);

	/* Lock the _cv_mutex to prevent a race in do_cv_wait(). */
	_umtx_op(&_cv_mutex, UMTX_OP_MUTEX_LOCK, 0, NULL, NULL);
	ret = get_errno(_umtx_op(g2h(target_ucond_addr), UMTX_OP_CV_BROADCAST,
		0, NULL, NULL));
	_umtx_op(&_cv_mutex, UMTX_OP_MUTEX_UNLOCK, 0, NULL, NULL);

	return (ret);
}

static int
do_umtx_op_wait(abi_ulong target_addr, abi_ulong id, struct timespec *ts)
{

	/* We want to check the user memory but not lock it.  We might sleep. */
	if (! access_ok(VERIFY_READ, target_addr, sizeof(abi_ulong)))
		return (-TARGET_EFAULT);

	/* id has already been byte swapped to match what may be in user mem. */
#ifdef TARGET_ABI32
	return (get_errno(_umtx_op(g2h(target_addr), UMTX_OP_WAIT_UINT, id, NULL,
		    ts)));
#else
	return (get_errno(_umtx_op(g2h(target_addr), UMTX_OP_WAIT, id, NULL,
		    ts)));
#endif
}

static int
do_umtx_op_wake(abi_ulong target_addr, abi_ulong n_wake)
{

	return (get_errno(_umtx_op(g2h(target_addr), UMTX_OP_WAKE, n_wake, NULL,
		    0)));
}

static int
do_rw_rdlock(abi_ulong target_addr, long fflag, struct timespec *ts)
{
	struct target_urwlock *target_urwlock;
	uint32_t flags, wrflags;
	uint32_t state;
	uint32_t blocked_readers;
	int ret;

	if (!lock_user_struct(VERIFY_WRITE, target_urwlock, target_addr, 0))
		return (-TARGET_EFAULT);

	__get_user(flags, &target_urwlock->rw_flags);
	wrflags = TARGET_URWLOCK_WRITE_OWNER;
	if (!(fflag & TARGET_URWLOCK_PREFER_READER) &&
	    !(flags & TARGET_URWLOCK_PREFER_READER))
		wrflags |= TARGET_URWLOCK_WRITE_WAITERS;

	for (;;) {
		__get_user(state, &target_urwlock->rw_state);
		/* try to lock it */
		while (!(state & wrflags)) {
			if (TARGET_URWLOCK_READER_COUNT(state) ==
			    TARGET_URWLOCK_MAX_READERS) {
				unlock_user_struct(target_urwlock,
				    target_addr, 1);
				return (-TARGET_EAGAIN);
			}
			if (tcmpset_32(&target_urwlock->rw_state, state,
				(state + 1))) {
				/* The acquired succeeded. */
				unlock_user_struct(target_urwlock,
				    target_addr, 1);
				return (0);
			}
			__get_user(state, &target_urwlock->rw_state);
		}

		/* set read contention bit */
		if (! tcmpset_32(&target_urwlock->rw_state, state,
			state | TARGET_URWLOCK_READ_WAITERS)) {
			/* The state has changed.  Start over. */
			continue;
		}

		/* contention bit is set, increase read waiter count */
		__get_user(blocked_readers, &target_urwlock->rw_blocked_readers);
		while (! tcmpset_32(&target_urwlock->rw_blocked_readers,
			blocked_readers, blocked_readers + 1)) {
			__get_user(blocked_readers,
			    &target_urwlock->rw_blocked_readers);
		}

		while (state & wrflags) {
			/* sleep/wait */
			unlock_user_struct(target_urwlock, target_addr, 1);
			ret = get_errno(_umtx_op(
				&target_urwlock->rw_blocked_readers,
				UMTX_OP_WAIT_UINT, blocked_readers, 0, ts));
			if (ret)
				return (ret);
			if (!lock_user_struct(VERIFY_WRITE, target_urwlock,
				target_addr, 0))
				return (-TARGET_EFAULT);
			__get_user(state, &target_urwlock->rw_state);
		}

		/* decrease read waiter count */
		__get_user(blocked_readers, &target_urwlock->rw_blocked_readers);
		while (! tcmpset_32(&target_urwlock->rw_blocked_readers,
			blocked_readers, (blocked_readers - 1))) {
			__get_user(blocked_readers,
			    &target_urwlock->rw_blocked_readers);
		}
		if (1 == blocked_readers) {
			/* clear read contention bit */
			__get_user(state, &target_urwlock->rw_state);
			while(! tcmpset_32(&target_urwlock->rw_state, state,
				state & ~TARGET_URWLOCK_READ_WAITERS)) {
				__get_user(state, &target_urwlock->rw_state);
			}
		}
	}
}

static int
do_rw_wrlock(abi_ulong target_addr, long fflag, struct timespec *ts)
{
	struct target_urwlock *target_urwlock;
	uint32_t blocked_readers, blocked_writers;
	uint32_t state;
	int ret;

	if (!lock_user_struct(VERIFY_WRITE, target_urwlock, target_addr, 0))
		return (-TARGET_EFAULT);

	blocked_readers = 0;
	for (;;) {
		__get_user(state, &target_urwlock->rw_state);
		while (!(state & TARGET_URWLOCK_WRITE_OWNER) &&
		    TARGET_URWLOCK_READER_COUNT(state) == 0) {
			if (tcmpset_32(&target_urwlock->rw_state, state,
				state | TARGET_URWLOCK_WRITE_OWNER)) {
				unlock_user_struct(target_urwlock,
				    target_addr, 1);
				return (0);
			}
			__get_user(state, &target_urwlock->rw_state);
		}

		if (!(state & (TARGET_URWLOCK_WRITE_OWNER |
			    TARGET_URWLOCK_WRITE_WAITERS)) &&
		    blocked_readers != 0) {
			ret = get_errno(_umtx_op(
				&target_urwlock->rw_blocked_readers,
				UMTX_OP_WAKE, INT_MAX, NULL, NULL));
			return (ret);
		}

		/* re-read the state */
		__get_user(state, &target_urwlock->rw_state);

		/* and set TARGET_URWLOCK_WRITE_WAITERS */
		while (((state & TARGET_URWLOCK_WRITE_OWNER) ||
			TARGET_URWLOCK_READER_COUNT(state) != 0) &&
		    (state & TARGET_URWLOCK_WRITE_WAITERS) == 0) {
			if (tcmpset_32(&target_urwlock->rw_state, state,
				state | TARGET_URWLOCK_WRITE_WAITERS)) {
				break;
			}
			__get_user(state, &target_urwlock->rw_state);
		}

		/* contention bit is set, increase write waiter count */
		__get_user(blocked_writers, &target_urwlock->rw_blocked_writers);
		while (! tcmpset_32(&target_urwlock->rw_blocked_writers,
			blocked_writers, blocked_writers + 1)) {
			__get_user(blocked_writers,
			    &target_urwlock->rw_blocked_writers);
		}

		/* sleep */
		while ((state & TARGET_URWLOCK_WRITE_OWNER) ||
		    (TARGET_URWLOCK_READER_COUNT(state) != 0)) {
			unlock_user_struct(target_urwlock, target_addr, 1);
			ret = get_errno(_umtx_op(
				&target_urwlock->rw_blocked_writers,
				UMTX_OP_WAIT_UINT, blocked_writers, 0, ts));
			if (ret)
				return (ret);
			if (!lock_user_struct(VERIFY_WRITE, target_urwlock,
				target_addr, 0))
				return (-TARGET_EFAULT);
			__get_user(state, &target_urwlock->rw_state);
		}

		/* decrease the write waiter count */
		__get_user(blocked_writers, &target_urwlock->rw_blocked_writers);
		while (! tcmpset_32(&target_urwlock->rw_blocked_writers,
			blocked_writers, (blocked_writers - 1))) {
			__get_user(blocked_writers,
			    &target_urwlock->rw_blocked_writers);
		}
		if (1 == blocked_writers) {
			/* clear write contention bit */
			__get_user(state, &target_urwlock->rw_state);
			while(! tcmpset_32(&target_urwlock->rw_state, state,
				state & ~TARGET_URWLOCK_WRITE_WAITERS)) {
				__get_user(state, &target_urwlock->rw_state);
			}
			__get_user(blocked_readers,
			    &target_urwlock->rw_blocked_readers);
		} else
			blocked_readers = 0;
	}
}

static int
do_rw_unlock(abi_ulong target_addr)
{
	struct target_urwlock *target_urwlock;
	uint32_t flags, state, count;
	void *q = NULL;

	if (!lock_user_struct(VERIFY_WRITE, target_urwlock, target_addr, 0))
		return (-TARGET_EFAULT);

	__get_user(flags, &target_urwlock->rw_flags);
	__get_user(state, &target_urwlock->rw_state);

	if (state & TARGET_URWLOCK_WRITE_OWNER) {
		for (;;) {
			if (! tcmpset_32(&target_urwlock->rw_state, state,
				state & ~TARGET_URWLOCK_WRITE_OWNER)) {
				__get_user(state, &target_urwlock->rw_state);
				if (!(state & TARGET_URWLOCK_WRITE_OWNER)) {
					unlock_user_struct(target_urwlock,
					    target_addr, 1);
					return (-TARGET_EPERM);
				}
			} else
				break;
		}
	} else if (TARGET_URWLOCK_READER_COUNT(state) != 0) {
		/* decrement reader count */
		for (;;) {
			if (! tcmpset_32(&target_urwlock->rw_state,
				state, (state  - 1))) {
				if (TARGET_URWLOCK_READER_COUNT(state) == 0) {
					unlock_user_struct(target_urwlock,
						target_addr, 1);
					    return (-TARGET_EPERM);
				 }
			} else
				break;
		}
	} else {
		unlock_user_struct(target_urwlock, target_addr, 1);
		return (-TARGET_EPERM);
	}

	count = 0;

	if (! (flags & TARGET_URWLOCK_PREFER_READER)) {
		if (state & TARGET_URWLOCK_WRITE_WAITERS) {
			count = 1;
			q = &target_urwlock->rw_blocked_writers;
		} else if (state & TARGET_URWLOCK_READ_WAITERS) {
			count = INT_MAX;
			q = &target_urwlock->rw_blocked_readers;
		}
	} else {
		if (state & TARGET_URWLOCK_READ_WAITERS) {
			count = INT_MAX;
			q = &target_urwlock->rw_blocked_readers;
		} else if (state & TARGET_URWLOCK_WRITE_WAITERS) {
			count = 1;
			q = &target_urwlock->rw_blocked_writers;
		}
	}

	unlock_user_struct(target_urwlock, target_addr, 1);
	if (q != NULL)
		return (get_errno(_umtx_op(q, UMTX_OP_WAKE, count, NULL, NULL)));
	else
		return (0);
}

static inline abi_long
target_to_host_statfs(struct statfs *host_statfs, abi_ulong target_addr)
{
	struct target_statfs *target_statfs;

	if (!lock_user_struct(VERIFY_READ, target_statfs, target_addr, 1))
		return (-TARGET_EFAULT);
	__get_user(host_statfs->f_version, &target_statfs->f_version);
	__get_user(host_statfs->f_type, &target_statfs->f_type);
	__get_user(host_statfs->f_flags, &target_statfs->f_flags);
	__get_user(host_statfs->f_bsize, &target_statfs->f_bsize);
	__get_user(host_statfs->f_iosize, &target_statfs->f_iosize);
	__get_user(host_statfs->f_blocks, &target_statfs->f_blocks);
	__get_user(host_statfs->f_bfree, &target_statfs->f_bfree);
	__get_user(host_statfs->f_bavail, &target_statfs->f_bavail);
	__get_user(host_statfs->f_files, &target_statfs->f_files);
	__get_user(host_statfs->f_ffree, &target_statfs->f_ffree);
	__get_user(host_statfs->f_syncwrites, &target_statfs->f_syncwrites);
	__get_user(host_statfs->f_asyncwrites, &target_statfs->f_asyncwrites);
	__get_user(host_statfs->f_syncreads, &target_statfs->f_syncreads);
	__get_user(host_statfs->f_asyncreads, &target_statfs->f_asyncreads);
	/* uint64_t f_spare[10]; */
	__get_user(host_statfs->f_namemax, &target_statfs->f_namemax);
	__get_user(host_statfs->f_owner, &target_statfs->f_owner);
	__get_user(host_statfs->f_fsid.val[0], &target_statfs->f_fsid.val[0]);
	__get_user(host_statfs->f_fsid.val[1], &target_statfs->f_fsid.val[1]);
	/* char f_charspace[80]; */
	strncpy(host_statfs->f_fstypename, &target_statfs->f_fstypename[0],
	    TARGET_MFSNAMELEN);
	strncpy(host_statfs->f_mntfromname, &target_statfs->f_mntfromname[0],
	    TARGET_MNAMELEN);
	strncpy(host_statfs->f_mntonname, &target_statfs->f_mntonname[0],
	    TARGET_MNAMELEN);
	unlock_user_struct(target_statfs, target_addr, 0);
	return (0);
}

static inline abi_long
host_to_target_statfs(abi_ulong target_addr, struct statfs *host_statfs)
{
	struct target_statfs *target_statfs;

	if (!lock_user_struct(VERIFY_WRITE, target_statfs, target_addr, 0))
		return (-TARGET_EFAULT);
	__put_user(host_statfs->f_version, &target_statfs->f_version);
	__put_user(host_statfs->f_type, &target_statfs->f_type);
	__put_user(host_statfs->f_flags, &target_statfs->f_flags);
	__put_user(host_statfs->f_bsize, &target_statfs->f_bsize);
	__put_user(host_statfs->f_iosize, &target_statfs->f_iosize);
	__put_user(host_statfs->f_blocks, &target_statfs->f_blocks);
	__put_user(host_statfs->f_bfree, &target_statfs->f_bfree);
	__put_user(host_statfs->f_bavail, &target_statfs->f_bavail);
	__put_user(host_statfs->f_files, &target_statfs->f_files);
	__put_user(host_statfs->f_ffree, &target_statfs->f_ffree);
	__put_user(host_statfs->f_syncwrites, &target_statfs->f_syncwrites);
	__put_user(host_statfs->f_asyncwrites, &target_statfs->f_asyncwrites);
	__put_user(host_statfs->f_syncreads, &target_statfs->f_syncreads);
	__put_user(host_statfs->f_asyncreads, &target_statfs->f_asyncreads);
	/* uint64_t f_spare[10]; */
	__put_user(host_statfs->f_namemax, &target_statfs->f_namemax);
	__put_user(host_statfs->f_owner, &target_statfs->f_owner);
	__put_user(host_statfs->f_fsid.val[0], &target_statfs->f_fsid.val[0]);
	__put_user(host_statfs->f_fsid.val[1], &target_statfs->f_fsid.val[1]);
	/* char f_charspace[80]; */
	strncpy(&target_statfs->f_fstypename[0], host_statfs->f_fstypename,
	    TARGET_MFSNAMELEN);
	strncpy(&target_statfs->f_mntfromname[0], host_statfs->f_mntfromname,
	    TARGET_MNAMELEN);
	strncpy(&target_statfs->f_mntonname[0], host_statfs->f_mntonname,
	    TARGET_MNAMELEN);
	unlock_user_struct(target_statfs, target_addr, 1);
	return (0);
}

static inline abi_long
target_to_host_fhandle(fhandle_t *host_fh, abi_ulong target_addr)
{
	target_fhandle_t *target_fh;

	if (!lock_user_struct(VERIFY_READ, target_fh, target_addr, 1))
		return (-TARGET_EFAULT);
	__get_user(host_fh->fh_fsid.val[0], &target_fh->fh_fsid.val[0]);
	__get_user(host_fh->fh_fsid.val[1], &target_fh->fh_fsid.val[0]);

	__get_user(host_fh->fh_fid.fid_len, &target_fh->fh_fid.fid_len);
	/* u_short         fid_data0; */
	memcpy(host_fh->fh_fid.fid_data, target_fh->fh_fid.fid_data,
	    TARGET_MAXFIDSZ);
	unlock_user_struct(target_fh, target_addr, 0);
	return (0);
}

static inline abi_long
host_to_target_fhandle(abi_ulong target_addr, fhandle_t *host_fh)
{
	target_fhandle_t *target_fh;

	if (!lock_user_struct(VERIFY_WRITE, target_fh, target_addr, 0))
		return (-TARGET_EFAULT);
	__put_user(host_fh->fh_fsid.val[0], &target_fh->fh_fsid.val[0]);
	__put_user(host_fh->fh_fsid.val[1], &target_fh->fh_fsid.val[0]);

	__put_user(host_fh->fh_fid.fid_len, &target_fh->fh_fid.fid_len);
	/* u_short         fid_data0; */
	memcpy(target_fh->fh_fid.fid_data, host_fh->fh_fid.fid_data,
	    TARGET_MAXFIDSZ);
	unlock_user_struct(target_fh, target_addr, 1);
	return (0);
}

static inline abi_long
target_to_host_rtprio(struct rtprio *host_rtp, abi_ulong target_addr)
{
	struct target_rtprio *target_rtp;

	if (!lock_user_struct(VERIFY_READ, target_rtp, target_addr, 1))
		return (-TARGET_EFAULT);
	__get_user(host_rtp->type, &target_rtp->type);
	__get_user(host_rtp->prio, &target_rtp->prio);
	unlock_user_struct(target_rtp, target_addr, 0);
	return (0);
}

static inline abi_long
host_to_target_rtprio(abi_ulong target_addr, struct rtprio *host_rtp)
{
	struct target_rtprio *target_rtp;

	if (!lock_user_struct(VERIFY_WRITE, target_rtp, target_addr, 0))
		return (-TARGET_EFAULT);
	__put_user(host_rtp->type, &target_rtp->type);
	__put_user(host_rtp->prio, &target_rtp->prio);
	unlock_user_struct(target_rtp, target_addr, 1);
	return (0);
}

static inline abi_long
do_rtprio_thread(int function, lwpid_t lwpid, abi_ulong target_addr)
{
	int ret;
	struct rtprio rtp;

	ret = target_to_host_rtprio(&rtp, target_addr);
	if (0 == ret)
		ret = get_errno(rtprio_thread(function, lwpid, &rtp));
	if (0 == ret)
		ret = host_to_target_rtprio(target_addr, &rtp);

	return (ret);
}

static inline abi_long
target_to_host_sched_param(struct sched_param *host_sp, abi_ulong target_addr)
{
	struct target_sched_param *target_sp;

	if (!lock_user_struct(VERIFY_READ, target_sp, target_addr, 1))
		return (-TARGET_EFAULT);
	__get_user(host_sp->sched_priority, &target_sp->sched_priority);
	unlock_user_struct(target_sp, target_addr, 0);
	return (0);
}

static inline abi_long
host_to_target_sched_param(abi_ulong target_addr, struct sched_param *host_sp)
{
	struct target_sched_param *target_sp;

	if (!lock_user_struct(VERIFY_WRITE, target_sp, target_addr, 0))
		return (-TARGET_EFAULT);
	__put_user(host_sp->sched_priority, &target_sp->sched_priority);
	unlock_user_struct(target_sp, target_addr, 1);
	return (0);
}

static inline abi_long
target_to_host_acl(struct acl *host_acl, abi_ulong target_addr)
{
	uint32_t i;
	struct target_acl *target_acl;

	if (!lock_user_struct(VERIFY_READ, target_acl, target_addr, 1))
		return (-TARGET_EFAULT);

	__get_user(host_acl->acl_maxcnt, &target_acl->acl_maxcnt);
	__get_user(host_acl->acl_cnt, &target_acl->acl_cnt);

	for(i = 0; i < host_acl->acl_maxcnt; i++) {
		__get_user(host_acl->acl_entry[i].ae_tag,
		    &target_acl->acl_entry[i].ae_tag);
		__get_user(host_acl->acl_entry[i].ae_id,
		    &target_acl->acl_entry[i].ae_id);
		__get_user(host_acl->acl_entry[i].ae_perm,
		    &target_acl->acl_entry[i].ae_perm);
		__get_user(host_acl->acl_entry[i].ae_entry_type,
		    &target_acl->acl_entry[i].ae_entry_type);
		__get_user(host_acl->acl_entry[i].ae_flags,
		    &target_acl->acl_entry[i].ae_flags);
	}

	unlock_user_struct(target_acl, target_addr, 0);
	return (0);
}

static inline abi_long
host_to_target_acl(abi_ulong target_addr, struct acl *host_acl)
{
	uint32_t i;
	struct target_acl *target_acl;

	if (!lock_user_struct(VERIFY_WRITE, target_acl, target_addr, 0))
		return (-TARGET_EFAULT);

	__put_user(host_acl->acl_maxcnt, &target_acl->acl_maxcnt);
	__put_user(host_acl->acl_cnt, &target_acl->acl_cnt);

	for(i = 0; i < host_acl->acl_maxcnt; i++) {
		__put_user(host_acl->acl_entry[i].ae_tag,
		    &target_acl->acl_entry[i].ae_tag);
		__put_user(host_acl->acl_entry[i].ae_id,
		    &target_acl->acl_entry[i].ae_id);
		__put_user(host_acl->acl_entry[i].ae_perm,
		    &target_acl->acl_entry[i].ae_perm);
		__get_user(host_acl->acl_entry[i].ae_entry_type,
		    &target_acl->acl_entry[i].ae_entry_type);
		__get_user(host_acl->acl_entry[i].ae_flags,
		    &target_acl->acl_entry[i].ae_flags);
	}

	unlock_user_struct(target_acl, target_addr, 1);
	return (0);
}

static inline abi_long
do_sched_setparam(pid_t pid, abi_ulong target_sp_addr)
{
	int ret;
	struct sched_param host_sp;

	ret = target_to_host_sched_param(&host_sp, target_sp_addr);
	if (0 == ret)
		ret = get_errno(sched_setparam(pid, &host_sp));

	return (ret);
}

static inline abi_long
do_sched_getparam(pid_t pid, abi_ulong target_sp_addr)
{
	int ret;
	struct sched_param host_sp;

	ret = get_errno(sched_getparam(pid, &host_sp));
	if (0 == ret)
		ret = host_to_target_sched_param(target_sp_addr, &host_sp);

	return (ret);
}

static inline abi_long
do_sched_setscheduler(pid_t pid, int policy, abi_ulong target_sp_addr)
{
	int ret;
	struct sched_param host_sp;

	ret = target_to_host_sched_param(&host_sp, target_sp_addr);
	if (0 == ret)
		ret = get_errno(sched_setscheduler(pid, policy, &host_sp));

	return (ret);
}

static inline abi_long
do_sched_rr_get_interval(pid_t pid, abi_ulong target_ts_addr)
{
	int ret;
	struct timespec host_ts;

	ret = get_errno(sched_rr_get_interval(pid, &host_ts));
	if (0 == ret)
		ret = host_to_target_timespec(target_ts_addr, &host_ts);

	return (ret);
}

static inline abi_long
host_to_target_uuid(abi_ulong target_addr, struct uuid *host_uuid)
{
	struct target_uuid *target_uuid;

	if (!lock_user_struct(VERIFY_WRITE, target_uuid, target_addr, 0))
		return (-TARGET_EFAULT);
	__put_user(host_uuid->time_low, &target_uuid->time_low);
	__put_user(host_uuid->time_mid, &target_uuid->time_mid);
	__put_user(host_uuid->time_hi_and_version,
	    &target_uuid->time_hi_and_version);
	host_uuid->clock_seq_hi_and_reserved =
	    target_uuid->clock_seq_hi_and_reserved;
	host_uuid->clock_seq_low = target_uuid->clock_seq_low;
	memcpy(host_uuid->node, target_uuid->node, TARGET_UUID_NODE_LEN);
	unlock_user_struct(target_uuid, target_addr, 1);
	return (0);
}

static inline abi_long
host_to_target_stat(abi_ulong target_addr, struct stat *host_st)
{
	struct target_freebsd_stat *target_st;

	if (!lock_user_struct(VERIFY_WRITE, target_st, target_addr, 0))
		return (-TARGET_EFAULT);
	memset(target_st, 0, sizeof(*target_st));
	__put_user(host_st->st_dev, &target_st->st_dev);
	__put_user(host_st->st_ino, &target_st->st_ino);
	__put_user(host_st->st_mode, &target_st->st_mode);
	__put_user(host_st->st_nlink, &target_st->st_nlink);
	__put_user(host_st->st_uid, &target_st->st_uid);
	__put_user(host_st->st_gid, &target_st->st_gid);
	__put_user(host_st->st_rdev, &target_st->st_rdev);
	__put_user(host_st->st_atim.tv_sec, &target_st->st_atim.tv_sec);
	__put_user(host_st->st_atim.tv_nsec, &target_st->st_atim.tv_nsec);
	__put_user(host_st->st_mtim.tv_sec, &target_st->st_mtim.tv_sec);
	__put_user(host_st->st_mtim.tv_nsec, &target_st->st_mtim.tv_nsec);
	__put_user(host_st->st_ctim.tv_sec, &target_st->st_ctim.tv_sec);
	__put_user(host_st->st_ctim.tv_nsec, &target_st->st_ctim.tv_nsec);
	__put_user(host_st->st_size, &target_st->st_size);
	__put_user(host_st->st_blocks, &target_st->st_blocks);
	__put_user(host_st->st_blksize, &target_st->st_blksize);
	__put_user(host_st->st_flags, &target_st->st_flags);
	__put_user(host_st->st_gen, &target_st->st_gen);
	/* st_lspare not used */
	__put_user(host_st->st_birthtim.tv_sec, &target_st->st_birthtim.tv_sec);
	__put_user(host_st->st_birthtim.tv_nsec,
	    &target_st->st_birthtim.tv_nsec);
	unlock_user_struct(target_st, target_addr, 1);

	return (0);
}

static inline abi_long
do_getfh(const char *path, abi_ulong target_addr)
{
	abi_long ret;
	fhandle_t host_fh;

	ret = get_errno(getfh(path, &host_fh));
	if (ret)
		return (ret);

	return (host_to_target_fhandle(target_addr, &host_fh));
}

static inline abi_long
do_lgetfh(const char *path, abi_ulong target_addr)
{
	abi_long ret;
	fhandle_t host_fh;

	ret = get_errno(lgetfh(path, &host_fh));
	if (ret)
		return (ret);

	return (host_to_target_fhandle(target_addr, &host_fh));
}

static inline abi_long
do_fhopen(abi_ulong target_addr, int flags)
{
	abi_long ret;
	fhandle_t host_fh;

	ret = target_to_host_fhandle(&host_fh, target_addr);
	if (ret)
		return (ret);

	return (get_errno(fhopen(&host_fh, flags)));
}

static inline abi_long
do_fhstat(abi_ulong target_fhp_addr, abi_ulong target_sb_addr)
{
	abi_long ret;
	fhandle_t host_fh;
	struct stat host_sb;

	ret = target_to_host_fhandle(&host_fh, target_fhp_addr);
	if (ret)
		return (ret);

	ret = get_errno(fhstat(&host_fh, &host_sb));
	if (ret)
		return (ret);

	return (host_to_target_stat(target_sb_addr, &host_sb));
}

static inline abi_long
do_fhstatfs(abi_ulong target_fhp_addr, abi_ulong target_stfs_addr)
{
	abi_long ret;
	fhandle_t host_fh;
	struct statfs host_stfs;

	ret = target_to_host_fhandle(&host_fh, target_fhp_addr);
	if (ret)
		return (ret);

	ret = get_errno(fhstatfs(&host_fh, &host_stfs));
	if (ret)
		return (ret);

	return (host_to_target_statfs(target_stfs_addr, &host_stfs));
}

static inline abi_long
do_statfs(const char *path, abi_ulong target_addr)
{
	abi_long ret;
	struct statfs host_stfs;

	ret = get_errno(statfs(path, &host_stfs));
	if (ret)
		return (ret);

	return (host_to_target_statfs(target_addr, &host_stfs));
}

static inline abi_long
do_fstatfs(int fd, abi_ulong target_addr)
{
	abi_long ret;
	struct statfs host_stfs;

	ret = get_errno(fstatfs(fd, &host_stfs));
	if (ret)
		return (ret);

	return (host_to_target_statfs(target_addr, &host_stfs));
}

static inline abi_long
do_getfsstat(abi_ulong target_addr, abi_long bufsize, int flags)
{
	abi_long ret;
	struct statfs *host_stfs;
	int count;
	long host_bufsize;

	count = bufsize / sizeof(struct target_statfs);

	/* if user buffer is NULL then return number of mounted FS's */
	if (0 == target_addr || 0 == count)
		return (get_errno(getfsstat(NULL, 0, flags)));

	/* XXX check count to be reasonable */
	host_bufsize = sizeof(struct statfs) * count;
	host_stfs = alloca(host_bufsize);
	if (! host_stfs)
		return (-TARGET_EINVAL);

	ret = count = get_errno(getfsstat(host_stfs, host_bufsize, flags));
	if (ret < 0)
		return (ret);

	while (count--)
		if (host_to_target_statfs(
			(target_addr + (count * sizeof(struct target_statfs))),
			&host_stfs[count]))
			return (-TARGET_EFAULT);

	return (ret);
}

static abi_long
do_uuidgen(abi_ulong target_addr, int count)
{
	int i;
	abi_long ret;
	struct uuid *host_uuid;

	if (count < 1 || count > 2048)
		return (-TARGET_EINVAL);

	host_uuid = (struct uuid *)g_malloc(count * sizeof(struct uuid));

	if (NULL == host_uuid)
		return (-TARGET_EINVAL);

	ret = get_errno(uuidgen(host_uuid, count));
	if (ret)
		goto out;
	for(i = 0; i < count; i++) {
		ret = host_to_target_uuid(target_addr +
		    (abi_ulong)(sizeof(struct target_uuid) * i), &host_uuid[i]);
		if (ret)
			goto out;
	}

out:
	g_free(host_uuid);
	return (ret);
}

static abi_long
do_adjtime(abi_ulong target_delta_addr, abi_ulong target_old_addr)
{
	abi_long ret;
	struct timeval host_delta, host_old;

	ret = target_to_host_timeval(&host_delta, target_delta_addr);
	if (ret)
		goto out;

	if (target_old_addr) {
		ret = get_errno(adjtime(&host_delta, &host_old));
		if (ret)
			goto out;
		ret = host_to_target_timeval(&host_old, target_old_addr);
	} else
		ret = get_errno(adjtime(&host_delta, NULL));

out:
	return (ret);
}

static abi_long
do_ntp_adjtime(abi_ulong target_tx_addr)
{
	abi_long ret;
	struct timex host_tx;

	ret = target_to_host_timex(&host_tx, target_tx_addr);
	if (ret)
		goto out;

	ret = get_errno(ntp_adjtime(&host_tx));

out:
	return (ret);
}

static abi_long
do_ntp_gettime(abi_ulong target_ntv_addr)
{
	abi_long ret;
	struct ntptimeval host_ntv;

	ret = get_errno(ntp_gettime(&host_ntv));
	if (ret)
		goto out;

	ret = host_to_target_ntptimeval(target_ntv_addr, &host_ntv);
out:
	return (ret);
}

/*
 * ioctl()
 */

static const bitmask_transtbl iflag_tbl[] = {
	{ TARGET_IGNBRK, TARGET_IGNBRK, IGNBRK, IGNBRK },
	{ TARGET_BRKINT, TARGET_BRKINT, BRKINT, BRKINT },
	{ TARGET_IGNPAR, TARGET_IGNPAR, IGNPAR, IGNPAR },
	{ TARGET_PARMRK, TARGET_PARMRK, PARMRK, PARMRK },
	{ TARGET_INPCK, TARGET_INPCK, INPCK, INPCK },
	{ TARGET_ISTRIP, TARGET_ISTRIP, ISTRIP, ISTRIP },
	{ TARGET_INLCR, TARGET_INLCR, INLCR, INLCR },
	{ TARGET_IGNCR, TARGET_IGNCR, IGNCR, IGNCR },
	{ TARGET_ICRNL, TARGET_ICRNL, ICRNL, ICRNL },
	{ TARGET_IXON, TARGET_IXON, IXON, IXON },
	{ TARGET_IXOFF, TARGET_IXOFF, IXOFF, IXOFF },
#ifdef IXANY
	{ TARGET_IXANY, TARGET_IXANY, IXANY, IXANY },
#endif
#ifdef IMAXBEL
	{ TARGET_IMAXBEL, TARGET_IMAXBEL, IMAXBEL, IMAXBEL },
#endif
	{ 0, 0, 0, 0 }
};

static const bitmask_transtbl oflag_tbl[] = {
	{ TARGET_OPOST, TARGET_OPOST, OPOST, OPOST },
#ifdef ONLCR
	{ TARGET_ONLCR, TARGET_ONLCR, ONLCR, ONLCR },
#endif
#ifdef TABDLY
	{ TARGET_TABDLY, TARGET_TAB0, TABDLY, TAB0 },
	{ TARGET_TABDLY, TARGET_TAB3, TABDLY, TAB3 },
#endif
#ifdef ONOEOT
	{ TARGET_ONOEOT, TARGET_ONOEOT, ONOEOT, ONOEOT },
#endif
#ifdef OCRNL
	{ TARGET_OCRNL, TARGET_OCRNL, OCRNL, OCRNL },
#endif
#ifdef ONOCR
	{ TARGET_ONOCR, TARGET_ONOCR, ONOCR, ONOCR },
#endif
#ifdef ONLRET
	{ TARGET_ONLRET, TARGET_ONLRET, ONLRET, ONLRET },
#endif
	{ 0, 0, 0, 0 }
};

static const bitmask_transtbl cflag_tbl[] = {
#ifdef CIGNORE
	{ TARGET_CIGNORE, TARGET_CIGNORE, CIGNORE, CIGNORE },
#endif
	{ TARGET_CSIZE, TARGET_CS5, CSIZE, CS5 },
	{ TARGET_CSIZE, TARGET_CS6, CSIZE, CS6 },
	{ TARGET_CSIZE, TARGET_CS7, CSIZE, CS7 },
	{ TARGET_CSIZE, TARGET_CS8, CSIZE, CS8 },
	{ TARGET_CSTOPB, TARGET_CSTOPB, CSTOPB, CSTOPB },
	{ TARGET_CREAD, TARGET_CREAD, CREAD, CREAD },
	{ TARGET_PARENB, TARGET_PARENB, PARENB, PARENB },
	{ TARGET_PARODD, TARGET_PARODD, PARODD, PARODD },
	{ TARGET_HUPCL, TARGET_HUPCL, HUPCL, HUPCL },
	{ TARGET_CLOCAL, TARGET_CLOCAL, CLOCAL, CLOCAL },
#ifdef CCTS_OFLOW
	{ TARGET_CCTS_OFLOW, TARGET_CCTS_OFLOW, CCTS_OFLOW, CCTS_OFLOW },
#endif
#ifdef CRTSCTS
	{ TARGET_CRTSCTS, TARGET_CRTSCTS, CRTSCTS, CRTSCTS },
#endif
#ifdef CRTS_IFLOW
	{ TARGET_CRTS_IFLOW, TARGET_CRTS_IFLOW, CRTS_IFLOW, CRTS_IFLOW },
#endif
#ifdef CDTS_IFLOW
	{ TARGET_CDTR_IFLOW, TARGET_CDTR_IFLOW, CDTR_IFLOW, CDTR_IFLOW },
#endif
#ifdef CDSR_OFLOW
	{ TARGET_CDSR_OFLOW, TARGET_CDSR_OFLOW, CDSR_OFLOW, CDSR_OFLOW },
#endif
#ifdef CCAR_OFLOW
	{ TARGET_CCAR_OFLOW, TARGET_CCAR_OFLOW, CCAR_OFLOW, CCAR_OFLOW },
#endif
	{ 0, 0, 0, 0 }
};

static const bitmask_transtbl lflag_tbl[] = {
#ifdef ECHOKE
	{ TARGET_ECHOKE, TARGET_ECHOKE, ECHOKE, ECHOKE },
#endif
	{ TARGET_ECHOE, TARGET_ECHOE, ECHOE, ECHOE },
	{ TARGET_ECHOK, TARGET_ECHOK, ECHOK, ECHOK },
	{ TARGET_ECHO, TARGET_ECHO, ECHO, ECHO },
	{ TARGET_ECHONL, TARGET_ECHONL, ECHONL, ECHONL },
#ifdef ECHOPRT
	{ TARGET_ECHOPRT, TARGET_ECHOPRT, ECHOPRT, ECHOPRT },
#endif
#ifdef ECHOCTL
	{ TARGET_ECHOCTL, TARGET_ECHOCTL, ECHOCTL, ECHOCTL },
#endif
	{ TARGET_ISIG, TARGET_ISIG, ISIG, ISIG },
	{ TARGET_ICANON, TARGET_ICANON, ICANON, ICANON },
#ifdef ALTWERASE
	{ TARGET_ALTWERASE, TARGET_ALTWERASE, ALTWERASE, ALTWERASE },
#endif
	{ TARGET_IEXTEN, TARGET_IEXTEN, IEXTEN, IEXTEN },
	{ TARGET_EXTPROC, TARGET_EXTPROC, EXTPROC, EXTPROC },
	{ TARGET_TOSTOP, TARGET_TOSTOP, TOSTOP, TOSTOP },
#ifdef FLUSHO
	{ TARGET_FLUSHO, TARGET_FLUSHO, FLUSHO, FLUSHO },
#endif
#ifdef NOKERNINFO
	{ TARGET_NOKERNINFO, TARGET_NOKERNINFO, NOKERNINFO, NOKERNINFO },
#endif
#ifdef PENDIN
	{ TARGET_PENDIN, TARGET_PENDIN, PENDIN, PENDIN },
#endif
	{ TARGET_NOFLSH, TARGET_NOFLSH, NOFLSH, NOFLSH },
	{ 0, 0, 0, 0 }
};

static void
target_to_host_termios(void *dst, const void *src)
{
	struct termios *host = dst;
	const struct target_termios *target = src;

	host->c_iflag =
	    target_to_host_bitmask(tswap32(target->c_iflag), iflag_tbl);
	host->c_oflag =
	    target_to_host_bitmask(tswap32(target->c_oflag), oflag_tbl);
	host->c_cflag =
	    target_to_host_bitmask(tswap32(target->c_cflag), cflag_tbl);
	host->c_lflag =
	    target_to_host_bitmask(tswap32(target->c_lflag), lflag_tbl);

	memset(host->c_cc, 0, sizeof(host->c_cc));
	host->c_cc[VEOF] = target->c_cc[TARGET_VEOF];
	host->c_cc[VEOL] = target->c_cc[TARGET_VEOL];
#ifdef VEOL2
	host->c_cc[VEOL2] = target->c_cc[TARGET_VEOL2];
#endif
	host->c_cc[VERASE] = target->c_cc[TARGET_VERASE];
#ifdef VWERASE
	host->c_cc[VWERASE] = target->c_cc[TARGET_VWERASE];
#endif
	host->c_cc[VKILL] = target->c_cc[TARGET_VKILL];
#ifdef VREPRINT
	host->c_cc[VREPRINT] = target->c_cc[TARGET_VREPRINT];
#endif
#ifdef VERASE2
	host->c_cc[VERASE2] = target->c_cc[TARGET_VERASE2];
#endif
	host->c_cc[VINTR] = target->c_cc[TARGET_VINTR];
	host->c_cc[VQUIT] = target->c_cc[TARGET_VQUIT];
	host->c_cc[VSUSP] = target->c_cc[TARGET_VSUSP];
#ifdef VDSUSP
	host->c_cc[VDSUSP] = target->c_cc[TARGET_VDSUSP];
#endif
	host->c_cc[VSTART] = target->c_cc[TARGET_VSTART];
	host->c_cc[VSTOP] = target->c_cc[TARGET_VSTOP];
#ifdef VLNEXT
	host->c_cc[VLNEXT] = target->c_cc[TARGET_VLNEXT];
#endif
#ifdef VDISCARD
	host->c_cc[VDISCARD] = target->c_cc[TARGET_VDISCARD];
#endif
	host->c_cc[VMIN] = target->c_cc[TARGET_VMIN];
	host->c_cc[VTIME] = target->c_cc[TARGET_VTIME];
#ifdef VSTATUS
	host->c_cc[VSTATUS] = target->c_cc[TARGET_VSTATUS];
#endif

	host->c_ispeed = tswap32(target->c_ispeed);
	host->c_ospeed = tswap32(target->c_ospeed);
}

static void
host_to_target_termios(void *dst, const void *src)
{
	struct target_termios *target = dst;
	const struct termios *host = src;

	target->c_iflag =
	    tswap32(host_to_target_bitmask(host->c_iflag, iflag_tbl));
	target->c_oflag =
	    tswap32(host_to_target_bitmask(host->c_oflag, oflag_tbl));
	target->c_cflag =
	    tswap32(host_to_target_bitmask(host->c_cflag, cflag_tbl));
	target->c_lflag =
	    tswap32(host_to_target_bitmask(host->c_lflag, lflag_tbl));

	memset(target->c_cc, 0, sizeof(target->c_cc));
	target->c_cc[TARGET_VEOF] = host->c_cc[VEOF];
	target->c_cc[TARGET_VEOL] = host->c_cc[VEOL];
#ifdef VEOL2
	target->c_cc[TARGET_VEOL2] = host->c_cc[VEOL2];
#endif
	target->c_cc[TARGET_VERASE] = host->c_cc[VERASE];
#ifdef VWERASE
	target->c_cc[TARGET_VWERASE] = host->c_cc[VWERASE];
#endif
	target->c_cc[TARGET_VKILL] = host->c_cc[VKILL];
#ifdef VREPRINT
	target->c_cc[TARGET_VREPRINT] = host->c_cc[VREPRINT];
#endif
#ifdef VERASE2
	target->c_cc[TARGET_VERASE2] = host->c_cc[VERASE2];
#endif
	target->c_cc[TARGET_VINTR] = host->c_cc[VINTR];
	target->c_cc[TARGET_VQUIT] = host->c_cc[VQUIT];
	target->c_cc[TARGET_VSUSP] = host->c_cc[VSUSP];
#ifdef VDSUSP
	target->c_cc[TARGET_VDSUSP] = host->c_cc[VDSUSP];
#endif
	target->c_cc[TARGET_VSTART] = host->c_cc[VSTART];
	target->c_cc[TARGET_VSTOP] = host->c_cc[VSTOP];
#ifdef VLNEXT
	target->c_cc[TARGET_VLNEXT] = host->c_cc[VLNEXT];
#endif
#ifdef VDISCARD
	target->c_cc[TARGET_VDISCARD] = host->c_cc[VDISCARD];
#endif
	target->c_cc[TARGET_VMIN] = host->c_cc[VMIN];
	target->c_cc[TARGET_VTIME] = host->c_cc[VTIME];
#ifdef VSTATUS
	target->c_cc[TARGET_VSTATUS] = host->c_cc[VSTATUS];
#endif

	target->c_ispeed = tswap32(host->c_ispeed);
	target->c_ospeed = tswap32(host->c_ospeed);
}

static const StructEntry struct_termios_def = {
	.convert = { host_to_target_termios, target_to_host_termios },
	.size = { sizeof(struct target_termios), sizeof(struct termios) },
	.align = { __alignof__(struct target_termios),
		__alignof__(struct termios) },
};

/* kernel structure types definitions */

#define STRUCT(name, ...) STRUCT_ ## name,
#define	STRUCT_SPECIAL(name) STRUCT_ ## name,
enum {
#ifdef __FreeBSD__
#include "freebsd/syscall_types.h"
#else
#warning No syscall_types.h
#endif
};
#undef STRUCT
#undef STRUCT_SPECIAL

#define STRUCT(name, ...) \
    static const argtype struct_ ## name ## _def[] = { __VA_ARGS__, TYPE_NULL };
#define STRUCT_SPECIAL(name)
#ifdef __FreeBSD__
#include "freebsd/syscall_types.h"
#else
#warning No syscall_types.h
#endif
#undef STRUCT
#undef STRUCT_SPECIAL

typedef struct IOCTLEntry IOCTLEntry;

typedef abi_long do_ioctl_fn(const IOCTLEntry *ie, uint8_t *buf_temp,
				int fd, abi_long cmd, abi_long arg);

struct IOCTLEntry {
	unsigned int target_cmd;
	unsigned int host_cmd;
	const char *name;
	int access;
	do_ioctl_fn *do_ioctl;
	const argtype arg_type[5];
};

#define MAX_STRUCT_SIZE 4096

static IOCTLEntry ioctl_entries[] = {
#define	IOC_	0x0000
#define	IOC_R	0x0001
#define	IOC_W	0x0002
#define	IOC_RW	(IOC_R | IOC_W)
#define IOCTL(cmd, access, ...) \
	{ TARGET_ ## cmd, cmd, #cmd, access, 0, { __VA_ARGS__ } },
#define	IOCTL_SPECIAL(cmd, access, dofn, ...) \
	{ TARGET_ ## cmd, cmd, #cmd, access, dofn, { __VA_ARGS__ } },
#if defined(__FreeBSD__)
#include "freebsd/ioctls.h"
#else
#warning No *bsd/ioctls.h
#endif
	{ 0, 0 },
};

static abi_long
do_ioctl(int fd, abi_long cmd, abi_long arg)
{
	const IOCTLEntry *ie;
	const argtype *arg_type;
	abi_long ret;
	uint8_t buf_temp[MAX_STRUCT_SIZE];
	int target_size;
	void *argptr;

	ie = ioctl_entries;
	for(;;) {
		if (0 == ie->target_cmd) {
			gemu_log("Unsupported ioctl: cmd=0x%04lx\n", (long)cmd);
			return (-TARGET_ENOSYS);
		}
		if (ie->target_cmd == cmd)
			break;
		ie++;
	}
	arg_type = ie->arg_type;
#if defined(DEBUG)
	gemu_log("ioctl: cmd=0x%04lx (%s)\n", (long)cmd, ie->name);
#endif
	if (ie->do_ioctl) {
		return (ie->do_ioctl(ie, buf_temp, fd, cmd, arg));
	}

	switch(arg_type[0]) {
	case TYPE_NULL:
		/* no argument */
		ret = get_errno(ioctl(fd, ie->host_cmd));
		break;

	case TYPE_PTRVOID:
	case TYPE_INT:
		/* int argument */
		ret = get_errno(ioctl(fd, ie->host_cmd, arg));
		break;

	case TYPE_PTR:
		arg_type++;
		target_size = thunk_type_size(arg_type, 0);
		switch(ie->access) {
		case IOC_R:
			ret = get_errno(ioctl(fd, ie->host_cmd, buf_temp));
			if (!is_error(ret)) {
				argptr = lock_user(VERIFY_WRITE, arg,
				    target_size, 0);
				if (!argptr)
					return (-TARGET_EFAULT);
				thunk_convert(argptr, buf_temp, arg_type,
				    THUNK_TARGET);
				unlock_user(argptr, arg, target_size);
			}
			break;

		case IOC_W:
			argptr = lock_user(VERIFY_READ, arg, target_size, 1);
			if (!argptr)
				return (-TARGET_EFAULT);
			thunk_convert(buf_temp, argptr, arg_type, THUNK_HOST);
			unlock_user(argptr, arg, 0);
			ret = get_errno(ioctl(fd, ie->host_cmd, buf_temp));

		case IOC_RW:
		default:
			argptr = lock_user(VERIFY_READ, arg, target_size, 1);
			if (!argptr)
				return (-TARGET_EFAULT);
			thunk_convert(buf_temp, argptr, arg_type, THUNK_HOST);
			unlock_user(argptr, arg, 0);
			ret = get_errno(ioctl(fd, ie->host_cmd, buf_temp));
			if (!is_error(ret)) {
				argptr = lock_user(VERIFY_WRITE, arg,
				    target_size, 0);
				if (!argptr)
					return (-TARGET_EFAULT);
				thunk_convert(argptr, buf_temp, arg_type,
				    THUNK_TARGET);
				unlock_user(argptr, arg, target_size);
			}
			break;
		}
		break;

	default:
		gemu_log("Unsupported ioctl type: cmd=0x%04lx type=%d\n",
		    (long)cmd, arg_type[0]);
		ret = -TARGET_ENOSYS;
		break;
	}
	return (ret);
}

static inline abi_long
freebsd_exec_common(abi_ulong path_or_fd, abi_ulong guest_argp,
    abi_ulong guest_envp, int do_fexec)
{
	char **argp, **envp, **qargp, **qarg1;
	int argc, envc;
	abi_ulong gp;
	abi_ulong addr;
	char **q;
	int total_size = 0;
	void *p;
	abi_long ret;

	argc = 0;
	for (gp = guest_argp; gp; gp += sizeof(abi_ulong)) {
		if (get_user_ual(addr, gp))
			return (-TARGET_EFAULT);
		if (!addr)
			break;
		argc++;
	}
	envc = 0;
	for (gp = guest_envp; gp; gp += sizeof(abi_ulong)) {
		if (get_user_ual(addr, gp))
			return (-TARGET_EFAULT);
		if (!addr)
			break;
		envc++;
	}

	qargp = argp =  alloca((argc + 3) * sizeof(void *));
	/* save the first agrument for the emulator */
	*argp++ = (char *)getprogname();
	qarg1 = argp;
	envp = alloca((envc + 1) * sizeof(void *));
	for (gp = guest_argp, q = argp; gp; gp += sizeof(abi_ulong), q++) {
		if (get_user_ual(addr, gp)) {
			ret = -TARGET_EFAULT;
			goto execve_end;
		}
		if (!addr)
			break;
		if (!(*q = lock_user_string(addr))) {
			ret = -TARGET_EFAULT;
			goto execve_end;
		}
		total_size += strlen(*q) + 1;
	}
	*q = NULL;

	for (gp = guest_envp, q = envp; gp; gp += sizeof(abi_ulong), q++) {
                if (get_user_ual(addr, gp)) {
			ret = -TARGET_EFAULT;
			goto execve_end;
		}
                if (!addr)
                    break;
                if (!(*q = lock_user_string(addr))) {
			ret = -TARGET_EFAULT;
			goto execve_end;
		}
                total_size += strlen(*q) + 1;
	}
	*q = NULL;

	/*
	 * This case will not be caught by the host's execve() if its
	 * page size is bigger than the target's.
	 */
	if (total_size > MAX_ARG_PAGES * TARGET_PAGE_SIZE) {
		ret = -TARGET_E2BIG;
		goto execve_end;
	}

	if (do_fexec) {
		if (((int)path_or_fd > 0 &&
		    is_target_elf_binary((int)path_or_fd)) == 1) {
			char execpath[PATH_MAX];

			/*
			 * The executable is an elf binary for the target
			 * arch.  execve() it using the emulator if we can
			 * determine the filename path from the fd.
			 */
			if (get_filename_from_fd(getpid(), (int)path_or_fd,
				execpath, sizeof(execpath)) != NULL) {
				*qarg1 = execpath;
				ret = get_errno(execve(qemu_proc_pathname,
					qargp, envp));
			} else {
				/* Getting the filename path failed. */
				ret = -TARGET_EBADF;
				goto execve_end;
			}
		} else {
			ret = get_errno(fexecve((int)path_or_fd, argp, envp));
		}
	} else {
		int fd;

		if (!(p = lock_user_string(path_or_fd))) {
			ret = -TARGET_EFAULT;
			goto execve_end;
		}

		/*
		 * Check the header and see if it a target elf binary.  If so
		 * then execute using qemu user mode emulator.
		 */
		fd = open(p, O_RDONLY | O_CLOEXEC);
		if (fd > 0 && is_target_elf_binary(fd) == 1) {
			close(fd);
			/* Execve() as a target binary using emulator. */
			*qarg1 = (char *)p;
			ret = get_errno(execve(qemu_proc_pathname, qargp, envp));
		} else {
			close(fd);
			/* Execve() as a host native binary. */
			ret = get_errno(execve(p, argp, envp));
		}
		unlock_user(p, path_or_fd, 0);
	}

execve_end:
	for (gp = guest_argp, q = argp; *q; gp += sizeof(abi_ulong), q++) {
		if (get_user_ual(addr, gp) || !addr)
			break;
		unlock_user(*q, addr, 0);
	}

	for (gp = guest_envp, q = envp; *q; gp += sizeof(abi_ulong), q++) {
		if (get_user_ual(addr, gp) || !addr)
			break;
		unlock_user(*q, addr, 0);
	}
	return (ret);
}

static inline abi_long
do_freebsd_execve(abi_ulong path_or_fd, abi_ulong argp, abi_ulong envp)
{

	return (freebsd_exec_common(path_or_fd, argp, envp, 0));
}

static inline abi_long
do_freebsd_fexecve(abi_ulong path_or_fd, abi_ulong argp, abi_ulong envp)
{

	return (freebsd_exec_common(path_or_fd, argp, envp, 1));
}

/* do_syscall() should always have a single exit point at the end so
   that actions, such as logging of syscall results, can be performed.
   All errnos that do_syscall() returns must be -TARGET_<errcode>. */
abi_long do_freebsd_syscall(void *cpu_env, int num, abi_long arg1,
                            abi_long arg2, abi_long arg3, abi_long arg4,
                            abi_long arg5, abi_long arg6, abi_long arg7,
                            abi_long arg8)
{
    abi_long ret;
    void *p;

#ifdef DEBUG
    gemu_log("freebsd syscall %d\n", num);
#endif
    if(do_strace)
        print_freebsd_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6);

    switch(num) {
    case TARGET_FREEBSD_NR_exit:
#ifdef TARGET_GPROF
        _mcleanup();
#endif
        gdb_exit(cpu_env, arg1);
        /* XXX: should free thread stack and CPU env */
        _exit(arg1);
        ret = 0; /* avoid warning */
        break;
    case TARGET_FREEBSD_NR_read:
        if (!(p = lock_user(VERIFY_WRITE, arg2, arg3, 0)))
            goto efault;
        ret = get_errno(read(arg1, p, arg3));
        unlock_user(p, arg2, ret);
        break;

    case TARGET_FREEBSD_NR_readv:
	{
		int count = arg3;
		struct iovec *vec;

		vec = alloca(count * sizeof(struct iovec));
		if (lock_iovec(VERIFY_WRITE, vec, arg2, count, 0) < 0)
			goto efault;
		ret = get_errno(readv(arg1, vec, count));
		unlock_iovec(vec, arg2, count, 1);
	}
	break;

    case TARGET_FREEBSD_NR_pread:
	if (!(p = lock_user(VERIFY_WRITE, arg2, arg3, 0)))
		goto efault;
	ret = get_errno(pread(arg1, p, arg3, target_offset64(arg4, arg5)));
	unlock_user(p, arg2, ret);
	break;

    case TARGET_FREEBSD_NR_preadv:
	{
		int count = arg3;
		struct iovec *vec;

		vec = alloca(count * sizeof(struct iovec));
		if (lock_iovec(VERIFY_WRITE, vec, arg2, count, 0) < 0)
			goto efault;
		ret = get_errno(preadv(arg1, vec, count,
			target_offset64(arg4, arg5)));
		unlock_iovec(vec, arg2, count, 1);
	}
	break;

    case TARGET_FREEBSD_NR_write:
        if (!(p = lock_user(VERIFY_READ, arg2, arg3, 1)))
            goto efault;
        ret = get_errno(write(arg1, p, arg3));
        unlock_user(p, arg2, 0);
        break;

    case TARGET_FREEBSD_NR_writev:
        {
            int count = arg3;
            struct iovec *vec;

            vec = alloca(count * sizeof(struct iovec));
            if (lock_iovec(VERIFY_READ, vec, arg2, count, 1) < 0)
                goto efault;
            ret = get_errno(writev(arg1, vec, count));
            unlock_iovec(vec, arg2, count, 0);
        }
        break;

    case TARGET_FREEBSD_NR_pwrite:
	if (!(p = lock_user(VERIFY_READ, arg2, arg3, 1)))
		goto efault;
	ret = get_errno(pwrite(arg1, p, arg3, target_offset64(arg4, arg5)));
	unlock_user(p, arg2, 0); 
	break;

    case TARGET_FREEBSD_NR_pwritev:
	{
		int count = arg3;
		struct iovec *vec;

		vec = alloca(count * sizeof(struct iovec));
		if (lock_iovec(VERIFY_READ, vec, arg2, count, 1) < 0)
			goto efault;
		ret = get_errno(pwritev(arg1, vec, count,
			target_offset64(arg4, arg5)));
		unlock_iovec(vec, arg2, count, 0);
	}
	break;

    case TARGET_FREEBSD_NR_open:
        if (!(p = lock_user_string(arg1)))
            goto efault;
        ret = get_errno(open(path(p),
                             target_to_host_bitmask(arg2, fcntl_flags_tbl),
                             arg3));
        unlock_user(p, arg1, 0);
        break;

    case TARGET_FREEBSD_NR_openat:
        if (!(p = lock_user_string(arg2)))
            goto efault;
        ret = get_errno(openat(arg1, path(p),
                             target_to_host_bitmask(arg3, fcntl_flags_tbl),
                             arg4));
        unlock_user(p, arg2, 0);
        break;

    case TARGET_FREEBSD_NR_close:
	ret = get_errno(close(arg1));
	break;

    case TARGET_FREEBSD_NR_closefrom:
	ret = 0;
	closefrom(arg1);
	break;

    case TARGET_FREEBSD_NR_revoke:
        if (!(p = lock_user_string(arg1)))
            goto efault;
	ret = get_errno(revoke(p));
        unlock_user(p, arg1, 0);
	break;

#ifdef TARGET_FREEBSD_NR_creat
    case TARGET_FREEBSD_NR_creat:
	if (!(p = lock_user_string(arg1)))
		goto efault;
	ret = get_errno(creat(p, arg2));
	unlock_user(p, arg1, 0);
	break;
#endif

    case TARGET_FREEBSD_NR_mmap:
        ret = get_errno(target_mmap(arg1, arg2, arg3,
                                    target_to_host_bitmask(arg4, mmap_flags_tbl),
                                    arg5,
                                    arg6));
        break;

    case TARGET_FREEBSD_NR_munmap:
        ret = get_errno(target_munmap(arg1, arg2));
        break;

    case TARGET_FREEBSD_NR_mprotect:
        ret = get_errno(target_mprotect(arg1, arg2, arg3));
        break;

    case TARGET_FREEBSD_NR_msync:
	ret = get_errno(msync(g2h(arg1), arg2, arg3));
	break;

    case TARGET_FREEBSD_NR_mlock:
	ret = get_errno(mlock(g2h(arg1), arg2));
	break;

    case TARGET_FREEBSD_NR_munlock:
	ret = get_errno(munlock(g2h(arg1), arg2));
	break;

    case TARGET_FREEBSD_NR_mlockall:
	ret = get_errno(mlockall(arg1));
	break;

    case TARGET_FREEBSD_NR_munlockall:
	ret = get_errno(munlockall());
	break;

    case TARGET_FREEBSD_NR_madvise:
	/*
	 * A straight passthrough may not be safe because qemu sometimes
	 * turns private file-backed mapping into anonymous mappings. This
	 * will break MADV_DONTNEED.  This is a hint, so ignoring and returing
	 * success is ok.
	 */
	ret = get_errno(0);
	break;

    case TARGET_FREEBSD_NR_break:
        ret = do_obreak(arg1);
        break;
#ifdef __FreeBSD__
    case TARGET_FREEBSD_NR___sysctl:
        ret = do_freebsd_sysctl(arg1, arg2, arg3, arg4, arg5, arg6);
        break;
#endif
    case TARGET_FREEBSD_NR_sysarch:
        ret = do_freebsd_sysarch(cpu_env, arg1, arg2);
        break;
    case TARGET_FREEBSD_NR_syscall:
    case TARGET_FREEBSD_NR___syscall:
        ret = do_freebsd_syscall(cpu_env,arg1 & 0xffff,arg2,arg3,arg4,arg5,arg6,arg7,arg8,0);
        break;

    case TARGET_FREEBSD_NR_stat:
	{
	    struct stat st;

	    if (!(p = lock_user_string(arg1)))
		    goto efault;
	    ret = get_errno(stat(path(p), &st));
	    unlock_user(p, arg1, 0);
	    if (0 == ret)
		    ret = host_to_target_stat(arg2, &st);
	}
	break;

    case TARGET_FREEBSD_NR_lstat:
	{
	    struct stat st;

	    if (!(p = lock_user_string(arg1)))
		    goto efault;
	    ret = get_errno(lstat(path(p), &st));
	    unlock_user(p, arg1, 0);
	    if (0 == ret)
		    ret = host_to_target_stat(arg2, &st);
	}
	break;

    case TARGET_FREEBSD_NR_nstat:
    case TARGET_FREEBSD_NR_nfstat:
    case TARGET_FREEBSD_NR_nlstat:
	ret = unimplemented(num);
	break;

    case TARGET_FREEBSD_NR_fstat:
        {
	    struct stat st;

            ret = get_errno(fstat(arg1, &st));
	    if (!is_error(ret))
		    ret = host_to_target_stat(arg2, &st);
	}
        break;

    case TARGET_FREEBSD_NR_nanosleep:
	 {
		 struct timespec req, rem;

		 ret = target_to_host_timespec(&req, arg1);
		 if (!is_error(ret)) {
		     ret = get_errno(nanosleep(&req, &rem));
		     if (!is_error(ret) && arg2)
			     host_to_target_timespec(arg2, &rem);
		 }
	 }
	 break;

    case TARGET_FREEBSD_NR_clock_gettime:
	{
		struct timespec ts;

		ret = get_errno(clock_gettime(arg1, &ts));
		if (!is_error(ret)) {
			if (host_to_target_timespec(arg2, &ts))
				goto efault;
		}
    	}
        break;

   case TARGET_FREEBSD_NR_clock_getres:
	{
		struct timespec ts;

		ret = get_errno(clock_getres(arg1, &ts));
		if (!is_error(ret)) {
			if (host_to_target_timespec(arg2, &ts))
				goto efault;
		}
	}
	break;

    case TARGET_FREEBSD_NR_clock_settime:
	{
		struct timespec ts;

		if (target_to_host_timespec(&ts, arg2) != 0)
			goto efault;
		ret = get_errno(clock_settime(arg1, &ts));
	}
        break;

     case TARGET_FREEBSD_NR_gettimeofday:
	{
		struct timeval tv;
		struct timezone tz, *target_tz;
		if (arg2 != 0) {
			if (!lock_user_struct(VERIFY_READ, target_tz, arg2, 0))
				goto efault;
			__get_user(tz.tz_minuteswest,
			    &target_tz->tz_minuteswest);
			__get_user(tz.tz_dsttime, &target_tz->tz_dsttime);
			unlock_user_struct(target_tz, arg2, 1);
		}
		ret = get_errno(gettimeofday(&tv, arg2 != 0 ? &tz : NULL));
		if (!is_error(ret)) {
			if (host_to_target_timeval(&tv, arg1))
				goto efault;
		}
	}
	break;

    case TARGET_FREEBSD_NR_settimeofday:
	{
		struct timeval tv;
		struct timezone tz, *target_tz;

		if (arg2 != 0) {
			if (!lock_user_struct(VERIFY_READ, target_tz, arg2, 0))
				goto efault;
			__get_user(tz.tz_minuteswest,
			    &target_tz->tz_minuteswest);
			__get_user(tz.tz_dsttime, &target_tz->tz_dsttime);
			unlock_user_struct(target_tz, arg2, 1);
		}
		if (target_to_host_timeval(&tv, arg1))
			goto efault;
		ret = get_errno(settimeofday(&tv, arg2 != 0 ? & tz : NULL));
	}
        break;

    case TARGET_FREEBSD_NR_ktimer_create:
    case TARGET_FREEBSD_NR_ktimer_delete:
    case TARGET_FREEBSD_NR_ktimer_settime:
    case TARGET_FREEBSD_NR_ktimer_gettime:
    case TARGET_FREEBSD_NR_ktimer_getoverrun:
    case TARGET_FREEBSD_NR_minherit:
	ret = unimplemented(num);
	break;

    case TARGET_FREEBSD_NR_kqueue:
	ret = get_errno(kqueue());
	break;

#ifdef __FreeBSD__
    case TARGET_FREEBSD_NR_kevent:
        {
           struct kevent *changelist = NULL, *eventlist = NULL;
           struct target_kevent *target_changelist, *target_eventlist;
           struct timespec ts;
           int i;
           
           if (arg3 != 0) {
              if (!(target_changelist = lock_user(VERIFY_READ, arg2,
                  sizeof(struct target_kevent) * arg3, 1)))
                     goto efault;
              changelist = alloca(sizeof(struct kevent) * arg3);

              for (i = 0; i < arg3; i++) {
                 __get_user(changelist[i].ident, &target_changelist[i].ident);
                 __get_user(changelist[i].filter, &target_changelist[i].filter);
                 __get_user(changelist[i].flags, &target_changelist[i].flags);
                 __get_user(changelist[i].fflags, &target_changelist[i].fflags);
                 __get_user(changelist[i].data, &target_changelist[i].data);
		/* XXX: This is broken when running a 64bits target on a 32bits host */
                 /* __get_user(changelist[i].udata, &target_changelist[i].udata); */
#if TARGET_ABI_BITS == 32
		 changelist[i].udata = (void *)(uintptr_t)target_changelist[i].udata;
		 tswap32s((uint32_t *)&changelist[i].udata);
#else
		 changelist[i].udata = (void *)(uintptr_t)target_changelist[i].udata;
		 tswap64s((uint64_t *)&changelist[i].udata);
#endif
               }
               unlock_user(target_changelist, arg2, 0);
           }

           if (arg5 != 0)
              eventlist = alloca(sizeof(struct kevent) * arg5);
           if (arg6 != 0)
              if (target_to_host_timespec(&ts, arg6))
                goto efault;
           ret = get_errno(kevent(arg1, changelist, arg3, eventlist, arg5,
              arg6 != 0 ? &ts : NULL));
           if (!is_error(ret)) {
               if (!(target_eventlist = lock_user(VERIFY_WRITE, arg4, 
                   sizeof(struct target_kevent) * arg5, 0)))
                      goto efault;
               for (i = 0; i < arg5; i++) {
                 __put_user(eventlist[i].ident, &target_eventlist[i].ident);
                 __put_user(eventlist[i].filter, &target_eventlist[i].filter);
                 __put_user(eventlist[i].flags, &target_eventlist[i].flags);
                 __put_user(eventlist[i].fflags, &target_eventlist[i].fflags);
                 __put_user(eventlist[i].data, &target_eventlist[i].data);
               /* __put_user(eventlist[i].udata, &target_eventlist[i].udata); */
#if TARGET_ABI_BITS == 32
		 tswap32s((uint32_t *)&eventlist[i].data);
		 target_eventlist[i].data = (uintptr_t)eventlist[i].data;
#else
		 tswap64s((uint64_t *)&eventlist[i].data);
		 target_eventlist[i].data = (uintptr_t)eventlist[i].data;
#endif
               }
               unlock_user(target_eventlist, arg4, sizeof(struct target_kevent) * arg5);

              
           }
        }
	break;
#endif

    case TARGET_FREEBSD_NR_execve:
	ret = do_freebsd_execve(arg1, arg2, arg3);
        break;

    case TARGET_FREEBSD_NR_fexecve:
	ret = do_freebsd_fexecve(arg1, arg2, arg3);
        break;


    case TARGET_FREEBSD_NR_pipe:
	{
		int host_pipe[2];
		int host_ret = pipe(host_pipe);

		if (!is_error(host_ret)) {
			set_second_rval(cpu_env, host_pipe[1]);
			ret = host_pipe[0];
		} else
			ret = get_errno(host_ret);
	}
	break;

    case TARGET_FREEBSD_NR_lseek:
	{
#if defined(TARGET_MIPS) && TARGET_ABI_BITS == 32
		/* 32-bit MIPS uses two 32 registers for 64 bit arguments */
		int64_t res = lseek(arg1, target_offset64(arg2, arg3), arg4);

		if (res == -1) {
			ret = get_errno(res);
		} else {
			ret = res & 0xFFFFFFFF;
			((CPUMIPSState*)cpu_env)->active_tc.gpr[3] =
			    (res >> 32) & 0xFFFFFFFF;
		}
#else
		ret = get_errno(lseek(arg1, arg2, arg3));
#endif
	}
	break;

    case TARGET_FREEBSD_NR_select:
	ret = do_freebsd_select(arg1, arg2, arg3, arg4, arg5);
	break;

    case TARGET_FREEBSD_NR_pselect:
	ret = do_freebsd_pselect(arg1, arg2, arg3, arg4, arg5, arg6);
	break;

    case TARGET_FREEBSD_NR_poll:
	{
		nfds_t i, nfds = arg2;
		int timeout = arg3;
		struct pollfd *pfd;
		struct target_pollfd *target_pfd = lock_user(VERIFY_WRITE, arg1,
		    sizeof(struct target_pollfd) * nfds, 1);

		if (!target_pfd)
			goto efault;

		pfd = alloca(sizeof(struct pollfd) * nfds);
		for(i = 0; i < nfds; i++) {
			pfd[i].fd = tswap32(target_pfd[i].fd);
			pfd[i].events = tswap16(target_pfd[i].events);
		}
		ret = get_errno(poll(pfd, nfds, timeout));

		if (!is_error(ret)) {
			for(i = 0; i < nfds; i++) {
				target_pfd[i].revents = tswap16(pfd[i].revents);
			}
		}
		unlock_user(target_pfd, arg1, sizeof(struct target_pollfd) *
		    nfds);
	}
	break;

    case TARGET_FREEBSD_NR_openbsd_poll:
	ret = unimplemented(num);
	break;

    case TARGET_FREEBSD_NR_setrlimit:
	{
		int resource = target_to_host_resource(arg1);
		struct target_rlimit *target_rlim;
		struct rlimit rlim;

		if (RLIMIT_STACK == resource) {
			/* XXX We should, maybe, allow the stack size to shrink */
			ret = -TARGET_EPERM;
		} else {
			if (!lock_user_struct(VERIFY_READ, target_rlim, arg2, 1))
				goto efault;
			rlim.rlim_cur = target_to_host_rlim(target_rlim->rlim_cur);
			rlim.rlim_max = target_to_host_rlim(target_rlim->rlim_max);
			unlock_user_struct(target_rlim, arg2, 0);
			ret = get_errno(setrlimit(resource, &rlim));
		}
	}
	break;


    case TARGET_FREEBSD_NR_getrlimit:
	{
		int resource = target_to_host_resource(arg1);
		struct target_rlimit *target_rlim;
		struct rlimit rlim;

		switch (resource) {
		case RLIMIT_STACK:
			rlim.rlim_cur = target_dflssiz;
			rlim.rlim_max = target_maxssiz;
			ret = 0;
			break;

		case RLIMIT_DATA:
			rlim.rlim_cur = target_dfldsiz;
			rlim.rlim_max = target_maxdsiz;
			ret = 0;
			break;

		default:
			ret = get_errno(getrlimit(resource, &rlim));
			break;
		}
		if (!is_error(ret)) {
			if (!lock_user_struct(VERIFY_WRITE, target_rlim, arg2,
				0))
				goto efault;
			target_rlim->rlim_cur =
			    host_to_target_rlim(rlim.rlim_cur);
			target_rlim->rlim_max =
			    host_to_target_rlim(rlim.rlim_max);
			unlock_user_struct(target_rlim, arg2, 1);
		}
	}
	break;

    case TARGET_FREEBSD_NR_setitimer:
	{
		struct itimerval value, ovalue, *pvalue;

		if (arg2) {
			pvalue = &value;
			if (target_to_host_timeval(&pvalue->it_interval,
				arg2) || target_to_host_timeval(
				&pvalue->it_value, arg2 +
				sizeof(struct target_timeval)))
				goto efault;
		} else {
			pvalue = NULL;
		}
		ret = get_errno(setitimer(arg1, pvalue, &ovalue));
		if (!is_error(ret) && arg3) {
			if (host_to_target_timeval(&ovalue.it_interval, arg3)
			    || host_to_target_timeval(&ovalue.it_value,
				arg3 + sizeof(struct target_timeval)))
				goto efault;
		}
	}
	break;

    case TARGET_FREEBSD_NR_getitimer:
	{
		struct itimerval value;

		ret = get_errno(getitimer(arg1, &value));
		if (!is_error(ret) && arg2) {
			if (host_to_target_timeval(&value.it_interval, arg2)
			    || host_to_target_timeval(&value.it_value,
				arg2 + sizeof(struct target_timeval)))
				goto efault;
		}
	}
	break;

    case TARGET_FREEBSD_NR_utimes:
	{
		struct timeval *tvp, tv[2];

		if (arg2) {
			if (target_to_host_timeval(&tv[0], arg2)
			    || target_to_host_timeval(&tv[1],
				arg2 + sizeof(struct target_timeval)))

				goto efault;
			tvp = tv;
		} else {
			tvp = NULL;
		}
		if (!(p = lock_user_string(arg1)))
			goto efault;
		ret = get_errno(utimes(p, tvp));
		unlock_user(p, arg1, 0);
	}
	break;

    case TARGET_FREEBSD_NR_lutimes:
	{
		struct timeval *tvp, tv[2];

		if (arg2) {
			if (target_to_host_timeval(&tv[0], arg2)
			    || target_to_host_timeval(&tv[1],
				arg2 + sizeof(struct target_timeval)))

				goto efault;
			tvp = tv;
		} else {
			tvp = NULL;
		}
		if (!(p = lock_user_string(arg1)))
			goto efault;
		ret = get_errno(lutimes(p, tvp));
		unlock_user(p, arg1, 0);
	}
	break;

    case TARGET_FREEBSD_NR_futimes:
	{
		struct timeval *tvp, tv[2];

		if (arg2) {
			if (target_to_host_timeval(&tv[0], arg2)
			    || target_to_host_timeval(&tv[1],
				arg2 + sizeof(struct target_timeval)))
				goto efault;
			tvp = tv;
		} else {
			tvp = NULL;
		}
		ret = get_errno(futimes(arg1, tvp));
	}
	break;

    case TARGET_FREEBSD_NR_futimesat:
	{
		struct timeval *tvp, tv[2];

		if (arg3) {
			if (target_to_host_timeval(&tv[0], arg3)
			    || target_to_host_timeval(&tv[1],
				arg3 + sizeof(struct target_timeval)))
				goto efault;
			tvp = tv;
		} else {
			tvp = NULL;
		}
		if (!(p = lock_user_string(arg2)))
			goto efault;
		ret = get_errno(futimesat(arg1, path(p), tvp));
		unlock_user(p, arg2, 0);
	}
	break;

    case TARGET_FREEBSD_NR_access:
	if (!(p = lock_user_string(arg1)))
		goto efault;
	ret = get_errno(access(path(p), arg2));
	unlock_user(p, arg1, 0);

    case TARGET_FREEBSD_NR_eaccess:
	if (!(p = lock_user_string(arg1)))
		goto efault;
	ret = get_errno(eaccess(path(p), arg2));
	unlock_user(p, arg1, 0);
	break;

    case TARGET_FREEBSD_NR_faccessat:
	if (!(p = lock_user_string(arg2)))
		goto efault;
	ret = get_errno(faccessat(arg1, p, arg3, arg4));
	unlock_user(p, arg2, 0);
	break;

    case TARGET_FREEBSD_NR_chdir:
	if (!(p = lock_user_string(arg1)))
		goto efault;
	ret = get_errno(chdir(p));
	unlock_user(p, arg1, 0);
	break;

    case TARGET_FREEBSD_NR_fchdir:
	ret = get_errno(fchdir(arg1));
	break;

    case TARGET_FREEBSD_NR_rename:
	{
		void *p2;

		p = lock_user_string(arg1);
		p2 = lock_user_string(arg2);
		if (!p || !p2)
			ret = -TARGET_EFAULT;
		else
			ret = get_errno(rename(p, p2));
		unlock_user(p2, arg2, 0);
		unlock_user(p, arg1, 0);
	}
	break;

    case TARGET_FREEBSD_NR_renameat:
	{
		void *p2;

		p  = lock_user_string(arg2);
		p2 = lock_user_string(arg4);
		if (!p || !p2)
			ret = -TARGET_EFAULT;
		else
			ret = get_errno(renameat(arg1, p, arg3, p2));
		unlock_user(p2, arg4, 0);
		unlock_user(p, arg2, 0);
	}
	break;

    case TARGET_FREEBSD_NR_link:
	{
		void * p2;

		p = lock_user_string(arg1);
		p2 = lock_user_string(arg2);
		if (!p || !p2)
			ret = -TARGET_EFAULT;
		else
			ret = get_errno(link(p, p2));
		unlock_user(p2, arg2, 0);
		unlock_user(p, arg1, 0);
	}
	break;

    case TARGET_FREEBSD_NR_linkat:
	{
		void * p2 = NULL;

		if (!arg2 || !arg4)
			goto efault;

		p  = lock_user_string(arg2);
		p2 = lock_user_string(arg4);
		if (!p || !p2)
			ret = -TARGET_EFAULT;
		else
			ret = get_errno(linkat(arg1, p, arg3, p2, arg5));
		unlock_user(p, arg2, 0);
		unlock_user(p2, arg4, 0);
	}
	break;

    case TARGET_FREEBSD_NR_unlink:
	if (!(p = lock_user_string(arg1)))
		goto efault;
	ret = get_errno(unlink(p));
	unlock_user(p, arg1, 0);
	break;

    case TARGET_FREEBSD_NR_unlinkat:
	if (!(p = lock_user_string(arg2)))
		goto efault;
	ret = get_errno(unlinkat(arg1, p, arg3));
	unlock_user(p, arg2, 0);
	break;

    case TARGET_FREEBSD_NR_mkdir:
	if (!(p = lock_user_string(arg1)))
		goto efault;
	ret = get_errno(mkdir(p, arg2));
	unlock_user(p, arg1, 0);
	break;

    case TARGET_FREEBSD_NR_mkdirat:
	 if (!(p = lock_user_string(arg2)))
		 goto efault;
	 ret = get_errno(mkdirat(arg1, p, arg3));
	 unlock_user(p, arg2, 0);
	 break;

    case TARGET_FREEBSD_NR_rmdir:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(rmdir(p));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR___getcwd:
	 if (!(p = lock_user(VERIFY_WRITE, arg1, arg2, 0)))
		 goto efault;
	 ret = get_errno(__getcwd(p, arg2));
	 unlock_user(p, arg1, ret);
	 break;

    case TARGET_FREEBSD_NR_dup:
	 ret = get_errno(dup(arg1));
	 break;

    case TARGET_FREEBSD_NR_dup2:
	 ret = get_errno(dup2(arg1, arg2));
	 break;

    case TARGET_FREEBSD_NR_truncate:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 if (regpairs_aligned(cpu_env)) {
		 arg2 = arg3;
		 arg3 = arg4;
	 }
	 ret = get_errno(truncate(p, target_offset64(arg2, arg3)));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR_ftruncate:
	 if (regpairs_aligned(cpu_env)) {
		 arg2 = arg3;
		 arg3 = arg4;
	 }
	 ret = get_errno(ftruncate(arg1, target_offset64(arg2, arg3)));
	 break;

    case TARGET_FREEBSD_NR_acct:
	 if (arg1 == 0) {
		 ret = get_errno(acct(NULL));
	 } else {
		 if (!(p = lock_user_string(arg1)))
			 goto efault;
		 ret = get_errno(acct(path(p)));
		 unlock_user(p, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_sync:
	 sync();
	 ret = 0;
	 break;

    case TARGET_FREEBSD_NR_mount:
	 {
		 void *p2;

		 /* We need to look at the data field. */
		 p = lock_user_string(arg1);	/* type */
		 p2 = lock_user_string(arg2);	/* dir */
		 if (!p || !p2)
			 ret = -TARGET_EFAULT;
		 else {
			 /*
			  * XXX arg5 should be locked, but it isn't clear
			  * how to do that since it's it may be not be a
			  * NULL-terminated string.
			  */
			 if ( ! arg5 )
				 ret = get_errno(mount(p, p2, arg3, NULL));
			 else
				 ret = get_errno(mount(p, p2, arg3, g2h(arg5)));
		 }
		 unlock_user(p, arg1, 0);
		 unlock_user(p2, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_unmount:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(unmount(p, arg2));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR_nmount:
	 {
		 int count = arg2;
		 struct iovec *vec;

		 vec = alloca(count * sizeof(struct iovec));
		 if (lock_iovec(VERIFY_READ, vec, arg2, count, 1) < 0)
			 goto efault;
		 ret = get_errno(nmount(vec, count, arg3));
		 unlock_iovec(vec, arg2, count, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_symlink:
	 {
		 void *p2;

		 p = lock_user_string(arg1);
		 p2 = lock_user_string(arg2);
		 if (!p || !p2)
			 ret = -TARGET_EFAULT;
		 else
			 ret = get_errno(symlink(p, p2));
		 unlock_user(p2, arg2, 0);
		 unlock_user(p, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_symlinkat:
	 {
		 void *p2;

		 p  = lock_user_string(arg1);
		 p2 = lock_user_string(arg3);
		 if (!p || !p2)
			 ret = -TARGET_EFAULT;
		 else
			 ret = get_errno(symlinkat(p, arg2, p2));
		 unlock_user(p2, arg3, 0);
		 unlock_user(p, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_readlink:
	 {
		 void *p2;

		 p = lock_user_string(arg1);
		 p2 = lock_user(VERIFY_WRITE, arg2, arg3, 0);
		 if (!p || !p2)
			 ret = -TARGET_EFAULT;
		 else
			 ret = get_errno(readlink(path(p), p2, arg3));
		 unlock_user(p2, arg2, ret);
		 unlock_user(p, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_readlinkat:
	 {
		 void *p2;
		 p = lock_user_string(arg2);
		 p2 = lock_user(VERIFY_WRITE, arg3, arg4, 0);

		 if (!p || !p2)
			 ret = -TARGET_EFAULT;
		 else
			 ret = get_errno(readlinkat(arg1, path(p), p2, arg4));
		 unlock_user(p2, arg3, ret);
		 unlock_user(p, arg2, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_chmod:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(chmod(p, arg2));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR_fchmod:
	 ret = get_errno(fchmod(arg1, arg2));
	 break;

    case TARGET_FREEBSD_NR_lchmod:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(lchmod(p, arg2));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR_fchmodat:
	 if (!(p = lock_user_string(arg2)))
		 goto efault;
	 ret = get_errno(fchmodat(arg1, p, arg3, arg4));
	 unlock_user(p, arg2, 0);
	 break;

    case TARGET_FREEBSD_NR_mknod:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(mknod(p, arg2, arg3));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR_mknodat:
	 if (!(p = lock_user_string(arg2)))
		 goto efault;
	 ret = get_errno(mknodat(arg1, p, arg3, arg4));
	 unlock_user(p, arg2, 0);
	 break;

    case TARGET_FREEBSD_NR_chown:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(chown(p, arg2, arg3));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR_fchown:
	 ret = get_errno(fchown(arg1, arg2, arg3));
	 break;

    case TARGET_FREEBSD_NR_lchown:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(lchown(p, arg2, arg3));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR_fchownat:
	 if (!(p = lock_user_string(arg2)))
		 goto efault;
	 ret = get_errno(fchownat(arg1, p, arg3, arg4, arg5));
	 unlock_user(p, arg2, 0);
	 break;

    case TARGET_FREEBSD_NR_chflags:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(chflags(p, arg2));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR_lchflags:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(lchflags(p, arg2));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR_fchflags:
	 ret = get_errno(fchflags(arg1, arg2));
	 break;

    case TARGET_FREEBSD_NR_getgroups:
	 {
		 int gidsetsize = arg1;
		 uint32_t *target_grouplist;
		 gid_t *grouplist;
		 int i;

		 grouplist = alloca(gidsetsize * sizeof(gid_t));
		 ret = get_errno(getgroups(gidsetsize, grouplist));
		 if (gidsetsize == 0)
			 break;
		 if (!is_error(ret)) {
			 target_grouplist = lock_user(VERIFY_WRITE, arg2,
			     gidsetsize * 2, 0);
			 if (!target_grouplist)
				 goto efault;
			 for (i = 0;i < ret; i++)
				 target_grouplist[i] = tswap32(grouplist[i]);
			 unlock_user(target_grouplist, arg2, gidsetsize * 2);
		 }
	 }
	 break;

    case TARGET_FREEBSD_NR_setgroups:
	 {
		 int gidsetsize = arg1;
		 uint32_t *target_grouplist;
		 gid_t *grouplist;
		 int i;

		 grouplist = alloca(gidsetsize * sizeof(gid_t));
		 target_grouplist = lock_user(VERIFY_READ, arg2,
		     gidsetsize * 2, 1);
		 if (!target_grouplist) {
			 ret = -TARGET_EFAULT;
			 goto fail;
		 }
		 for(i = 0;i < gidsetsize; i++)
			 grouplist[i] = tswap32(target_grouplist[i]);
		 unlock_user(target_grouplist, arg2, 0);
		 ret = get_errno(setgroups(gidsetsize, grouplist));
	 }
	 break;

    case TARGET_FREEBSD_NR_umask:
	 ret = get_errno(umask(arg1));
	 break;

    case TARGET_FREEBSD_NR_fcntl:
	 {
		 int host_cmd;
		 struct flock fl;
		 struct target_flock *target_fl;

		 host_cmd = target_to_host_fcntl_cmd(arg2);
		 if (-TARGET_EINVAL == host_cmd) {
			 ret = host_cmd;
			 break;
		 }

		 switch(arg2) {
		 case TARGET_F_GETLK:
			 if (!lock_user_struct(VERIFY_READ, target_fl, arg3, 1))
				 return (-TARGET_EFAULT);
			 fl.l_type = tswap16(target_fl->l_type);
			 fl.l_whence = tswap16(target_fl->l_whence);
			 fl.l_start = tswap64(target_fl->l_start);
			 fl.l_len = tswap64(target_fl->l_len);
			 fl.l_pid = tswap32(target_fl->l_pid);
			 fl.l_sysid = tswap32(target_fl->l_sysid);
			 unlock_user_struct(target_fl, arg3, 0);
			 ret = get_errno(fcntl(arg1, host_cmd, &fl));
			 if (0 == ret) {
				 if (!lock_user_struct(VERIFY_WRITE, target_fl,
					 arg3, 0))
					 return (-TARGET_EFAULT);
				 target_fl->l_type = tswap16(fl.l_type);
				 target_fl->l_whence = tswap16(fl.l_whence);
				 target_fl->l_start = tswap64(fl.l_start);
				 target_fl->l_len = tswap64(fl.l_len);
				 target_fl->l_pid = tswap32(fl.l_pid);
				 target_fl->l_sysid = tswap32(fl.l_sysid);
				 unlock_user_struct(target_fl, arg3, 1);
			 }
			 break;

		 case TARGET_F_SETLK:
		 case TARGET_F_SETLKW:
			 if (!lock_user_struct(VERIFY_READ, target_fl, arg3, 1))
				 return (-TARGET_EFAULT);
			 fl.l_start = tswap64(target_fl->l_start);
			 fl.l_len = tswap64(target_fl->l_len);
			 fl.l_pid = tswap32(target_fl->l_pid);
			 fl.l_type = tswap16(target_fl->l_type);
			 fl.l_whence = tswap16(target_fl->l_whence);
			 fl.l_sysid = tswap32(target_fl->l_sysid);
			 unlock_user_struct(target_fl, arg3, 0);
			 ret = get_errno(fcntl(arg1, host_cmd, &fl));
			 break;

		 case TARGET_F_DUPFD:
		 case TARGET_F_DUP2FD:
		 case TARGET_F_GETOWN:
		 case TARGET_F_SETOWN:
		 case TARGET_F_GETFD:
		 case TARGET_F_SETFD:
		 case TARGET_F_GETFL:
		 case TARGET_F_SETFL:
		 case TARGET_F_READAHEAD:
		 case TARGET_F_RDAHEAD:
		 default:
			 ret = get_errno(fcntl(arg1, host_cmd, arg3));
			 break;
		 }
	 }
	 break;

    case TARGET_FREEBSD_NR_getdents:
	 {
		 struct dirent *dirp;
		 int32_t nbytes =  arg3;

		 if (!(dirp = lock_user(VERIFY_WRITE, arg2, nbytes, 0)))
			 goto efault;
		 ret = get_errno(getdents(arg1, (char *)dirp, nbytes));
		 if (!is_error(ret)) {
			 struct dirent *de;
			 int len = ret;
			 int reclen;

			 de = dirp;
			 while (len > 0) {
				 reclen = de->d_reclen;
				 if (reclen > len)
					 break;
				 de->d_reclen = tswap16(reclen);
				 len -= reclen;
			 }
		 }
		 unlock_user(dirp, arg2, ret);
	 }
	 break;

    case TARGET_FREEBSD_NR_getdirentries:
	 {
		 struct dirent *dirp;
		 int32_t nbytes =  arg3;
		 long basep;

		 if (!(dirp = lock_user(VERIFY_WRITE, arg2, nbytes, 0)))
			 goto efault;
		 ret = get_errno(getdirentries(arg1, (char *)dirp, nbytes,
			 &basep));
		 if (!is_error(ret)) {
			 struct dirent *de;
			 int len = ret;
			 int reclen;

			 de = dirp;
			 while (len > 0) {
				 reclen = de->d_reclen;
				 if (reclen > len)
					 break;
				 de->d_reclen = tswap16(reclen);
				 de->d_fileno = tswap32(de->d_fileno);
				 len -= reclen;
				 de = (struct dirent *)((void *)de + reclen);
			 }
		 }
		 unlock_user(dirp, arg2, ret);
		 if (arg4) {
			 if (put_user(basep, arg4, abi_ulong))
				 ret = -TARGET_EFAULT;
		 }
	 }
	 break;

    case TARGET_FREEBSD_NR_chroot:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(chroot(p));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR_flock:
	 ret = get_errno(flock(arg1, arg2));
	 break;

    case TARGET_FREEBSD_NR_mkfifo:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(mkfifo(p, arg2));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR_mkfifoat:
	 if (!(p = lock_user_string(arg2)))
		 goto efault;
	 ret = get_errno(mkfifoat(arg1, p, arg2));
	 unlock_user(p, arg2, 0);
	 break;

    case TARGET_FREEBSD_NR_pathconf:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(pathconf(p, arg2));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR_lpathconf:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(lpathconf(p, arg2));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR_fpathconf:
	 ret = get_errno(fpathconf(arg1, arg2));
	 break;

    case TARGET_FREEBSD_NR_undelete:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(undelete(p));
	 unlock_user(p, arg1, 0);
	 break;


    case TARGET_FREEBSD_NR___acl_aclcheck_fd:
	 {
		 struct acl host_acl;

		 ret = target_to_host_acl(&host_acl, arg3);
		 if (!is_error(ret))
			 ret = get_errno(__acl_aclcheck_fd(arg1, arg2,
				 &host_acl));
	 }
	 break;

    case TARGET_FREEBSD_NR___acl_aclcheck_file:
	 {
		 struct acl host_acl;

		 if (!(p = lock_user_string(arg1)))
			 goto efault;

		 ret = target_to_host_acl(&host_acl, arg3);
		 if (!is_error(ret))
			 ret = get_errno(__acl_aclcheck_file(path(p) , arg2,
				 &host_acl));

		 unlock_user(p, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR___acl_aclcheck_link:
	 {
		 struct acl host_acl;

		 if (!(p = lock_user_string(arg1)))
			 goto efault;

		 ret = target_to_host_acl(&host_acl, arg3);
		 if (!is_error(ret))
			 ret = get_errno(__acl_aclcheck_link(path(p), arg2,
				 &host_acl));

		 unlock_user(p, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR___acl_delete_fd:
	 ret = get_errno(__acl_delete_fd(arg1, arg2));
	 break;

    case TARGET_FREEBSD_NR___acl_delete_file:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;

	 ret = get_errno(__acl_delete_file(path(p), arg2));

	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR___acl_delete_link:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;

	 ret = get_errno(__acl_delete_link(path(p), arg2));

	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR___acl_get_fd:
	 {
		 struct acl host_acl;

		 ret = get_errno(__acl_get_fd(arg1, arg2, &host_acl));

		 if (!is_error(ret))
			ret = host_to_target_acl(arg3, &host_acl);
	 }
	 break;

    case TARGET_FREEBSD_NR___acl_get_file:
	 {
		 struct acl host_acl;

		 if (!(p = lock_user_string(arg1)))
			 goto efault;

		 ret = get_errno(__acl_get_file(path(p), arg2, &host_acl));

		 if (!is_error(ret))
			 ret = host_to_target_acl(arg3, &host_acl);

		 unlock_user(p, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR___acl_get_link:
	 {
		 struct acl host_acl;

		 if (!(p = lock_user_string(arg1)))
			 goto efault;

		 ret = get_errno(__acl_get_link(path(p), arg2, &host_acl));

		 if (!is_error(ret))
			 ret = host_to_target_acl(arg3, &host_acl);

		 unlock_user(p, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR___acl_set_fd:
	 {
		 struct acl host_acl;

		 if (!(p = lock_user_string(arg1)))
			 goto efault;

		 ret = target_to_host_acl(&host_acl, arg3);
		 if (!is_error(ret))
			ret = get_errno(__acl_set_fd(arg1, arg2, &host_acl));

		 unlock_user(p, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR___acl_set_file:
	 {
		 struct acl host_acl;

		 if (!(p = lock_user_string(arg1)))
			 goto efault;

		 ret = target_to_host_acl(&host_acl, arg3);
		 if (!is_error(ret))
			ret = get_errno(__acl_set_file(path(p), arg2,
				&host_acl));

		 unlock_user(p, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR___acl_set_link:
	 {
		 struct acl host_acl;

		 if (!(p = lock_user_string(arg1)))
			 goto efault;

		 ret = target_to_host_acl(&host_acl, arg3);
		 if (!is_error(ret))
			ret = get_errno(__acl_set_link(path(p), arg2,
				&host_acl));

		 unlock_user(p, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_extattrctl:
	 {
		 void *a, *f;

		 if (!(p = lock_user_string(arg1)))
			 goto efault;
		 if (!(f = lock_user_string(arg3)))
			 goto efault;
		 if (!(a = lock_user_string(arg5)))
			 goto efault;

		 ret = get_errno(extattrctl(path(p), arg2, f, arg4, a));

		 unlock_user(a, arg5, 0);
		 unlock_user(f, arg3, 0);
		 unlock_user(p, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_extattr_set_file:
	 {
		 void *a, *d;

		 if (!(p = lock_user_string(arg1)))
			 goto efault;
		 if (!(a = lock_user_string(arg3)))
			 goto efault;
		 if (!(d = lock_user(VERIFY_READ, arg4, arg5, 1)))
			 goto efault;

		 ret = get_errno(extattr_set_file(path(p), arg2, a, d, arg5));

		 unlock_user(d, arg4, arg5);
		 unlock_user(a, arg3, 0);
		 unlock_user(p, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_extattr_get_file:
	 {
		 void *a, *d;

		 if (!(p = lock_user_string(arg1)))
			 goto efault;
		 if (!(a = lock_user_string(arg3)))
			 goto efault;

		 if (arg4 && arg5 > 0) {
			 if (!(d = lock_user(VERIFY_WRITE, arg4, arg5, 0)))
				 goto efault;
			 ret = get_errno(extattr_get_file(path(p), arg2, a, d,
				 arg5));
			 unlock_user(d, arg4, arg5);
		 } else {
			 ret = get_errno(extattr_get_file(path(p), arg2, a,
				 NULL, arg5));
		 }
		 unlock_user(a, arg3, 0);
		 unlock_user(p, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_extattr_delete_file:
	 {
		 void *a;

		 if (!(p = lock_user_string(arg1)))
			 goto efault;
		 if (!(a = lock_user_string(arg3)))
			 goto efault;

		 ret = get_errno(extattr_delete_file(path(p), arg2, a));

		 unlock_user(a, arg3, 0);
		 unlock_user(p, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_extattr_set_fd:
	 {
		 void *a, *d;

		 if (!(a = lock_user_string(arg3)))
			 goto efault;
		 if (!(d = lock_user(VERIFY_READ, arg4, arg5, 1)))
			 goto efault;

		 ret = get_errno(extattr_set_fd(arg1, arg2, a, d, arg5));

		 unlock_user(d, arg4, arg5);
		 unlock_user(a, arg3, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_extattr_get_fd:
	 {
		 void *a, *d;

		 if (!(a = lock_user_string(arg3)))
			 goto efault;

		 if (arg4 && arg5 > 0) {
			 if (!(d = lock_user(VERIFY_WRITE, arg4, arg5, 0)))
				 goto efault;
			 ret = get_errno(extattr_get_fd(arg1, arg2, a, d,
				 arg5));
			 unlock_user(d, arg4, arg5);
		 } else {
			 ret = get_errno(extattr_get_fd(arg1, arg2, a,
				 NULL, arg5));
		 }
		 unlock_user(a, arg3, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_extattr_delete_fd:
	 {
		 void *a;

		 if (!(a = lock_user_string(arg3)))
			 goto efault;

		 ret = get_errno(extattr_delete_fd(arg1, arg2, a));

		 unlock_user(a, arg3, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_extattr_get_link:
	 {
		 void *a, *d;

		 if (!(p = lock_user_string(arg1)))
			 goto efault;
		 if (!(a = lock_user_string(arg3)))
			 goto efault;

		 if (arg4 && arg5 > 0) {
			 if (!(d = lock_user(VERIFY_WRITE, arg4, arg5, 0)))
				 goto efault;
			 ret = get_errno(extattr_get_link(path(p), arg2, a, d,
				 arg5));
			 unlock_user(d, arg4, arg5);
		 } else {
			 ret = get_errno(extattr_get_link(path(p), arg2, a,
				 NULL, arg5));
		 }
		 unlock_user(a, arg3, 0);
		 unlock_user(p, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_extattr_set_link:
	 {
		 void *a, *d;

		 if (!(p = lock_user_string(arg1)))
			 goto efault;
		 if (!(a = lock_user_string(arg3)))
			 goto efault;
		 if (!(d = lock_user(VERIFY_READ, arg4, arg5, 1)))
			 goto efault;

		 ret = get_errno(extattr_set_link(path(p), arg2, a, d, arg5));

		 unlock_user(d, arg4, arg5);
		 unlock_user(a, arg3, 0);
		 unlock_user(p, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_extattr_delete_link:
	 {
		 void *a;

		 if (!(p = lock_user_string(arg1)))
			 goto efault;
		 if (!(a = lock_user_string(arg3)))
			 goto efault;

		 ret = get_errno(extattr_delete_link(path(p), arg2, a));

		 unlock_user(a, arg3, 0);
		 unlock_user(p, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_extattr_list_fd:
	 {
		 void *d;

		 if (arg3 && arg4 > 0) {
			 if (!(d = lock_user(VERIFY_WRITE, arg3, arg4, 0)))
				 goto efault;
			 ret = get_errno(extattr_list_fd(arg1, arg2, d,
				 arg4));
			 unlock_user(d, arg3, arg4);
		 } else {
			 ret = get_errno(extattr_list_fd(arg1, arg2,
				 NULL, arg4));
		 }
	 }
	 break;

    case TARGET_FREEBSD_NR_extattr_list_file:
	 {
		 void *d;

		 if (!(p = lock_user_string(arg1)))
			 goto efault;

		 if (arg3 && arg4 > 0) {
			 if (!(d = lock_user(VERIFY_WRITE, arg3, arg4, 0)))
				 goto efault;
			 ret = get_errno(extattr_list_file(path(p), arg2, d,
				 arg4));
			 unlock_user(d, arg3, arg4);
		 } else {
			 ret = get_errno(extattr_list_file(path(p), arg2,
				 NULL, arg4));
		 }
		 unlock_user(p, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_extattr_list_link:
	 {
		 void *d;

		 if (!(p = lock_user_string(arg1)))
			 goto efault;

		 if (arg3 && arg4 > 0) {
			 if (!(d = lock_user(VERIFY_WRITE, arg3, arg4, 0)))
				 goto efault;
			 ret = get_errno(extattr_list_link(path(p), arg2, d,
				 arg4));
			 unlock_user(d, arg3, arg4);
		 } else {
			 ret = get_errno(extattr_list_link(path(p), arg2,
				 NULL, arg4));
		 }

		 unlock_user(p, arg1, 0);
	 }
	 break;

    case TARGET_FREEBSD_NR_setlogin:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(setlogin(p));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR_getlogin:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(_getlogin(p, arg2));
	 unlock_user(p, arg1, 0);
	 break;

#if defined(__FreeBSD_version) && __FreeBSD_version > 900000
    case TARGET_FREEBSD_NR_setloginclass:
	 if (!(p = lock_user_string(arg1)))
		goto efault;
	 ret = get_errno(setloginclass(p));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR_getloginclass:
	 if (!(p = lock_user_string(arg1)))
		goto efault;
	 ret = get_errno(getloginclass(p, arg2));
	 unlock_user(p, arg1, 0);
	 break;
#endif

    case TARGET_FREEBSD_NR_getrusage:
	 {
		 struct rusage rusage;
		 ret = get_errno(getrusage(arg1, &rusage));
		 if (!is_error(ret))
			 host_to_target_rusage(arg2, &rusage);
	 }
	 break;

    case TARGET_FREEBSD_NR_wait4:
	 {
		 int status;
		 abi_long status_ptr = arg2;
		 struct rusage rusage, *rusage_ptr;
		 abi_ulong target_rusage = arg4;

		 if (target_rusage)
			 rusage_ptr = &rusage;
		 else
			 rusage_ptr = NULL;
		 ret = get_errno(wait4(arg1, &status, arg3, rusage_ptr));
		 if (!is_error(ret)) {
			 status = host_to_target_waitstatus(status);
			 if (put_user_s32(status, status_ptr))
				 goto efault;
			 if (target_rusage)
				 host_to_target_rusage(target_rusage, &rusage);
		 }
	 }
	 break;

#ifdef TARGET_FREEBSD_NR_pdwait4
    case TARGET_FREEBSD_NR_pdwait4:
	 {
		 int status;
		 abi_long status_ptr = arg2;
		 struct rusage rusage, *rusage_ptr;
		 abi_long target_rusage = arg4;

		 if (target_rusage)
			 rusage_ptr = &rusage;
		 else
			 rusage_ptr = NULL;
		 ret = get_errno(wait4(arg1, &status, arg3, rusage_ptr));
		 if (!is_error(ret)) {
			 status = host_to_target_waitstatus(status);
			 if (put_user_s32(status, status_ptr))
				 goto efault;
			 if (target_rusage)
				 host_to_target_rusage(target_rusage, &rusage);
		 }
	 }
	 break;
#endif /* TARGET_FREEBSD_NR_pdwait4 */

    case TARGET_FREEBSD_NR_accept:
	 ret = do_accept(arg1, arg2, arg3);
	 break;

    case TARGET_FREEBSD_NR_bind:
	 ret = do_bind(arg1, arg2, arg3);
	 break;

    case TARGET_FREEBSD_NR_connect:
	 ret = do_connect(arg1, arg2, arg3);
	 break;

    case TARGET_FREEBSD_NR_getpeername:
	 ret = do_getpeername(arg1, arg2, arg3);
	 break;

    case TARGET_FREEBSD_NR_getsockname:
	 ret = do_getsockname(arg1, arg2, arg3);
	 break;

    case TARGET_FREEBSD_NR_getsockopt:
	 ret = do_getsockopt(arg1, arg2, arg3, arg4, arg5);
	 break;

    case TARGET_FREEBSD_NR_setsockopt:
	 ret = do_setsockopt(arg1, arg2, arg3, arg4, arg5);
	 break;

    case TARGET_FREEBSD_NR_listen:
	 ret = get_errno(listen(arg1, arg2));
	 break;

    case TARGET_FREEBSD_NR_recvfrom:
	 ret = do_recvfrom(arg1, arg2, arg3, arg4, arg5, arg6);
	 break;

    case TARGET_FREEBSD_NR_recvmsg:
	 ret = do_sendrecvmsg(arg1, arg2, arg3, 0);
	 break;

    case TARGET_FREEBSD_NR_sendmsg:
	 ret = do_sendrecvmsg(arg1, arg2, arg3, 1);
	 break;

    case TARGET_FREEBSD_NR_sendto:
	 ret = do_sendto(arg1, arg2, arg3, arg4, arg5, arg6);
	 break;

    case TARGET_FREEBSD_NR_socket:
	 ret = get_errno(socket(arg1, arg2, arg3));
	 break;

    case TARGET_FREEBSD_NR_socketpair:
	 ret = do_socketpair(arg1, arg2, arg3, arg4);
	 break;

    case TARGET_FREEBSD_NR_shutdown:
	ret = get_errno(shutdown(arg1, arg2));
	break;

    case TARGET_FREEBSD_NR_getpriority:
	 /*
	  * Note that negative values are valid for getpriority, so we must
	  * differentiate based on errno settings.
	  */
	 errno = 0;
	 ret = getpriority(arg1, arg2);
	 if (ret == -1 && errno != 0) {
		 ret = -host_to_target_errno(errno);
		 break;
	 }
	 /* Return value is a biased priority to avoid negative numbers. */
	 ret = 20 - ret;
	 break;

    case TARGET_FREEBSD_NR_setpriority:
	 ret = get_errno(setpriority(arg1, arg2, arg3));
	 break;

    case TARGET_FREEBSD_NR_semget:
	 ret = get_errno(semget(arg1, arg2, arg3));
	 break;

    case TARGET_FREEBSD_NR_semop:
	 ret = get_errno(do_semop(arg1, arg2, arg3));
	 break;

    case TARGET_FREEBSD_NR___semctl:
	 ret = do_semctl(arg1, arg2, arg3, (union target_semun)(abi_ulong)arg4);
	 break;

    case TARGET_FREEBSD_NR_freebsd7___semctl:
	 ret = unimplemented(num);
	 break;

    case TARGET_FREEBSD_NR_msgctl:
	 ret = do_msgctl(arg1, arg2, arg3);
	 break;

    case TARGET_FREEBSD_NR_msgrcv:
	 ret = do_msgrcv(arg1, arg2, arg3, arg4, arg5);
	 break;

    case TARGET_FREEBSD_NR_msgsnd:
	 ret = do_msgsnd(arg1, arg2, arg3, arg4);
	 break;

    case TARGET_FREEBSD_NR_shmget:
	 ret = get_errno(shmget(arg1, arg2, arg3));
	 break;

    case TARGET_FREEBSD_NR_shmctl:
	 ret = do_shmctl(arg1, arg2, arg3);
	 break;

    case TARGET_FREEBSD_NR_shmat:
	 ret = do_shmat(arg1, arg2, arg3);
	 break;

    case TARGET_FREEBSD_NR_shmdt:
	 ret = do_shmdt(arg1);
	 break;

    case TARGET_FREEBSD_NR_shm_open:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(shm_open(path(p),
		 target_to_host_bitmask(arg2, fcntl_flags_tbl),
		 arg3));
	 unlock_user(p, arg1, 0);
	 break;

    case TARGET_FREEBSD_NR_shm_unlink:
	 if (!(p = lock_user_string(arg1)))
		 goto efault;
	 ret = get_errno(shm_unlink(p));
	 break;

    case TARGET_FREEBSD_NR_getpid:
	 ret = get_errno(getpid());
	 break;

    case TARGET_FREEBSD_NR_getppid:
	 ret = get_errno(getppid());
	 break;

    case TARGET_FREEBSD_NR_getuid:
	 ret = get_errno(getuid());
	 break;

    case TARGET_FREEBSD_NR_geteuid:
	 ret = get_errno(geteuid());
	 break;

    case TARGET_FREEBSD_NR_getgid:
	 ret = get_errno(getgid());
	 break;

    case TARGET_FREEBSD_NR_getegid:
	 ret = get_errno(getegid());
	 break;

    case TARGET_FREEBSD_NR_setuid:
	 ret = get_errno(setuid(arg1));
	 break;

    case TARGET_FREEBSD_NR_setgid:
	 ret = get_errno(setgid(arg1));
	 break;

    case TARGET_FREEBSD_NR_setegid:
	 ret = get_errno(setegid(arg1));
	 break;

    case TARGET_FREEBSD_NR_seteuid:
	 ret = get_errno(seteuid(arg1));
	 break;

    case TARGET_FREEBSD_NR_getpgrp:
	 ret = get_errno(getpgrp());
	 break;

#ifdef TARGET_FREEBSD_NR_setpgrp
    case TARGET_FREEBSD_NR_setpgrp:
	 ret = get_errno(setpgrp(arg1, arg2));
	 break;
#endif

    case TARGET_FREEBSD_NR_setreuid:
	 ret = get_errno(setreuid(arg1, arg2));
	 break;

    case TARGET_FREEBSD_NR_setregid:
	 ret = get_errno(setregid(arg1, arg2));
	 break;

    case TARGET_FREEBSD_NR_setresuid:
	 ret = get_errno(setresuid(arg1, arg2, arg3));
	 break;

    case TARGET_FREEBSD_NR_setresgid:
	 ret = get_errno(setresgid(arg1, arg2, arg3));
	 break;

    case TARGET_FREEBSD_NR_getresuid:
	 {
		 uid_t ruid, euid, suid;

		 ret = get_errno(getresuid(&ruid, &euid, &suid));
		 if (put_user_s32(ruid, arg1))
			 goto efault;
		 if (put_user_s32(euid, arg2))
			 goto efault;
		 if (put_user_s32(suid, arg3))
			 goto efault;
	 }
	 break;

    case TARGET_FREEBSD_NR_getresgid:
	 {
		gid_t rgid, egid, sgid;

		ret = get_errno(getresgid(&rgid, &egid, &sgid));
		if (put_user_s32(rgid, arg1))
			goto efault;
		if (put_user_s32(egid, arg2))
			goto efault;
		if (put_user_s32(sgid, arg3))
			goto efault;
	 }
	 break;

    case TARGET_FREEBSD_NR_setsid:
	 ret = get_errno(setsid());
	 break;

    case TARGET_FREEBSD_NR_getsid:
	 ret = get_errno(getsid(arg1));
	 break;

    case TARGET_FREEBSD_NR_setfib:
	 ret = get_errno(setfib(arg1));
	 break;

    case TARGET_FREEBSD_NR___setugid:
	 ret = get_errno(__setugid(arg1));
	 break;

    case TARGET_FREEBSD_NR_issetugid:
	 ret = get_errno(issetugid());
	 break;

#ifdef TARGET_FREEBSD_NR_wait
    case TARGET_FREEBSD_NR_wait:
	 ret = get_errno(wait());
	 break;
#endif

    case TARGET_FREEBSD_NR_fork:
	 ret = get_errno(do_fork(cpu_env, num, 0, NULL));
	 break;

    case TARGET_FREEBSD_NR_rfork:
	 ret = get_errno(do_fork(cpu_env, num, arg1, NULL));
	 break;

    case TARGET_FREEBSD_NR_vfork:
	 ret = get_errno(do_fork(cpu_env, num, 0, NULL));
	 break;

    case TARGET_FREEBSD_NR_pdfork:
	 {
		int pd;

		ret = get_errno(do_fork(cpu_env, num, arg2, &pd));
		if (put_user_s32(pd, arg1))
			goto efault;
	 }
	 break;

    case TARGET_FREEBSD_NR_kill:
	 ret = get_errno(kill(arg1, target_to_host_signal(arg2)));
	 break;

#ifdef TARGET_FREEBSD_NR_killpg
    case TARGET_FREEBSD_NR_killpg:
	 ret = get_errno(killpg(arg1, target_to_host_signal(arg2)));
	 break;
#endif

#if defined(__FreeBSD_version) && __FreeBSD_version > 900000
    case TARGET_FREEBSD_NR_pdkill:
	 ret = get_errno(pdkill(arg1, target_to_host_signal(arg2)));
	 break;

    case TARGET_FREEBSD_NR_pdgetpid:
	 {
		 pid_t pid;

		 ret = get_errno(pdgetpid(arg1, &pid));
		 if (put_user_u32(pid, arg2))
			 goto efault;
	 }
	 break;
#endif

    case TARGET_FREEBSD_NR_sigaction:
	 {
		 struct target_sigaction *old_act, act, oact, *pact;

		 if (arg2) {
			 if (!lock_user_struct(VERIFY_READ, old_act, arg2, 1))
				 goto efault;
			 act._sa_handler = old_act->_sa_handler;
			 act.sa_flags = old_act->sa_flags;
			 memcpy(&act.sa_mask, &old_act->sa_mask,
			     sizeof(target_sigset_t));
			 unlock_user_struct(old_act, arg2, 0);
			 pact = &act;
		 } else {
			 pact = NULL;
		 }
		 ret = get_errno(do_sigaction(arg1, pact, &oact));
		 if (!is_error(ret) && arg3) {
			 if (!lock_user_struct(VERIFY_WRITE, old_act, arg3, 0))
			     goto efault;
			 old_act->_sa_handler = oact._sa_handler;
			 old_act->sa_flags = oact.sa_flags;
			 memcpy(&old_act->sa_mask, &oact.sa_mask,
			     sizeof(target_sigset_t));
			 unlock_user_struct(old_act, arg3, 1);
		 }
	 }
	 break;

    case TARGET_FREEBSD_NR_sigprocmask:
	 {
		 sigset_t set, oldset, *set_ptr;
		 int how;

		 if (arg2) {
			 switch (arg1) {
			 case TARGET_SIG_BLOCK:
				 how = SIG_BLOCK;
				 break;

			 case TARGET_SIG_UNBLOCK:
				 how = SIG_UNBLOCK;
				 break;

			 case TARGET_SIG_SETMASK:
				 how = SIG_SETMASK;
				 break;

			 default:
				 ret = -TARGET_EINVAL;
				 goto fail;
			 }
			 if (!(p = lock_user(VERIFY_READ, arg2,
				     sizeof(target_sigset_t), 1)))
				 goto efault;
			 target_to_host_sigset(&set, p);
			 unlock_user(p, arg2, 0);
			 set_ptr = &set;
		 } else {
			 how = 0;
			 set_ptr = NULL;
		 }
		 ret = get_errno(sigprocmask(how, set_ptr, &oldset));
		 if (!is_error(ret) && arg3) {
			 if (!(p = lock_user(VERIFY_WRITE, arg3,
				     sizeof(target_sigset_t), 0)))
				 goto efault;
			 host_to_target_sigset(p, &oldset);
			 unlock_user(p, arg3, sizeof(target_sigset_t));
		 }
	 }
	 break;

    case TARGET_FREEBSD_NR_sigpending:
	 {
		 sigset_t set;

		 ret = get_errno(sigpending(&set));
		 if (!is_error(ret)) {
			 if (!(p = lock_user(VERIFY_WRITE, arg1,
				     sizeof(target_sigset_t), 0)))
				 goto efault;
			 host_to_target_sigset(p, &set);
			 unlock_user(p, arg1, sizeof(target_sigset_t));
		 }
	 }
	 break;

    case TARGET_FREEBSD_NR_sigsuspend:
	 {
		 sigset_t set;

		 if (!(p = lock_user(VERIFY_READ, arg1,
			     sizeof(target_sigset_t), 1)))
			 goto efault;
		 target_to_host_sigset(&set, p);
		 unlock_user(p, arg1, 0);
		 ret = get_errno(sigsuspend(&set));
	 }
	 break;

    case TARGET_FREEBSD_NR_sigreturn:
	 ret = do_sigreturn(cpu_env, arg1);
	 break;

#ifdef TARGET_FREEBSD_NR_sigvec
    case TARGET_FREEBSD_NR_sigvec:
	 ret = unimplemented(num);
	 break;
#endif
#ifdef TARGET_FREEBSD_NR_sigblock
    case TARGET_FREEBSD_NR_sigblock:
	 ret = unimplemented(num);
	 break;
#endif
#ifdef TARGET_FREEBSD_NR_sigsetmask
    case TARGET_FREEBSD_NR_sigsetmask:
	 ret = unimplemented(num);
	 break;
#endif
#ifdef TARGET_FREEBSD_NR_sigstack
    case TARGET_FREEBSD_NR_sigstack:
	 ret = unimplemented(num);
	 break;
#endif

    case TARGET_FREEBSD_NR_sigwait:
	 {
		 sigset_t set;
		 int sig;

		 if (!(p = lock_user(VERIFY_READ, arg1,
			     sizeof(target_sigset_t), 1)))
			 goto efault;
		 target_to_host_sigset(&set, p);
		 unlock_user(p, arg1, 0);
		 ret = get_errno(sigwait(&set, &sig));
		 if (!is_error(ret) && arg2) {
			 /* XXX */
		 }
	 }
	 break;

    case TARGET_FREEBSD_NR_sigtimedwait:
	 {
		 sigset_t set;
		 struct timespec uts, *puts;
		 siginfo_t uinfo;

		 if (!(p = lock_user(VERIFY_READ, arg1,
			     sizeof(target_sigset_t), 1)))
			 goto efault;
		 target_to_host_sigset(&set, p);
		 unlock_user(p, arg1, 0);
		 if (arg3) {
			 puts = &uts;
			 target_to_host_timespec(puts, arg3);
		 } else {
			 puts = NULL;
		 }
		 ret = get_errno(sigtimedwait(&set, &uinfo, puts));
		 if (!is_error(ret) && arg2) {
			 if (!(p = lock_user(VERIFY_WRITE, arg2,
				     sizeof(target_siginfo_t), 0)))
				 goto efault;
			 host_to_target_siginfo(p, &uinfo);
			 unlock_user(p, arg2, sizeof(target_siginfo_t));
		 }
	 }
	 break;

    case TARGET_FREEBSD_NR_sigwaitinfo:
	 {
		 sigset_t set;
		 siginfo_t uinfo;

		 if (!(p = lock_user(VERIFY_READ, arg1,
			     sizeof(target_sigset_t), 1)))
			 goto efault;
		 target_to_host_sigset(&set, p);
		 unlock_user(p, arg1, 0);
		 ret = get_errno(sigwaitinfo(&set, &uinfo));
		 if (!is_error(ret) && arg2) {
			 if (!(p = lock_user(VERIFY_WRITE, arg2,
				     sizeof(target_siginfo_t), 0)))
				 goto efault;
			 host_to_target_siginfo(p, &uinfo);
			 unlock_user(p, arg2, sizeof(target_siginfo_t));
		 }
	 }
	 break;

    case TARGET_FREEBSD_NR_sigqueue:
	 {
		 union sigval value;

		 value.sival_ptr = (void *)(uintptr_t)arg3;
		 ret = get_errno(sigqueue(arg1, target_to_host_signal(arg2),
			 value));
	 }
	 break;

    case TARGET_FREEBSD_NR_sigaltstack:
	 {

		 ret = do_sigaltstack(arg1, arg2,
		     get_sp_from_cpustate((CPUArchState *)cpu_env));
	 }

#ifdef TARGET_FREEBSD_NR_aio_read
    case TARGET_FREEBSD_NR_aio_read:
	 ret = unimplemented(num);
	 break;
#endif
#ifdef TARGET_FREEBSD_NR_aio_write
    case TARGET_FREEBSD_NR_aio_write:
	 ret = unimplemented(num);
	 break;
#endif
#ifdef TARGET_FREEBSD_NR_aio_return
    case TARGET_FREEBSD_NR_aio_return:
	 ret = unimplemented(num);
	 break;
#endif
#ifdef TARGET_FREEBSD_NR_aio_suspend
    case TARGET_FREEBSD_NR_aio_suspend:
	 ret = unimplemented(num);
	 break;
#endif
#ifdef TARGET_FREEBSD_NR_aio_cancel
    case TARGET_FREEBSD_NR_aio_cancel:
	 ret = unimplemented(num);
	 break;
#endif
#ifdef TARGET_FREEBSD_NR_aio_error
    case TARGET_FREEBSD_NR_aio_error:
	 ret = unimplemented(num);
	 break;
#endif
#ifdef TARGET_FREEBSD_NR_aio_waitcomplete
    case TARGET_FREEBSD_NR_aio_waitcomplete:
	 ret = unimplemented(num);
	 break;
#endif
#ifdef TARGET_FREEBSD_NR_lio_listio
    case TARGET_FREEBSD_NR_lio_listio:
	 ret = unimplemented(num);
	 break;
#endif

#ifdef TARGET_FREEBSD_NR_getdomainname
    case TARGET_FREEBSD_NR_getdomainname:
	 ret = unimplemented(num);
	 break;
#endif
#ifdef TARGET_FREEBSD_NR_setdomainname
    case TARGET_FREEBSD_NR_setdomainname:
	 ret = unimplemented(num);
	 break;
#endif
#ifdef TARGET_FREEBSD_NR_uname
    case TARGET_FREEBSD_NR_uname:
	 ret = unimplemented(num);
	 break;
#endif


#if 0 /* XXX not supported in libc yet, it seems (10.0 addition). */
    case TARGET_FREEBSD_NR_posix_fadvise:
	 {
		 off_t offset = arg2, len = arg3;
		 int advice = arg4;

#if TARGET_ABI_BITS == 32
		 if (regpairs_aligned(cpu_env)) {
			 offset = target_offset64(arg3, arg4);
			 len = target_offset64(arg5, arg6);
			 advice = arg7;
		 } else {
			 offset = target_offset64(arg2, arg3);
			 len = target_offset64(arg4, arg5);
			 advice = arg6;
		 }
#endif
		 ret = get_errno(posix_fadvise(arg1, offset, len, advice));
	 }
	 break;
#endif

#if defined(__FreeBSD_version) && __FreeBSD_version > 900000
    case TARGET_FREEBSD_NR_posix_fallocate:
	 {
		 off_t offset = arg2, len = arg3;

#if TARGET_ABI_BITS == 32
		 if (regpairs_aligned(cpu_env)) {
			 offset = target_offset64(arg3, arg4);
			 len = target_offset64(arg5, arg6);
		 } else {
			 offset = target_offset64(arg2, arg3);
			 len = target_offset64(arg4, arg5);
		 }
#endif
		 ret = get_errno(posix_fallocate(arg1, offset, len));
	 }
	 break;
#endif

#ifdef TARGET_FREEBSD_posix_openpt
    case TARGET_FREEBSD_posix_openpt:
	 ret = get_errno(posix_openpt(arg1));
	 break;
#endif

    case TARGET_FREEBSD_NR_thr_new:
	 ret = do_thr_new(cpu_env, arg1, arg2);
	 break;

    case TARGET_FREEBSD_NR_thr_create:
	 {
		 ucontext_t ucxt;
		 long tid;

		 ret = do_thr_create(cpu_env, &ucxt, &tid, arg3);
	 }
	 break;

    case TARGET_FREEBSD_NR_thr_set_name:
	 if (!(p = lock_user_string(arg2)))
		 goto efault;
	 ret = do_thr_set_name(arg1, p);
	 unlock_user(p, arg2, 0);
	 break;

    case TARGET_FREEBSD_NR_thr_self:
	 {
		 long tid;

		 if ((ret = do_thr_self(&tid)) == 0) {
			 if (put_user((abi_long)tid, arg1, abi_long))
				 goto efault;
		 }
	 }
	 break;

    case TARGET_FREEBSD_NR_thr_suspend:
	 {
		 struct timespec ts;

		 if (arg1) {
			 if (target_to_host_timespec(&ts, arg1))
				 goto efault;
			 ret = do_thr_suspend(&ts);
		 } else
			 ret = do_thr_suspend(NULL);

	 }
	 break;

    case TARGET_FREEBSD_NR_thr_wake:
	 ret = do_thr_wake(arg1);
	 break;

    case TARGET_FREEBSD_NR_thr_kill:
	 ret = do_thr_kill(arg1, arg2);
	 break;

    case TARGET_FREEBSD_NR_thr_kill2:
	 ret = do_thr_kill2(arg1, arg2, arg3);
	 break;

    case TARGET_FREEBSD_NR_thr_exit:
	 ret = 0; /* suspress compile warning */
	 do_thr_exit(cpu_env, arg1);
	 /* Shouldn't be reached. */
	 break;

    case TARGET_FREEBSD_NR_rtprio_thread:
	 ret = do_rtprio_thread(arg1, arg2, arg3);
	 break;

    case TARGET_FREEBSD_NR_getcontext:
	 {
		 target_ucontext_t *ucp;
		 sigset_t sigmask;

		 if (0 == arg1) {
			 ret = -TARGET_EINVAL;
		 } else {
			 ret = get_errno(sigprocmask(0, NULL, &sigmask));
			 if (!is_error(ret)) {
				 if (!(ucp = lock_user(VERIFY_WRITE, arg1,
					     sizeof(target_ucontext_t), 0)))
					 goto efault;
				 ret = get_mcontext(cpu_env, &ucp->uc_mcontext,
				     TARGET_MC_GET_CLEAR_RET);
				 host_to_target_sigset(&ucp->uc_sigmask,
				     &sigmask);
				 memset(ucp->__spare__, 0,
				     sizeof(ucp->__spare__));
				 unlock_user(ucp, arg1,
				     sizeof(target_ucontext_t));
			 }
		 }
	 }
	 break;

    case TARGET_FREEBSD_NR_setcontext:
	 {
		 target_ucontext_t *ucp;
		 sigset_t sigmask;

		 if (0 == arg1) {
			 ret = -TARGET_EINVAL;
		 } else {
			 if (!(ucp = lock_user(VERIFY_READ, arg1,
				     sizeof(target_ucontext_t), 1)))
				 goto efault;
			 ret = set_mcontext(cpu_env, &ucp->uc_mcontext, 0);
			 target_to_host_sigset(&sigmask, &ucp->uc_sigmask);
			 unlock_user(ucp, arg1, sizeof(target_ucontext_t));
			 if (0 == ret)
				 (void)sigprocmask(SIG_SETMASK, &sigmask, NULL);
		 }
	 }
	 break;

    case TARGET_FREEBSD_NR_swapcontext:
	 /*
	  * XXX Does anything besides old implementations of
	  * setjmp()/longjmp() uses these?
	  */
	 ret = unimplemented(num);
	 break;

    case TARGET_FREEBSD_NR__umtx_lock:
	 {
		 long tid;

		 thr_self(&tid);
		 ret = do_lock_umtx(arg1, tid, NULL);
	 }
	 break;

    case TARGET_FREEBSD_NR__umtx_unlock:
	 {
		 long tid;

		 thr_self(&tid);
		 ret = do_unlock_umtx(arg1, tid);
	 }
	 break;

    case TARGET_FREEBSD_NR__umtx_op:
	 {
		 struct timespec ts;
		 long tid;

		 /* int _umtx_op(void *obj, int op, u_long val,
		  * void *uaddr, void *target_ts); */

		 abi_ulong obj = arg1;
		 int op = (int)arg2;
		 u_long val = arg3;
		 abi_ulong uaddr = arg4;
		 abi_ulong target_ts = arg5;

		 switch(op) {
		 case TARGET_UMTX_OP_LOCK:
			 thr_self(&tid);
			 if (target_ts) {
				 if (target_to_host_timespec(&ts, target_ts))
					 goto efault;
				 ret = do_lock_umtx(obj, tid, &ts);
			 } else
				 ret = do_lock_umtx(obj, tid, NULL);
			 break;

		 case TARGET_UMTX_OP_UNLOCK:
			 thr_self(&tid);
			 ret = do_unlock_umtx(obj, tid);
			 break;

		 case TARGET_UMTX_OP_WAIT:
			 /* args: obj *, val, ts * */
			if (target_ts) {
				 if (target_to_host_timespec(&ts, target_ts))
					 goto efault;
				 ret = do_umtx_op_wait(obj, tswapal(val), &ts);
			 } else
				 ret = do_umtx_op_wait(obj, tswapal(val), NULL);
			 break;

		 case TARGET_UMTX_OP_WAKE:
			/* args: obj *, nr_wakeup */ 
			 ret = do_umtx_op_wake(obj, val);
			 break;

		 case TARGET_UMTX_OP_MUTEX_LOCK:
			 thr_self(&tid);
			 if (target_ts) {
				 if (target_to_host_timespec(&ts, target_ts))
					 goto efault;
				 ret = do_lock_umutex(obj, tid, &ts, 0);
			 } else {
				 ret = do_lock_umutex(obj, tid, NULL, 0);
			 }
			 break;

		 case TARGET_UMTX_OP_MUTEX_UNLOCK:
			 thr_self(&tid);
			 ret = do_unlock_umutex(obj, tid);
			 break;

		 case TARGET_UMTX_OP_MUTEX_TRYLOCK:
			 thr_self(&tid);
			 ret = do_lock_umutex(obj, tid, NULL, TARGET_UMUTEX_TRY);
			 break;

		 case TARGET_UMTX_OP_MUTEX_WAIT:
			 thr_self(&tid);
			 if (target_ts) {
				 if (target_to_host_timespec(&ts, target_ts))
					 goto efault;
				 ret = do_lock_umutex(obj, tid, &ts,
				     TARGET_UMUTEX_WAIT);
			 } else {
				 ret = do_lock_umutex(obj, tid, NULL,
				     TARGET_UMUTEX_WAIT);
			 }
			 break;

		 case TARGET_UMTX_OP_MUTEX_WAKE:
			 /* Don't need to do access_ok(). */
			 ret = get_errno(_umtx_op(g2h(obj), UMTX_OP_MUTEX_WAKE,
				val, NULL, NULL));
			 break;

		 case TARGET_UMTX_OP_SET_CEILING:
			 ret = 0; /* XXX quietly ignore these things for now */
			 break;

		 case TARGET_UMTX_OP_CV_WAIT:
			 /*
			  * Initialization of the struct conv is done by
			  * bzero'ing everything in userland.
			  */
			if (target_ts) {
				if (target_to_host_timespec(&ts, target_ts))
					goto efault;
				ret = do_cv_wait(obj, uaddr, &ts, val);
			} else {
				ret = do_cv_wait(obj, uaddr, NULL, val);
			}
			break;

		 case TARGET_UMTX_OP_CV_SIGNAL:
			 /*
			  * XXX
			  * User code may check if c_has_waiters is zero.  Other
			  * than that it is assume that user code doesn't do
			  * much with the struct conv fields and is pretty
			  * much opauque to userland.
			  */
			ret = do_cv_signal(obj);
			break;

		 case TARGET_UMTX_OP_CV_BROADCAST:
			 /*
			  * XXX
			  * User code may check if c_has_waiters is zero.  Other
			  * than that it is assume that user code doesn't do
			  * much with the struct conv fields and is pretty
			  * much opauque to userland.
			  */
			ret = do_cv_broadcast(obj);
			break;

		 case TARGET_UMTX_OP_WAIT_UINT:
			if (! access_ok(VERIFY_READ, obj, sizeof(abi_ulong)))
				goto efault;
			 if (target_ts) {
				 if (target_to_host_timespec(&ts, target_ts))
					 goto efault;
				 ret = get_errno(_umtx_op(g2h(obj),
					 UMTX_OP_WAIT_UINT,
					 tswap32((uint32_t)val), NULL, &ts));
			 } else
				 ret = get_errno(_umtx_op(g2h(obj),
					 UMTX_OP_WAIT_UINT,
					 tswap32((uint32_t)val), NULL, NULL));

			 break;

		 case TARGET_UMTX_OP_WAIT_UINT_PRIVATE:
			if (! access_ok(VERIFY_READ, obj, sizeof(abi_ulong)))
				goto efault;
			if (target_ts) {
				if (target_to_host_timespec(&ts, target_ts))
					goto efault;
				ret = get_errno(_umtx_op(g2h(obj),
					UMTX_OP_WAIT_UINT_PRIVATE,
					tswap32((uint32_t)val), NULL, &ts));
			} else
				ret = get_errno(_umtx_op(g2h(obj),
					UMTX_OP_WAIT_UINT_PRIVATE,
					tswap32((uint32_t)val), NULL, NULL));

			break;

		 case TARGET_UMTX_OP_WAKE_PRIVATE:
			 /* Don't need to do access_ok(). */
			 ret = get_errno(_umtx_op(g2h(obj), UMTX_OP_WAKE_PRIVATE,
				val, NULL, NULL));
			break;

#if defined(__FreeBSD_version) && __FreeBSD_version > 900000
		 case TARGET_UMTX_OP_NWAKE_PRIVATE:
			{
				int i;
				abi_ulong *uaddr;

				if (! access_ok(VERIFY_READ, obj,
					val * sizeof(uint32_t)))
					goto efault;

				ret = get_errno(_umtx_op(g2h(obj), UMTX_OP_NWAKE_PRIVATE,
					val, NULL, NULL));

				uaddr = (abi_ulong *)g2h(obj);
				ret = 0;
				for(i = 0; i < (int32_t)val; i++) {
					ret = get_errno(_umtx_op(g2h(tswapal(uaddr[i])),
						UMTX_OP_WAKE_PRIVATE, tswap32(INT_MAX),
						NULL, NULL));
					if (ret)
						break;
				}

			}
			break;
#endif

		 case TARGET_UMTX_OP_RW_RDLOCK:
			 if (target_ts) {
				 if (target_to_host_timespec(&ts, target_ts))
					 goto efault;
				 ret = do_rw_rdlock(obj, val, &ts);
			 } else
				 ret = do_rw_rdlock(obj, val, NULL);
			 break;

		 case TARGET_UMTX_OP_RW_WRLOCK:
			 if (target_ts) {
				 if (target_to_host_timespec(&ts, target_ts))
					 goto efault;
				 ret = do_rw_wrlock(obj, val, &ts);
			 } else
				 ret = do_rw_wrlock(obj, val, NULL);
			 break;

		 case TARGET_UMTX_OP_RW_UNLOCK:
			 ret = do_rw_unlock(obj);
			 break;

#ifdef	UMTX_OP_MUTEX_WAKE2
		 case TARGET_UMTX_OP_MUTEX_WAKE2:
			if (! access_ok(VERIFY_WRITE, obj,
				sizeof(struct target_ucond))) {
				goto efault;
			}
			ret = get_errno(_umtx_op(g2h(obj),
				UMTX_OP_MUTEX_WAKE2, val, NULL, NULL));
			break;
#endif

#if defined(__FreeBSD_version) && __FreeBSD_version > 900000
		 case TARGET_UMTX_OP_SEM_WAIT:
			/* XXX Assumes struct _usem is opauque to the user */
			if (! access_ok(VERIFY_WRITE, obj,
				sizeof(struct target__usem))) {
				goto efault;
			}
			if (target_ts) {
				if (target_to_host_timespec(&ts, target_ts))
					goto efault;
				ret = get_errno(_umtx_op(g2h(obj),
					UMTX_OP_SEM_WAIT, 0, NULL, &ts));
			} else {
				ret = get_errno(_umtx_op(g2h(obj),
					UMTX_OP_SEM_WAIT, 0, NULL, NULL));
			}
			break;

		 case TARGET_UMTX_OP_SEM_WAKE:
			 /* Don't need to do access_ok(). */
			 ret = get_errno(_umtx_op(g2h(obj), UMTX_OP_SEM_WAKE,
				val, NULL, NULL));
			break;
#endif

		 default:
			 ret = -TARGET_EINVAL;
			 break;
		 }
	 }
	 break;

    case TARGET_FREEBSD_NR_getfh:
        if (!(p = lock_user_string(arg1)))
            goto efault;
        ret = do_getfh(path(p), arg2);
        unlock_user(p, arg1, 0);
	break;

    case TARGET_FREEBSD_NR_lgetfh:
        if (!(p = lock_user_string(arg1)))
            goto efault;
        ret = do_lgetfh(path(p), arg2);
        unlock_user(p, arg1, 0);
	break;

    case TARGET_FREEBSD_NR_fhopen:
	ret = do_fhopen(arg1, arg2);
	break;

    case TARGET_FREEBSD_NR_fhstat:
	ret = do_fhstat(arg1, arg2);
	break;

    case TARGET_FREEBSD_NR_fhstatfs:
	ret = do_fhstatfs(arg1, arg2);
	break;

    case TARGET_FREEBSD_NR_getfsstat:
	ret = do_getfsstat(arg1, arg2, arg3);
	break;

    case TARGET_FREEBSD_NR_statfs:
        if (!(p = lock_user_string(arg1)))
            goto efault;
	ret = do_statfs(path(p), arg2);
        unlock_user(p, arg1, 0);
	break;

    case TARGET_FREEBSD_NR_fstatfs:
	ret = do_fstatfs(arg1, arg2);
	break;

    case TARGET_FREEBSD_NR_ioctl:
	ret = do_ioctl(arg1, arg2, arg3);
	break;

    case TARGET_FREEBSD_NR_kenv:
	{
		char *n, *v;

		if (!(n = lock_user_string(arg2)))
			goto efault;
		if (!(v = lock_user_string(arg3)))
			goto efault;
		ret = get_errno(kenv(arg1, n, v, arg4));
		unlock_user(v, arg3, 0);
		unlock_user(n, arg2, 0);
	}
	break;

    case TARGET_FREEBSD_NR_swapon:
	if (!(p = lock_user_string(arg1)))
		goto efault;
	ret = get_errno(swapon(path(p)));
	unlock_user(p, arg1, 0);
	break;

    case TARGET_FREEBSD_NR_swapoff:
	if (!(p = lock_user_string(arg1)))
		goto efault;
	ret = get_errno(swapoff(path(p)));
	unlock_user(p, arg1, 0);
	break;

    case TARGET_FREEBSD_NR_reboot:
	ret = get_errno(reboot(arg1));
	break;

    case TARGET_FREEBSD_NR_uuidgen:
	ret = do_uuidgen(arg1, arg2);
	break;

    case TARGET_FREEBSD_NR_mincore:
        if (!(p = lock_user(VERIFY_WRITE, arg3, arg2, 0)))
            goto efault;
	ret = get_errno(mincore(g2h(arg1), arg2, p));
        unlock_user(p, arg3, ret);
	break;

    case TARGET_FREEBSD_NR_adjtime:
	ret = do_adjtime(arg1, arg2);
	break;

    case TARGET_FREEBSD_NR_ntp_adjtime:
	ret = do_ntp_adjtime(arg1);
	break;

    case TARGET_FREEBSD_NR_ntp_gettime:
	ret = do_ntp_gettime(arg1);
	break;

    case TARGET_FREEBSD_NR_vadvise:
	ret = -TARGET_EINVAL;	/* See sys_ovadvise() in vm_unix.c */
	break;

    case TARGET_FREEBSD_NR_sbrk:
	ret = -TARGET_EOPNOTSUPP; /* see sys_sbrk() in vm_mmap.c */
	break;

    case TARGET_FREEBSD_NR_sstk:
	ret = -TARGET_EOPNOTSUPP; /* see sys_sstk() in vm_mmap.c */
	break;

    case TARGET_FREEBSD_NR_yield:
    case TARGET_FREEBSD_NR_sched_yield:
	ret = get_errno(sched_yield());
	break;

    case TARGET_FREEBSD_NR_sched_setparam:
	ret = do_sched_setparam(arg1, arg2);
	break;

    case TARGET_FREEBSD_NR_sched_getparam:
	ret = do_sched_getparam(arg1, arg2);
	break;

    case TARGET_FREEBSD_NR_sched_setscheduler:
	ret = do_sched_setscheduler(arg1, arg2, arg3);
	break;

    case TARGET_FREEBSD_NR_sched_getscheduler:
	ret = get_errno(sched_getscheduler(arg1));
	break;

    case TARGET_FREEBSD_NR_sched_get_priority_max:
	ret = get_errno(sched_get_priority_max(arg1));
	break;

    case TARGET_FREEBSD_NR_sched_get_priority_min:
	ret = get_errno(sched_get_priority_min(arg1));
	break;

    case TARGET_FREEBSD_NR_sched_rr_get_interval:
	ret = do_sched_rr_get_interval(arg1, arg2);
	break;

    case TARGET_FREEBSD_NR_cpuset:
    case TARGET_FREEBSD_NR_cpuset_getid:
    case TARGET_FREEBSD_NR_cpuset_setid:
    case TARGET_FREEBSD_NR_cpuset_getaffinity:
    case TARGET_FREEBSD_NR_cpuset_setaffinity:

    case TARGET_FREEBSD_NR_rctl_get_racct:
    case TARGET_FREEBSD_NR_rctl_get_rules:
    case TARGET_FREEBSD_NR_rctl_add_rule:
    case TARGET_FREEBSD_NR_rctl_remove_rule:
    case TARGET_FREEBSD_NR_rctl_get_limits:

    case TARGET_FREEBSD_NR_sctp_peeloff:
    case TARGET_FREEBSD_NR_sctp_generic_sendmsg:
    case TARGET_FREEBSD_NR_sctp_generic_recvmsg:

    case TARGET_FREEBSD_NR_modfnext:
    case TARGET_FREEBSD_NR_modfind:
    case TARGET_FREEBSD_NR_kldload:
    case TARGET_FREEBSD_NR_kldunload:
    case TARGET_FREEBSD_NR_kldunloadf:
    case TARGET_FREEBSD_NR_kldfind:
    case TARGET_FREEBSD_NR_kldnext:
    case TARGET_FREEBSD_NR_kldstat:
    case TARGET_FREEBSD_NR_kldfirstmod:
    case TARGET_FREEBSD_NR_kldsym:

    case TARGET_FREEBSD_NR_quotactl:
#ifdef TARGET_FREEBSD_NR_quota
    case TARGET_FREEBSD_NR_quota:
#endif

#ifdef TARGET_FREEBSD_NR_gethostid
    case TARGET_FREEBSD_NR_gethostid:
#endif
#ifdef TARGET_FREEBSD_NR_gethostname
    case TARGET_FREEBSD_NR_gethostname:
#endif
#ifdef TARGET_FREEBSD_NR_sethostname
    case TARGET_FREEBSD_NR_sethostname:
#endif

#ifdef TARGET_FREEBSD_NR_getkerninfo
    case TARGET_FREEBSD_NR_getkerninfo:
#endif
#ifdef TARGET_FREEBSD_NR_getpagesize
    case TARGET_FREEBSD_NR_getpagesize:
#endif

    case TARGET_FREEBSD_NR_profil:
    case TARGET_FREEBSD_NR_ktrace:

    case TARGET_FREEBSD_NR_jail:
    case TARGET_FREEBSD_NR_jail_attach:
    case TARGET_FREEBSD_NR_jail_get:
    case TARGET_FREEBSD_NR_jail_set:
    case TARGET_FREEBSD_NR_jail_remove:
	ret = unimplemented(num);
	break;

    case TARGET_FREEBSD_NR_cap_enter:
    case TARGET_FREEBSD_NR_cap_getmode:
	ret = unimplemented(num);
	break;

    case TARGET_FREEBSD_NR___mac_get_proc:
    case TARGET_FREEBSD_NR___mac_set_proc:
    case TARGET_FREEBSD_NR___mac_get_fd:
    case TARGET_FREEBSD_NR___mac_set_fd:
    case TARGET_FREEBSD_NR___mac_get_file:
    case TARGET_FREEBSD_NR___mac_set_file:
    case TARGET_FREEBSD_NR___mac_get_link:
    case TARGET_FREEBSD_NR___mac_set_link:
    case TARGET_FREEBSD_NR_mac_syscall:
	ret = unimplemented(num);
	break;

    case TARGET_FREEBSD_NR_audit:
    case TARGET_FREEBSD_NR_auditon:
    case TARGET_FREEBSD_NR_getaudit:
    case TARGET_FREEBSD_NR_setaudit:
    case TARGET_FREEBSD_NR_getaudit_addr:
    case TARGET_FREEBSD_NR_setaudit_addr:
    case TARGET_FREEBSD_NR_auditctl:
	ret = unimplemented(num);
	break;


#ifdef TARGET_FREEBSD_NR_obreak
    case TARGET_FREEBSD_NR_obreak:
#endif
    case TARGET_FREEBSD_NR_freebsd6_pread:
    case TARGET_FREEBSD_NR_freebsd6_pwrite:
    case TARGET_FREEBSD_NR_freebsd6_lseek:
    case TARGET_FREEBSD_NR_freebsd6_truncate:
    case TARGET_FREEBSD_NR_freebsd6_ftruncate:
    case TARGET_FREEBSD_NR_sendfile:
    case TARGET_FREEBSD_NR_ptrace:
    case TARGET_FREEBSD_NR_utrace:
	ret = unimplemented(num);
	break;


    default:
        ret = get_errno(syscall(num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8));
        break;
    }
 fail:
#ifdef DEBUG
    gemu_log(" = %ld\n", ret);
#endif
    if (do_strace)
        print_freebsd_syscall_ret(num, ret);
    return ret;
 efault:
    ret = -TARGET_EFAULT;
    goto fail;
}

abi_long do_netbsd_syscall(void *cpu_env, int num, abi_long arg1,
                           abi_long arg2, abi_long arg3, abi_long arg4,
                           abi_long arg5, abi_long arg6)
{
    abi_long ret;
    void *p;

#ifdef DEBUG
    gemu_log("netbsd syscall %d\n", num);
#endif
    if(do_strace)
        print_netbsd_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6);

    switch(num) {
    case TARGET_NETBSD_NR_exit:
#ifdef TARGET_GPROF
        _mcleanup();
#endif
        gdb_exit(cpu_env, arg1);
        /* XXX: should free thread stack and CPU env */
        _exit(arg1);
        ret = 0; /* avoid warning */
        break;
    case TARGET_NETBSD_NR_read:
        if (!(p = lock_user(VERIFY_WRITE, arg2, arg3, 0)))
            goto efault;
        ret = get_errno(read(arg1, p, arg3));
        unlock_user(p, arg2, ret);
        break;
    case TARGET_NETBSD_NR_write:
        if (!(p = lock_user(VERIFY_READ, arg2, arg3, 1)))
            goto efault;
        ret = get_errno(write(arg1, p, arg3));
        unlock_user(p, arg2, 0);
        break;
    case TARGET_NETBSD_NR_open:
        if (!(p = lock_user_string(arg1)))
            goto efault;
        ret = get_errno(open(path(p),
                             target_to_host_bitmask(arg2, fcntl_flags_tbl),
                             arg3));
        unlock_user(p, arg1, 0);
        break;
    case TARGET_NETBSD_NR_mmap:
        ret = get_errno(target_mmap(arg1, arg2, arg3,
                                    target_to_host_bitmask(arg4, mmap_flags_tbl),
                                    arg5,
                                    arg6));
        break;
    case TARGET_NETBSD_NR_mprotect:
        ret = get_errno(target_mprotect(arg1, arg2, arg3));
        break;
    case TARGET_NETBSD_NR_syscall:
    case TARGET_NETBSD_NR___syscall:
        ret = do_netbsd_syscall(cpu_env,arg1 & 0xffff,arg2,arg3,arg4,arg5,arg6,0);
        break;
    default:
        ret = syscall(num, arg1, arg2, arg3, arg4, arg5, arg6);
        break;
    }
 fail:
#ifdef DEBUG
    gemu_log(" = %ld\n", ret);
#endif
    if (do_strace)
        print_netbsd_syscall_ret(num, ret);
    return ret;
 efault:
    ret = -TARGET_EFAULT;
    goto fail;
}

abi_long do_openbsd_syscall(void *cpu_env, int num, abi_long arg1,
                            abi_long arg2, abi_long arg3, abi_long arg4,
                            abi_long arg5, abi_long arg6)
{
    abi_long ret;
    void *p;

#ifdef DEBUG
    gemu_log("openbsd syscall %d\n", num);
#endif
    if(do_strace)
        print_openbsd_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6);

    switch(num) {
    case TARGET_OPENBSD_NR_exit:
#ifdef TARGET_GPROF
        _mcleanup();
#endif
        gdb_exit(cpu_env, arg1);
        /* XXX: should free thread stack and CPU env */
        _exit(arg1);
        ret = 0; /* avoid warning */
        break;
    case TARGET_OPENBSD_NR_read:
        if (!(p = lock_user(VERIFY_WRITE, arg2, arg3, 0)))
            goto efault;
        ret = get_errno(read(arg1, p, arg3));
        unlock_user(p, arg2, ret);
        break;
    case TARGET_OPENBSD_NR_write:
        if (!(p = lock_user(VERIFY_READ, arg2, arg3, 1)))
            goto efault;
        ret = get_errno(write(arg1, p, arg3));
        unlock_user(p, arg2, 0);
        break;
    case TARGET_OPENBSD_NR_open:
        if (!(p = lock_user_string(arg1)))
            goto efault;
        ret = get_errno(open(path(p),
                             target_to_host_bitmask(arg2, fcntl_flags_tbl),
                             arg3));
        unlock_user(p, arg1, 0);
        break;
    case TARGET_OPENBSD_NR_mmap:
        ret = get_errno(target_mmap(arg1, arg2, arg3,
                                    target_to_host_bitmask(arg4, mmap_flags_tbl),
                                    arg5,
                                    arg6));
        break;
    case TARGET_OPENBSD_NR_mprotect:
        ret = get_errno(target_mprotect(arg1, arg2, arg3));
        break;
    case TARGET_OPENBSD_NR_syscall:
    case TARGET_OPENBSD_NR___syscall:
        ret = do_openbsd_syscall(cpu_env,arg1 & 0xffff,arg2,arg3,arg4,arg5,arg6,0);
        break;
    default:
        ret = syscall(num, arg1, arg2, arg3, arg4, arg5, arg6);
        break;
    }
 fail:
#ifdef DEBUG
    gemu_log(" = %ld\n", ret);
#endif
    if (do_strace)
        print_openbsd_syscall_ret(num, ret);
    return ret;
 efault:
    ret = -TARGET_EFAULT;
    goto fail;
}

void syscall_init(void)
{
	IOCTLEntry *ie;
	const argtype *arg_type;
	int size;

#define STRUCT(name, ...) thunk_register_struct(STRUCT_ ## name, #name, struct_ ## name ## _def);
#define STRUCT_SPECIAL(name) thunk_register_struct_direct(STRUCT_ ## name, #name, &struct_ ## name ## _def);
#if defined(__FreeBSD__)
#include "freebsd/syscall_types.h"
#else
#warning No syscall_types.h
#endif
#undef STRUCT
#undef STRUCT_SPECIAL

	/*
	 * Patch the ioctl size if necessary using the fact that no
	 * ioctl has all the bits at '1' in the size field
	 * (IOCPARM_MAX - 1).
	 */
	ie = ioctl_entries;
	while (ie->target_cmd != 0) {
		if (((ie->target_cmd >> TARGET_IOCPARM_SHIFT) &
			TARGET_IOCPARM_MASK) == TARGET_IOCPARM_MASK) {
			arg_type = ie->arg_type;
			if (arg_type[0] != TYPE_PTR) {
				fprintf(stderr,
				    "cannot patch size for ioctl 0x%x\n",
				    ie->target_cmd);
				exit(1);
			}
			arg_type++;
			size = thunk_type_size(arg_type, 0);
			ie->target_cmd = (ie->target_cmd & ~(TARGET_IOCPARM_MASK
				<< TARGET_IOCPARM_SHIFT)) |
			    (size << TARGET_IOCPARM_SHIFT);
		}
		ie++;
	}

}
