/*      $OpenBSD: signal.h,v 1.19 2006/01/08 14:20:16 millert Exp $     */
/*      $NetBSD: signal.h,v 1.21 1996/02/09 18:25:32 christos Exp $     */

/*
 * Copyright (c) 1982, 1986, 1989, 1991, 1993
 *      The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)signal.h    8.2 (Berkeley) 1/21/94
 */

#define TARGET_SIGHUP  1       /* hangup */
#define TARGET_SIGINT  2       /* interrupt */
#define TARGET_SIGQUIT 3       /* quit */
#define TARGET_SIGILL  4       /* illegal instruction (not reset when caught) */
#define TARGET_SIGTRAP 5       /* trace trap (not reset when caught) */
#define TARGET_SIGABRT 6       /* abort() */
#define TARGET_SIGIOT  SIGABRT /* compatibility */
#define TARGET_SIGEMT  7       /* EMT instruction */
#define TARGET_SIGFPE  8       /* floating point exception */
#define TARGET_SIGKILL 9       /* kill (cannot be caught or ignored) */
#define TARGET_SIGBUS  10      /* bus error */
#define TARGET_SIGSEGV 11      /* segmentation violation */
#define TARGET_SIGSYS  12      /* bad argument to system call */
#define TARGET_SIGPIPE 13      /* write on a pipe with no one to read it */
#define TARGET_SIGALRM 14      /* alarm clock */
#define TARGET_SIGTERM 15      /* software termination signal from kill */
#define TARGET_SIGURG  16      /* urgent condition on IO channel */
#define TARGET_SIGSTOP 17      /* sendable stop signal not from tty */
#define TARGET_SIGTSTP 18      /* stop signal from tty */
#define TARGET_SIGCONT 19      /* continue a stopped process */
#define TARGET_SIGCHLD 20      /* to parent on child stop or exit */
#define TARGET_SIGTTIN 21      /* to readers pgrp upon background tty read */
#define TARGET_SIGTTOU 22      /* like TTIN for output if (tp->t_local&LTOSTOP) */
#define TARGET_SIGIO   23      /* input/output possible signal */
#define TARGET_SIGXCPU 24      /* exceeded CPU time limit */
#define TARGET_SIGXFSZ 25      /* exceeded file size limit */
#define TARGET_SIGVTALRM 26    /* virtual time alarm */
#define TARGET_SIGPROF 27      /* profiling time alarm */
#define TARGET_SIGWINCH 28      /* window size changes */
#define TARGET_SIGINFO  29      /* information request */
#define TARGET_SIGUSR1 30       /* user defined signal 1 */
#define TARGET_SIGUSR2 31       /* user defined signal 2 */
#define	TARGET_SIGTHR 32	/* reserved by thread library */
#define	TARGET_SIGLWP SIGTHR	/* compatibility */
#define	TARGET_SIGLIBRT 33	/* reserved by the real-time library */
#define	TARGET_SIGRTMIN 65
#define	TARGET_SIGRTMAX	126
#define	TARGET_QEMU_ESIGRETURN	255	/* fake errno value for use by sigreturn */


/*
 * Language spec says we must list exactly one parameter, even though we
 * actually supply three.  Ugh!
 */
#define	TARGET_SIG_DFL		((abi_long)0)	/* default signal handling */
#define TARGET_SIG_IGN		((abi_long)1)	/* ignore signal */
#define	TARGET_SIG_ERR		((abi_long)-1)	/* error return from signal */

#define TARGET_SA_ONSTACK       0x0001  /* take signal on signal stack */
#define TARGET_SA_RESTART       0x0002  /* restart system on signal return */
#define TARGET_SA_RESETHAND     0x0004  /* reset to SIG_DFL when taking signal */
#define TARGET_SA_NODEFER       0x0010  /* don't mask the signal we're delivering */
#define TARGET_SA_NOCLDWAIT     0x0020  /* don't create zombies (assign to pid 1) */
#define TARGET_SA_USERTRAMP    0x0100  /* do not bounce off kernel's sigtramp */
#define TARGET_SA_NOCLDSTOP     0x0008  /* do not generate SIGCHLD on child stop */
#define TARGET_SA_SIGINFO       0x0040  /* generate siginfo_t */

/*
 * Flags for sigprocmask:
 */
#define TARGET_SIG_BLOCK       1       /* block specified signal set */
#define TARGET_SIG_UNBLOCK     2       /* unblock specified signal set */
#define TARGET_SIG_SETMASK     3       /* set specified signal set */

#define TARGET_BADSIG          SIG_ERR

/*
 * sigaltstack controls
 */
#define TARGET_SS_ONSTACK       0x0001  /* take signals on alternate stack */
#define TARGET_SS_DISABLE       0x0004  /* disable taking signals on alternate
					   stack */

#define TARGET_NSIG		128
#define	TARGET_NSIG_BPW		(sizeof(uint32_t) * 8)
#define	TARGET_NSIG_WORDS	(TARGET_NSIG / TARGET_NSIG_BPW)

/*
 * si_code values
 * Digital reserves positive values for kernel-generated signals.
 */

/*
 * SIGSEGV si_codes
 */
#define TARGET_SEGV_MAPERR	(1)	/* address not mapped to object */
#define	TARGET_SEGV_ACCERR	(2)	/* invalid permissions for mapped
					   object */
/*
 * SIGTRAP si_codes
 */
#define	TARGET_TRAP_BRKPT	(1)	/* process beakpoint */
#define	TARGET_TRAP_TRACE	(2)	/* process trace trap */

struct target_rlimit {
	uint64_t rlim_cur;
	uint64_t rlim_max;
};

#if defined(TARGET_ALPHA)
#define	TARGET_RLIM_INFINITY	0x7fffffffffffffffull
#elif defined(TARGET_MIPS) || (defined(TARGET_SPARC) && TARGET_ABI_BITS == 32)
#define	TARGET_RLIM_INFINITY	0x7fffffffUL
#else
#define	TARGET_RLIM_INFINITY	((abi_ulong)-1)
#endif

#define TARGET_RLIMIT_CPU	0
#define TARGET_RLIMIT_FSIZE	1
#define TARGET_RLIMIT_DATA	2
#define TARGET_RLIMIT_STACK	3
#define TARGET_RLIMIT_CORE	4
#define TARGET_RLIMIT_RSS	5
#define TARGET_RLIMIT_MEMLOCK	6
#define TARGET_RLIMIT_NPROC	7
#define TARGET_RLIMIT_NOFILE	8
#define TARGET_RLIMIT_SBSIZE	9
#define TARGET_RLIMIT_AS	10
#define TARGET_RLIMIT_NPTS	11
#define TARGET_RLIMIT_SWAP	12

struct target_pollfd {
	int fd;		/* file descriptor */
	short events;	/* requested events */
	short revents;	/* returned events */
};

/*
 * Constants used for fcntl(2).
 */

/* command values */
#define	TARGET_F_DUPFD		0
#define	TARGET_F_GETFD		1
#define	TARGET_F_SETFD		2
#define	TARGET_F_GETFL		3
#define	TARGET_F_SETFL		4
#define	TARGET_F_GETOWN		5
#define	TARGET_F_SETOWN		6
#define	TARGET_F_OGETLK		7
#define	TARGET_F_OSETLK		8
#define	TARGET_F_OSETLKW	9
#define	TARGET_F_DUP2FD		10
#define	TARGET_F_GETLK		11
#define	TARGET_F_SETLK		12
#define	TARGET_F_SETLKW		13
#define	TARGET_F_SETLK_REMOTE	14
#define	TARGET_F_READAHEAD	15
#define	TARGET_F_RDAHEAD	16

#define	TARGET_O_NONBLOCK	0x00000004 
#define	TARGET_O_APPEND		0x00000008
#define	TARGET_O_ASYNC		0x00000040
#define	TARGET_O_DIRECT		0x00010000

#define	TARGET_SPARC_UTRAP_INSTALL	1
#define	TARGET_SPARC_SIGTRAMP_INSTALL	2

#include "socket.h"
#include "errno_defs.h"

#include "freebsd/syscall_nr.h"
#include "netbsd/syscall_nr.h"
#include "openbsd/syscall_nr.h"

struct target_flock {
    int64_t l_start;
    int64_t l_len;
    int32_t l_pid;
    int16_t l_type;
    int16_t l_whence;
    int32_t l_sysid;
} QEMU_PACKED;

struct target_iovec {
    abi_long iov_base;   /* Starting address */
    abi_long iov_len;   /* Number of bytes */
};

struct target_msghdr {
	abi_long	msg_name;       /* Socket name */
	int		msg_namelen;    /* Length of name */
	abi_long	msg_iov;        /* Data blocks */
	abi_long	msg_iovlen;     /* Number of blocks */
	abi_long	msg_control;    /* Per protocol magic
					   (eg BSD file descriptor passing) */
	abi_long	msg_controllen; /* Length of cmsg list */
	int		msg_flags;	/* flags on received message */
};

struct target_cmsghdr {
	abi_long	cmsg_len;
	int		cmsg_level;
	int		cmsg_type;
};

#define TARGET_CMSG_DATA(cmsg)	\
    ((unsigned char *) ((struct target_cmsghdr *) (cmsg) + 1))
#define	TARGET_CMSG_NXTHDR(mhdr, cmsg) __target_cmsg_nxthdr (mhdr, cmsg)
#define	TARGET_CMSG_ALIGN(len) (((len) + sizeof (abi_long) - 1) \
    & (size_t) ~(sizeof (abi_long) - 1))
#define	TARGET_CMSG_SPACE(len) (TARGET_CMSG_ALIGN (len) \
    + TARGET_CMSG_ALIGN (sizeof (struct target_cmsghdr)))
#define TARGET_CMSG_LEN(len)  \
    (TARGET_CMSG_ALIGN (sizeof (struct target_cmsghdr)) + (len))

static __inline__ struct target_cmsghdr *
__target_cmsg_nxthdr (struct target_msghdr *__mhdr,
    struct target_cmsghdr *__cmsg)
{
	struct target_cmsghdr *__ptr;

	__ptr = (struct target_cmsghdr *)((unsigned char *) __cmsg +
	    TARGET_CMSG_ALIGN (tswapal(__cmsg->cmsg_len)));
	if ((unsigned long)((char *)(__ptr+1) -
		(char *)(size_t)tswapal(__mhdr->msg_control)) >
	    tswapal(__mhdr->msg_controllen))
		/* No more entries.  */
		return ((struct target_cmsghdr *)0);
	return (__cmsg);
}

struct target_sockaddr {
	uint8_t sa_len;
	uint8_t sa_family;
	uint8_t sa_data[14];
} QEMU_PACKED;

struct target_in_addr {
	uint32_t s_addr; /* big endian */
};

/*
 * FreeBSD/{arm, mips} uses a 64bits time_t, even in 32bits mode,
 * so we have to add a special case here.
 */
#if defined(TARGET_ARM) || defined(TARGET_MIPS)
typedef int64_t target_freebsd_time_t;
#else
typedef abi_long target_freebsd_time_t;
#endif

struct target_timeval {
	target_freebsd_time_t tv_sec;
	abi_long tv_usec;
} QEMU_PACKED;

typedef abi_long target_clock_t;

struct target_rusage {
	struct target_timeval ru_utime;	/* user time used */
	struct target_timeval ru_stime;	/* system time used */
	abi_long    ru_maxrss;		/* maximum resident set size */
	abi_long    ru_ixrss;		/* integral shared memory size */
	abi_long    ru_idrss;		/* integral unshared data size */
	abi_long    ru_isrss;		/* integral unshared stack size */
	abi_long    ru_minflt;		/* page reclaims */
	abi_long    ru_majflt;		/* page faults */
	abi_long    ru_nswap;		/* swaps */
	abi_long    ru_inblock;		/* block input operations */
	abi_long    ru_oublock;		/* block output operations */
	abi_long    ru_msgsnd;		/* messages sent */
	abi_long    ru_msgrcv;		/* messages received */
	abi_long    ru_nsignals;	/* signals received */
	abi_long    ru_nvcsw;		/* voluntary context switches */
	abi_long    ru_nivcsw;		/* involuntary context switches */
};

struct target_kevent {
    abi_ulong  ident;
    short      filter;
    u_short    flags;
    u_int      fflags;
    abi_long   data;
    abi_ulong  udata;
} __packed;


struct target_freebsd_timespec {
	target_freebsd_time_t	tv_sec;		/* seconds */
	abi_long		tv_nsec;	/* and nanoseconds */
} __packed;

/* XXX We have target_*_timeval defined twice.  */
struct target_freebsd_timeval {
	target_freebsd_time_t	tv_sec;
	abi_long		tv_usec;
} __packed;

struct target_freebsd_stat {
	uint32_t  st_dev;		/* inode's device */
	uint32_t  st_ino;		/* inode's number */
	int16_t	  st_mode;		/* inode protection mode */
	int16_t	  st_nlink;		/* number of hard links */
	uint32_t  st_uid;		/* user ID of the file's owner */
	uint32_t  st_gid;		/* group ID of the file's group */
	uint32_t  st_rdev;		/* device type */
	struct	target_freebsd_timespec st_atim;	/* time of last access */
	struct	target_freebsd_timespec st_mtim;	/* time of last data modification */
	struct	target_freebsd_timespec st_ctim;	/* time of last file status change */
	int64_t	  st_size;		/* file size, in bytes */
	int64_t st_blocks;		/* blocks allocated for file */
	uint32_t st_blksize;		/* optimal blocksize for I/O */
	uint32_t  st_flags;		/* user defined flags for file */
	__uint32_t st_gen;		/* file generation number */
	__int32_t st_lspare;
	struct target_freebsd_timespec st_birthtim;	/* time of file creation */
	/*
	 * Explicitly pad st_birthtim to 16 bytes so that the size of
	 * struct stat is backwards compatible.  We use bitfields instead
	 * of an array of chars so that this doesn't require a C99 compiler
	 * to compile if the size of the padding is 0.  We use 2 bitfields
	 * to cover up to 64 bits on 32-bit machines.  We assume that
	 * CHAR_BIT is 8...
	 */
	unsigned int :(8 / 2) * (16 - (int)sizeof(struct timespec));
	unsigned int :(8 / 2) * (16 - (int)sizeof(struct timespec));
} __packed;

int __getcwd(char *, size_t);

struct target_sembuf {
	unsigned short	sem_num;	/* semaphore # */
	short		sem_op;		/* semaphore operation */
	short		sem_flg;	/* operation flags */
};

union target_semun {
	int		val;		/* value for SETVAL */
	abi_ulong	buf; 		/* buffer for IPC_STAT & IPC_SET */
	abi_ulong	array;		/* array for GETALL & SETALL */
};

struct target_ipc_perm {
	uint32_t	cuid;		/* creator user id */
	uint32_t	cgid;		/* creator group id */
	uint32_t	uid;		/* user id */
	uint32_t	gid;		/* group id */
	uint16_t	mode;		/* r/w permission */
	uint16_t	seq;		/* sequence # */
	abi_long	key;		/* user specified msg/sem/shm key */
};

struct target_msqid_ds {
	struct  target_ipc_perm msg_perm; /* msg queue permission bits */
	abi_ulong	msg_first;	/* first message in the queue */
	abi_ulong	msg_last;	/* last message in the queue */
	abi_ulong	msg_cbytes;	/* # of bytes in use on the queue */
	abi_ulong	msg_qnum;	/* number of msgs in the queue */
	abi_ulong	msg_qbytes;	/* max # of bytes on the queue */
	int32_t		msg_lspid;	/* pid of last msgsnd() */
	int32_t		msg_lrpid;	/* pid of last msgrcv() */
	abi_ulong	msg_stime;	/* time of last msgsnd() */
	abi_ulong	msg_rtime;	/* time of last msgrcv() */
	abi_ulong	msg_ctime;	/* time of last msgctl() */
};

struct target_msgbuf {
	abi_long	mtype;		/* message type */
	char		mtext[1];	/* body of message */
};

struct target_semid_ds {
	struct target_ipc_perm sem_perm; /* operation permission struct */
	abi_ulong	sem_base;	/* pointer to first semaphore in set */
	uint16_t	sem_nsems;	/* number of sems in set */
	abi_ulong	sem_otime;	/* last operation time */
	abi_ulong	sem_ctime;	/* times measured in secs */
};

struct target_shmid_ds {
	struct  target_ipc_perm shm_perm; /* peration permission structure */
	abi_ulong	shm_segsz;	/* size of segment in bytes */
	int32_t		shm_lpid;	/* process ID of last shared memory op */
	int32_t		shm_cpid;	/* process ID of creator */
	int32_t		shm_nattch;	/* number of current attaches */
	abi_ulong	shm_atime;	/* time of last shmat() */
	abi_ulong	shm_dtime;	/* time of last shmdt() */
	abi_ulong	shm_ctime;	/* time of last change by shmctl() */
};

#define TARGET_UCONTEXT_MAGIC	0xACEDBADE
#define TARGET_MC_GET_CLEAR_RET	0x0001
#define TARGET_MC_ADD_MAGIC	0x0002
#define TARGET_MC_SET_ONSTACK	0x0004

/* this struct defines a stack used during syscall handling */
typedef struct target_sigaltstack {
	abi_long	ss_sp;
	abi_ulong	ss_size;
	abi_long	ss_flags;
} target_stack_t;

typedef struct {
	uint32_t __bits[TARGET_NSIG_WORDS];
} target_sigset_t;

struct target_sigaction {
	abi_ulong	_sa_handler;
	int32_t		sa_flags;
	target_sigset_t	sa_mask;
};

union target_sigval {
	int32_t	sival_int;
	abi_ulong sival_ptr;
	int32_t	sigval_int;
	abi_ulong sigval_ptr;
};

typedef struct target_siginfo {
	int32_t si_signo;	/* signal number */
	int32_t si_errno;	/* errno association */
	int32_t si_code;	/* signal code */
	int32_t	si_pid;		/* sending process */
	int32_t	si_uid;		/* sender's ruid */
	int32_t si_status;	/* exit value */
	abi_ulong si_addr;	/* faulting instruction */

	union target_sigval si_value;	/* signal value */

	union {
		struct {
			int32_t	_trapno;	/* machine specific trap code */
		} _fault;

		/* POSIX.1b timers */
		struct {
			int32_t _timerid;
			int32_t _overrun;
		} _timer;

		struct {
			int32_t _mqd;
		} _mesgp;

		/* SIGPOLL */
		struct {
			int _band;	/* POLL_IN, POLL_OUT, POLL_MSG */
		} _poll;

		struct {
			abi_long __spare1__;
			int32_t  __spare2_[7];
		} __spare__;
	} _reason;
} target_siginfo_t;

#ifdef BSWAP_NEEDED
static inline void
tswap_sigset(target_sigset_t *d, const target_sigset_t *s)
{
	int i;

	for(i = 0;i < TARGET_NSIG_WORDS; i++)
		d->__bits[i] = tswapal(s->__bits[i]);
}

#else
static inline void
tswap_sigset(target_sigset_t *d, const target_sigset_t *s)
{

	*d = *s;
}
#endif

/* XXX
static inline void
target_siginitset(target_sigset_t *d, abi_ulong set)
{
	int i;

	d->sig[0] = set;
	for(i = 1;i < TARGET_NSIG_WORDS; i++)
		d->sig[i] = 0;
}
*/

void host_to_target_sigset(target_sigset_t *d, const sigset_t *s);
void target_to_host_sigset(sigset_t *d, const target_sigset_t *s);
void host_to_target_old_sigset(abi_ulong *old_sigset, const sigset_t *sigset);
void target_to_host_old_sigset(sigset_t *sigset, const abi_ulong *old_sigset);
int do_sigaction(int sig, const struct target_sigaction *act,
    struct target_sigaction *oact);


/*
 * FreeBSD thread support.
 */

#define	TARGET_THR_SUSPENDED	0x0001
#define	TARGET_THR_SYSTEM_SCOPE	0x0002

/* sysarch() ops */
#define	TARGET_MIPS_SET_TLS	1
#define	TARGET_MIPS_GET_TLS	2

struct target_thr_param {
	abi_ulong	start_func;	/* thread entry function. */
	abi_ulong	arg;		/* argument for entry function. */
	abi_ulong	stack_base;	/* stack base address. */
	abi_ulong	stack_size;	/* stack size. */
	abi_ulong	tls_base;	/* tls base address. */
	abi_ulong	tls_size;	/* tls size. */
	abi_ulong	child_tid;	/* address to store new TID. */
	abi_ulong	parent_tid;	/* parent access the new TID here. */
	int32_t		flags;		/* thread flags. */
	abi_ulong	rtp;		/* Real-time scheduling priority. */
	abi_ulong	spare[3];	/* spares. */
};

struct target_rtprio {
	uint16_t	type;
	uint16_t	prio;
};

/*
 * sys/_umtx.h
 */

struct target_umtx {
	abi_ulong	u_owner;	/* Owner of the mutex. */
};

struct target_umutex {
	uint32_t	m_owner;	/* Owner of the mutex */
	uint32_t	m_flags;	/* Flags of the mutex */
	uint32_t	m_ceiling[2];	/* Priority protect ceiling */
	uint32_t	m_spare[4];
};

struct target_ucond {
	uint32_t	c_has_waiters;	/* Has waiters in kernel */
	uint32_t	c_flags;	/* Flags of the condition variable */
	uint32_t	c_clockid;	/* Clock id */
	uint32_t	c_spare[1];
};

struct target_urwlock {
	uint32_t	rw_state;
	uint32_t	rw_flags;
	uint32_t	rw_blocked_readers;
	uint32_t	rw_blocked_writers;
	uint32_t	rw_spare[4];
};

struct target__usem {
	uint32_t	_has_waiters;
	uint32_t	_count;
	uint32_t	_flags;
};

/*
 * sys/utmx.h
 */

/* op code for _umtx_op */
#define	TARGET_UMTX_OP_LOCK			0
#define	TARGET_UMTX_OP_UNLOCK			1
#define	TARGET_UMTX_OP_WAIT			2
#define	TARGET_UMTX_OP_WAKE			3
#define	TARGET_UMTX_OP_MUTEX_TRYLOCK		4
#define	TARGET_UMTX_OP_MUTEX_LOCK		5
#define	TARGET_UMTX_OP_MUTEX_UNLOCK		6
#define	TARGET_UMTX_OP_SET_CEILING		7
#define	TARGET_UMTX_OP_CV_WAIT			8
#define	TARGET_UMTX_OP_CV_SIGNAL		9
#define	TARGET_UMTX_OP_CV_BROADCAST		10
#define	TARGET_UMTX_OP_WAIT_UINT		11
#define	TARGET_UMTX_OP_RW_RDLOCK		12
#define	TARGET_UMTX_OP_RW_WRLOCK		13
#define	TARGET_UMTX_OP_RW_UNLOCK		14
#define	TARGET_UMTX_OP_WAIT_UINT_PRIVATE	15
#define	TARGET_UMTX_OP_WAKE_PRIVATE		16
#define	TARGET_UMTX_OP_MUTEX_WAIT		17
#define	TARGET_UMTX_OP_MUTEX_WAKE		18
#define	TARGET_UMTX_OP_SEM_WAIT			19
#define	TARGET_UMTX_OP_SEM_WAKE			20
#define	TARGET_UMTX_OP_NWAKE_PRIVATE		21
#define	TARGET_UMTX_OP_MUTEX_WAKE2		22
#define	TARGET_UMTX_OP_MAX			23

/* flags for UMTX_OP_CV_WAIT */
#define	TARGET_CVWAIT_CHECK_UNPARKING		0x01
#define	TARGET_CVWAIT_ABSTIME			0x02
#define	TARGET_CVWAIT_CLOCKID			0x04

#define	TARGET_UMTX_UNOWNED			0x0
#define	TARGET_UMUTEX_UNOWNED			0x0
#define	TARGET_UMTX_CONTESTED			(abi_long)(0x8000000000000000)
#define	TARGET_UMUTEX_CONTESTED			0x80000000U

/* flags for umutex */
#define	TARGET_UMUTEX_ERROR_CHECK	0x0002	/* Error-checking mutex */
#define	TARGET_UMUTEX_PRIO_INHERIT	0x0004	/* Priority inherited mutex */
#define	TARGET_UMUTEX_PRIO_PROTECT	0x0008	/* Priority protect mutex */

#define	TARGET_UMUTEX_TRY			1
#define	TARGET_UMUTEX_WAIT			2

/* urwlock flags */
#define	TARGET_URWLOCK_PREFER_READER	0x0002
#define	TARGET_URWLOCK_WRITE_OWNER	0x80000000U
#define	TARGET_URWLOCK_WRITE_WAITERS	0x40000000U
#define	TARGET_URWLOCK_READ_WAITERS	0x20000000U
#define	TARGET_URWLOCK_MAX_READERS	0x1fffffffU
#define	TARGET_URWLOCK_READER_COUNT(c)	((c) & TARGET_URWLOCK_MAX_READERS)

/* mount.h statfs */
/*
 * filesystem id type
 */
typedef struct target_fsid { int32_t val[2]; } target_fsid_t;

/*
 * filesystem statistics
 */
#define	TARGET_MFSNAMELEN	16	/* length of type name include null */
#define	TARGET_MNAMELEN		88	/* size of on/from name bufs */
#define	TARGET_STATFS_VERSION	0x20030518	/* current version number */
struct target_statfs {
	uint32_t f_version;	/* structure version number */
	uint32_t f_type;	/* type of filesystem */
	uint64_t f_flags;	/* copy of mount exported flags */
	uint64_t f_bsize;	/* filesystem fragment size */
	uint64_t f_iosize;	/* optimal transfer block size */
	uint64_t f_blocks;	/* total data blocks in filesystem */
	uint64_t f_bfree;	/* free blocks in filesystem */
	int64_t  f_bavail;	/* free blocks avail to non-superuser */
	uint64_t f_files;	/* total file nodes in filesystem */
	int64_t  f_ffree;	/* free nodes avail to non-superuser */
	uint64_t f_syncwrites;	/* count of sync writes since mount */
	uint64_t f_asyncwrites;	/* count of async writes since mount */
	uint64_t f_syncreads;	/* count of sync reads since mount */
	uint64_t f_asyncreads;	/* count of async reads since mount */
	uint64_t f_spare[10];	/* unused spare */
	uint32_t f_namemax;	/* maximum filename length */
	uint32_t f_owner;	/* user that mounted the filesystem */
	target_fsid_t   f_fsid;	/* filesystem id */
	char     f_charspare[80];			/* spare string space */
	char     f_fstypename[TARGET_MFSNAMELEN];	/* filesys type name */
	char     f_mntfromname[TARGET_MNAMELEN];	/* mount filesystem */
	char     f_mntonname[TARGET_MNAMELEN];		/* dir on which mounted*/
};

/*
 * File identifier.
 * These are unique per filesystem on a single machine.
 */
#define TARGET_MAXFIDSZ		16

struct target_fid {
	u_short		fid_len;			/* len of data in bytes */
	u_short		fid_data0;			/* force longword align */
	char		fid_data[TARGET_MAXFIDSZ];	/* data (variable len) */
};

/*
 * Generic file handle
 */
struct target_fhandle {
	target_fsid_t	fh_fsid;	/* Filesystem id of mount point */
	struct target_fid fh_fid;	/* Filesys specific id */
};
typedef struct target_fhandle target_fhandle_t;


/*
 * uuidgen.  From sys/uuid.h.
 */

#define TARGET_UUID_NODE_LEN	6

struct target_uuid {
	uint32_t	time_low;
	uint16_t	time_mid;
	uint16_t	time_hi_and_version;
	uint8_t		clock_seq_hi_and_reserved;
	uint8_t		clock_seq_low;
	uint8_t		node[TARGET_UUID_NODE_LEN];
};

/*
 * ntp.  From sys/timex.h.
 */

struct target_ntptimeval {
	struct target_freebsd_timespec	time;
	abi_long	maxerror;
	abi_long	esterror;
	abi_long	tai;
	int32_t		time_state;
};

struct target_timex {
	uint32_t	modes;
	abi_long	offset;
	abi_long	freq;
	abi_long	maxerror;
	abi_long	esterror;
	int32_t		status;
	abi_long	constant;
	abi_long	precision;
	abi_long	tolerance;

	abi_long	ppsfreq;
	abi_long	jitter;
	int32_t		shift;
	abi_long	stabil;
	abi_long	jitcnt;
	abi_long	calcnt;
	abi_long	errcnt;
	abi_long	stbcnt;
};

/*
 * sched.h  From sched.h
 */

struct target_sched_param {
	int32_t	sched_priority;
};


/*
 * sys/acl.h
 */

#define	TARGET_ACL_MAX_ENTRIES	254

struct target_acl_entry {
	int32_t		ae_tag;
	uint32_t	ae_id;
	uint16_t	ae_perm;
	uint16_t	ae_entry_type;
	uint16_t	ae_flags;
};

struct target_acl {
	uint32_t			acl_maxcnt;
	uint32_t			acl_cnt;
	int32_t				acl_space[4];
	struct target_acl_entry		acl_entry[TARGET_ACL_MAX_ENTRIES];
};


/*
 * netinet/in.h
 */

struct target_ip_mreq {
	struct target_in_addr	imr_multiaddr;
	struct target_in_addr 	imr_interface;
};

struct target_ip_mreqn {
	struct target_in_addr	imr_multiaddr;
	struct target_in_addr 	imr_address;
	int32_t			imr_ifindex;
};
