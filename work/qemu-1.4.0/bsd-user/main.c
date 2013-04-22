/*
 *  qemu user main
 *
 *  Copyright (c) 2003-2008 Fabrice Bellard
 *  Copyright (c) 2012-2013 Stacey Son
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
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <machine/trap.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/sysctl.h>

#include "qemu.h"
#include "qemu-common.h"
/* For tb_lock */
#include "cpu.h"
#include "tcg.h"
#include "qemu/timer.h"
#include "qemu/envlist.h"
#include "target_signal.h"

#if defined(CONFIG_USE_NPTL) && defined(__FreeBSD__)
#include <sys/thr.h>
#endif

#define DEBUG_LOGFILE "/tmp/qemu.log"

int singlestep;
#if defined(CONFIG_USE_GUEST_BASE)
unsigned long mmap_min_addr;
unsigned long guest_base;
int have_guest_base;
unsigned long reserved_va;
#endif

static const char *interp_prefix = CONFIG_QEMU_INTERP_PREFIX;
const char *qemu_uname_release = CONFIG_UNAME_RELEASE;
extern char **environ;
enum BSDType bsd_type;

unsigned long target_maxtsiz = TARGET_MAXTSIZ;	/* max text size */
unsigned long target_dfldsiz = TARGET_DFLDSIZ;	/* initial data size limit */
unsigned long target_maxdsiz = TARGET_MAXDSIZ;	/* max data size */
/* XXX: on x86 MAP_GROWSDOWN only works if ESP <= address + 32, so
   we allocate a bigger stack. Need a better solution, for example
   by remapping the process stack directly at the right place */
unsigned long target_dflssiz = TARGET_DFLSSIZ;	/* initial data size limit */
unsigned long target_maxssiz = TARGET_MAXSSIZ;	/* max stack size */
unsigned long target_sgrowsiz = TARGET_SGROWSIZ;/* amount to grow stack */

static void save_proc_pathname(void);
char qemu_proc_pathname[PATH_MAX];
char target_proc_pathname[PATH_MAX];

#ifdef __FreeBSD__
static void
save_proc_pathname(void)
{
	int mib[4];
	size_t len;

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PATHNAME;
	mib[3] = -1;

	len = sizeof(qemu_proc_pathname);

	if (sysctl(mib, 4, qemu_proc_pathname, &len, NULL, 0))
		perror("sysctl");
}

#else

static void
save_proc_pathname(void)
{
}

#endif /* !__FreeBSD__ */

void gemu_log(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

#if defined(TARGET_I386)
int cpu_get_pic_interrupt(CPUX86State *env)
{
    return -1;
}
#endif

#if defined(CONFIG_USE_NPTL)
/* Helper routines for implementing atomic operations. */

/*
 * To implement exclusive operations we force all cpus to synchronize.
 * We don't require a full sync, only that no cpus are executing guest code.
 * The alternative is to map target atomic ops onto host eqivalents,
 * which requires quite a lot of per host/target work.
 */
static pthread_mutex_t cpu_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t exclusive_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t exclusive_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t exclusive_resume = PTHREAD_COND_INITIALIZER;
static int pending_cpus;

/* Make sure everything is in a consistent state for calling fork(). */
void fork_start(void)
{
	spin_lock(&tb_lock);
	pthread_mutex_lock(&exclusive_lock);
	mmap_fork_start();
}

void fork_end(int child)
{
	mmap_fork_end(child);
	if (child) {
		/*
		 * Child processes created by fork() only have a single thread.
		 * Discard information about the parent threads.
		 */
		first_cpu = thread_env;
		thread_env->next_cpu = NULL;
		pending_cpus = 0;
		pthread_mutex_init(&exclusive_lock, NULL);
		pthread_mutex_init(&cpu_list_mutex, NULL);
		pthread_cond_init(&exclusive_cond, NULL);
		pthread_cond_init(&exclusive_resume, NULL);
		spin_lock_init(&tb_lock);
		gdbserver_fork(thread_env);
	} else {
		pthread_mutex_unlock(&exclusive_lock);
		spin_unlock(&tb_lock);
	}
}

/*
 * Wait for pending exclusive operations to complete.  The exclusive lock
 * must be held.
 */
static inline void
exclusive_idle(void)
{
	while (pending_cpus) {
		pthread_cond_wait(&exclusive_resume, &exclusive_lock);
	}
}

/* Start an exclusive operation.  Must only be called outside of cpu_exec. */
static inline void
start_exclusive(void)
{
	CPUArchState *other;

	pthread_mutex_lock(&exclusive_lock);
	exclusive_idle();

	pending_cpus = 1;
	/* Make all other cpus stop executing. */
	for (other = first_cpu; other; other = other->next_cpu) {
		if (other->running) {
			pending_cpus++;
			cpu_exit(other);
		}
	}
	if (pending_cpus > 1) {
		pthread_cond_wait(&exclusive_cond, &exclusive_lock);
	}
}

/* Finish an exclusive operation. */
static inline void
end_exclusive(void)
{
	pending_cpus = 0;
	pthread_cond_broadcast(&exclusive_resume);
	pthread_mutex_unlock(&exclusive_lock);
}

/* Wait for exclusive ops to finish, and begin cpu execution. */
static inline void
cpu_exec_start(CPUArchState *env)
{
	pthread_mutex_lock(&exclusive_lock);
	exclusive_idle();
	env->running = 1;
	pthread_mutex_unlock(&exclusive_lock);
}

/* Mark cpu as not excuting, and release pending exclusive ops. */
static inline void
cpu_exec_end(CPUArchState *env)
{
	pthread_mutex_lock(&exclusive_lock);
	env->running = 0;
	if (pending_cpus > 1) {
		pending_cpus--;
		if (pending_cpus == 1) {
			pthread_cond_signal(&exclusive_cond);
		}
	}
	exclusive_idle();
	pthread_mutex_unlock(&exclusive_lock);
}

void
cpu_list_lock(void)
{
	pthread_mutex_lock(&cpu_list_mutex);
}

void
cpu_list_unlock(void)
{
	pthread_mutex_unlock(&cpu_list_mutex);
}

#else /* ! CONFIG_USE_NPTL */

/* These are no-ops because we are not threadsafe.  */
void
fork_start(void)
{
}

void
fork_end(int child)
{
    if (child) {
        gdbserver_fork(thread_env);
    }
}

static inline void
exclusive_idle(void)
{
}

static inline void
start_exclusive(void)
{
}

static inline void
end_exclusive(void)
{
}

static inline void
cpu_exec_start(CPUArchState *env)
{
}


static inline void
cpu_exec_end(CPUArchState *env)
{
}

void
cpu_list_lock(void)
{
}

void
cpu_list_unlock(void)
{
}
#endif /* CONFIG_USE_NPTL */

#ifdef TARGET_I386
/***********************************************************/
/* CPUX86 core interface */

void cpu_smm_update(CPUX86State *env)
{
}

uint64_t cpu_get_tsc(CPUX86State *env)
{
    return cpu_get_real_ticks();
}

static void write_dt(void *ptr, unsigned long addr, unsigned long limit,
                     int flags)
{
    unsigned int e1, e2;
    uint32_t *p;
    e1 = (addr << 16) | (limit & 0xffff);
    e2 = ((addr >> 16) & 0xff) | (addr & 0xff000000) | (limit & 0x000f0000);
    e2 |= flags;
    p = ptr;
    p[0] = tswap32(e1);
    p[1] = tswap32(e2);
}

static uint64_t *idt_table;
#ifdef TARGET_X86_64
static void set_gate64(void *ptr, unsigned int type, unsigned int dpl,
                       uint64_t addr, unsigned int sel)
{
    uint32_t *p, e1, e2;
    e1 = (addr & 0xffff) | (sel << 16);
    e2 = (addr & 0xffff0000) | 0x8000 | (dpl << 13) | (type << 8);
    p = ptr;
    p[0] = tswap32(e1);
    p[1] = tswap32(e2);
    p[2] = tswap32(addr >> 32);
    p[3] = 0;
}
/* only dpl matters as we do only user space emulation */
static void set_idt(int n, unsigned int dpl)
{
    set_gate64(idt_table + n * 2, 0, dpl, 0, 0);
}
#else
static void set_gate(void *ptr, unsigned int type, unsigned int dpl,
                     uint32_t addr, unsigned int sel)
{
    uint32_t *p, e1, e2;
    e1 = (addr & 0xffff) | (sel << 16);
    e2 = (addr & 0xffff0000) | 0x8000 | (dpl << 13) | (type << 8);
    p = ptr;
    p[0] = tswap32(e1);
    p[1] = tswap32(e2);
}

/* only dpl matters as we do only user space emulation */
static void set_idt(int n, unsigned int dpl)
{
    set_gate(idt_table + n, 0, dpl, 0, 0);
}
#endif

void cpu_loop(CPUX86State *env)
{
    int trapnr;
    abi_ulong pc;
    //target_siginfo_t info;

    for(;;) {
        trapnr = cpu_x86_exec(env);
        switch(trapnr) {
        case 0x80:
            /* syscall from int $0x80 */
            if (bsd_type == target_freebsd) {
                abi_ulong params = (abi_ulong) env->regs[R_ESP] +
                    sizeof(int32_t);
                int32_t syscall_nr = env->regs[R_EAX];
                int32_t arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8;

                if (syscall_nr == TARGET_FREEBSD_NR_syscall) {
                    get_user_s32(syscall_nr, params);
                    params += sizeof(int32_t);
                } else if (syscall_nr == TARGET_FREEBSD_NR___syscall) {
                    get_user_s32(syscall_nr, params);
                    params += sizeof(int64_t);
                }
                get_user_s32(arg1, params);
                params += sizeof(int32_t);
                get_user_s32(arg2, params);
                params += sizeof(int32_t);
                get_user_s32(arg3, params);
                params += sizeof(int32_t);
                get_user_s32(arg4, params);
                params += sizeof(int32_t);
                get_user_s32(arg5, params);
                params += sizeof(int32_t);
                get_user_s32(arg6, params);
                params += sizeof(int32_t);
                get_user_s32(arg7, params);
                params += sizeof(int32_t);
                get_user_s32(arg8, params);
                env->regs[R_EAX] = do_freebsd_syscall(env,
                                                      syscall_nr,
                                                      arg1,
                                                      arg2,
                                                      arg3,
                                                      arg4,
                                                      arg5,
                                                      arg6,
                                                      arg7,
                                                      arg8);
            } else { //if (bsd_type == target_openbsd)
                env->regs[R_EAX] = do_openbsd_syscall(env,
                                                      env->regs[R_EAX],
                                                      env->regs[R_EBX],
                                                      env->regs[R_ECX],
                                                      env->regs[R_EDX],
                                                      env->regs[R_ESI],
                                                      env->regs[R_EDI],
                                                      env->regs[R_EBP]);
            }
            if (((abi_ulong)env->regs[R_EAX]) >= (abi_ulong)(-515)) {
                env->regs[R_EAX] = -env->regs[R_EAX];
                env->eflags |= CC_C;
            } else {
                env->eflags &= ~CC_C;
            }
            break;
#ifndef TARGET_ABI32
        case EXCP_SYSCALL:
            /* syscall from syscall instruction */
            if (bsd_type == target_freebsd)
                env->regs[R_EAX] = do_freebsd_syscall(env,
                                                      env->regs[R_EAX],
                                                      env->regs[R_EDI],
                                                      env->regs[R_ESI],
                                                      env->regs[R_EDX],
                                                      env->regs[R_ECX],
                                                      env->regs[8],
                                                      env->regs[9], 0, 0);
            else { //if (bsd_type == target_openbsd)
                env->regs[R_EAX] = do_openbsd_syscall(env,
                                                      env->regs[R_EAX],
                                                      env->regs[R_EDI],
                                                      env->regs[R_ESI],
                                                      env->regs[R_EDX],
                                                      env->regs[10],
                                                      env->regs[8],
                                                      env->regs[9]);
            }
            env->eip = env->exception_next_eip;
            if (((abi_ulong)env->regs[R_EAX]) >= (abi_ulong)(-515)) {
                env->regs[R_EAX] = -env->regs[R_EAX];
                env->eflags |= CC_C;
            } else {
                env->eflags &= ~CC_C;
            }
            break;
#endif
#if 0
        case EXCP0B_NOSEG:
        case EXCP0C_STACK:
            info.si_signo = SIGBUS;
            info.si_errno = 0;
            info.si_code = TARGET_SI_KERNEL;
            info._sifields._sigfault._addr = 0;
            queue_signal(env, info.si_signo, &info);
            break;
        case EXCP0D_GPF:
            /* XXX: potential problem if ABI32 */
#ifndef TARGET_X86_64
            if (env->eflags & VM_MASK) {
                handle_vm86_fault(env);
            } else
#endif
            {
                info.si_signo = SIGSEGV;
                info.si_errno = 0;
                info.si_code = TARGET_SI_KERNEL;
                info._sifields._sigfault._addr = 0;
                queue_signal(env, info.si_signo, &info);
            }
            break;
        case EXCP0E_PAGE:
            info.si_signo = SIGSEGV;
            info.si_errno = 0;
            if (!(env->error_code & 1))
                info.si_code = TARGET_SEGV_MAPERR;
            else
                info.si_code = TARGET_SEGV_ACCERR;
            info._sifields._sigfault._addr = env->cr[2];
            queue_signal(env, info.si_signo, &info);
            break;
        case EXCP00_DIVZ:
#ifndef TARGET_X86_64
            if (env->eflags & VM_MASK) {
                handle_vm86_trap(env, trapnr);
            } else
#endif
            {
                /* division by zero */
                info.si_signo = SIGFPE;
                info.si_errno = 0;
                info.si_code = TARGET_FPE_INTDIV;
                info._sifields._sigfault._addr = env->eip;
                queue_signal(env, info.si_signo, &info);
            }
            break;
        case EXCP01_DB:
        case EXCP03_INT3:
#ifndef TARGET_X86_64
            if (env->eflags & VM_MASK) {
                handle_vm86_trap(env, trapnr);
            } else
#endif
            {
                info.si_signo = SIGTRAP;
                info.si_errno = 0;
                if (trapnr == EXCP01_DB) {
                    info.si_code = TARGET_TRAP_BRKPT;
                    info._sifields._sigfault._addr = env->eip;
                } else {
                    info.si_code = TARGET_SI_KERNEL;
                    info._sifields._sigfault._addr = 0;
                }
                queue_signal(env, info.si_signo, &info);
            }
            break;
        case EXCP04_INTO:
        case EXCP05_BOUND:
#ifndef TARGET_X86_64
            if (env->eflags & VM_MASK) {
                handle_vm86_trap(env, trapnr);
            } else
#endif
            {
                info.si_signo = SIGSEGV;
                info.si_errno = 0;
                info.si_code = TARGET_SI_KERNEL;
                info._sifields._sigfault._addr = 0;
                queue_signal(env, info.si_signo, &info);
            }
            break;
        case EXCP06_ILLOP:
            info.si_signo = SIGILL;
            info.si_errno = 0;
            info.si_code = TARGET_ILL_ILLOPN;
            info._sifields._sigfault._addr = env->eip;
            queue_signal(env, info.si_signo, &info);
            break;
#endif
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
#if 0
        case EXCP_DEBUG:
            {
                int sig;

                sig = gdb_handlesig (env, TARGET_SIGTRAP);
                if (sig)
                  {
                    info.si_signo = sig;
                    info.si_errno = 0;
                    info.si_code = TARGET_TRAP_BRKPT;
                    queue_signal(env, info.si_signo, &info);
                  }
            }
            break;
#endif
        default:
            pc = env->segs[R_CS].base + env->eip;
            fprintf(stderr, "qemu: 0x%08lx: unhandled CPU exception 0x%x - aborting\n",
                    (long)pc, trapnr);
            abort();
        }
        process_pending_signals(env);
    }
}
#endif

#ifdef TARGET_ARM
// #define DEBUG_ARM

static int do_strex(CPUARMState *env)
{
    uint32_t val;
    int size;
    int rc = 1;
    int segv = 0;
    uint32_t addr;
    start_exclusive();
    addr = env->exclusive_addr;
    if (addr != env->exclusive_test) {
        goto fail;
    }
    size = env->exclusive_info & 0xf;
    switch (size) {
    case 0:
        segv = get_user_u8(val, addr);
        break;
    case 1:
        segv = get_user_u16(val, addr);
        break;
    case 2:
    case 3:
        segv = get_user_u32(val, addr);
        break;
    default:
        abort();
    }
    if (segv) {
        env->cp15.c6_data = addr;
        goto done;
    }
    if (val != env->exclusive_val) {
        goto fail;
    }
    if (size == 3) {
        segv = get_user_u32(val, addr + 4);
        if (segv) {
            env->cp15.c6_data = addr + 4;
            goto done;
        }
        if (val != env->exclusive_high) {
            goto fail;
        }
    }
    val = env->regs[(env->exclusive_info >> 8) & 0xf];
    switch (size) {
    case 0:
        segv = put_user_u8(val, addr);
        break;
    case 1:
        segv = put_user_u16(val, addr);
        break;
    case 2:
    case 3:
        segv = put_user_u32(val, addr);
        break;
    }
    if (segv) {
        env->cp15.c6_data = addr;
        goto done;
    }
    if (size == 3) {
        val = env->regs[(env->exclusive_info >> 12) & 0xf];
        segv = put_user_u32(val, addr + 4);
        if (segv) {
            env->cp15.c6_data = addr + 4;
            goto done;
        }
    }
    rc = 0;
fail:
    env->regs[15] += 4;
    env->regs[(env->exclusive_info >> 4) & 0xf] = rc;
done:
    end_exclusive();
    return segv;
}

void cpu_loop(CPUARMState *env)
{
    int trapnr;
    unsigned int n, insn;
    uint32_t addr;

    for(;;) {
#ifdef DEBUG_ARM
	printf("CPU LOOPING\n");
#endif
        cpu_exec_start(env);
#ifdef DEBUG_ARM
	printf("EXECUTING...\n");
#endif
        trapnr = cpu_arm_exec(env);
#ifdef DEBUG_ARM
	printf("trapnr %d\n", trapnr);
#endif
        cpu_exec_end(env);
        switch(trapnr) {
        case EXCP_UDEF:
            {
#if 0
                TaskState *ts = env->opaque;
                uint32_t opcode;
                int rc;

                /* we handle the FPU emulation here, as Linux */
                /* we get the opcode */
                /* FIXME - what to do if get_user() fails? */
                get_user_u32(opcode, env->regs[15]);

                rc = EmulateAll(opcode, &ts->fpa, env);
                if (rc == 0) { /* illegal instruction */
                    info.si_signo = SIGILL;
                    info.si_errno = 0;
                    info.si_code = TARGET_ILL_ILLOPN;
                    info._sifields._sigfault._addr = env->regs[15];
                    queue_signal(env, info.si_signo, &info);

                } else if (rc < 0) { /* FP exception */
                    int arm_fpe=0;

                    /* translate softfloat flags to FPSR flags */
                    if (-rc & float_flag_invalid)
                      arm_fpe |= BIT_IOC;
                    if (-rc & float_flag_divbyzero)
                      arm_fpe |= BIT_DZC;
                    if (-rc & float_flag_overflow)
                      arm_fpe |= BIT_OFC;
                    if (-rc & float_flag_underflow)
                      arm_fpe |= BIT_UFC;
                    if (-rc & float_flag_inexact)
                      arm_fpe |= BIT_IXC;

                    FPSR fpsr = ts->fpa.fpsr;
                    //printf("fpsr 0x%x, arm_fpe 0x%x\n",fpsr,arm_fpe);

                    if (fpsr & (arm_fpe << 16)) { /* exception enabled? */
                      info.si_signo = SIGFPE;
                      info.si_errno = 0;

                      /* ordered by priority, least first */
                      if (arm_fpe & BIT_IXC) info.si_code = TARGET_FPE_FLTRES;
                      if (arm_fpe & BIT_UFC) info.si_code = TARGET_FPE_FLTUND;
                      if (arm_fpe & BIT_OFC) info.si_code = TARGET_FPE_FLTOVF;
                      if (arm_fpe & BIT_DZC) info.si_code = TARGET_FPE_FLTDIV;
                      if (arm_fpe & BIT_IOC) info.si_code = TARGET_FPE_FLTINV;

                      info._sifields._sigfault._addr = env->regs[15];
                      queue_signal(env, info.si_signo, &info);
                    } else {
                      env->regs[15] += 4;
                    }

                    /* accumulate unenabled exceptions */
                    if ((!(fpsr & BIT_IXE)) && (arm_fpe & BIT_IXC))
                      fpsr |= BIT_IXC;
                    if ((!(fpsr & BIT_UFE)) && (arm_fpe & BIT_UFC))
                      fpsr |= BIT_UFC;
                    if ((!(fpsr & BIT_OFE)) && (arm_fpe & BIT_OFC))
                      fpsr |= BIT_OFC;
                    if ((!(fpsr & BIT_DZE)) && (arm_fpe & BIT_DZC))
                      fpsr |= BIT_DZC;
                    if ((!(fpsr & BIT_IOE)) && (arm_fpe & BIT_IOC))
                      fpsr |= BIT_IOC;
                    ts->fpa.fpsr=fpsr;
                } else { /* everything OK */
                    /* increment PC */
                    env->regs[15] += 4;
                }
            }
#endif
            break;
        case EXCP_SWI:
        case EXCP_BKPT:
            {
                env->eabi = 1;
                /* system call */
                if (trapnr == EXCP_BKPT) {
                    if (env->thumb) {
                        /* FIXME - what to do if get_user() fails? */
                        get_user_u16(insn, env->regs[15]);
                        n = insn & 0xff;
                        env->regs[15] += 2;
                    } else {
                        /* FIXME - what to do if get_user() fails? */
                        get_user_u32(insn, env->regs[15]);
                        n = (insn & 0xf) | ((insn >> 4) & 0xff0);
                        env->regs[15] += 4;
                    }
                } else {
                    if (env->thumb) {
                        /* FIXME - what to do if get_user() fails? */
                        get_user_u16(insn, env->regs[15] - 2);
                        n = insn & 0xff;
                    } else {
                        /* FIXME - what to do if get_user() fails? */
                        get_user_u32(insn, env->regs[15] - 4);
                        n = insn & 0xffffff;
                    }
                }

#ifdef DEBUG_ARM
		printf("AVANT CALL %d\n", n);
#endif
                if (bsd_type == target_freebsd) {
                    int ret;
                    abi_ulong params = get_sp_from_cpustate(env);
                    int32_t syscall_nr = n;
                    int32_t arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8;

#if 0 // XXX FIXME
                    if (syscall_nr == TARGET_FREEBSD_NR_syscall) {
                        get_user_s32(syscall_nr, params);
                        params += sizeof(int32_t);
                    } else if (syscall_nr == TARGET_FREEBSD_NR___syscall) {
                        get_user_s32(syscall_nr, params);
                        params += sizeof(int64_t);
                    }
#endif
                    arg1 = env->regs[0];
                    arg2 = env->regs[1];
                    arg3 = env->regs[2];
                    arg4 = env->regs[3];
                    get_user_s32(arg5, params);
                    params += sizeof(int32_t);
                    get_user_s32(arg6, params);
                    params += sizeof(int32_t);
                    get_user_s32(arg7, params);
                    params += sizeof(int32_t);
                    get_user_s32(arg8, params);
                    ret = do_freebsd_syscall(env,
                                                      syscall_nr,
                                                      arg1,
                                                      arg2,
                                                      arg3,
                                                      arg4,
                                                      arg5,
                                                      arg6,
                                                      arg7,
                                                      arg8);
		    /* Compare to arm/arm/vm_machdep.c cpu_set_syscall_retval() */
		    /* XXX armeb may need some extra magic here */
		    if (-TARGET_EJUSTRETURN == ret) {
			    /*
			     * Returning from a successful sigreturn syscall.
			     * Avoid clobbering register state.
			     */
				break;
		    }
		    /* XXX Need to handle ERESTART. Backup the PC by 1 instruction*/
		    if ((unsigned int)ret >= (unsigned int)(-515)) {
			    ret = -ret;
			    cpsr_write(env, CPSR_C, CPSR_C);
			    env->regs[0] = ret;
		    } else {
			    cpsr_write(env, 0, CPSR_C);
			    env->regs[0] = ret; // XXX need to handle lseek()?
			    // env->regs[1] = 0;
		    }
                } else {
                    // XXX is this correct?
                    env->regs[0] = do_openbsd_syscall(env,
                        n,
                        env->regs[0],
                        env->regs[1],
                        env->regs[2],
                        env->regs[3],
                        env->regs[4],
                        env->regs[5]);
                }
#ifdef DEBUG_ARM
		printf("APRES CALL\n");
#endif
            }
        }
            break;
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_PREFETCH_ABORT:
            addr = env->cp15.c6_insn;
            goto do_segv;
        case EXCP_DATA_ABORT:
            addr = env->cp15.c6_data;
        do_segv:
            {
#if 0
#
                info.si_signo = SIGSEGV;
                info.si_errno = 0;
                /* XXX: check env->error_code */
                info.si_code = TARGET_SEGV_MAPERR;
                info._sifields._sigfault._addr = addr;
                queue_signal(env, info.si_signo, &info);
#endif
            }
            break;
        case EXCP_DEBUG:
            {
                int sig;

                sig = gdb_handlesig (env, TARGET_SIGTRAP);
                if (sig)
                  {
#if 0
                    info.si_signo = sig;
                    info.si_errno = 0;
                    info.si_code = TARGET_TRAP_BRKPT;
                    queue_signal(env, info.si_signo, &info);
#endif
                  }
            }
            break;
#if 0
        case EXCP_KERNEL_TRAP:
            if (do_kernel_trap(env))
              goto error;
            break;
#endif
        case EXCP_STREX:
            if (do_strex(env)) {
                addr = env->cp15.c6_data;
                goto do_segv;
            }
            break;
#if 0
        error:
#endif
        default:
            fprintf(stderr, "qemu: unhandled CPU exception 0x%x - aborting\n",
                    trapnr);
            cpu_dump_state(env, stderr, fprintf, 0);
            abort();
        }
        process_pending_signals(env);
    }
}

#endif

#if defined(TARGET_MIPS) || defined(TARGET_MIPS64)

/*
 * From sys/mips/mips/trap.c syscalls have the following stored away in the
 * registers:
 *
 * v0(2): if either SYS___syscall (198) or SYS_syscall (0) then indirect syscall
 * 	  otherwise it is a direct syscall.
 *
 * If direct syscall:
 *
 * MIPS		MIPS64
 * v0(2):	v0(2)		syscall #
 * a0(4):	a0(4)		arg0
 * a1(5):	a1(5)		arg1
 * a2(6):	a2(6)		arg2
 * a3(7):	a3(7)		arg3
 * t4(12):	a4(8)		arg4
 * t5(13):	a5(9)		arg5
 * t6(14):	a6(10)		arg6
 * t7(15):	a7(11)		arg7
 *
 * If indirect syscall:
 *
 * MIPS		MIPS64
 * a0(4):	a0(4)		syscall #
 * a1(5):	a1(5)		arg0
 * a2(6):	a2(6)		arg1
 * a3(7):	a3(7)		arg2
 * t4(12):	a4(8)		arg3
 * t5(13):	a5(9)		arg4
 * t6(14):	a6(10)		arg5
 * t7(15):	a7(11)		arg6
 *
 */

#include <sys/syscall.h>	/* For SYS_[__]syscall, SYS_MAXSYSCALL */

static int do_store_exclusive(CPUMIPSState *env)
{
	target_ulong addr;
	target_ulong page_addr;
	target_ulong val;
	int flags;
	int segv = 0;
	int reg;
	int d;

	addr = env->lladdr;
	page_addr = addr & TARGET_PAGE_MASK;
	start_exclusive();
	mmap_lock();
	flags = page_get_flags(page_addr);
	if ((flags & PAGE_READ) == 0) {
		segv = 1;
	} else {
		reg = env->llreg & 0x1f;
		d = (env->llreg & 0x20) != 0;
		if (d) {
			segv = get_user_s64(val, addr);
		} else {
			segv = get_user_s32(val, addr);
		}
		if (!segv) {
			if (val != env->llval) {
				env->active_tc.gpr[reg] = 0;
			} else {
				if (d) {
					segv =
					    put_user_u64(env->llnewval, addr);
				} else {
					segv =
					    put_user_u32(env->llnewval, addr);
				}
				if (!segv) {
					env->active_tc.gpr[reg] = 1;
				}
			}
		}
	}
	env->lladdr = -1;
	if (!segv) {
		env->active_tc.PC += 4;
	}
	mmap_unlock();
	end_exclusive();
	return (segv);
}

void cpu_loop(CPUMIPSState *env)
{
	target_siginfo_t info;
	int trapnr;
	abi_long ret;
	unsigned int syscall_num;

	for(;;) {
		cpu_exec_start(env);
		trapnr = cpu_mips_exec(env);
		cpu_exec_end(env);
		switch(trapnr) {
		case EXCP_SYSCALL: /* syscall exception */
			syscall_num = env->active_tc.gpr[2]; /* v0 */
			env->active_tc.PC += TARGET_INSN_SIZE;
			if (syscall_num >= SYS_MAXSYSCALL) {
				ret = -TARGET_ENOSYS;
			} else {
				if (SYS_syscall == syscall_num ||
				    SYS___syscall == syscall_num) {
#if defined(TARGET_MIPS64)
					ret = do_freebsd_syscall(env,
					    env->active_tc.gpr[4],/* syscall #*/
					    env->active_tc.gpr[5], /* arg0 */
					    env->active_tc.gpr[6], /* arg1 */
					    env->active_tc.gpr[7], /* arg2 */
					    env->active_tc.gpr[8], /* arg3 */
					    env->active_tc.gpr[9], /* arg4 */
					    env->active_tc.gpr[10],/* arg5 */
					    env->active_tc.gpr[11],/* arg6 */
					    0 /* no arg 7 */);
				} else {
					ret = do_freebsd_syscall(env,
					    syscall_num,
					    env->active_tc.gpr[4],
					    env->active_tc.gpr[5],
					    env->active_tc.gpr[6],
					    env->active_tc.gpr[7],
					    env->active_tc.gpr[8],
					    env->active_tc.gpr[9],
					    env->active_tc.gpr[10],
					    env->active_tc.gpr[11]
					    );

#else /* ! TARGET_MIPS64 */
					/* indirect syscall */
					ret = do_freebsd_syscall(env,
					    env->active_tc.gpr[4],/* syscall #*/
					    env->active_tc.gpr[5], /* a1/arg0 */
					    env->active_tc.gpr[6], /* a2/arg1 */
					    env->active_tc.gpr[7], /* a3/arg2 */
					    env->active_tc.gpr[12],/* t4/arg3 */
					    env->active_tc.gpr[13],/* t5/arg4 */
					    env->active_tc.gpr[14],/* t6/arg5 */
					    env->active_tc.gpr[15],/* t7/arg6 */
					    0 /* no arg7 */ );
				} else {
					/* direct syscall */
					ret = do_freebsd_syscall(env,
					    syscall_num,
					    env->active_tc.gpr[4], /* a0/arg0 */
					    env->active_tc.gpr[5], /* a1/arg1 */
					    env->active_tc.gpr[6], /* a2/arg2 */
					    env->active_tc.gpr[7], /* a3/arg3 */
					    env->active_tc.gpr[12],/* t4/arg4 */
					    env->active_tc.gpr[13],/* t5/arg5 */
					    env->active_tc.gpr[14],/* t6/arg6 */
					    env->active_tc.gpr[15] /* t7/arg7 */
					    );
#endif /* ! TARGET_MIPS64 */
				}
			}
/* done_syscall: */
			/*
			 * Compare to mips/mips/vm_machdep.c
			 * cpu_set_syscall_retval()
			 *
			 * XXX need to handle lseek here.
			 */
			if (-TARGET_EJUSTRETURN == ret) {
				/*
				 * Returning from a successful sigreturn
				 * syscall.  Avoid clobbering register state.
				 */
				break;
			}
			if (-TARGET_ERESTART == ret) {
				/* Backup the pc to point at the swi. */
				env->active_tc.PC -= TARGET_INSN_SIZE;
				break;
			}
			if ((unsigned int)ret >= (unsigned int)(-1133)) {
				env->active_tc.gpr[7] = 1;
				ret = -ret;
			} else {
				env->active_tc.gpr[7] = 0;
			}
			env->active_tc.gpr[2] = ret; /* v0 <- ret */
			break;

		case EXCP_TLBL:	/* TLB miss on load */
		case EXCP_TLBS: /* TLB miss on store */
		case EXCP_AdEL:	/* bad address on load */
		case EXCP_AdES: /* bad address on store */
			info.si_signo = TARGET_SIGSEGV;
			info.si_errno = 0;
			/* XXX: check env->error_code */
			info.si_code = TARGET_SEGV_MAPERR;
			info.si_addr = env->CP0_BadVAddr;
			queue_signal(env, info.si_signo, &info);
			break;

		case EXCP_CpU: /* coprocessor unusable */
		case EXCP_RI:  /* reserved instruction */
			info.si_signo = TARGET_SIGILL;
			info.si_errno = 0;
			info.si_code = 0;
			queue_signal(env, info.si_signo, &info);
			break;

		case EXCP_INTERRUPT: /* async interrupt */
			/* just indicate that signals should be handled asap */
			break;

		case EXCP_DEBUG: /* cpu stopped after a breakpoint */
			{
				int sig;

				sig = gdb_handlesig(env, TARGET_SIGTRAP);
				if (sig) {
					info.si_signo = sig;
					info.si_errno = 0;
					info.si_code = TARGET_TRAP_BRKPT;
					queue_signal(env, info.si_signo, &info);
				}
			}
			break;

		case EXCP_SC:
			if (do_store_exclusive(env)) {
				info.si_signo = TARGET_SIGSEGV;
				info.si_errno = 0;
				info.si_code = TARGET_SEGV_MAPERR;
				info.si_addr = env->active_tc.PC;
				queue_signal(env, info.si_signo, &info);
			}
			break;

		default:
			fprintf(stderr, "qemu: unhandled CPU exception "
			    "0x%x - aborting\n", trapnr);
			cpu_dump_state(env, stderr, fprintf, 0);
			abort();
		}
		process_pending_signals(env);
	}
}
#endif /* defined(TARGET_MIPS) */

#ifdef TARGET_SPARC
#define SPARC64_STACK_BIAS 2047

//#define DEBUG_WIN
/* WARNING: dealing with register windows _is_ complicated. More info
   can be found at http://www.sics.se/~psm/sparcstack.html */
static inline int get_reg_index(CPUSPARCState *env, int cwp, int index)
{
    index = (index + cwp * 16) % (16 * env->nwindows);
    /* wrap handling : if cwp is on the last window, then we use the
       registers 'after' the end */
    if (index < 8 && env->cwp == env->nwindows - 1)
        index += 16 * env->nwindows;
    return index;
}

/* save the register window 'cwp1' */
static inline void save_window_offset(CPUSPARCState *env, int cwp1)
{
    unsigned int i;
    abi_ulong sp_ptr;

    sp_ptr = env->regbase[get_reg_index(env, cwp1, 6)];
#ifdef TARGET_SPARC64
    if (sp_ptr & 3)
        sp_ptr += SPARC64_STACK_BIAS;
#endif
#if defined(DEBUG_WIN)
    printf("win_overflow: sp_ptr=0x" TARGET_ABI_FMT_lx " save_cwp=%d\n",
           sp_ptr, cwp1);
#endif
    for(i = 0; i < 16; i++) {
        /* FIXME - what to do if put_user() fails? */
        put_user_ual(env->regbase[get_reg_index(env, cwp1, 8 + i)], sp_ptr);
        sp_ptr += sizeof(abi_ulong);
    }
}

static void save_window(CPUSPARCState *env)
{
#ifndef TARGET_SPARC64
    unsigned int new_wim;
    new_wim = ((env->wim >> 1) | (env->wim << (env->nwindows - 1))) &
        ((1LL << env->nwindows) - 1);
    save_window_offset(env, cpu_cwp_dec(env, env->cwp - 2));
    env->wim = new_wim;
#else
    save_window_offset(env, cpu_cwp_dec(env, env->cwp - 2));
    env->cansave++;
    env->canrestore--;
#endif
}

static void restore_window(CPUSPARCState *env)
{
#ifndef TARGET_SPARC64
    unsigned int new_wim;
#endif
    unsigned int i, cwp1;
    abi_ulong sp_ptr;

#ifndef TARGET_SPARC64
    new_wim = ((env->wim << 1) | (env->wim >> (env->nwindows - 1))) &
        ((1LL << env->nwindows) - 1);
#endif

    /* restore the invalid window */
    cwp1 = cpu_cwp_inc(env, env->cwp + 1);
    sp_ptr = env->regbase[get_reg_index(env, cwp1, 6)];
#ifdef TARGET_SPARC64
    if (sp_ptr & 3)
        sp_ptr += SPARC64_STACK_BIAS;
#endif
#if defined(DEBUG_WIN)
    printf("win_underflow: sp_ptr=0x" TARGET_ABI_FMT_lx " load_cwp=%d\n",
           sp_ptr, cwp1);
#endif
    for(i = 0; i < 16; i++) {
        /* FIXME - what to do if get_user() fails? */
        get_user_ual(env->regbase[get_reg_index(env, cwp1, 8 + i)], sp_ptr);
        sp_ptr += sizeof(abi_ulong);
    }
#ifdef TARGET_SPARC64
    env->canrestore++;
    if (env->cleanwin < env->nwindows - 1)
        env->cleanwin++;
    env->cansave--;
#else
    env->wim = new_wim;
#endif
}

static void flush_windows(CPUSPARCState *env)
{
    int offset, cwp1;

    offset = 1;
    for(;;) {
        /* if restore would invoke restore_window(), then we can stop */
        cwp1 = cpu_cwp_inc(env, env->cwp + offset);
#ifndef TARGET_SPARC64
        if (env->wim & (1 << cwp1))
            break;
#else
        if (env->canrestore == 0)
            break;
        env->cansave++;
        env->canrestore--;
#endif
        save_window_offset(env, cwp1);
        offset++;
    }
    cwp1 = cpu_cwp_inc(env, env->cwp + 1);
#ifndef TARGET_SPARC64
    /* set wim so that restore will reload the registers */
    env->wim = 1 << cwp1;
#endif
#if defined(DEBUG_WIN)
    printf("flush_windows: nb=%d\n", offset - 1);
#endif
}

void cpu_loop(CPUSPARCState *env)
{
    int trapnr, ret, syscall_nr;
    //target_siginfo_t info;

    while (1) {
        trapnr = cpu_sparc_exec (env);

        switch (trapnr) {
#ifndef TARGET_SPARC64
        case 0x80:
#else
        /* FreeBSD uses 0x141 for syscalls too */
        case 0x141:
            if (bsd_type != target_freebsd)
                goto badtrap;
        case 0x100:
#endif
            syscall_nr = env->gregs[1];
            if (bsd_type == target_freebsd)
                ret = do_freebsd_syscall(env, syscall_nr,
                                         env->regwptr[0], env->regwptr[1],
                                         env->regwptr[2], env->regwptr[3],
                                         env->regwptr[4], env->regwptr[5], 0, 0);
            else if (bsd_type == target_netbsd)
                ret = do_netbsd_syscall(env, syscall_nr,
                                        env->regwptr[0], env->regwptr[1],
                                        env->regwptr[2], env->regwptr[3],
                                        env->regwptr[4], env->regwptr[5]);
            else { //if (bsd_type == target_openbsd)
#if defined(TARGET_SPARC64)
                syscall_nr &= ~(TARGET_OPENBSD_SYSCALL_G7RFLAG |
                                TARGET_OPENBSD_SYSCALL_G2RFLAG);
#endif
                ret = do_openbsd_syscall(env, syscall_nr,
                                         env->regwptr[0], env->regwptr[1],
                                         env->regwptr[2], env->regwptr[3],
                                         env->regwptr[4], env->regwptr[5]);
            }
            if ((unsigned int)ret >= (unsigned int)(-515)) {
                ret = -ret;
#if defined(TARGET_SPARC64) && !defined(TARGET_ABI32)
                env->xcc |= PSR_CARRY;
#else
                env->psr |= PSR_CARRY;
#endif
            } else {
#if defined(TARGET_SPARC64) && !defined(TARGET_ABI32)
                env->xcc &= ~PSR_CARRY;
#else
                env->psr &= ~PSR_CARRY;
#endif
            }
            env->regwptr[0] = ret;
            /* next instruction */
#if defined(TARGET_SPARC64)
            if (bsd_type == target_openbsd &&
                env->gregs[1] & TARGET_OPENBSD_SYSCALL_G2RFLAG) {
                env->pc = env->gregs[2];
                env->npc = env->pc + 4;
            } else if (bsd_type == target_openbsd &&
                       env->gregs[1] & TARGET_OPENBSD_SYSCALL_G7RFLAG) {
                env->pc = env->gregs[7];
                env->npc = env->pc + 4;
            } else {
                env->pc = env->npc;
                env->npc = env->npc + 4;
            }
#else
            env->pc = env->npc;
            env->npc = env->npc + 4;
#endif
            break;
        case 0x83: /* flush windows */
#ifdef TARGET_ABI32
        case 0x103:
#endif
            flush_windows(env);
            /* next instruction */
            env->pc = env->npc;
            env->npc = env->npc + 4;
            break;
#ifndef TARGET_SPARC64
        case TT_WIN_OVF: /* window overflow */
            save_window(env);
            break;
        case TT_WIN_UNF: /* window underflow */
            restore_window(env);
            break;
        case TT_TFAULT:
        case TT_DFAULT:
#if 0
            {
                info.si_signo = SIGSEGV;
                info.si_errno = 0;
                /* XXX: check env->error_code */
                info.si_code = TARGET_SEGV_MAPERR;
                info._sifields._sigfault._addr = env->mmuregs[4];
                queue_signal(env, info.si_signo, &info);
            }
#endif
            break;
#else
        case TT_SPILL: /* window overflow */
            save_window(env);
            break;
        case TT_FILL: /* window underflow */
            restore_window(env);
            break;
        case TT_TFAULT:
        case TT_DFAULT:
#if 0
            {
                info.si_signo = SIGSEGV;
                info.si_errno = 0;
                /* XXX: check env->error_code */
                info.si_code = TARGET_SEGV_MAPERR;
                if (trapnr == TT_DFAULT)
                    info._sifields._sigfault._addr = env->dmmuregs[4];
                else
                    info._sifields._sigfault._addr = env->tsptr->tpc;
                //queue_signal(env, info.si_signo, &info);
            }
#endif
            break;
#endif
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_DEBUG:
            {
                int sig;

                sig = gdb_handlesig (env, TARGET_SIGTRAP);
#if 0
                if (sig)
                  {
                    info.si_signo = sig;
                    info.si_errno = 0;
                    info.si_code = TARGET_TRAP_BRKPT;
                    //queue_signal(env, info.si_signo, &info);
                  }
#endif
            }
            break;
        default:
#ifdef TARGET_SPARC64
        badtrap:
#endif
            printf ("Unhandled trap: 0x%x\n", trapnr);
            cpu_dump_state(env, stderr, fprintf, 0);
            exit (1);
        }
        process_pending_signals (env);
    }
}

#endif

static void usage(void)
{
    printf("qemu-" TARGET_ARCH " version " QEMU_VERSION ", Copyright (c) 2003-2008 Fabrice Bellard\n"
           "usage: qemu-" TARGET_ARCH " [options] program [arguments...]\n"
           "BSD CPU emulator (compiled for %s emulation)\n"
           "\n"
           "Standard options:\n"
           "-h                print this help\n"
           "-g port           wait gdb connection to port\n"
           "-L path           set the elf interpreter prefix (default=%s)\n"
           "-s size           set the stack size in bytes (default=%ld)\n"
           "-cpu model        select CPU (-cpu help for list)\n"
           "-drop-ld-preload  drop LD_PRELOAD for target process\n"
           "-E var=value      sets/modifies targets environment variable(s)\n"
           "-U var            unsets targets environment variable(s)\n"
#if defined(CONFIG_USE_GUEST_BASE)
           "-B address        set guest_base address to address\n"
#endif
           "-bsd type         select emulated BSD type FreeBSD/NetBSD/OpenBSD (default)\n"
           "\n"
           "Debug options:\n"
           "-d options   activate log (default logfile=%s)\n"
           "-D logfile   override default logfile location\n"
           "-p pagesize  set the host page size to 'pagesize'\n"
           "-singlestep  always run in singlestep mode\n"
           "-strace      log system calls\n"
           "\n"
           "Environment variables:\n"
           "QEMU_STRACE       Print system calls and arguments similar to the\n"
           "                  'strace' program.  Enable by setting to any value.\n"
           "You can use -E and -U options to set/unset environment variables\n"
           "for target process.  It is possible to provide several variables\n"
           "by repeating the option.  For example:\n"
           "    -E var1=val2 -E var2=val2 -U LD_PRELOAD -U LD_DEBUG\n"
           "Note that if you provide several changes to single variable\n"
           "last change will stay in effect.\n"
           ,
           TARGET_ARCH,
           interp_prefix,
           target_dflssiz,
           DEBUG_LOGFILE);
    exit(1);
}

THREAD CPUArchState *thread_env;

void task_settid(TaskState *ts)
{
	if (0 == ts->ts_tid) {
#ifdef CONFIG_USE_NPTL
		(void)thr_self(&ts->ts_tid);
#else
		/* When no threads then just use PID */
		ts->ts_tid = getpid();
#endif
	}
}

void stop_all_tasks(void)
{
	/*
	 * We trust when using NPTL (pthreads) start_exclusive() handles thread
	 * stopping correctly.
	 */
	start_exclusive();
}

/* Assumes contents are already zeroed.  */
void init_task_state(TaskState *ts)
{
    int i;

    ts->used = 1;
    ts->first_free = ts->sigqueue_table;
    for (i = 0; i < MAX_SIGQUEUE_SIZE - 1; i++) {
        ts->sigqueue_table[i].next = &ts->sigqueue_table[i + 1];
    }
    ts->sigqueue_table[i].next = NULL;
}

int main(int argc, char **argv)
{
    const char *filename;
    const char *cpu_model;
    const char *log_file = DEBUG_LOGFILE;
    const char *log_mask = NULL;
    struct target_pt_regs regs1, *regs = &regs1;
    struct image_info info1, *info = &info1;
    struct bsd_binprm bprm;
    TaskState ts1, *ts = &ts1;
    CPUArchState *env;
    int optind;
    const char *r;
    int gdbstub_port = 0;
    char **target_environ, **wrk;
    envlist_t *envlist = NULL;
#ifdef __FreeBSD__
    bsd_type = target_freebsd;
#else
    bsd_type = target_openbsd;
#endif

    if (argc <= 1)
        usage();

    save_proc_pathname();

    module_call_init(MODULE_INIT_QOM);

    if ((envlist = envlist_create()) == NULL) {
        (void) fprintf(stderr, "Unable to allocate envlist\n");
        exit(1);
    }

    /* add current environment into the list */
    for (wrk = environ; *wrk != NULL; wrk++) {
        (void) envlist_setenv(envlist, *wrk);
    }

    cpu_model = NULL;
#if defined(cpudef_setup)
    cpudef_setup(); /* parse cpu definitions in target config file (TBD) */
#endif

    optind = 1;
    for(;;) {
        if (optind >= argc)
            break;
        r = argv[optind];
        if (r[0] != '-')
            break;
        optind++;
        r++;
        if (!strcmp(r, "-")) {
            break;
        } else if (!strcmp(r, "d")) {
            if (optind >= argc) {
                break;
            }
            log_mask = argv[optind++];
        } else if (!strcmp(r, "D")) {
            if (optind >= argc) {
                break;
            }
            log_file = argv[optind++];
        } else if (!strcmp(r, "E")) {
            r = argv[optind++];
            if (envlist_setenv(envlist, r) != 0)
                usage();
        } else if (!strcmp(r, "ignore-environment")) {
            envlist_free(envlist);
            if ((envlist = envlist_create()) == NULL) {
                (void) fprintf(stderr, "Unable to allocate envlist\n");
                exit(1);
            }
        } else if (!strcmp(r, "U")) {
            r = argv[optind++];
            if (envlist_unsetenv(envlist, r) != 0)
                usage();
        } else if (!strcmp(r, "s")) {
            r = argv[optind++];
            target_dflssiz = strtol(r, (char **)&r, 0);
            if (target_dflssiz <= 0)
                usage();
            if (*r == 'M')
                target_dflssiz *= 1024 * 1024;
            else if (*r == 'k' || *r == 'K')
                target_dflssiz *= 1024;
	    if (target_dflssiz > target_maxssiz)
		    usage();
        } else if (!strcmp(r, "L")) {
            interp_prefix = argv[optind++];
        } else if (!strcmp(r, "p")) {
            qemu_host_page_size = atoi(argv[optind++]);
            if (qemu_host_page_size == 0 ||
                (qemu_host_page_size & (qemu_host_page_size - 1)) != 0) {
                fprintf(stderr, "page size must be a power of two\n");
                exit(1);
            }
        } else if (!strcmp(r, "g")) {
            gdbstub_port = atoi(argv[optind++]);
        } else if (!strcmp(r, "r")) {
            qemu_uname_release = argv[optind++];
        } else if (!strcmp(r, "cpu")) {
            cpu_model = argv[optind++];
            if (is_help_option(cpu_model)) {
/* XXX: implement xxx_cpu_list for targets that still miss it */
#if defined(cpu_list)
                    cpu_list(stdout, &fprintf);
#endif
                exit(1);
            }
#if defined(CONFIG_USE_GUEST_BASE)
        } else if (!strcmp(r, "B")) {
           guest_base = strtol(argv[optind++], NULL, 0);
           have_guest_base = 1;
#endif
        } else if (!strcmp(r, "drop-ld-preload")) {
            (void) envlist_unsetenv(envlist, "LD_PRELOAD");
        } else if (!strcmp(r, "bsd")) {
            if (!strcasecmp(argv[optind], "freebsd")) {
                bsd_type = target_freebsd;
            } else if (!strcasecmp(argv[optind], "netbsd")) {
                bsd_type = target_netbsd;
            } else if (!strcasecmp(argv[optind], "openbsd")) {
                bsd_type = target_openbsd;
            } else {
                usage();
            }
            optind++;
        } else if (!strcmp(r, "singlestep")) {
            singlestep = 1;
        } else if (!strcmp(r, "strace")) {
            do_strace = 1;
        } else
        {
            usage();
        }
    }

    /* init debug */
    cpu_set_log_filename(log_file);
    if (log_mask) {
        int mask;
        const CPULogItem *item;

        mask = cpu_str_to_log_mask(log_mask);
        if (!mask) {
            printf("Log items (comma separated):\n");
            for (item = cpu_log_items; item->mask != 0; item++) {
                printf("%-10s %s\n", item->name, item->help);
            }
            exit(1);
        }
        cpu_set_log(mask);
    }

    if (optind >= argc) {
        usage();
    }
    filename = argv[optind];

    /* Zero out regs */
    memset(regs, 0, sizeof(struct target_pt_regs));

    /* Zero out image_info */
    memset(info, 0, sizeof(struct image_info));

    memset(&bprm, 0, sizeof(bprm));

    /* Scan interp_prefix dir for replacement files. */
    init_paths(interp_prefix);

    if (cpu_model == NULL) {
#if defined(TARGET_I386)
#ifdef TARGET_X86_64
        cpu_model = "qemu64";
#else
        cpu_model = "qemu32";
#endif
#elif defined(TARGET_MIPS) || defined(TARGET_MIPS64)
#if defined(TARGET_ABI_MIPSN32) || defined(TARGET_ABI_MIPSN64)
	cpu_model = "20Kc";
#else
	cpu_model = "24Kf";
#endif
#elif defined(TARGET_SPARC)
#ifdef TARGET_SPARC64
        cpu_model = "TI UltraSparc II";
#else
        cpu_model = "Fujitsu MB86904";
#endif
#else
        cpu_model = "any";
#endif
    }
    tcg_exec_init(0);
    cpu_exec_init_all();
    /* NOTE: we need to init the CPU at this stage to get
       qemu_host_page_size */
    env = cpu_init(cpu_model);
    if (!env) {
        fprintf(stderr, "Unable to find CPU definition\n");
        exit(1);
    }
#if defined(TARGET_SPARC) || defined(TARGET_PPC)
    cpu_reset(ENV_GET_CPU(env));
#endif
    thread_env = env;

    if (getenv("QEMU_STRACE")) {
        do_strace = 1;
    }

    target_environ = envlist_to_environ(envlist, NULL);
    envlist_free(envlist);

#if defined(CONFIG_USE_GUEST_BASE)
    /*
     * Now that page sizes are configured in cpu_init() we can do
     * proper page alignment for guest_base.
     */
    guest_base = HOST_PAGE_ALIGN(guest_base);

    /*
     * Read in mmap_min_addr kernel parameter.  This value is used
     * When loading the ELF image to determine whether guest_base
     * is needed.
     *
     * When user has explicitly set the quest base, we skip this
     * test.
     */
    if (!have_guest_base) {
        FILE *fp;

        if ((fp = fopen("/proc/sys/vm/mmap_min_addr", "r")) != NULL) {
            unsigned long tmp;
            if (fscanf(fp, "%lu", &tmp) == 1) {
                mmap_min_addr = tmp;
                qemu_log("host mmap_min_addr=0x%lx\n", mmap_min_addr);
            }
            fclose(fp);
        }
    }
#endif /* CONFIG_USE_GUEST_BASE */

    if (loader_exec(filename, argv+optind, target_environ, regs, info,
	    &bprm)!= 0) {
        printf("Error loading %s\n", filename);
        _exit(1);
    }

    for (wrk = target_environ; *wrk; wrk++) {
        free(*wrk);
    }

    free(target_environ);

    if (qemu_log_enabled()) {
#if defined(CONFIG_USE_GUEST_BASE)
        qemu_log("guest_base  0x%lx\n", guest_base);
#endif
        log_page_dump();

        qemu_log("start_brk   0x" TARGET_ABI_FMT_lx "\n", info->start_brk);
        qemu_log("end_code    0x" TARGET_ABI_FMT_lx "\n", info->end_code);
        qemu_log("start_code  0x" TARGET_ABI_FMT_lx "\n",
                 info->start_code);
        qemu_log("start_data  0x" TARGET_ABI_FMT_lx "\n",
                 info->start_data);
        qemu_log("end_data    0x" TARGET_ABI_FMT_lx "\n", info->end_data);
        qemu_log("start_stack 0x" TARGET_ABI_FMT_lx "\n",
                 info->start_stack);
        qemu_log("brk         0x" TARGET_ABI_FMT_lx "\n", info->brk);
        qemu_log("entry       0x" TARGET_ABI_FMT_lx "\n", info->entry);
    }

    target_set_brk(info->start_data, info->brk, info->end_data);
    syscall_init();
    signal_init();

#if defined(CONFIG_USE_GUEST_BASE)
    /* Now that we've loaded the binary, GUEST_BASE is fixed.  Delay
       generating the prologue until now so that the prologue can take
       the real value of GUEST_BASE into account.  */
    tcg_prologue_init(&tcg_ctx);
#endif

    /* build Task State */
    memset(ts, 0, sizeof(TaskState));
    init_task_state(ts);
    ts->info = info;
    ts->bprm = &bprm;
    env->opaque = ts;

#if defined(TARGET_I386)
    cpu_x86_set_cpl(env, 3);

    env->cr[0] = CR0_PG_MASK | CR0_WP_MASK | CR0_PE_MASK;
    env->hflags |= HF_PE_MASK;
    if (env->cpuid_features & CPUID_SSE) {
        env->cr[4] |= CR4_OSFXSR_MASK;
        env->hflags |= HF_OSFXSR_MASK;
    }
#ifndef TARGET_ABI32
    /* enable 64 bit mode if possible */
    if (!(env->cpuid_ext2_features & CPUID_EXT2_LM)) {
        fprintf(stderr, "The selected x86 CPU does not support 64 bit mode\n");
        exit(1);
    }
    env->cr[4] |= CR4_PAE_MASK;
    env->efer |= MSR_EFER_LMA | MSR_EFER_LME;
    env->hflags |= HF_LMA_MASK;
#endif

    /* flags setup : we activate the IRQs by default as in user mode */
    env->eflags |= IF_MASK;

    /* linux register setup */
#ifndef TARGET_ABI32
    env->regs[R_EAX] = regs->rax;
    env->regs[R_EBX] = regs->rbx;
    env->regs[R_ECX] = regs->rcx;
    env->regs[R_EDX] = regs->rdx;
    env->regs[R_ESI] = regs->rsi;
    env->regs[R_EDI] = regs->rdi;
    env->regs[R_EBP] = regs->rbp;
    env->regs[R_ESP] = regs->rsp;
    env->eip = regs->rip;
#else
    env->regs[R_EAX] = regs->eax;
    env->regs[R_EBX] = regs->ebx;
    env->regs[R_ECX] = regs->ecx;
    env->regs[R_EDX] = regs->edx;
    env->regs[R_ESI] = regs->esi;
    env->regs[R_EDI] = regs->edi;
    env->regs[R_EBP] = regs->ebp;
    env->regs[R_ESP] = regs->esp;
    env->eip = regs->eip;
#endif

    /* linux interrupt setup */
#ifndef TARGET_ABI32
    env->idt.limit = 511;
#else
    env->idt.limit = 255;
#endif
    env->idt.base = target_mmap(0, sizeof(uint64_t) * (env->idt.limit + 1),
                                PROT_READ|PROT_WRITE,
                                MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    idt_table = g2h(env->idt.base);
    set_idt(0, 0);
    set_idt(1, 0);
    set_idt(2, 0);
    set_idt(3, 3);
    set_idt(4, 3);
    set_idt(5, 0);
    set_idt(6, 0);
    set_idt(7, 0);
    set_idt(8, 0);
    set_idt(9, 0);
    set_idt(10, 0);
    set_idt(11, 0);
    set_idt(12, 0);
    set_idt(13, 0);
    set_idt(14, 0);
    set_idt(15, 0);
    set_idt(16, 0);
    set_idt(17, 0);
    set_idt(18, 0);
    set_idt(19, 0);
    set_idt(0x80, 3);

    /* linux segment setup */
    {
        uint64_t *gdt_table;
        env->gdt.base = target_mmap(0, sizeof(uint64_t) * TARGET_GDT_ENTRIES,
                                    PROT_READ|PROT_WRITE,
                                    MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
        env->gdt.limit = sizeof(uint64_t) * TARGET_GDT_ENTRIES - 1;
        gdt_table = g2h(env->gdt.base);
#ifdef TARGET_ABI32
        write_dt(&gdt_table[__USER_CS >> 3], 0, 0xfffff,
                 DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
                 (3 << DESC_DPL_SHIFT) | (0xa << DESC_TYPE_SHIFT));
#else
        /* 64 bit code segment */
        write_dt(&gdt_table[__USER_CS >> 3], 0, 0xfffff,
                 DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
                 DESC_L_MASK |
                 (3 << DESC_DPL_SHIFT) | (0xa << DESC_TYPE_SHIFT));
#endif
        write_dt(&gdt_table[__USER_DS >> 3], 0, 0xfffff,
                 DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
                 (3 << DESC_DPL_SHIFT) | (0x2 << DESC_TYPE_SHIFT));
    }

    cpu_x86_load_seg(env, R_CS, __USER_CS);
    cpu_x86_load_seg(env, R_SS, __USER_DS);
#ifdef TARGET_ABI32
    cpu_x86_load_seg(env, R_DS, __USER_DS);
    cpu_x86_load_seg(env, R_ES, __USER_DS);
    cpu_x86_load_seg(env, R_FS, __USER_DS);
    cpu_x86_load_seg(env, R_GS, __USER_DS);
    /* This hack makes Wine work... */
    env->segs[R_FS].selector = 0;
#else
    cpu_x86_load_seg(env, R_DS, 0);
    cpu_x86_load_seg(env, R_ES, 0);
    cpu_x86_load_seg(env, R_FS, 0);
    cpu_x86_load_seg(env, R_GS, 0);
#endif
#elif defined(TARGET_SPARC)
    {
        int i;
        env->pc = regs->pc;
        env->npc = regs->npc;
        env->y = regs->y;
        for(i = 0; i < 8; i++)
            env->gregs[i] = regs->u_regs[i];
        for(i = 0; i < 8; i++)
            env->regwptr[i] = regs->u_regs[i + 8];
    }
#elif defined(TARGET_ARM)
    {
        int i;
        cpsr_write(env, regs->uregs[16], 0xffffffff);
        for (i = 0; i < 16; i++) {
                env->regs[i] = regs->uregs[i];
        }
    }
#elif defined(TARGET_MIPS)
    {
	int i;
	for(i = 0; i < 32; i++) {
		env->active_tc.gpr[i] = regs->regs[i];
	}
	env->active_tc.PC = regs->cp0_epc & ~(target_ulong)1;
	if (regs->cp0_epc & 1) {
		env->hflags |= MIPS_HFLAG_M16;
	}
#if defined(TARGET_MIPS64)
	env->hflags |= MIPS_HFLAG_UX | MIPS_HFLAG_64;
#endif
    }
#else
#error unsupported target CPU
#endif

    if (gdbstub_port) {
        gdbserver_start (gdbstub_port);
        gdb_handlesig(env, 0);
    }
    cpu_loop(env);
    /* never exits */
    return 0;
}
