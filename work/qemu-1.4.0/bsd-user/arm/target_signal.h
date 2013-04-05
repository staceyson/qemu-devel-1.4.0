#ifndef TARGET_SIGNAL_H
#define TARGET_SIGNAL_H

#include "cpu.h"

#define	TARGET_REG_R0	0
#define	TARGET_REG_R1	1
#define	TARGET_REG_R2	2
#define	TARGET_REG_R3	3
#define	TARGET_REG_R4	4
#define	TARGET_REG_R5	5
#define	TARGET_REG_R6	6
#define	TARGET_REG_R7	7
#define	TARGET_REG_R8	8
#define	TARGET_REG_R9	9
#define	TARGET_REG_R10	10
#define	TARGET_REG_R11	11
#define	TARGET_REG_R12	12
#define	TARGET_REG_R13	13
#define	TARGET_REG_R14	14
#define	TARGET_REG_R15	15
#define	TARGET_REG_CPSR	16
/* Convenience synonyms */
#define	TARGET_REG_FP	TARGET_REG_R11
#define	TARGET_REG_SP	TARGET_REG_R13
#define	TARGET_REG_LR	TARGET_REG_R14
#define	TARGET_REG_PC	TARGET_REG_R15

#define	TARGET_MINSIGSTKSZ	(1024 * 4)
#define	TARGET_SIGSTKSZ		(TARGET_MINSIGSTKSZ + 32768)
#define	TARGET__NGREG		17

typedef struct {
	uint32_t	__fp_fpsr;
	struct {
		uint32_t	__fp_exponent;
		uint32_t	__fp_mantissa_hi;
		uint32_t	__fp_mantissa_lo;
	} 		__fp_fr[8];
} target__fpregset_t;

typedef struct {
	uint32_t	__vfp_fpscr;
	uint32_t	__vfp_fstmx[33];
	uint32_t	__vfp_fpsid;
} target__vfpregset_t;

typedef struct {
	uint32_t		__gregs[TARGET__NGREG];
	union {
		target__fpregset_t	__fpregs;
		target__vfpregset_t	__vfpregs;
	} __fpu;
} target_mcontext_t;

typedef struct target_ucontext {
	target_sigset_t		uc_sigmask;
	target_mcontext_t	uc_mcontext;
	abi_ulong		uc_link;
	target_stack_t		uc_stack;
	int32_t			uc_flags;
	int32_t			__spare__[4];
} target_ucontext_t;

struct target_sigframe {
	target_siginfo_t	sf_si;	/* saved siginfo */
	target_ucontext_t	sf_uc;	/* saved ucontext */
};

/* compare to sys/arm/include/frame.h */
typedef struct target_trapframe {
	abi_ulong tf_spsr; /* Zero on arm26 */
	abi_ulong tf_r0;
	abi_ulong tf_r1;
	abi_ulong tf_r2;
	abi_ulong tf_r3;
	abi_ulong tf_r4;
	abi_ulong tf_r5;
	abi_ulong tf_r6;
	abi_ulong tf_r7;
	abi_ulong tf_r8;
	abi_ulong tf_r9;
	abi_ulong tf_r10;
	abi_ulong tf_r11;
	abi_ulong tf_r12;
	abi_ulong tf_usr_sp;
	abi_ulong tf_usr_lr;
	abi_ulong tf_svc_sp; /* Not used on arm26 */
	abi_ulong tf_svc_lr; /* Not used on arm26 */
	abi_ulong tf_pc;
} target_trapframe_t;

#define	TARGET_SZSIGCODE	(8 * 4)

/* Compare to arm/arm/locore.S ENTRY_NP(sigcode) */
static inline int
install_sigtramp(abi_ulong offset, unsigned sigf_us, uint32_t sys_sigreturn)
{
	int i;
	uint32_t sys_exit = TARGET_FREEBSD_NR_exit;
	/*
	 * The code has to load r7 manually rather than using
	 * "ldr r7, =SYS_return to make sure the size of the
	 * code is correct.
	 */
	uint32_t sigtramp_code[] = {
	/* 1 */	0xE1A0000D,			/* mov r0, sp */
	/* 2 */	0xE59F700C,			/* ldr r7, [pc, #12] */
	/* 3 */	0xEF000000 + sys_sigreturn,	/* swi (SYS_sigreturn) */
	/* 4 */	0xE59F7008,			/* ldr r7, [pc, #8] */
	/* 5 */	0xEF000000 + sys_exit, 		/* swi (SYS_exit)*/
	/* 6 */	0xEAFFFFFA,			/* b . -16 */
	/* 7 */	sys_sigreturn,
	/* 8 */	sys_exit
	};

	for(i = 0; i < 8; i++)
		tswap32s(&sigtramp_code[i]);

	return(memcpy_to_target(offset, sigtramp_code, TARGET_SZSIGCODE));
}

static inline abi_ulong
get_sp_from_cpustate(CPUARMState *state)
{
    return state->regs[13]; /* sp */
}

/*
 * Compare to arm/arm/machdep.c sendsig()
 * Assumes that the target stack frame memory is locked.
 */
static inline abi_ulong
set_sigtramp_args(CPUARMState *regs, int sig, struct target_sigframe *frame,
    abi_ulong frame_addr, struct target_sigaction *ka)
{
	/*
	 * Arguments to signal handler:
	 * 	r0 = signal number
	 * 	r1 = siginfo pointer
	 * 	r2 = ucontext pointer
	 * 	r5 = ucontext pointer
	 * 	pc = signal handler pointer
	 * 	sp = sigframe struct pointer
	 * 	lr = sigtramp at base of user stack
	 */

	regs->regs[0] = sig;
	regs->regs[1] = frame_addr +
	    offsetof(struct target_sigframe, sf_si);
	regs->regs[2] = frame_addr +
	    offsetof(struct target_sigframe, sf_uc);

	/* the trampoline uses r5 as the uc address */
	regs->regs[5] = frame_addr +
	    offsetof(struct target_sigframe, sf_uc);
	regs->regs[TARGET_REG_PC] = ka->_sa_handler;
	regs->regs[TARGET_REG_SP] = frame_addr;
	regs->regs[TARGET_REG_LR] = TARGET_PS_STRINGS - TARGET_SZSIGCODE;

	return (0);
}

/* Compare to arm/arm/machdep.c get_mcontext() */
static inline abi_long
get_mcontext(CPUARMState *regs, target_mcontext_t *mcp, int clear_ret)
{
	int err = 0;
	uint32_t *gr = mcp->__gregs;


	if (clear_ret & TARGET_MC_GET_CLEAR_RET)
		gr[TARGET_REG_R0] = 0;
	else
		gr[TARGET_REG_R0] = tswap32(regs->regs[0]);

	gr[TARGET_REG_R1 ] = tswap32(regs->regs[ 1]);
	gr[TARGET_REG_R2 ] = tswap32(regs->regs[ 2]);
	gr[TARGET_REG_R3 ] = tswap32(regs->regs[ 3]);
	gr[TARGET_REG_R4 ] = tswap32(regs->regs[ 4]);
	gr[TARGET_REG_R5 ] = tswap32(regs->regs[ 5]);
	gr[TARGET_REG_R6 ] = tswap32(regs->regs[ 6]);
	gr[TARGET_REG_R7 ] = tswap32(regs->regs[ 7]);
	gr[TARGET_REG_R8 ] = tswap32(regs->regs[ 8]);
	gr[TARGET_REG_R9 ] = tswap32(regs->regs[ 9]);
	gr[TARGET_REG_R10] = tswap32(regs->regs[10]);
	gr[TARGET_REG_R11] = tswap32(regs->regs[11]);
	gr[TARGET_REG_R12] = tswap32(regs->regs[12]);

	gr[TARGET_REG_SP] = tswap32(regs->regs[13]);
	gr[TARGET_REG_LR] = tswap32(regs->regs[14]);
	gr[TARGET_REG_PC] = tswap32(regs->regs[15]);
	gr[TARGET_REG_CPSR] = tswap32(cpsr_read(regs));

	return (err);
}

/* Compare to arm/arm/machdep.c set_mcontext() */
static inline abi_long
set_mcontext(CPUARMState *regs, target_mcontext_t *mcp, int srflag)
{
	int err = 0;
	const uint32_t *gr = mcp->__gregs;
	uint32_t cpsr;

	regs->regs[ 0] = tswap32(gr[TARGET_REG_R0 ]);
	regs->regs[ 1] = tswap32(gr[TARGET_REG_R1 ]);
	regs->regs[ 2] = tswap32(gr[TARGET_REG_R2 ]);
	regs->regs[ 3] = tswap32(gr[TARGET_REG_R3 ]);
	regs->regs[ 4] = tswap32(gr[TARGET_REG_R4 ]);
	regs->regs[ 5] = tswap32(gr[TARGET_REG_R5 ]);
	regs->regs[ 6] = tswap32(gr[TARGET_REG_R6 ]);
	regs->regs[ 7] = tswap32(gr[TARGET_REG_R7 ]);
	regs->regs[ 8] = tswap32(gr[TARGET_REG_R8 ]);
	regs->regs[ 9] = tswap32(gr[TARGET_REG_R9 ]);
	regs->regs[10] = tswap32(gr[TARGET_REG_R10]);
	regs->regs[11] = tswap32(gr[TARGET_REG_R11]);
	regs->regs[12] = tswap32(gr[TARGET_REG_R12]);

	regs->regs[13] = tswap32(gr[TARGET_REG_SP]);
	regs->regs[14] = tswap32(gr[TARGET_REG_LR]);
	regs->regs[15] = tswap32(gr[TARGET_REG_PC]);
	cpsr = tswap32(gr[TARGET_REG_CPSR]);
	cpsr_write(regs, cpsr, CPSR_USER | CPSR_EXEC);

	return (err);
}

/* Compare to arm/arm/machdep.c sys_sigreturn() */
static inline abi_long
get_ucontext_sigreturn(CPUARMState *regs, abi_ulong sf_addr,
    target_ucontext_t **ucontext, void **locked_addr)
{
	struct target_sigframe *sf;
	uint32_t cpsr = cpsr_read(regs);

	if ((cpsr & CPSR_M) != ARM_CPU_MODE_USR ||
	    (cpsr & (CPSR_I | CPSR_F)) != 0)
		return (-TARGET_EINVAL);

	if (!lock_user_struct(VERIFY_READ, sf, sf_addr, 0))
		return (-TARGET_EFAULT);

	*locked_addr = sf;
	*ucontext = (target_ucontext_t *)g2h(tswapal(sf_addr +
		offsetof(struct target_sigframe, sf_uc)));
	return (0);
}

/* Compare to arm/arm/vm_machdep.c cpu_set_upcall_kse() */
/* XXX crashes on first shared lib call */
static inline void
thread_set_upcall(CPUARMState *regs, abi_ulong entry, abi_ulong arg,
    abi_ulong stack_base, abi_ulong stack_size)
{
	abi_ulong sp;

	sp = ((stack_base + stack_size) & (8 - 1)) - sizeof(struct target_trapframe);

	/* fp = sp = stack base */
	regs->regs[11] = regs->regs[13] = sp;
	/* pc = start function entry */
	regs->regs[15] = regs->regs[14] = entry & 0xfffffffe;
	/* r0 = arg */
	regs->regs[0] = arg;
}

#endif /* TARGET_SIGNAL_H */
