#ifndef TARGET_SIGNAL_H
#define TARGET_SIGNAL_H

#include "cpu.h"

#define	TARGET_MINSIGSTKSZ	(512 * 4)
#define	TARGET_SIGSTKSZ		(TARGET_MINSIGSTKSZ + 32768)

/* compare to sys/mips/include/asm.h */
#define	TARGET_SZREG		4
#define	TARGET_CALLFRAME_SIZ	(TARGET_SZREG * 4)

struct target_sigcontext {
	target_sigset_t	sc_mask;        /* signal mask to retstore */
	int32_t		sc_onstack;     /* sigstack state to restore */
	abi_long	sc_pc;          /* pc at time of signal */
	abi_long	sc_reg[32];     /* processor regs 0 to 31 */
	abi_long	mullo, mulhi;   /* mullo and mulhi registers */
	int32_t		sc_fpused;      /* fp has been used */
	abi_long	sc_fpregs[33];  /* fp regs 0 to 31 & csr */
	abi_long	sc_fpc_eir;     /* fp exception instr reg */
	/* int32_t reserved[8]; */
};

typedef struct target_mcontext {
	int32_t		mc_onstack;    /* sigstack state to restore */
	abi_long	mc_pc;         /* pc at time of signal */
	abi_long	mc_regs[32];   /* process regs 0 to 31 */
	abi_long	sr;             /* status register */
	abi_long	mullo, mulhi;
	int32_t		mc_fpused;     /* fp has been used */
	abi_long	mc_fpregs[33]; /* fp regs 0 to 32 & csr */
	abi_long	mc_fpc_eir;    /* fp exception instr reg */
	abi_ulong	mc_tls;        /* pointer to TLS area */
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
	abi_ulong	sf_signum;
	abi_ulong	sf_siginfo;	/* code or pointer to sf_si */
	abi_ulong	sf_ucontext;	/* points to sf_uc */
	abi_ulong	sf_addr;	/* undocumented 4th arg */
	target_ucontext_t	sf_uc;	/* = *sf_uncontext */
	target_siginfo_t	sf_si;	/* = *sf_siginfo (SA_SIGINFO case)*/
	uint32_t	__spare__[2];
};


/* Get the stack pointer. */
static inline abi_ulong
get_sp_from_cpustate(CPUMIPSState *state)
{
    return state->active_tc.gpr[29];
}

/*
 * Compare to mips/mips/pm_machdep.c sendsig()
 * Assumes that "frame" memory is locked.
 */
static inline abi_long
set_sigtramp_args(CPUMIPSState *regs, int sig, struct target_sigframe *frame,
    abi_ulong frame_addr, struct target_sigaction *ka)
{

	frame->sf_signum = sig;
	frame->sf_siginfo = 0;
	frame->sf_ucontext = 0;

	frame->sf_si.si_signo = sig;
	frame->sf_si.si_code = TARGET_SA_SIGINFO;
	frame->sf_si.si_addr = regs->CP0_BadVAddr;

	/*
	 * Arguments to signal handler:
	 * 	a0 ($4) = signal number
	 * 	a1 ($5) = siginfo pointer
	 * 	a2 ($6) = ucontext pointer
	 * 	PC = signal handler pointer
	 * 	t9 ($25) = signal handler pointer
	 * 	$29 = point to sigframe struct
	 * 	ra ($31) = sigtramp at base of user stack
	 */
	regs->active_tc.gpr[ 4] = sig;
	regs->active_tc.gpr[ 5] = frame_addr +
	    offsetof(struct target_sigframe, sf_si);
	regs->active_tc.gpr[25] = regs->active_tc.PC = ka->_sa_handler;
	regs->active_tc.gpr[29] = frame_addr;
	regs->active_tc.gpr[31] = TARGET_PS_STRINGS - TARGET_SZSIGCODE;

	return (0);
}

/*
 * Compare to mips/mips/pm_machdep.c get_mcontext()
 * Assumes that the memory is locked if mcp points to user memory.
 */
static inline abi_long
get_mcontext(CPUMIPSState *regs, target_mcontext_t *mcp, int flags)
{
	int i, err = 0;

	if (flags & TARGET_MC_ADD_MAGIC) {
		mcp->mc_regs[0] = tswapal(TARGET_UCONTEXT_MAGIC);
	} else {
		mcp->mc_regs[0] = 0;
	}

	if (flags & TARGET_MC_SET_ONSTACK) {
		mcp->mc_onstack = tswapal(1);
	} else {
		mcp->mc_onstack = 0;
	}

	for(i = 1; i < 32; i++)
		mcp->mc_regs[i] = tswapal(regs->active_tc.gpr[i]);

#if 0 /* XXX FP is not used right now. */
	abi_ulong used_fp = used_math() ? TARGET_MDTD_FPUSED : 0;

	mcp->mc_fpused = used_fp;
	if (used_fp) {
		preempt_disable();
		if (!is_fpu_owner()) {
			own_fpu();
			for(i = 0; i < 33; i++)
				mcp->mc_fpregs[i] = tswapal(regs->active_fpu.fpr[i]);
		}
		preempt_enable();
	}
#else
	mcp->mc_fpused = 0;
#endif

	if (flags & TARGET_MC_GET_CLEAR_RET) {
		mcp->mc_regs[2] = 0;	/* v0 = 0 */
		mcp->mc_regs[3] = 0;	/* v1 = 0 */
		mcp->mc_regs[7] = 0;	/* a3 = 0 */
	}

	mcp->mc_pc = tswapal(regs->active_tc.PC);
	mcp->mullo = tswapal(regs->active_tc.LO[0]);
	mcp->mulhi = tswapal(regs->active_tc.HI[0]);
	mcp->mc_tls = tswapal(regs->tls_value);

	/* Don't do any of the status and cause registers. */

	return (err);
}

/* Compare to mips/mips/pm_machdep.c set_mcontext() */
static inline abi_long
set_mcontext(CPUMIPSState *regs, target_mcontext_t *mcp, int srflag)
{
	int i, err = 0;

	for(i = 1; i < 32; i++)
		regs->active_tc.gpr[i] = tswapal(mcp->mc_regs[i]);

#if 0  /* XXX FP is not used right now */
	abi_ulong used_fp = 0;

	used_fp = tswapal(mcp->mc_fpused)
	conditional_used_math(used_fp);

	preempt_disabled();
	if (used_math()) {
		/* restore fpu context if we have used it before */
		own_fpu();
		for (i = 0; i < 32; i++)
			regs->active_fpu.fpr[i] = tswapal(mcp->mc_fpregs[i]);
	} else {
		/* Signal handler may have used FPU.  Give it up. */
		lose_fpu();
	}
	preempt_enable();
#endif

	regs->CP0_EPC = tswapal(mcp->mc_pc);
	regs->active_tc.LO[0] = tswapal(mcp->mullo);
	regs->active_tc.HI[0] = tswapal(mcp->mulhi);
	regs->tls_value = tswapal(mcp->mc_tls);

	if (srflag) {
		/* doing sigreturn() */
		regs->active_tc.PC = regs->CP0_EPC;
		regs->CP0_EPC = 0;  /* XXX  for nested signals ? */
	}

	/* Don't do any of the status and cause registers. */

	return (err);
}

/*  mips/mips/pm_machdep.c sys_sigreturn() */
static inline abi_long
get_ucontext_sigreturn(CPUMIPSState *regs, abi_ulong uc_addr,
    target_ucontext_t **ucontext, void **locked_addr)
{
	if (!lock_user_struct(VERIFY_READ, *ucontext, uc_addr, 0))
		return (-TARGET_EFAULT);

	*locked_addr = *ucontext;
	return (0);
}

/* Compare to mips/mips/vm_machdep.c cpu_set_upcall_kse() */
static inline void
thread_set_upcall(CPUMIPSState *regs, abi_ulong entry,
    abi_ulong arg, abi_ulong stack_base, abi_ulong stack_size)
{
	abi_ulong sp;

	/*
	 * At the point where a function is called, sp must be 8
	 * byte aligned[for compatibility with 64-bit CPUs]
	 * in ``See MIPS Run'' by D. Sweetman, p. 269
	 * align stack
	 */
	sp = ((stack_base + stack_size) & ~0x7) - TARGET_CALLFRAME_SIZ;

	/* t9 = pc = start function entry */
	regs->active_tc.gpr[25] = regs->active_tc.PC = entry;
	/* a0 = arg */
	regs->active_tc.gpr[ 4] = arg;
	/* sp = top of the stack */
	regs->active_tc.gpr[29] = sp;
}

#endif /* TARGET_SIGNAL_H */
