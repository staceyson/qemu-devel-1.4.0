#ifndef TARGET_SIGNAL_H
#define TARGET_SIGNAL_H

#include "cpu.h"

#ifndef UREG_I6
#define UREG_I6        6
#endif
#ifndef UREG_FP
#define UREG_FP        UREG_I6
#endif

#define	mc_flags	mc_global[0]
#define	mc_sp		mc_out[6]
#define	mc_fprs		mc_local[0]
#define	mc_fsr		mc_local[1]
#define	mc_gsr		mc_local[2]
#define	mc_tnpc		mc_in[0]
#define	mc_tpc		mc_in[1]
#define	mc_tstate	mc_in[2]
#define	mc_y		mc_in[4]
#define	mc_wstate	mc_in[5]

#define ureg_i0		regwptr[0 ]
#define	ureg_i1		regwptr[1 ]
#define	ureg_i2		regwptr[2 ]
#define	ureg_i3		regwptr[3 ]
#define	ureg_i4		regwptr[4 ]
#define	ureg_i5		regwptr[5 ]
#define	ureg_i6		regwptr[6 ]
#define	ureg_i7		regwptr[7 ]
#define	ureg_l0		regwptr[8 ]
#define	ureg_l1		regwptr[9 ]
#define	ureg_l2		regwptr[10]
#define	ureg_l3		regwptr[11]
#define	ureg_l4		regwptr[12]
#define	ureg_l5		regwptr[13]
#define	ureg_l6		regwptr[14]
#define	ureg_l7		regwptr[15]
#define	ureg_o0		regwptr[16]
#define	ureg_o1		regwptr[17]
#define	ureg_o2		regwptr[18]
#define	ureg_o3		regwptr[19]
#define	ureg_o4		regwptr[20]
#define	ureg_o5		regwptr[21]
#define	ureg_o6		regwptr[22]
#define	ureg_o7		regwptr[23]
#define	ureg_fp		ureg_i6
#define	ureg_sp		ureg_o6
#define	ureg_fprs	fprs
#define	ureg_fsr	fsr
#define	ureg_gsr	gsr
#define	ureg_tnpc	npc
#define	ureg_tpc	pc
#define	ureg_y		y

#define TARGET_FPRS_FEF (1 << 2)
#define TARGET_MC_VERSION 1L

#define	TARGET_MINSIGSTKSZ	(1024 * 4)
#define	TARGET_SIGSTKSZ		(TARGET_MINSIGSTKSZ + 32768)

#define	TARGET_STACK_BIAS	2047	/* AKA. SPOFF */

struct target_mcontext {
	uint64_t mc_global[8];
	uint64_t mc_out[8];
	uint64_t mc_local[8];
	uint64_t mc_in[8];
	uint32_t mc_fp[64];
} __aligned(64);

typedef struct target_mcontext target_mcontext_t;

typedef struct target_ucontext {
	target_sigset_t		uc_sigmask;
	target_mcontext_t	uc_mcontext;
	abi_ulong		uc_link;
	target_stack_t		uc_stack;
	int32_t			uc_flags;
	int32_t			__spare__[4];
} target_ucontext_t;

struct target_sigframe {
	target_ucontext_t	sf_uc;
	target_siginfo_t	sf_si;
};

extern abi_ulong sparc_user_sigtramp;

static inline int
set_sigtramp_args(CPUSPARCState *regs, int sig, struct target_sigframe *frame,
        abi_ulong frame_addr, struct target_sigaction *ka)
{

	frame->sf_si.si_signo = sig;
	frame->sf_si.si_code = TARGET_SA_SIGINFO;

	/* Arguments to signal handler:
	 *
	 * i0 = signal number
	 * i1 = pointer to siginfo struct
	 * i2 = pointer to ucontext struct
	 * i3 = (not used in new style)
	 * i4 = signal handler address (called by sigtramp)
	 */
	regs->ureg_i0 = sig;
	regs->ureg_i1 = frame_addr +
	    offsetof(struct target_sigframe, sf_si);
	regs->ureg_i2 = frame_addr +
	    offsetof(struct target_sigframe, sf_uc);
	/* env->ureg_o3 used in the Old FreeBSD-style arguments. */
	regs->ureg_i4 = ka->_sa_handler;
	regs->ureg_tpc = sparc_user_sigtramp;
	regs->ureg_tnpc = (regs->ureg_tpc + 4);
	regs->ureg_sp = frame_addr - TARGET_STACK_BIAS;

	return (0);
}

static inline abi_ulong
get_sp_from_cpustate(CPUSPARCState *state)
{

    return state->regwptr[UREG_FP];
}

/* compare to sparc64/sparc64/machdep.c get_mcontext() */
static inline int
get_mcontext(CPUSPARCState *regs, target_mcontext_t *mcp, int flags)
{

	/* Skip over the trap instruction, first. */
	regs->pc = regs->npc;
	regs->npc += 4;

	mcp->mc_flags = TARGET_MC_VERSION;	/* mc_global[0] */
	mcp->mc_global[1] = tswapal(regs->gregs[1]);
	mcp->mc_global[2] = tswapal(regs->gregs[2]);
	mcp->mc_global[3] = tswapal(regs->gregs[3]);
	mcp->mc_global[4] = tswapal(regs->gregs[4]);
	mcp->mc_global[5] = tswapal(regs->gregs[5]);
	mcp->mc_global[6] = tswapal(regs->gregs[6]);
	/* skip %g7 since it is used as the userland TLS register */

	if (flags & TARGET_MC_GET_CLEAR_RET) {
		mcp->mc_out[0] = 0;
		mcp->mc_out[1] = 0;
	} else {
		mcp->mc_out[0] = tswapal(regs->ureg_i0);
		mcp->mc_out[1] = tswapal(regs->ureg_i1);
	}
	mcp->mc_out[2] = tswapal(regs->ureg_i2);
	mcp->mc_out[3] = tswapal(regs->ureg_i3);
	mcp->mc_out[4] = tswapal(regs->ureg_i4);
	mcp->mc_out[5] = tswapal(regs->ureg_i5);
	mcp->mc_out[6] = tswapal(regs->ureg_i6);
	mcp->mc_out[7] = tswapal(regs->ureg_i7);

	mcp->mc_fprs = tswapal(regs->fprs);		/* mc_local[0] */
	mcp->mc_fsr = tswapal(regs->fsr);		/* mc_local[1] */
	mcp->mc_gsr = tswapal(regs->gsr);		/* mc_local[2] */

	mcp->mc_tnpc = tswapal(regs->npc);		/* mc_in[0] */
	mcp->mc_tpc = tswapal(regs->pc);		/* mc_in[1] */
#if 0
	mcp->mc_tstate = tswapal(regs->ureg_tstate);	/* mc_in[2] */
#else
	abi_ulong cwp64 = cpu_get_cwp64(regs);
	abi_ulong ccr = cpu_get_ccr(regs) << 32;
	abi_ulong asi = (regs->asi & 0xff) << 24;
	mcp->mc_tstate = tswapal(ccr | asi | cwp64);
#endif

	mcp->mc_y = tswapal(regs->y);			/* mc_in[4] */

	/* XXX
	if ((regs->ureg_l0 & TARGET_FPRS_FEF) != 0) {
		int i;

		for(i = 0; i < 64; i++)
			mcp->mc_fp[i] = tswapal(regs->fpr[i]);
	}
	*/

	return (0);
}

extern void helper_flushw(CPUSPARCState *env);

/* compare to sparc64/sparc64/machdep.c set_mcontext() */
static inline int
set_mcontext(CPUSPARCState *regs, target_mcontext_t *mcp, int flags)
{
	/* XXX need to add version check here. */

	/* Make sure the windows are spilled first. */
	helper_flushw(regs);

	regs->gregs[1] = tswapal(mcp->mc_global[1]);
	regs->gregs[2] = tswapal(mcp->mc_global[2]);
	regs->gregs[3] = tswapal(mcp->mc_global[3]);
	regs->gregs[4] = tswapal(mcp->mc_global[4]);
	regs->gregs[5] = tswapal(mcp->mc_global[5]);
	regs->gregs[6] = tswapal(mcp->mc_global[6]);

	regs->ureg_i0 = tswapal(mcp->mc_out[0]);
	regs->ureg_i1 = tswapal(mcp->mc_out[1]);
	regs->ureg_i2 = tswapal(mcp->mc_out[2]);
	regs->ureg_i3 = tswapal(mcp->mc_out[3]);
	regs->ureg_i4 = tswapal(mcp->mc_out[4]);
	regs->ureg_i5 = tswapal(mcp->mc_out[5]);
	regs->ureg_i6 = tswapal(mcp->mc_out[6]);
	regs->ureg_i7 = tswapal(mcp->mc_out[7]);

	regs->fprs = tswapal(mcp->mc_fprs);		/* mc_local[0] */
	regs->fsr = tswapal(mcp->mc_fsr);		/* mc_local[1] */
	regs->gsr = tswapal(mcp->mc_gsr);		/* mc_local[2] */

	regs->npc = tswapal(mcp->mc_tnpc);		/* mc_in[0] */
	regs->pc = tswapal(mcp->mc_tpc);		/* mc_in[1] */

#if 0
	regs->ureg_tstate = tswapal(mcp->mc_tstate);	/* mc_in[2] */
#else
	abi_ulong tstate = tswapal(mcp->mc_tstate);	/* mc_in[2] */

	regs->asi =  (tstate >> 24) & 0xff;
	cpu_put_ccr(regs, tstate >> 32);
	cpu_put_cwp64(regs, tstate & 0x1f);

#endif
	regs->ureg_y = tswapal(mcp->mc_y);		/* mc_in[4] */

	/* XXX
	if ((regs->ureg_fprs & TARGET_FPRS_FEF) != 0) {
		int i;

		regs->ureg_l0 = 0;
		for(i = 0; i < 64; i++)
			regs->fpr[i] = tswapal(mcp->mc_fp[i]);
	}
	*/

	return (0);
}

static inline abi_long
get_ucontext_sigreturn(CPUArchState *regs, abi_ulong sf_addr,
        target_ucontext_t **ucontext, void **locked_addr)
{
	fprintf(stderr, "SPARC64 doesn't have support for do_sigreturn()\n");
	return (-TARGET_ENOSYS);
}

/* Compare to arm/arm/vm_machdep.c cpu_set_upcall_kse() */
static inline void
thread_set_upcall(CPUArchState *regs, abi_ulong entry, abi_ulong arg,
        abi_ulong stack_base, abi_ulong stack_size)
{
	fprintf(stderr, "SPARC64 doesn't have support for thread_set_upcall()\n");
}

#endif /* TARGET_SIGNAL_H */
