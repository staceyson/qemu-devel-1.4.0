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

#define	TARGET_GET_MC_CLEAR_RET	1

static inline abi_ulong get_sp_from_cpustate(CPUARMState *state)
{
    return state->regs[13];
}

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

/* Compare to arm/arm/machdep.c get_mcontext() */
static inline int
get_mcontext(CPUARMState *regs, target_mcontext_t *mcp, int clear_ret)
{
	int i, err = 0;
	uint32_t *gr = mcp->__gregs;


	if (clear_ret & TARGET_GET_MC_CLEAR_RET)
		gr[TARGET_REG_R0] = 0;
	else
		gr[TARGET_REG_R0] = tswap32(regs->regs[0]);
	for(i = 1; i < 12; i++)
		gr[i] = tswap32(regs->regs[i]);
	gr[TARGET_REG_SP] = tswap32(regs->regs[13]);
	gr[TARGET_REG_LR] = tswap32(regs->regs[14]);
	gr[TARGET_REG_PC] = tswap32(regs->regs[15]);
	gr[TARGET_REG_CPSR] = tswap32(regs->spsr);

	return (err);
}

/* Compare to arm/arm/machdep.c set_mcontext() */
static inline int
set_mcontext(CPUARMState *regs, target_mcontext_t *mcp, int flags)
{
	int i, err = 0;
	const uint32_t *gr = mcp->__gregs;

	for(i = 0; i < 12; i++)
		regs->regs[i] =  tswap32(gr[i]);
	regs->regs[13] = tswap32(gr[TARGET_REG_SP]);
	regs->regs[14] = tswap32(gr[TARGET_REG_LR]);
	regs->regs[15] = tswap32(gr[TARGET_REG_PC]);
	regs->spsr = tswap32(gr[TARGET_REG_CPSR]);

	return (err);
}

#endif /* TARGET_SIGNAL_H */
