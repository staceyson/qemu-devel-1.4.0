#ifndef TARGET_SIGNAL_H
#define TARGET_SIGNAL_H

#include "cpu.h"

#ifndef UREG_I6
#define UREG_I6        6
#endif
#ifndef UREG_FP
#define UREG_FP        UREG_I6
#endif

#define	TARGET_MINSIGSTKSZ	(512 * 4)
#define	TARGET_SIGSTKSZ		(TARGET_MINSIGSTKSZ + 32768)

typedef target_ulong target_mcontext_t; /* dummy */

typedef struct target_ucontext {
	target_sigset_t		uc_sigmask;
	target_mcontext_t	uc_mcontext;
	abi_ulong		uc_link;
	target_stack_t		uc_stack;
	int32_t			uc_flags;
	int32_t			__spare__[4];
} target_ucontext_t;

static inline abi_ulong get_sp_from_cpustate(CPUSPARCState *state)
{
    return state->regwptr[UREG_FP];
}

static inline int
get_mcontext(CPUArchState *regs, target_mcontext_t *mcp, int flags)
{
	fprintf(stderr, "SPARC doesn't have support for get_mcontext()\n");
	return (-TARGET_ENOSYS);
}

static inline int
set_mcontext(CPUArchState *regs, target_mcontext_t *mcp, int flags)
{
	fprintf(stderr, "SPARC doesn't have support for set_mcontext()\n");
	return (-TARGET_ENOSYS);
}

#endif /* TARGET_SIGNAL_H */
