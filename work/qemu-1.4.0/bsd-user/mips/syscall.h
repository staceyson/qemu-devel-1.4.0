
/* this struct defines the way the registers are stored on the
   stack during a system call. */

struct target_pt_regs {
	/* Pad bytes for argument save space on the stack. */
	abi_ulong pad0[6];

	/* Saved main processor registers. */
	abi_ulong regs[32];

	/* Saved special registers. */
	abi_ulong cp0_status;
	abi_ulong lo;
	abi_ulong hi;
	abi_ulong cp0_badvaddr;
	abi_ulong cp0_cause;
	abi_ulong cp0_epc;
};

#define UNAME_MACHINE "mips"
