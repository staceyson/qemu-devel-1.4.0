#ifndef _TARGET_VMPARAM_H_
#define _TARGET_VMPARAM_H_

#define	TARGET_HW_MACHINE	"mips"
#define	TARGET_HW_MACHINE_ARCH	"mips"

#if defined(__FreeBSD__)
#define	TARGET_VM_MINUSER_ADDRESS	(0x00000000)
#define	TARGET_VM_MAXUSER_ADDRESS	(0x80000000)

#define	TARGET_USRSTACK	(TARGET_VM_MAXUSER_ADDRESS - TARGET_PAGE_SIZE)

struct target_ps_strings {
	abi_ulong ps_argvstr;
	uint32_t ps_nargvstr;
	abi_ulong ps_envstr;
	uint32_t ps_nenvstr;
};

#define TARGET_SPACE_USRSPACE   4096
#define TARGET_ARG_MAX          262144

#define TARGET_PS_STRINGS  (TARGET_USRSTACK - sizeof(struct target_ps_strings))

#define TARGET_SZSIGCODE 0

/* compare to sys/mips/include/vmparam.h */
#define	TARGET_STACK_SIZE	(8UL*1024*1024)		/* initial stack size limit */
#define	TARGET_STACK_SIZE_MAX	(64UL*1024*1024)	/* max stack size limit */


#else

#define	TARGET_USRSTACK 0
#endif


#endif /* _TARGET_VMPARAM_H_ */
