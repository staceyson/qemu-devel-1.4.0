#ifndef _TARGET_VMPARAM_H_
#define _TARGET_VMPARAM_H_

#define	TARGET_HW_MACHINE	"sparc"
#define	TARGET_HW_MACHINE_ARCH  "sparc64"

#if defined(__FreeBSD__)

/* compare to amd64/include/vmparam.h */
#define	TARGET_MAXTSIZ	(1*1024*1024*1024)	/* max text size */
#define	TARGET_DFLDSIZ	(128*1024*1024)		/* initial data size limit */
#define	TARGET_MAXDSIZ	(1*1024*1024*1024)	/* max data size */
#define	TARGET_DFLSSIZ	(128*1024*1024)		/* initial stack size limit */
#define	TARGET_MAXSSIZ	(1*1024*1024*1024)	/* max stack size */
#define	TARGET_SGROWSIZ	(128*1024)		/* amount to grow stack */

#define	TARGET_VM_MINUSER_ADDRESS	(0x0000000000000000UL)
#define	TARGET_VM_MAXUSER_ADDRESS	(0x000007fe00000000UL)

#define	TARGET_USRSTACK			TARGET_VM_MAXUSER_ADDRESS

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

#else

#define	TARGET_USRSTACK 0
#endif

#endif /* _TARGET_VMPARAM_H_ */

