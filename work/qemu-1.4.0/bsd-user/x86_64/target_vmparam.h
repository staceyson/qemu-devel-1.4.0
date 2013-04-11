#ifndef _TARGET_VMPARAM_H_
#define _TARGET_VMPARAM_H_

#define	TARGET_HW_MACHINE	"amd64"
#define	TARGET_HW_MACHINE_ARCH	"amd64"

#if defined(__FreeBSD__)

/* compare to amd64/include/vmparam.h */
#define	TARGET_MAXTSIZ	(128UL*1024*1024)	/* max text size */
#define	TARGET_DFLDSIZ	(32768UL*1024*1024)	/* initial data size limit */
#define	TARGET_MAXDSIZ	(32768UL*1024*1024)	/* max data size */
#define	TARGET_DFLSSIZ	(8UL*1024*1024)		/* initial stack size limit */
#define	TARGET_MAXSSIZ	(512UL*1024*1024)	/* max stack size */
#define	TARGET_SGROWSIZ	(128UL*1024)		/* amount to grow stack */

#define	TARGET_VM_MAXUSER_ADDRESS	(0x0000800000000000UL)

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

#else

#define	TARGET_USRSTACK	 0
#endif

#endif /* _TARGET_VMPARAM_H_ */
