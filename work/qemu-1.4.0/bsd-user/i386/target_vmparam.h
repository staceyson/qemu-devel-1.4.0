#ifndef _TARGET_VMPARAM_H_
#define _TARGET_VMPARAM_H_

#define	TARGET_HW_MACHINE	"i386"
#define	TARGET_HW_MACHINE_ARCH	"i386"

#if defined(__FreeBSD__)

#define	TARGET_USRSTACK	(0xbfc00000)

struct target_ps_strings {
	abi_ulong ps_argvstr;
	uint32_t ps_nargvstr;
	abi_ulong ps_envstr;
	uint32_t ps_nenvstr;
};

#define TARGET_SPACE_USRSPACE 	4096
#define	TARGET_ARG_MAX		262144

#define TARGET_PS_STRINGS  (TARGET_USRSTACK - sizeof(struct target_ps_strings))

#define TARGET_SZSIGCODE 0

/* Make stack size large enough to hold everything. */
#define TARGET_STACK_SIZE ((x86_stack_size < MAX_ARG_PAGES*TARGET_PAGE_SIZE) ? \
    MAX_ARG_PAGES*TARGET_PAGE_SIZE : x86_stack_size)

#else

#define	TARGET_USRSTACK	 0
#endif

#endif /* _TARGET_VMPARAM_H_ */
