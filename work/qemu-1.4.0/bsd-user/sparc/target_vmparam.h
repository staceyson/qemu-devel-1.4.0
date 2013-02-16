#ifndef _TARGET_VMPARAM_H_
#define _TARGET_VMPARAM_H_

#define	TARGET_USRSTACK 0

#ifdef __FreeBSD__
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
#endif /* __FreeBSD__ */

#endif /* _TARGET_VMPARAM_H_ */

