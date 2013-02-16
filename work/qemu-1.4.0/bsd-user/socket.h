/*
 * Target socket definitions.
 */

/*
 * Types
 */
#define	TARGET_SOCK_STREAM	1	/* stream socket */
#define	TARGET_SOCK_DGRAM	2	/* datagram socket */
#define	TARGET_SOCK_RAW		3	/* raw-protocol interface */
#define	TARGET_SOCK_RDM		4	/* reliably-delivered message */
#define	TARGET_SOCK_SEQPACKET	5	/* sequenced packet stream */


/*
 * Option flags per-socket.
 */

#define	TARGET_SO_DEBUG		0x0001	/* turn on debugging info recording */
#define	TARGET_SO_ACCEPTCONN	0x0002	/* socket has had listen() */
#define	TARGET_SO_REUSEADDR	0x0004	/* allow local address reuse */
#define	TARGET_SO_KEEPALIVE	0x0008	/* keep connections alive */
#define	TARGET_SO_DONTROUTE	0x0010	/* just use interface addresses */
#define	TARGET_SO_BROADCAST	0x0020	/* permit sending of broadcast msgs */
#define	TARGET_SO_USELOOPBACK	0x0040	/* bypass hardware when possible */
#define	TARGET_SO_LINGER	0x0080	/* linger on close if data present */
#define	TARGET_SO_OOBINLINE	0x0100	/* leave received OOB data in line */
#define	TARGET_SO_REUSEPORT	0x0200	/* allow local address & port reuse */
#define	TARGET_SO_TIMESTAMP	0x0400	/* timestamp received dgram traffic */
#define	TARGET_SO_NOSIGPIPE	0x0800	/* no SIGPIPE from EPIPE */
#define	TARGET_SO_ACCEPTFILTER	0x1000	/* there is an accept filter */
#define	TARGET_SO_BINTIME	0x2000	/* timestamp received dgram traffic */
#define	TARGET_SO_NO_OFFLOAD	0x4000	/* socket cannot be offloaded */
#define	TARGET_SO_NO_DDP	0x8000	/* disable direct data placement */

/*
 * Additional options, not kept in so_options.
 */
#define	TARGET_SO_SNDBUF	0x1001	/* send buffer size */
#define	TARGET_SO_RCVBUF	0x1002	/* receive buffer size */
#define	TARGET_SO_SNDLOWAT	0x1003	/* send low-water mark */
#define	TARGET_SO_RCVLOWAT	0x1004	/* receive low-water mark */
#define	TARGET_SO_SNDTIMEO	0x1005	/* send timeout */
#define	TARGET_SO_RCVTIMEO	0x1006	/* receive timeout */
#define	TARGET_SO_ERROR		0x1007	/* get error status and clear */
#define	TARGET_SO_TYPE		0x1008	/* get socket type */
#define	TARGET_SO_LABEL		0x1009	/* socket's MAC label */
#define	TARGET_SO_PEERLABEL	0x1010	/* socket's peer's MAC label */
#define	TARGET_SO_LISTENQLIMIT	0x1011	/* socket's backlog limit */
#define	TARGET_SO_LISTENQLEN	0x1012	/* socket's complete queue length */
#define	TARGET_SO_LISTENINCQLEN	0x1013	/* socket's incomplete queue length */
#define	TARGET_SO_SETFIB	0x1014	/* use this FIB to route */
#define	TARGET_SO_USER_COOKIE	0x1015	/* user cookie (dummynet etc.) */
#define	TARGET_SO_PROTOCOL	0x1016	/* get socket protocol (Linux name) */

/* alias for SO_PROTOCOL (SunOS name) */
#define	TARGET_SO_PROTOTYPE    	TARGET_SO_PROTOCOL

/*
 * Level number for (get/set)sockopt() to apply to socket itself.
 */
#define	TARGET_SOL_SOCKET	0xffff	/* options for socket level */

#ifndef CMSG_ALIGN
#define CMSG_ALIGN(len) ( ((len)+sizeof(long)-1) & ~(sizeof(long)-1) )
#endif
