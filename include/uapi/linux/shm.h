#ifndef _UAPI_LINUX_SHM_H_
#define _UAPI_LINUX_SHM_H_

#include <linux/ipc.h>
#include <linux/errno.h>
#ifndef __KERNEL__
#include <unistd.h>
#endif

/*
 * SHMMNI, SHMMAX and SHMALL are default upper limits which can be
 * modified by sysctl. The SHMMAX and SHMALL values have been chosen to
 * be as large possible without facilitating scenarios where userspace
 * causes overflows when adjusting the limits via operations of the form
 * "retrieve current limit; add X; update limit". It is therefore not
 * advised to make SHMMAX and SHMALL any larger. These limits are
 * suitable for both 32 and 64-bit systems.
 */
#define SHMMIN 1			 /* min shared seg size (bytes) */
#define SHMMNI 4096			 /* max num of segs system wide */
#define SHMMAX (ULONG_MAX - (1UL << 24)) /* max shared seg size (bytes) */
#define SHMALL (ULONG_MAX - (1UL << 24)) /* max shm system wide (pages) */
#define SHMSEG SHMMNI			 /* max shared segs per process */

/* Obsolete, used only for backwards compatibility and libc5 compiles */
struct shmid_ds {
	struct ipc_perm		shm_perm;	/* operation perms */
	//共享内存的字节数
	int			shm_segsz;	/* size of segment (bytes) */
	//创建共享内存时设置成0，当进程通过shmat函数attach共享内存时，将时间更新为当前时间。
	__kernel_time_t		shm_atime;	/* last attach time */
	//创建共享内存时设置成0，当进程调用shmdt分离共享内存时，将时间更新成当前时间。
	__kernel_time_t		shm_dtime;	/* last detach time */
	//当创建共享内存时，设置该值为当前时间；当调用IPC_SET操作时，更新该值为当前时间
	__kernel_time_t		shm_ctime;	/* last change time */
	__kernel_ipc_pid_t	shm_cpid;	/* pid of creator */
	__kernel_ipc_pid_t	shm_lpid;	/* pid of last operator */
	//attach该共享内存到其地址空间的进程的个数。
	unsigned short		shm_nattch;	/* no. of current attaches */
	unsigned short 		shm_unused;	/* compatibility */
	void 			*shm_unused2;	/* ditto - used by DIPC */
	void			*shm_unused3;	/* unused */
};

/* Include the definition of shmid64_ds and shminfo64 */
#include <asm/shmbuf.h>

/* permission flag for shmget */
#define SHM_R		0400	/* or S_IRUGO from <linux/stat.h> */
#define SHM_W		0200	/* or S_IWUGO from <linux/stat.h> */

/* mode for attach */
#define	SHM_RDONLY	010000	/* read-only access */
#define	SHM_RND		020000	/* round attach address to SHMLBA boundary */
#define	SHM_REMAP	040000	/* take-over region on attach */
#define	SHM_EXEC	0100000	/* execution access */

/* super user shmctl commands */
#define SHM_LOCK 	11
#define SHM_UNLOCK 	12

/* ipcs ctl commands */
#define SHM_STAT 	13
#define SHM_INFO 	14

/* Obsolete, used only for backwards compatibility */
struct	shminfo {
	int shmmax;
	int shmmin;
	int shmmni;
	int shmseg;
	int shmall;
};

struct shm_info {
	int used_ids;
	__kernel_ulong_t shm_tot;	/* total allocated shm */
	__kernel_ulong_t shm_rss;	/* total resident shm */
	__kernel_ulong_t shm_swp;	/* total swapped shm */
	__kernel_ulong_t swap_attempts;
	__kernel_ulong_t swap_successes;
};


#endif /* _UAPI_LINUX_SHM_H_ */
