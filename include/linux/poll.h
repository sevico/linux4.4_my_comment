#ifndef _LINUX_POLL_H
#define _LINUX_POLL_H


#include <linux/compiler.h>
#include <linux/ktime.h>
#include <linux/wait.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/sysctl.h>
#include <asm/uaccess.h>
#include <uapi/linux/poll.h>

extern struct ctl_table epoll_table[]; /* for sysctl */
/* ~832 bytes of stack space used max in sys_select/sys_poll before allocating
   additional memory. */
#define MAX_STACK_ALLOC 832
#define FRONTEND_STACK_ALLOC	256
#define SELECT_STACK_ALLOC	FRONTEND_STACK_ALLOC
#define POLL_STACK_ALLOC	FRONTEND_STACK_ALLOC
#define WQUEUES_STACK_ALLOC	(MAX_STACK_ALLOC - FRONTEND_STACK_ALLOC)
#define N_INLINE_POLL_ENTRIES	(WQUEUES_STACK_ALLOC / sizeof(struct poll_table_entry))

#define DEFAULT_POLLMASK (POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM)

struct poll_table_struct;

/* 
 * structures and helpers for f_op->poll implementations
 */
typedef void (*poll_queue_proc)(struct file *, wait_queue_head_t *, struct poll_table_struct *);

/*
 * Do not touch the structure directly, use the access functions
 * poll_does_not_wait() and poll_requested_events() instead.
 */
typedef struct poll_table_struct {
	// 向wait_queue_head 添加回调节点(wait_queue_t)的接口函数
	poll_queue_proc _qproc;
	// 关注的事件掩码, 文件的实现利用此掩码将等待队列传递给_qproc  
	unsigned long _key;
} poll_table;
// 通用的poll_wait 函数, 文件的f_ops->poll 通常会调用此函数  

static inline void poll_wait(struct file * filp, wait_queue_head_t * wait_address, poll_table *p)
{
	if (p && p->_qproc && wait_address)
		// 调用_qproc 在wait_address 上添加节点和回调函数  
		 // 调用 poll_table_struct 上的函数指针向wait_address添加节点, 并设置节点的func  
		 // (如果是select或poll 则是 __pollwait, 如果是 epoll 则是 ep_ptable_queue_proc),
		p->_qproc(filp, wait_address, p);
}

/*
 * Return true if it is guaranteed that poll will not wait. This is the case
 * if the poll() of another file descriptor in the set got an event, so there
 * is no need for waiting.
 */
static inline bool poll_does_not_wait(const poll_table *p)
{
	return p == NULL || p->_qproc == NULL;
}

/*
 * Return the set of events that the application wants to poll for.
 * This is useful for drivers that need to know whether a DMA transfer has
 * to be started implicitly on poll(). You typically only want to do that
 * if the application is actually polling for POLLIN and/or POLLOUT.
 */
static inline unsigned long poll_requested_events(const poll_table *p)
{
	return p ? p->_key : ~0UL;
}

static inline void init_poll_funcptr(poll_table *pt, poll_queue_proc qproc)
{
	pt->_qproc = qproc;
	pt->_key   = ~0UL; /* all events enabled */
}

struct poll_table_entry {
	// 指向特定fd对应的file结构体
	struct file *filp;
	// 等待特定fd对应硬件设备的事件掩码，如POLLIN、POLLOUT、POLLERR
	unsigned long key;
	// 代表调用select()的应用进程，等待在fd对应设备的特定事件(读或者写)的等待队列头上，的等待队列项;
	wait_queue_t wait;
	// 设备驱动程序中特定事件的等待队列头
	wait_queue_head_t *wait_address;
};

/*
 * Structures and helpers for select/poll syscall
 */
 // select/poll 对poll_table的具体化实现
struct poll_wqueues {
	//给__pollwait的第三个参数，调用select()的应用进程中poll_wqueues结构体的poll_table项(该进程监测的所有fd调用fop->poll函数都用这一个poll_table结构体)
	poll_table pt;
	//如果inline_entries空间不够用会动态申请物理内存页以链表的形式挂载poll_wqueues.table上统一管理
	struct poll_table_page *table;
	//保存当前调用select的用户进程struct task_struct结构体
	struct task_struct *polling_task;
	// 当前用户进程被唤醒后置成1，以免该进程接着进睡眠
	int triggered;
	 // 错误码
	int error;
	  // 数组inline_entries的引用下标
	int inline_index;
	struct poll_table_entry inline_entries[N_INLINE_POLL_ENTRIES];
};

extern void poll_initwait(struct poll_wqueues *pwq);
extern void poll_freewait(struct poll_wqueues *pwq);
extern int poll_schedule_timeout(struct poll_wqueues *pwq, int state,
				 ktime_t *expires, unsigned long slack);
extern long select_estimate_accuracy(struct timespec *tv);


static inline int poll_schedule(struct poll_wqueues *pwq, int state)
{
	return poll_schedule_timeout(pwq, state, NULL, 0);
}

/*
 * Scalable version of the fd_set.
 */
//记录可读、可写、异常 的输入和输出结果信息

typedef struct {
	unsigned long *in, *out, *ex;
	unsigned long *res_in, *res_out, *res_ex;
} fd_set_bits;

/*
 * How many longwords for "nr" bits?
 */
#define FDS_BITPERLONG	(8*sizeof(long))
#define FDS_LONGS(nr)	(((nr)+FDS_BITPERLONG-1)/FDS_BITPERLONG)
#define FDS_BYTES(nr)	(FDS_LONGS(nr)*sizeof(long))

/*
 * We do a VERIFY_WRITE here even though we are only reading this time:
 * we'll write to it eventually..
 *
 * Use "unsigned long" accesses to let user-mode fd_set's be long-aligned.
 */
 // 将用户空间的ufdset拷贝到内核空间fdset
static inline
int get_fd_set(unsigned long nr, void __user *ufdset, unsigned long *fdset)
{
	nr = FDS_BYTES(nr);
	if (ufdset)
		return copy_from_user(fdset, ufdset, nr) ? -EFAULT : 0;

	memset(fdset, 0, nr);
	return 0;
}
// 将内核fdset拷贝到用户空间的ufdset

static inline unsigned long __must_check
set_fd_set(unsigned long nr, void __user *ufdset, unsigned long *fdset)
{
	if (ufdset)
		return __copy_to_user(ufdset, fdset, FDS_BYTES(nr));
	return 0;
}
//将fdset内容清零

static inline
void zero_fd_set(unsigned long nr, unsigned long *fdset)
{
	memset(fdset, 0, FDS_BYTES(nr));
}

#define MAX_INT64_SECONDS (((s64)(~((u64)0)>>1)/HZ)-1)

extern int do_select(int n, fd_set_bits *fds, struct timespec *end_time);
extern int do_sys_poll(struct pollfd __user * ufds, unsigned int nfds,
		       struct timespec *end_time);
extern int core_sys_select(int n, fd_set __user *inp, fd_set __user *outp,
			   fd_set __user *exp, struct timespec *end_time);

extern int poll_select_set_timeout(struct timespec *to, long sec, long nsec);

#endif /* _LINUX_POLL_H */
