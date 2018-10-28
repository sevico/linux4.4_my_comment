/*
 *  fs/eventpoll.c (Efficient event retrieval implementation)
 *  Copyright (C) 2001,...,2009	 Davide Libenzi
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  Davide Libenzi <davidel@xmailserver.org>
 *
 */


/*
 * 在深入了解epoll的实现之前, 先来了解内核的3个方面.
 * 1. 等待队列 waitqueue
 * 我们简单解释一下等待队列:
 * 队列头(wait_queue_head_t)往往是资源生产者,
 * 队列成员(wait_queue_t)往往是资源消费者,
 * 当头的资源ready后, 会逐个执行每个成员指定的回调函数,
 * 来通知它们资源已经ready了, 等待队列大致就这个意思.
 * 2. 内核的poll机制
 * 被Poll的fd, 必须在实现上支持内核的Poll技术,
 * 比如fd是某个字符设备,或者是个socket, 它必须实现
 * file_operations中的poll操作, 给自己分配有一个等待队列头.
 * 主动poll fd的某个进程必须分配一个等待队列成员, 添加到
 * fd的对待队列里面去, 并指定资源ready时的回调函数.
 * 用socket做例子, 它必须有实现一个poll操作, 这个Poll是
 * 发起轮询的代码必须主动调用的, 该函数中必须调用poll_wait(),
 * poll_wait会将发起者作为等待队列成员加入到socket的等待队列中去.
 * 这样socket发生状态变化时可以通过队列头逐个通知所有关心它的进程.
 * 这一点必须很清楚的理解, 否则会想不明白epoll是如何
 * 得知fd的状态发生变化的.
 * 3. epollfd本身也是个fd, 所以它本身也可以被epoll,
 * 可以猜测一下它是不是可以无限嵌套epoll下去...
 *
 * epoll基本上就是使用了上面的1,2点来完成.
 * 可见epoll本身并没有给内核引入什么特别复杂或者高深的技术,
 * 只不过是已有功能的重新组合, 达到了超过select的效果.
 */
/*
 * 相关的其它内核知识:
 * 1. fd我们知道是文件描述符, 在内核态, 与之对应的是struct file结构,
 * 可以看作是内核态的文件描述符.
 * 2. spinlock, 自旋锁, 必须要非常小心使用的锁,
 * 尤其是调用spin_lock_irqsave()的时候, 中断关闭, 不会发生进程调度,
 * 被保护的资源其它CPU也无法访问. 这个锁是很强力的, 所以只能锁一些
 * 非常轻量级的操作.
 * 3. 引用计数在内核中是非常重要的概念,
 * 内核代码里面经常有些release, free释放资源的函数几乎不加任何锁,
 * 这是因为这些函数往往是在对象的引用计数变成0时被调用,
 * 既然没有进程在使用在这些对象, 自然也不需要加锁.
 * struct file 是持有引用计数的.
 */
 /*
 epoll_create
从slab缓存中创建一个eventpoll对象,并且创建一个匿名的fd跟fd对应的file对象,
而eventpoll对象保存在struct file结构的private指针中,并且返回,
该fd对应的file operations只是实现了poll跟release操作

创建eventpoll对象的初始化操作
获取当前用户信息,是不是root,最大监听fd数目等并且保存到eventpoll对象中
初始化等待队列,初始化就绪链表,初始化红黑树的头结点

epoll_ctl操作
将epoll_event结构拷贝到内核空间中
并且判断加入的fd是否支持poll结构(epoll,poll,selectI/O多路复用必须支持poll操作).
并且从epfd->file->privatedata获取event_poll对象,根据op区分是添加删除还是修改,
首先在eventpoll结构中的红黑树查找是否已经存在了相对应的fd,没找到就支持插入操作,否则报重复的错误.
相对应的修改,删除比较简单就不啰嗦了

插入操作时,会创建一个与fd对应的epitem结构,并且初始化相关成员,比如保存监听的fd跟file结构之类的
重要的是指定了调用poll_wait时的回调函数用于数据就绪时唤醒进程,(其内部,初始化设备的等待队列,将该进程注册到等待队列)完成这一步, 我们的epitem就跟这个socket关联起来了, 当它有状态变化时,
会通过ep_poll_callback()来通知.
最后调用加入的fd的file operation->poll函数(最后会调用poll_wait操作)用于完成注册操作.
最后将epitem结构添加到红黑树中

epoll_wait操作
计算睡眠时间(如果有),判断eventpoll对象的链表是否为空,不为空那就干活不睡明.并且初始化一个等待队列,把自己挂上去,设置自己的进程状态
为可睡眠状态.判断是否有信号到来(有的话直接被中断醒来,),如果啥事都没有那就调用schedule_timeout进行睡眠,如果超时或者被唤醒,首先从自己初始化的等待队列删除
,然后开始拷贝资源给用户空间了
拷贝资源则是先把就绪事件链表转移到中间链表,然后挨个遍历拷贝到用户空间,
并且挨个判断其是否为水平触发,是的话再次插入到就绪链表
*/
/* --- epoll相关的数据结构 --- */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/signal.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/rbtree.h>
#include <linux/wait.h>
#include <linux/eventpoll.h>
#include <linux/mount.h>
#include <linux/bitops.h>
#include <linux/mutex.h>
#include <linux/anon_inodes.h>
#include <linux/device.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/mman.h>
#include <linux/atomic.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/compat.h>
#include <linux/rculist.h>

/*
 * LOCKING:
 * There are three level of locking required by epoll :
 *
 * 1) epmutex (mutex)
 * 2) ep->mtx (mutex)
 * 3) ep->lock (spinlock)
 *
 * The acquire order is the one listed above, from 1 to 3.
 * We need a spinlock (ep->lock) because we manipulate objects
 * from inside the poll callback, that might be triggered from
 * a wake_up() that in turn might be called from IRQ context.
 * So we can't sleep inside the poll callback and hence we need
 * a spinlock. During the event transfer loop (from kernel to
 * user space) we could end up sleeping due a copy_to_user(), so
 * we need a lock that will allow us to sleep. This lock is a
 * mutex (ep->mtx). It is acquired during the event transfer loop,
 * during epoll_ctl(EPOLL_CTL_DEL) and during eventpoll_release_file().
 * Then we also need a global mutex to serialize eventpoll_release_file()
 * and ep_free().
 * This mutex is acquired by ep_free() during the epoll file
 * cleanup path and it is also acquired by eventpoll_release_file()
 * if a file has been pushed inside an epoll set and it is then
 * close()d without a previous call to epoll_ctl(EPOLL_CTL_DEL).
 * It is also acquired when inserting an epoll fd onto another epoll
 * fd. We do this so that we walk the epoll tree and ensure that this
 * insertion does not create a cycle of epoll file descriptors, which
 * could lead to deadlock. We need a global mutex to prevent two
 * simultaneous inserts (A into B and B into A) from racing and
 * constructing a cycle without either insert observing that it is
 * going to.
 * It is necessary to acquire multiple "ep->mtx"es at once in the
 * case when one epoll fd is added to another. In this case, we
 * always acquire the locks in the order of nesting (i.e. after
 * epoll_ctl(e1, EPOLL_CTL_ADD, e2), e1->mtx will always be acquired
 * before e2->mtx). Since we disallow cycles of epoll file
 * descriptors, this ensures that the mutexes are well-ordered. In
 * order to communicate this nesting to lockdep, when walking a tree
 * of epoll file descriptors, we use the current recursion depth as
 * the lockdep subkey.
 * It is possible to drop the "ep->mtx" and to use the global
 * mutex "epmutex" (together with "ep->lock") to have it working,
 * but having "ep->mtx" will make the interface more scalable.
 * Events that require holding "epmutex" are very rare, while for
 * normal operations the epoll private "ep->mtx" will guarantee
 * a better scalability.
 */

/* Epoll private bits inside the event mask */
#define EP_PRIVATE_BITS (EPOLLWAKEUP | EPOLLONESHOT | EPOLLET)

/* Maximum number of nesting allowed inside epoll sets */
#define EP_MAX_NESTS 4

#define EP_MAX_EVENTS (INT_MAX / sizeof(struct epoll_event))

#define EP_UNACTIVE_PTR ((void *) -1L)

#define EP_ITEM_COST (sizeof(struct epitem) + sizeof(struct eppoll_entry))

struct epoll_filefd {
	struct file *file;
	int fd;
} __packed;

/*
 * Structure used to track possible nested calls, for too deep recursions
 * and loop cycles.
 */
struct nested_call_node {
	struct list_head llink;
	void *cookie;// 函数运行标识, 任务标志
	void *ctx; // 运行环境标识
};

/*
 * This structure is used as collector for nested calls, to check for
 * maximum recursion dept and loop cycles.
 */
struct nested_calls {
	struct list_head tasks_call_list;
	spinlock_t lock;
};

/*
 * Each file descriptor added to the eventpoll interface will
 * have an entry of this type linked to the "rbr" RB tree.
 * Avoid increasing the size of this struct, there can be many thousands
 * of these on a server and we do not want this to take another cache line.
 */
 /* epitem 表示一个被监听的fd */
// 对应于一个加入到epoll的文件  
struct epitem {

	
		/* RB tree node used to link this structure to the eventpoll RB tree */
		/* rb_node, 当使用epoll_ctl()将一批fds加入到某个epollfd时, 内核会分配
		 * 一批的epitem与fds们对应, 而且它们以rb_tree的形式组织起来, tree的root
		 * 保存在epollfd, 也就是struct eventpoll中.
		 * 在这里使用rb_tree的原因我认为是提高查找,插入以及删除的速度.
		 * rb_tree对以上3个操作都具有O(lgN)的时间复杂度 */

	union {
		/* RB tree node links this structure to the eventpoll RB tree */
		// 挂载到eventpoll 的红黑树节点  
		struct rb_node rbn;
		//用于主结构管理的红黑树
		/* Used to free the struct epitem */
		struct rcu_head rcu;
	};

	/* List header used to link this structure to the eventpoll ready list */
	// 挂载到eventpoll.rdllist 的节点  
	struct list_head rdllink;//事件就绪队列
	
	/*
	 * Works together "struct eventpoll"->ovflist in keeping the
	 * single linked chain of items.
	 */
	 // 连接到ovflist 的指针
	struct epitem *next; //用于主结构体中的链表

	/* The file descriptor information this item refers to */
	 /* 文件描述符信息fd + file, 红黑树的key */
	struct epoll_filefd ffd;  //这个结构体对应的被监听的文件描述符信息

	/* Number of active wait queue attached to poll operations */
	int nwait;  //poll操作中事件的个数

	/* List containing poll wait queues */
	    // 当前文件的等待队列(eppoll_entry)列表  
    // 同一个文件上可能会监视多种事件,  
    // 这些事件可能属于不同的wait_queue中  
    // (取决于对应文件类型的实现),  
    // 所以需要使用链表  
	struct list_head pwqlist;  //双向链表，保存着被监视文件的等待队列，功能类似于select/poll中的poll_table

	/* The "container" of this item */
	// 当前epitem 的所有者 
	struct eventpoll *ep; //该项属于哪个主结构体（多个epitm从属于一个eventpoll）

	/* List header used to link this item to the "struct file" items list */
	struct list_head fllink; //双向链表，用来链接被监视的文件描述符对应的struct file。因为file里有f_ep_link,用来保存所有监视这个文件的epoll节点

	/* wakeup_source used when EPOLLWAKEUP is set */
	struct wakeup_source __rcu *ws;

	/* The structure that describe the interested events and the source fd */
	/* epoll_ctl 传入的用户数据 */ 
	struct epoll_event event; //注册的感兴趣的事件,也就是用户空间的epoll_event
};

/*
 * This structure is stored inside the "private_data" member of the file
 * structure and represents the main data structure for the eventpoll
 * interface.
 */
 // epoll的核心实现对应于一个epoll描述符  
struct eventpoll {
	/* Protect the access to this structure */
	spinlock_t lock;

	/*
	 * This mutex is used to ensure that files are not removed
	 * while epoll is using them. This is held during the event
	 * collection loop, the file cleanup path, the epoll file exit
	 * code and the ctl operations.
	 */

    /* 添加, 修改或者删除监听fd的时候, 以及epoll_wait返回, 向用户空间
     * 传递数据时都会持有这个互斥锁, 所以在用户空间可以放心的在多个线程
     * 中同时执行epoll相关的操作, 内核级已经做了保护. */
	struct mutex mtx;

	/* Wait queue used by sys_epoll_wait() */
	/* 调用epoll_wait()时, 我们就是"睡"在了这个等待队列上... */
	wait_queue_head_t wq;  // sys_epoll_wait() 等待在这里

	/* Wait queue used by file->poll() */
	/* 这个用于epollfd本事被poll的时候... */
	// f_op->poll()  使用的, 被其他事件通知机制利用的wait_address 
	wait_queue_head_t poll_wait;

	/* List of ready file descriptors */
	/* 所有已经ready的epitem都在这个链表里面 */
	/* 已就绪的需要检查的epitem 列表 */ 
	struct list_head rdllist;

	/* RB tree root used to store monitored fd structs */
	/* 所有要监听的epitem都在这里 */
	/* 保存所有加入到当前epoll的文件对应的epitem*/  
	struct rb_root rbr;

	/*
	 * This is a single linked list that chains all the "struct epitem" that
	 * happened while transferring ready events to userspace w/out
	 * holding ->lock.
	 */
	 /*
        这是一个单链表链接着所有的struct epitem当event转移到用户空间时
     */
     // 当正在向用户空间复制数据时, 产生的可用文件
	struct epitem *ovflist;

	/* wakeup_source used when ep_scan_ready_list is running */
	struct wakeup_source *ws;

	/* The user that created the eventpoll descriptor */
	/* 这里保存了一些用户变量, 比如fd监听数量的最大值等等 */
	struct user_struct *user;

	struct file *file;

	/* used to optimize loop detection check */
	/*优化循环检查，避免循环检查中重复的遍历 */  
	int visited;
	struct list_head visited_list_link;
};

/* Wait structure used by the poll hooks */
// 与一个文件上的一个wait_queue_head 相关联，因为同一文件可能有多个等待的事件，这些事件可能使用不同的等待队列  
struct eppoll_entry {
	/* List header used to link this structure to the "struct epitem" */
	struct list_head llink;

	/* The "base" pointer is set to the container "struct epitem" */
	// 所有者 
	struct epitem *base;

	/*
	 * Wait queue item that will be linked to the target file wait
	 * queue head.
	 */
	 // 添加到wait_queue 中的节点
	wait_queue_t wait;

	/* The wait queue head that linked the "wait" wait queue item */
	// 文件wait_queue 头
	wait_queue_head_t *whead;
};

/* Wrapper struct used by poll queueing */
struct ep_pqueue {
	poll_table pt;
	struct epitem *epi;
};

/* Used by the ep_send_events() function as callback private data */
struct ep_send_events_data {
	int maxevents;
	struct epoll_event __user *events;
};

/*
 * Configuration options available inside /proc/sys/fs/epoll/
 */
/* Maximum number of epoll watched descriptors, per user */
static long max_user_watches __read_mostly;

/*
 * This mutex is used to serialize ep_free() and eventpoll_release_file().
 */
static DEFINE_MUTEX(epmutex);

/* Used to check for epoll file descriptor inclusion loops */
// 全局的不同调用使用的链表  
// 死循环检查和唤醒风暴检查链表  
static struct nested_calls poll_loop_ncalls;

/* Used for safe wake up implementation */
// 唤醒时使用的检查链表
static struct nested_calls poll_safewake_ncalls;

/* Used to call file's f_op->poll() under the nested calls boundaries */
// 扫描readylist 时使用的链表
static struct nested_calls poll_readywalk_ncalls;

/* Slab cache used to allocate "struct epitem" */
static struct kmem_cache *epi_cache __read_mostly;

/* Slab cache used to allocate "struct eppoll_entry" */
static struct kmem_cache *pwq_cache __read_mostly;

/* Visited nodes during ep_loop_check(), so we can unset them when we finish */
static LIST_HEAD(visited_list);

/*
 * List of files with newly added links, where we may need to limit the number
 * of emanating paths. Protected by the epmutex.
 */
static LIST_HEAD(tfile_check_list);

#ifdef CONFIG_SYSCTL

#include <linux/sysctl.h>

static long zero;
static long long_max = LONG_MAX;

struct ctl_table epoll_table[] = {
	{
		.procname	= "max_user_watches",
		.data		= &max_user_watches,
		.maxlen		= sizeof(max_user_watches),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax,
		.extra1		= &zero,
		.extra2		= &long_max,
	},
	{ }
};
#endif /* CONFIG_SYSCTL */

static const struct file_operations eventpoll_fops;

static inline int is_file_epoll(struct file *f)
{
	return f->f_op == &eventpoll_fops;
}

/* Setup the structure that is used as key for the RB tree */
static inline void ep_set_ffd(struct epoll_filefd *ffd,
			      struct file *file, int fd)
{
	ffd->file = file;
	ffd->fd = fd;
}

/* Compare RB tree keys */
static inline int ep_cmp_ffd(struct epoll_filefd *p1,
			     struct epoll_filefd *p2)
{
	return (p1->file > p2->file ? +1:
	        (p1->file < p2->file ? -1 : p1->fd - p2->fd));
}

/* Tells us if the item is currently linked */
static inline int ep_is_linked(struct list_head *p)
{
	return !list_empty(p);
}

static inline struct eppoll_entry *ep_pwq_from_wait(wait_queue_t *p)
{
	return container_of(p, struct eppoll_entry, wait);
}

/* Get the "struct epitem" from a wait queue pointer */
static inline struct epitem *ep_item_from_wait(wait_queue_t *p)
{
	return container_of(p, struct eppoll_entry, wait)->base;
}

/* Get the "struct epitem" from an epoll queue wrapper */
static inline struct epitem *ep_item_from_epqueue(poll_table *p)
{
	return container_of(p, struct ep_pqueue, pt)->epi;
}

/* Tells if the epoll_ctl(2) operation needs an event copy from userspace */
static inline int ep_op_has_event(int op)
{
	return op != EPOLL_CTL_DEL;
}

/* Initialize the poll safe wake up structure */
static void ep_nested_calls_init(struct nested_calls *ncalls)
{
	INIT_LIST_HEAD(&ncalls->tasks_call_list);
	spin_lock_init(&ncalls->lock);
}

/**
 * ep_events_available - Checks if ready events might be available.
 *
 * @ep: Pointer to the eventpoll context.
 *
 * Returns: Returns a value different than zero if ready events are available,
 *          or zero otherwise.
 */
static inline int ep_events_available(struct eventpoll *ep)
{
	return !list_empty(&ep->rdllist) || ep->ovflist != EP_UNACTIVE_PTR;
}

/**
 * ep_call_nested - Perform a bound (possibly) nested call, by checking
 *                  that the recursion limit is not exceeded, and that
 *                  the same nested call (by the meaning of same cookie) is
 *                  no re-entered.
 *
 * @ncalls: Pointer to the nested_calls structure to be used for this call.
 * @max_nests: Maximum number of allowed nesting calls.
 * @nproc: Nested call core function pointer.
 * @priv: Opaque data to be passed to the @nproc callback.
 * @cookie: Cookie to be used to identify this nested call.
 * @ctx: This instance context.
 *
 * Returns: Returns the code returned by the @nproc callback, or -1 if
 *          the maximum recursion limit has been exceeded.
 */
 // 限制epoll 中直接或间接递归调用的深度并防止死循环  
// ctx: 任务运行上下文(进程, CPU 等)  
// cookie: 每个任务的标识  
// priv: 任务运行需要的私有数据  
// 如果用面向对象语言实现应该就会是一个wapper类
static int ep_call_nested(struct nested_calls *ncalls, int max_nests,
			  int (*nproc)(void *, void *, int), void *priv,
			  void *cookie, void *ctx)
{
	int error, call_nests = 0;
	unsigned long flags;
	struct list_head *lsthead = &ncalls->tasks_call_list;
	struct nested_call_node *tncur;
	struct nested_call_node tnode;

	spin_lock_irqsave(&ncalls->lock, flags);

	/*
	 * Try to see if the current task is already inside this wakeup call.
	 * We use a list here, since the population inside this set is always
	 * very much limited.
	 */
	 // 检查原有的嵌套调用链表ncalls, 查看是否有深度超过限制的情况
	list_for_each_entry(tncur, lsthead, llink) {
	// 同一上下文中(ctx)有相同的任务(cookie)说明产生了死循环  
        // 同一上下文的递归深度call_nests 超过限制  
		if (tncur->ctx == ctx &&
		    (tncur->cookie == cookie || ++call_nests > max_nests)) {
			/*
			 * Ops ... loop detected or maximum nest level reached.
			 * We abort this wake by breaking the cycle itself.
			 */
			error = -1;
			goto out_unlock;
		}
	}

	/* Add the current task and cookie to the list */
	/* 将当前的任务请求添加到调用列表*/  
	tnode.ctx = ctx;
	tnode.cookie = cookie;
	list_add(&tnode.llink, lsthead);

	spin_unlock_irqrestore(&ncalls->lock, flags);

	/* Call the nested function */
	    /* nproc 可能会导致递归调用(直接或间接)ep_call_nested 
         * 如果发生递归调用, 那么在此函数返回之前, 
         * ncalls 又会被加入额外的节点, 
         * 这样通过前面的检测就可以知道递归调用的深度 
      */  
	error = (*nproc)(priv, cookie, call_nests);

	/* Remove the current task from the list */
	/* 从链表中删除当前任务*/
	spin_lock_irqsave(&ncalls->lock, flags);
	list_del(&tnode.llink);
out_unlock:
	spin_unlock_irqrestore(&ncalls->lock, flags);

	return error;
}

/*
 * As described in commit 0ccf831cb lockdep: annotate epoll
 * the use of wait queues used by epoll is done in a very controlled
 * manner. Wake ups can nest inside each other, but are never done
 * with the same locking. For example:
 *
 *   dfd = socket(...);
 *   efd1 = epoll_create();
 *   efd2 = epoll_create();
 *   epoll_ctl(efd1, EPOLL_CTL_ADD, dfd, ...);
 *   epoll_ctl(efd2, EPOLL_CTL_ADD, efd1, ...);
 *
 * When a packet arrives to the device underneath "dfd", the net code will
 * issue a wake_up() on its poll wake list. Epoll (efd1) has installed a
 * callback wakeup entry on that queue, and the wake_up() performed by the
 * "dfd" net code will end up in ep_poll_callback(). At this point epoll
 * (efd1) notices that it may have some event ready, so it needs to wake up
 * the waiters on its poll wait list (efd2). So it calls ep_poll_safewake()
 * that ends up in another wake_up(), after having checked about the
 * recursion constraints. That are, no more than EP_MAX_POLLWAKE_NESTS, to
 * avoid stack blasting.
 *
 * When CONFIG_DEBUG_LOCK_ALLOC is enabled, make sure lockdep can handle
 * this special case of epoll.
 */
#ifdef CONFIG_DEBUG_LOCK_ALLOC
static inline void ep_wake_up_nested(wait_queue_head_t *wqueue,
				     unsigned long events, int subclass)
{
	unsigned long flags;

	spin_lock_irqsave_nested(&wqueue->lock, flags, subclass);
	wake_up_locked_poll(wqueue, events);
	spin_unlock_irqrestore(&wqueue->lock, flags);
}
#else
static inline void ep_wake_up_nested(wait_queue_head_t *wqueue,
				     unsigned long events, int subclass)
{
    // 这回唤醒所有正在等待此epfd 的select/epoll/poll 等  
    // 如果唤醒的是epoll 就可能唤醒其他的epoll, 产生连锁反应  
    // 这个很可能在中断上下文中被调用  

	wake_up_poll(wqueue, events);
}
#endif

static int ep_poll_wakeup_proc(void *priv, void *cookie, int call_nests)
{
	ep_wake_up_nested((wait_queue_head_t *) cookie, POLLIN,
			  1 + call_nests);
	return 0;
}

/*
 * Perform a safe wake up of the poll wait list. The problem is that
 * with the new callback'd wake up system, it is possible that the
 * poll callback is reentered from inside the call to wake_up() done
 * on the poll wait queue head. The rule is that we cannot reenter the
 * wake up code from the same task more than EP_MAX_NESTS times,
 * and we cannot reenter the same wait queue head at all. This will
 * enable to have a hierarchy of epoll file descriptor of no more than
 * EP_MAX_NESTS deep.
 */
static void ep_poll_safewake(wait_queue_head_t *wq)
{
	int this_cpu = get_cpu();

	ep_call_nested(&poll_safewake_ncalls, EP_MAX_NESTS,
		       ep_poll_wakeup_proc, NULL, wq, (void *) (long) this_cpu);

	put_cpu();
}

static void ep_remove_wait_queue(struct eppoll_entry *pwq)
{
	wait_queue_head_t *whead;

	rcu_read_lock();
	/*
	 * If it is cleared by POLLFREE, it should be rcu-safe.
	 * If we read NULL we need a barrier paired with
	 * smp_store_release() in ep_poll_callback(), otherwise
	 * we rely on whead->lock.
	 */
	whead = smp_load_acquire(&pwq->whead);
	if (whead)
		remove_wait_queue(whead, &pwq->wait);
	rcu_read_unlock();
}

/*
 * This function unregisters poll callbacks from the associated file
 * descriptor.  Must be called with "mtx" held (or "epmutex" if called from
 * ep_free).
 */
static void ep_unregister_pollwait(struct eventpoll *ep, struct epitem *epi)
{
	struct list_head *lsthead = &epi->pwqlist;
	struct eppoll_entry *pwq;

	while (!list_empty(lsthead)) {
		pwq = list_first_entry(lsthead, struct eppoll_entry, llink);

		list_del(&pwq->llink);
		ep_remove_wait_queue(pwq);
		kmem_cache_free(pwq_cache, pwq);
	}
}

/* call only when ep->mtx is held */
static inline struct wakeup_source *ep_wakeup_source(struct epitem *epi)
{
	return rcu_dereference_check(epi->ws, lockdep_is_held(&epi->ep->mtx));
}

/* call only when ep->mtx is held */
static inline void ep_pm_stay_awake(struct epitem *epi)
{
	struct wakeup_source *ws = ep_wakeup_source(epi);

	if (ws)
		__pm_stay_awake(ws);
}

static inline bool ep_has_wakeup_source(struct epitem *epi)
{
	return rcu_access_pointer(epi->ws) ? true : false;
}

/* call when ep->mtx cannot be held (ep_poll_callback) */
static inline void ep_pm_stay_awake_rcu(struct epitem *epi)
{
	struct wakeup_source *ws;

	rcu_read_lock();
	ws = rcu_dereference(epi->ws);
	if (ws)
		__pm_stay_awake(ws);
	rcu_read_unlock();
}

/**
 * ep_scan_ready_list - Scans the ready list in a way that makes possible for
 *                      the scan code, to call f_op->poll(). Also allows for
 *                      O(NumReady) performance.
 *
 * @ep: Pointer to the epoll private data structure.
 * @sproc: Pointer to the scan callback.
 * @priv: Private opaque data passed to the @sproc callback.
 * @depth: The current depth of recursive f_op->poll calls.
 * @ep_locked: caller already holds ep->mtx
 *
 * Returns: The same integer error code returned by the @sproc callback.
 */
static int ep_scan_ready_list(struct eventpoll *ep,
			      int (*sproc)(struct eventpoll *,
					   struct list_head *, void *),
			      void *priv, int depth, bool ep_locked)
{
	int error, pwake = 0;
	unsigned long flags;
	struct epitem *epi, *nepi;
	LIST_HEAD(txlist);

	/*
	 * We need to lock this because we could be hit by
	 * eventpoll_release_file() and epoll_ctl().
	 */

	if (!ep_locked)
		mutex_lock_nested(&ep->mtx, depth);

	/*
	 * Steal the ready list, and re-init the original one to the
	 * empty list. Also, set ep->ovflist to NULL so that events
	 * happening while looping w/out locks, are not lost. We cannot
	 * have the poll callback to queue directly on ep->rdllist,
	 * because we want the "sproc" callback to be able to do it
	 * in a lockless way.
	 */
	spin_lock_irqsave(&ep->lock, flags);
   /* 这一步要注意, 首先, 所有监听到events的epitem都链到rdllist上了,
     * 但是这一步之后, 所有的epitem都转移到了txlist上, 而rdllist被清空了,
     * 要注意哦, rdllist已经被清空了! */
      // 移动rdllist 到新的链表txlist
	list_splice_init(&ep->rdllist, &txlist);
    /* ovflist, 在ep_poll_callback()里面我解释过, 此时此刻我们不希望
    * 有新的event加入到ready list中了, 保存后下次再处理... */
        // 改变ovflist 的状态, 如果ep->ovflist != EP_UNACTIVE_PTR,  
    // 当文件激活wait_queue时，就会将对应的epitem加入到ep->ovflist  
    // 否则将文件直接加入到ep->rdllist，  
    // 这样做的目的是避免丢失事件  
    // 这里不需要检查ep->ovflist 的状态，因为ep->mtx的存在保证此处的ep->ovflist  
    // 一定是EP_UNACTIVE_PTR  
	ep->ovflist = NULL;
	spin_unlock_irqrestore(&ep->lock, flags);

	/*
	 * Now call the callback function.
	 */
	/* 在这个回调函数里面处理每个epitem
    * sproc 就是 ep_send_events_proc, 下面会注释到. */
    // 调用扫描函数处理txlist 
	error = (*sproc)(ep, &txlist, priv);

	spin_lock_irqsave(&ep->lock, flags);
	/*
	 * During the time we spent inside the "sproc" callback, some
	 * other events might have been queued by the poll callback.
	 * We re-insert them inside the main ready-list here.
	 */
	 /* 现在我们来处理ovflist, 这些epitem都是我们在传递数据给用户空间时
     * 监听到了事件. */
     // 调用 sproc 时可能有新的事件，遍历这些新的事件将其插入到ready list
	for (nepi = ep->ovflist; (epi = nepi) != NULL;
	     nepi = epi->next, epi->next = EP_UNACTIVE_PTR) {
		/*
		 * We need to check if the item is already in the list.
		 * During the "sproc" callback execution time, items are
		 * queued into ->ovflist but the "txlist" might already
		 * contain them, and the list_splice() below takes care of them.
		 */
		  /* 将这些直接放入readylist */
		// #define EP_UNACTIVE_PTR (void *) -1  
        // epi 不在rdllist, 插入  
		if (!ep_is_linked(&epi->rdllink)) {
			list_add_tail(&epi->rdllink, &ep->rdllist);
			ep_pm_stay_awake(epi);
		}
	}
	/*
	 * We need to set back ep->ovflist to EP_UNACTIVE_PTR, so that after
	 * releasing the lock, events will be queued in the normal way inside
	 * ep->rdllist.
	 */
	 // 还原ep->ovflist的状态
	ep->ovflist = EP_UNACTIVE_PTR;

	/*
	 * Quickly re-inject items left on "txlist".
	 */
	 /* 上一次没有处理完的epitem, 重新插入到ready list */
	// 将处理后的 txlist 链接到 rdllist 
	list_splice(&txlist, &ep->rdllist);
	__pm_relax(ep->ws);
	/* ready list不为空, 直接唤醒... */
	if (!list_empty(&ep->rdllist)) {
		/*
		 * Wake up (if active) both the eventpoll wait list and
		 * the ->poll() wait list (delayed after we release the lock).
		 */
		 // 唤醒epoll_wait
		if (waitqueue_active(&ep->wq))
			wake_up_locked(&ep->wq);
		// 当前的ep有其他的事件通知机制监控
		if (waitqueue_active(&ep->poll_wait))
			pwake++;
	}
	spin_unlock_irqrestore(&ep->lock, flags);

	if (!ep_locked)
		mutex_unlock(&ep->mtx);

	/* We have to call this outside the lock */
	// 安全唤醒外部的事件通知机制
	if (pwake)
		ep_poll_safewake(&ep->poll_wait);

	return error;
}

static void epi_rcu_free(struct rcu_head *head)
{
	struct epitem *epi = container_of(head, struct epitem, rcu);
	kmem_cache_free(epi_cache, epi);
}

/*
 * Removes a "struct epitem" from the eventpoll RB tree and deallocates
 * all the associated resources. Must be called with "mtx" held.
 */
static int ep_remove(struct eventpoll *ep, struct epitem *epi)
{
	unsigned long flags;
	struct file *file = epi->ffd.file;

	/*
	 * Removes poll wait queue hooks. We _have_ to do this without holding
	 * the "ep->lock" otherwise a deadlock might occur. This because of the
	 * sequence of the lock acquisition. Here we do "ep->lock" then the wait
	 * queue head lock when unregistering the wait queue. The wakeup callback
	 * will run by holding the wait queue head lock and will call our callback
	 * that will try to get "ep->lock".
	 */
	ep_unregister_pollwait(ep, epi);

	/* Remove the current item from the list of epoll hooks */
	spin_lock(&file->f_lock);
	list_del_rcu(&epi->fllink);
	spin_unlock(&file->f_lock);

	rb_erase(&epi->rbn, &ep->rbr);

	spin_lock_irqsave(&ep->lock, flags);
	if (ep_is_linked(&epi->rdllink))
		list_del_init(&epi->rdllink);
	spin_unlock_irqrestore(&ep->lock, flags);

	wakeup_source_unregister(ep_wakeup_source(epi));
	/*
	 * At this point it is safe to free the eventpoll item. Use the union
	 * field epi->rcu, since we are trying to minimize the size of
	 * 'struct epitem'. The 'rbn' field is no longer in use. Protected by
	 * ep->mtx. The rcu read side, reverse_path_check_proc(), does not make
	 * use of the rbn field.
	 */
	call_rcu(&epi->rcu, epi_rcu_free);

	atomic_long_dec(&ep->user->epoll_watches);

	return 0;
}
/* ep_free在epollfd被close时调用,
 * 释放一些资源而已, 比较简单 */

static void ep_free(struct eventpoll *ep)
{
	struct rb_node *rbp;
	struct epitem *epi;

	/* We need to release all tasks waiting for these file */
	if (waitqueue_active(&ep->poll_wait))
		ep_poll_safewake(&ep->poll_wait);

	/*
	 * We need to lock this because we could be hit by
	 * eventpoll_release_file() while we're freeing the "struct eventpoll".
	 * We do not need to hold "ep->mtx" here because the epoll file
	 * is on the way to be removed and no one has references to it
	 * anymore. The only hit might come from eventpoll_release_file() but
	 * holding "epmutex" is sufficient here.
	 */
	mutex_lock(&epmutex);

	/*
	 * Walks through the whole tree by unregistering poll callbacks.
	 */
	for (rbp = rb_first(&ep->rbr); rbp; rbp = rb_next(rbp)) {
		epi = rb_entry(rbp, struct epitem, rbn);

		ep_unregister_pollwait(ep, epi);
		cond_resched();
	}

	/*
	 * Walks through the whole tree by freeing each "struct epitem". At this
	 * point we are sure no poll callbacks will be lingering around, and also by
	 * holding "epmutex" we can be sure that no file cleanup code will hit
	 * us during this operation. So we can avoid the lock on "ep->lock".
	 * We do not need to lock ep->mtx, either, we only do it to prevent
	 * a lockdep warning.
	 */
	 /* 之所以在关闭epollfd之前不需要调用epoll_ctl移除已经添加的fd,
     * 是因为这里已经做了... */
	mutex_lock(&ep->mtx);
	while ((rbp = rb_first(&ep->rbr)) != NULL) {
		epi = rb_entry(rbp, struct epitem, rbn);
		ep_remove(ep, epi);
		cond_resched();
	}
	mutex_unlock(&ep->mtx);

	mutex_unlock(&epmutex);
	mutex_destroy(&ep->mtx);
	free_uid(ep->user);
	wakeup_source_unregister(ep->ws);
	kfree(ep);
}

static int ep_eventpoll_release(struct inode *inode, struct file *file)
{
	struct eventpoll *ep = file->private_data;

	if (ep)
		ep_free(ep);

	return 0;
}

static inline unsigned int ep_item_poll(struct epitem *epi, poll_table *pt)
{
	// 设置事件掩码
	pt->_key = epi->event.events;
	//  内部会调用ep_ptable_queue_proc, 在文件对应的wait queue head 上
	// 注册回调函数, 并返回当前文件的状态 
	return epi->ffd.file->f_op->poll(epi->ffd.file, pt) & epi->event.events;
}

static int ep_read_events_proc(struct eventpoll *ep, struct list_head *head,
			       void *priv)
{
	struct epitem *epi, *tmp;
	poll_table pt;

	init_poll_funcptr(&pt, NULL);

	list_for_each_entry_safe(epi, tmp, head, rdllink) {
		if (ep_item_poll(epi, &pt))
			return POLLIN | POLLRDNORM;
		else {
			/*
			 * Item has been dropped into the ready list by the poll
			 * callback, but it's not actually ready, as far as
			 * caller requested events goes. We can remove it here.
			 */
			 // 这个事件虽然在就绪列表中,  
             // 但是实际上并没有就绪, 将他移除  
         // 这有可能是水平触发模式中没有将文件从就绪列表中移除  
         // 也可能是事件插入到就绪列表后有其他的线程对文件进行了操作  
			__pm_relax(ep_wakeup_source(epi));
			list_del_init(&epi->rdllink);
		}
	}

	return 0;
}

static void ep_ptable_queue_proc(struct file *file, wait_queue_head_t *whead,
				 poll_table *pt);

struct readyevents_arg {
	struct eventpoll *ep;
	bool locked;
};

static int ep_poll_readyevents_proc(void *priv, void *cookie, int call_nests)
{
	struct readyevents_arg *arg = priv;

	return ep_scan_ready_list(arg->ep, ep_read_events_proc, NULL,
				  call_nests + 1, arg->locked);
}

static unsigned int ep_eventpoll_poll(struct file *file, poll_table *wait)
{
	int pollflags;
	struct eventpoll *ep = file->private_data;
	struct readyevents_arg arg;

	/*
	 * During ep_insert() we already hold the ep->mtx for the tfile.
	 * Prevent re-aquisition.
	 */
	arg.locked = wait && (wait->_qproc == ep_ptable_queue_proc);
	arg.ep = ep;

	/* Insert inside our poll wait queue */
	 // 插入到wait_queue
	poll_wait(file, &ep->poll_wait, wait);

	/*
	 * Proceed to find out if wanted events are really available inside
	 * the ready list. This need to be done under ep_call_nested()
	 * supervision, since the call to f_op->poll() done on listed files
	 * could re-enter here.
	 */
	     // 扫描就绪的文件列表, 调用每个文件上的poll 检测是否真的就绪,  
    // 然后复制到用户空间  
    // 文件列表中有可能有epoll文件, 调用poll的时候有可能会产生递归,  
    // 调用所以用ep_call_nested 包装一下, 防止死循环和过深的调用  
	pollflags = ep_call_nested(&poll_readywalk_ncalls, EP_MAX_NESTS,
				   ep_poll_readyevents_proc, &arg, ep, current);

	return pollflags != -1 ? pollflags : 0;
}

#ifdef CONFIG_PROC_FS
static void ep_show_fdinfo(struct seq_file *m, struct file *f)
{
	struct eventpoll *ep = f->private_data;
	struct rb_node *rbp;

	mutex_lock(&ep->mtx);
	for (rbp = rb_first(&ep->rbr); rbp; rbp = rb_next(rbp)) {
		struct epitem *epi = rb_entry(rbp, struct epitem, rbn);

		seq_printf(m, "tfd: %8d events: %8x data: %16llx\n",
			   epi->ffd.fd, epi->event.events,
			   (long long)epi->event.data);
		if (seq_has_overflowed(m))
			break;
	}
	mutex_unlock(&ep->mtx);
}
#endif

/* File callbacks that implement the eventpoll file behaviour */
static const struct file_operations eventpoll_fops = {
#ifdef CONFIG_PROC_FS
	.show_fdinfo	= ep_show_fdinfo,
#endif
	.release	= ep_eventpoll_release,
	.poll		= ep_eventpoll_poll,
	.llseek		= noop_llseek,
};

/*
 * This is called from eventpoll_release() to unlink files from the eventpoll
 * interface. We need to have this facility to cleanup correctly files that are
 * closed without being removed from the eventpoll interface.
 */
void eventpoll_release_file(struct file *file)
{
	struct eventpoll *ep;
	struct epitem *epi, *next;

	/*
	 * We don't want to get "file->f_lock" because it is not
	 * necessary. It is not necessary because we're in the "struct file"
	 * cleanup path, and this means that no one is using this file anymore.
	 * So, for example, epoll_ctl() cannot hit here since if we reach this
	 * point, the file counter already went to zero and fget() would fail.
	 * The only hit might come from ep_free() but by holding the mutex
	 * will correctly serialize the operation. We do need to acquire
	 * "ep->mtx" after "epmutex" because ep_remove() requires it when called
	 * from anywhere but ep_free().
	 *
	 * Besides, ep_remove() acquires the lock, so we can't hold it here.
	 */
	mutex_lock(&epmutex);
	list_for_each_entry_safe(epi, next, &file->f_ep_links, fllink) {
		ep = epi->ep;
		mutex_lock_nested(&ep->mtx, 0);
		ep_remove(ep, epi);
		mutex_unlock(&ep->mtx);
	}
	mutex_unlock(&epmutex);
}

/* 分配一个eventpoll结构 */
static int ep_alloc(struct eventpoll **pep)
{
	int error;
	struct user_struct *user;
	struct eventpoll *ep;
	/* 获取当前用户的一些信息, 比如是不是root啦, 最大监听fd数目啦 */

	user = get_current_user();
	error = -ENOMEM;
	ep = kzalloc(sizeof(*ep), GFP_KERNEL);
	if (unlikely(!ep))
		goto free_uid;

	spin_lock_init(&ep->lock);
	mutex_init(&ep->mtx);
	init_waitqueue_head(&ep->wq); //初始化自己睡在的等待队列
	init_waitqueue_head(&ep->poll_wait);//初始化
	INIT_LIST_HEAD(&ep->rdllist);//初始化就绪链表
	ep->rbr = RB_ROOT;
	ep->ovflist = EP_UNACTIVE_PTR;
	ep->user = user;

	*pep = ep;

	return 0;

free_uid:
	free_uid(user);
	return error;
}

/*
 * Search the file inside the eventpoll tree. The RB tree operations
 * are protected by the "mtx" mutex, and ep_find() must be called with
 * "mtx" held.
 */
static struct epitem *ep_find(struct eventpoll *ep, struct file *file, int fd)
{
	int kcmp;
	struct rb_node *rbp;
	struct epitem *epi, *epir = NULL;
	struct epoll_filefd ffd;

	ep_set_ffd(&ffd, file, fd);
	for (rbp = ep->rbr.rb_node; rbp; ) {
		epi = rb_entry(rbp, struct epitem, rbn);
		kcmp = ep_cmp_ffd(&ffd, &epi->ffd);
		if (kcmp > 0)
			rbp = rbp->rb_right;
		else if (kcmp < 0)
			rbp = rbp->rb_left;
		else {
			epir = epi;
			break;
		}
	}

	return epir;
}

/*
 * This is the callback that is passed to the wait queue wakeup
 * mechanism. It is called by the stored file descriptors when they
 * have events to report.
 */
 /*
 * 这个是关键性的回调函数, 当我们监听的fd发生状态改变时, 它会被调用.
 * 参数key被当作一个unsigned long整数使用, 携带的是events.
 */
static int ep_poll_callback(wait_queue_t *wait, unsigned mode, int sync, void *key)
{
	int pwake = 0;
	unsigned long flags;
	struct epitem *epi = ep_item_from_wait(wait);//从等待队列获取epitem.需要知道哪个进程挂载到这个设备
	struct eventpoll *ep = epi->ep;//获取

	spin_lock_irqsave(&ep->lock, flags);

	/*
	 * If the event mask does not contain any poll(2) event, we consider the
	 * descriptor to be disabled. This condition is likely the effect of the
	 * EPOLLONESHOT bit that disables the descriptor when an event is received,
	 * until the next EPOLL_CTL_MOD will be issued.
	 */
	if (!(epi->event.events & ~EP_PRIVATE_BITS))
		goto out_unlock;

	/*
	 * Check the events coming with the callback. At this stage, not
	 * every device reports the events in the "key" parameter of the
	 * callback. We need to be able to handle both cases here, hence the
	 * test for "key" != NULL before the event match test.
	 */
	 /* 没有我们关心的event... */
	if (key && !((unsigned long) key & epi->event.events))
		goto out_unlock;

	/*
	 * If we are transferring events to userspace, we can hold no locks
	 * (because we're accessing user memory, and because of linux f_op->poll()
	 * semantics). All the events that happen during that period of time are
	 * chained in ep->ovflist and requeued later on.
	 */
    /*
     * 这里看起来可能有点费解, 其实干的事情比较简单:
     * 如果该callback被调用的同时, epoll_wait()已经返回了,
     * 也就是说, 此刻应用程序有可能已经在循环获取events,
     * 这种情况下, 内核将此刻发生event的epitem用一个单独的链表
     * 链起来, 不发给应用程序, 也不丢弃, 而是在下一次epoll_wait
     * 时返回给用户.
     */
	if (unlikely(ep->ovflist != EP_UNACTIVE_PTR)) {
		if (epi->next == EP_UNACTIVE_PTR) {
			epi->next = ep->ovflist;
			ep->ovflist = epi;
			if (epi->ws) {
				/*
				 * Activate ep->ws since epi->ws may get
				 * deactivated at any time.
				 */
				__pm_stay_awake(ep->ws);
			}

		}
		goto out_unlock;
	}

	/* If this file is already in the ready list we exit soon */
	/* 将当前的epitem放入ready list */
	if (!ep_is_linked(&epi->rdllink)) {
		list_add_tail(&epi->rdllink, &ep->rdllist);
		ep_pm_stay_awake_rcu(epi);
	}

	/*
	 * Wake up ( if active ) both the eventpoll wait list and the ->poll()
	 * wait list.
	 */
	 /* 唤醒epoll_wait... */
	if (waitqueue_active(&ep->wq))
		wake_up_locked(&ep->wq);
	/* 如果epollfd也在被poll, 那就唤醒队列里面的所有成员. */
	if (waitqueue_active(&ep->poll_wait))
		pwake++;

out_unlock:
	spin_unlock_irqrestore(&ep->lock, flags);

	/* We have to call this outside the lock */
	if (pwake)
		ep_poll_safewake(&ep->poll_wait);


	if ((unsigned long)key & POLLFREE) {
		/*
		 * If we race with ep_remove_wait_queue() it can miss
		 * ->whead = NULL and do another remove_wait_queue() after
		 * us, so we can't use __remove_wait_queue().
		 */
		list_del_init(&wait->task_list);
		/*
		 * ->whead != NULL protects us from the race with ep_free()
		 * or ep_remove(), ep_remove_wait_queue() takes whead->lock
		 * held by the caller. Once we nullify it, nothing protects
		 * ep/epi or even wait.
		 */
		smp_store_release(&ep_pwq_from_wait(wait)->whead, NULL);
	}

	return 1;
}

/*
 * This is the callback that is used to add our wait queue to the
 * target file wakeup lists.
 */


/*
 * 该函数在调用f_op->poll()时会被调用.
 * 也就是epoll主动poll某个fd时, 用来将epitem与指定的fd关联起来的.
 * 关联的办法就是使用等待队列(waitqueue)
 */
static void ep_ptable_queue_proc(struct file *file, wait_queue_head_t *whead,
				 poll_table *pt)
{
	struct epitem *epi = ep_item_from_epqueue(pt);
	struct eppoll_entry *pwq;

	if (epi->nwait >= 0 && (pwq = kmem_cache_alloc(pwq_cache, GFP_KERNEL))) {
        /* 初始化等待队列, 指定ep_poll_callback为唤醒时的回调函数,
         * 当我们监听的fd发生状态改变时, 也就是队列头被唤醒时,
         * 指定的回调函数将会被调用. */
		init_waitqueue_func_entry(&pwq->wait, ep_poll_callback);
		pwq->whead = whead;
		pwq->base = epi;
		 /* 将刚分配的等待队列成员加入到头中, 头是由fd持有的 */
		add_wait_queue(whead, &pwq->wait);
		list_add_tail(&pwq->llink, &epi->pwqlist);
		/* nwait记录了当前epitem加入到了多少个等待队列中,
         * 我认为这个值最大也只会是1... */
		epi->nwait++;
	} else {
		/* We have to signal that an error occurred */
		epi->nwait = -1;
	}
}

static void ep_rbtree_insert(struct eventpoll *ep, struct epitem *epi)
{
	int kcmp;
	struct rb_node **p = &ep->rbr.rb_node, *parent = NULL;
	struct epitem *epic;

	while (*p) {
		parent = *p;
		epic = rb_entry(parent, struct epitem, rbn);
		kcmp = ep_cmp_ffd(&epi->ffd, &epic->ffd);
		if (kcmp > 0)
			p = &parent->rb_right;
		else
			p = &parent->rb_left;
	}
	rb_link_node(&epi->rbn, parent, p);
	rb_insert_color(&epi->rbn, &ep->rbr);
}



#define PATH_ARR_SIZE 5
/*
 * These are the number paths of length 1 to 5, that we are allowing to emanate
 * from a single file of interest. For example, we allow 1000 paths of length
 * 1, to emanate from each file of interest. This essentially represents the
 * potential wakeup paths, which need to be limited in order to avoid massive
 * uncontrolled wakeup storms. The common use case should be a single ep which
 * is connected to n file sources. In this case each file source has 1 path
 * of length 1. Thus, the numbers below should be more than sufficient. These
 * path limits are enforced during an EPOLL_CTL_ADD operation, since a modify
 * and delete can't add additional paths. Protected by the epmutex.
 */
 // 在EPOLL_CTL_ADD 时, 检查是否有可能产生唤醒风暴  
// epoll 允许的单个文件的唤醒深度小于5, 例如  
// 一个文件最多允许唤醒1000个深度为1的epoll描述符,  
//允许所有被单个文件直接唤醒的epoll描述符再次唤醒的epoll描述符总数是500  
//  
// 深度限制 
static const int path_limits[PATH_ARR_SIZE] = { 1000, 500, 100, 50, 10 };
// 计算出来的深度
static int path_count[PATH_ARR_SIZE];

static int path_count_inc(int nests)
{
	/* Allow an arbitrary number of depth 1 paths */
	if (nests == 0)
		return 0;

	if (++path_count[nests] > path_limits[nests])
		return -1;
	return 0;
}

static void path_count_init(void)
{
	int i;

	for (i = 0; i < PATH_ARR_SIZE; i++)
		path_count[i] = 0;
}

static int reverse_path_check_proc(void *priv, void *cookie, int call_nests)
{
	int error = 0;
	struct file *file = priv;
	struct file *child_file;
	struct epitem *epi;

	/* CTL_DEL can remove links here, but that can't increase our count */
	rcu_read_lock();
	list_for_each_entry_rcu(epi, &file->f_ep_links, fllink) {
		// 遍历监视file 的epoll
		child_file = epi->ep->file;
		if (is_file_epoll(child_file)) {
			if (list_empty(&child_file->f_ep_links)) {
				// 没有其他的epoll监视当前的这个epoll,
				// 已经是叶子了
				if (path_count_inc(call_nests)) {
					error = -1;
					break;
				}
			} else {
			// 遍历监视这个epoll 文件的epoll, 
			// 递归调用
				error = ep_call_nested(&poll_loop_ncalls,
							EP_MAX_NESTS,
							reverse_path_check_proc,
							child_file, child_file,
							current);
			}
			if (error != 0)
				break;
		} else {
		// 不是epoll , 不可能吧?
			printk(KERN_ERR "reverse_path_check_proc: "
				"file is not an ep!\n");
		}
	}
	rcu_read_unlock();
	return error;
}

/**
 * reverse_path_check - The tfile_check_list is list of file *, which have
 *                      links that are proposed to be newly added. We need to
 *                      make sure that those added links don't add too many
 *                      paths such that we will spend all our time waking up
 *                      eventpoll objects.
 *
 * Returns: Returns zero if the proposed links don't create too many paths,
 *	    -1 otherwise.
 */
static int reverse_path_check(void)
{
	int error = 0;
	struct file *current_file;

	/* let's call this for all tfiles */
	// 遍历全局tfile_check_list 中的文件, 第一级
	list_for_each_entry(current_file, &tfile_check_list, f_tfile_llink) {
	// 初始化
		path_count_init();
	// 限制递归的深度, 并检查每个深度上唤醒的epoll 数量
		error = ep_call_nested(&poll_loop_ncalls, EP_MAX_NESTS,
					reverse_path_check_proc, current_file,
					current_file, current);
		if (error)
			break;
	}
	return error;
}

static int ep_create_wakeup_source(struct epitem *epi)
{
	const char *name;
	struct wakeup_source *ws;

	if (!epi->ep->ws) {
		epi->ep->ws = wakeup_source_register("eventpoll");
		if (!epi->ep->ws)
			return -ENOMEM;
	}

	name = epi->ffd.file->f_path.dentry->d_name.name;
	ws = wakeup_source_register(name);

	if (!ws)
		return -ENOMEM;
	rcu_assign_pointer(epi->ws, ws);

	return 0;
}

/* rare code path, only used when EPOLL_CTL_MOD removes a wakeup source */
static noinline void ep_destroy_wakeup_source(struct epitem *epi)
{
	struct wakeup_source *ws = ep_wakeup_source(epi);

	RCU_INIT_POINTER(epi->ws, NULL);

	/*
	 * wait for ep_pm_stay_awake_rcu to finish, synchronize_rcu is
	 * used internally by wakeup_source_remove, too (called by
	 * wakeup_source_unregister), so we cannot use call_rcu
	 */
	synchronize_rcu();
	wakeup_source_unregister(ws);
}

/*
 * Must be called with "mtx" held.
 */
 /*
 * ep_insert()在epoll_ctl()中被调用, 完成往epollfd里面添加一个监听fd的工作
 * tfile是fd在内核态的struct file结构
 */
static int ep_insert(struct eventpoll *ep, struct epoll_event *event,
		     struct file *tfile, int fd, int full_check)
{
	int error, revents, pwake = 0;
	unsigned long flags;
	long user_watches;
	struct epitem *epi;
	struct ep_pqueue epq;
	/* 查看是否达到当前用户的最大监听数 */
	// 增加监视文件数
	user_watches = atomic_long_read(&ep->user->epoll_watches);
	if (unlikely(user_watches >= max_user_watches))
		return -ENOSPC;
	/* 从著名的slab中分配一个epitem */
	// 分配初始化 epi 
	if (!(epi = kmem_cache_alloc(epi_cache, GFP_KERNEL)))
		return -ENOMEM;

	/* Item initialization follow here ... */
	INIT_LIST_HEAD(&epi->rdllink);
	INIT_LIST_HEAD(&epi->fllink);
	INIT_LIST_HEAD(&epi->pwqlist);
	epi->ep = ep;
	/* 这里保存了我们需要监听的文件fd和它的file结构 */
	// 初始化红黑树中的key 
	ep_set_ffd(&epi->ffd, tfile, fd);
	// 直接复制用户结构
	epi->event = *event;
	epi->nwait = 0;
	/* 这个指针的初值不是NULL哦... */
	epi->next = EP_UNACTIVE_PTR;
	if (epi->event.events & EPOLLWAKEUP) {
		error = ep_create_wakeup_source(epi);
		if (error)
			goto error_create_wakeup_source;
	} else {
		RCU_INIT_POINTER(epi->ws, NULL);
	}

	/* Initialize the poll table using the queue callback */
	// 初始化临时的 epq
	epq.epi = epi;
    /* 初始化一个poll_table
     * 其实就是指定调用poll_wait(注意不是epoll_wait!!!)时的回调函数,和我们关心哪些events,
     * ep_ptable_queue_proc()就是我们的回调啦, 初值是所有event都关心 */
	init_poll_funcptr(&epq.pt, ep_ptable_queue_proc);

	/*
	 * Attach the item to the poll hooks and get current event bits.
	 * We can safely use the file* here because its usage count has
	 * been increased by the caller of this function. Note that after
	 * this operation completes, the poll callback can start hitting
	 * the new item.
	 */

    /* 这一部很关键, 也比较难懂, 完全是内核的poll机制导致的...
     * 首先, f_op->poll()一般来说只是个wrapper, 它会调用真正的poll实现,
     * 拿UDP的socket来举例, 这里就是这样的调用流程: f_op->poll(), sock_poll(),
     * udp_poll(), datagram_poll(), sock_poll_wait(), 最后调用到我们上面指定的
     * ep_ptable_queue_proc()这个回调函数...(好深的调用路径...).
     * 完成这一步, 我们的epitem就跟这个socket关联起来了, 当它有状态变化时,
     * 会通过ep_poll_callback()来通知.
     * 最后, 这个函数还会查询当前的fd是不是已经有啥event已经ready了, 有的话
     * 会将event返回. */
	revents = ep_item_poll(epi, &epq.pt);

	/*
	 * We have to check if something went wrong during the poll wait queue
	 * install process. Namely an allocation for a wait queue failed due
	 * high memory pressure.
	 */
	 // 检查错误 
	error = -ENOMEM;
	if (epi->nwait < 0) // f_op->poll 过程出错 
		goto error_unregister;

	/* Add the current item to the list of active epoll hook for this file */
	/* 这个就是每个文件会将所有监听自己的epitem链起来 */
	// 添加当前的epitem 到文件的f_ep_links 链表
	spin_lock(&tfile->f_lock);
	list_add_tail_rcu(&epi->fllink, &tfile->f_ep_links);
	spin_unlock(&tfile->f_lock);

	/*
	 * Add the current item to the RB tree. All RB tree operations are
	 * protected by "mtx", and ep_insert() is called with "mtx" held.
	 */
	 /* 都搞定后, 将epitem插入到对应的eventpoll中去 */
	// 插入epi 到rbtree
	ep_rbtree_insert(ep, epi);

	/* now check if we've created too many backpaths */
	error = -EINVAL;
	if (full_check && reverse_path_check())
		goto error_remove_epi;

	/* We have to drop the new item inside our item list to keep track of it */
	spin_lock_irqsave(&ep->lock, flags);

	/* If the file is already "ready" we drop it inside the ready list */
	/* 到达这里后, 如果我们监听的fd已经有事件发生, 那就要处理一下 */
	/* 文件已经就绪插入到就绪链表rdllist */
	if ((revents & event->events) && !ep_is_linked(&epi->rdllink)) {
		/* 将当前的epitem加入到ready list中去 */
		list_add_tail(&epi->rdllink, &ep->rdllist);
		ep_pm_stay_awake(epi);

		/* Notify waiting tasks that events are available */
		/* 谁在epoll_wait, 就唤醒它... */
		if (waitqueue_active(&ep->wq))
			// 通知sys_epoll_wait , 调用回调函数唤醒sys_epoll_wait 进程
			wake_up_locked(&ep->wq);
		 // 先不通知调用eventpoll_poll 的进程
		if (waitqueue_active(&ep->poll_wait))
			pwake++;
	}

	spin_unlock_irqrestore(&ep->lock, flags);

	atomic_long_inc(&ep->user->epoll_watches);

	/* We have to call this outside the lock */
	// 安全通知调用eventpoll_poll 的进程 
	if (pwake)
		ep_poll_safewake(&ep->poll_wait);

	return 0;

error_remove_epi:
	spin_lock(&tfile->f_lock);
	// 删除文件上的 epi
	list_del_rcu(&epi->fllink);
	spin_unlock(&tfile->f_lock);
	// 从红黑树中删除

	rb_erase(&epi->rbn, &ep->rbr);

error_unregister:
	// 从文件的wait_queue 中删除, 释放epitem 关联的所有eppoll_entry
	ep_unregister_pollwait(ep, epi);

	/*
	 * We need to do this because an event could have been arrived on some
	 * allocated wait queue. Note that we don't care about the ep->ovflist
	 * list, since that is used/cleaned only inside a section bound by "mtx".
	 * And ep_insert() is called with "mtx" held.
	 */
	spin_lock_irqsave(&ep->lock, flags);
	if (ep_is_linked(&epi->rdllink))
		list_del_init(&epi->rdllink);
	spin_unlock_irqrestore(&ep->lock, flags);

	wakeup_source_unregister(ep_wakeup_source(epi));

error_create_wakeup_source:
	 // 释放epi
	kmem_cache_free(epi_cache, epi);

	return error;
}

/*
 * Modify the interest event mask by dropping an event if the new mask
 * has a match in the current file status. Must be called with "mtx" held.
 */
static int ep_modify(struct eventpoll *ep, struct epitem *epi, struct epoll_event *event)
{
	int pwake = 0;
	unsigned int revents;
	poll_table pt;

	init_poll_funcptr(&pt, NULL);

	/*
	 * Set the new event interest mask before calling f_op->poll();
	 * otherwise we might miss an event that happens between the
	 * f_op->poll() call and the new event set registering.
	 */
	epi->event.events = event->events; /* need barrier below */
	epi->event.data = event->data; /* protected by mtx */
	if (epi->event.events & EPOLLWAKEUP) {
		if (!ep_has_wakeup_source(epi))
			ep_create_wakeup_source(epi);
	} else if (ep_has_wakeup_source(epi)) {
		ep_destroy_wakeup_source(epi);
	}

	/*
	 * The following barrier has two effects:
	 *
	 * 1) Flush epi changes above to other CPUs.  This ensures
	 *    we do not miss events from ep_poll_callback if an
	 *    event occurs immediately after we call f_op->poll().
	 *    We need this because we did not take ep->lock while
	 *    changing epi above (but ep_poll_callback does take
	 *    ep->lock).
	 *
	 * 2) We also need to ensure we do not miss _past_ events
	 *    when calling f_op->poll().  This barrier also
	 *    pairs with the barrier in wq_has_sleeper (see
	 *    comments for wq_has_sleeper).
	 *
	 * This barrier will now guarantee ep_poll_callback or f_op->poll
	 * (or both) will notice the readiness of an item.
	 */
	smp_mb();

	/*
	 * Get current event bits. We can safely use the file* here because
	 * its usage count has been increased by the caller of this function.
	 */
	revents = ep_item_poll(epi, &pt);

	/*
	 * If the item is "hot" and it is not registered inside the ready
	 * list, push it inside.
	 */
	if (revents & event->events) {
		spin_lock_irq(&ep->lock);
		if (!ep_is_linked(&epi->rdllink)) {
			list_add_tail(&epi->rdllink, &ep->rdllist);
			ep_pm_stay_awake(epi);

			/* Notify waiting tasks that events are available */
			if (waitqueue_active(&ep->wq))
				wake_up_locked(&ep->wq);
			if (waitqueue_active(&ep->poll_wait))
				pwake++;
		}
		spin_unlock_irq(&ep->lock);
	}

	/* We have to call this outside the lock */
	if (pwake)
		ep_poll_safewake(&ep->poll_wait);

	return 0;
}

/* 该函数作为callbakc在ep_scan_ready_list()中被调用
 * head是一个链表, 包含了已经ready的epitem,
 * 这个不是eventpoll里面的ready list, 而是上面函数中的txlist.
 */

static int ep_send_events_proc(struct eventpoll *ep, struct list_head *head,
			       void *priv)
{
	struct ep_send_events_data *esed = priv;
	int eventcnt;
	unsigned int revents;
	struct epitem *epi;
	struct epoll_event __user *uevent;
	struct wakeup_source *ws;
	poll_table pt;

	init_poll_funcptr(&pt, NULL);

	/*
	 * We can loop without lock because we are passed a task private list.
	 * Items cannot vanish during the loop because ep_scan_ready_list() is
	 * holding "mtx" during this call.
	 */
	 /* 扫描整个链表... */
	// 遍历已就绪链表
	for (eventcnt = 0, uevent = esed->events;
	     !list_empty(head) && eventcnt < esed->maxevents;) {
		 /* 取出第一个成员 */
		epi = list_first_entry(head, struct epitem, rdllink);

		/*
		 * Activate ep->ws before deactivating epi->ws to prevent
		 * triggering auto-suspend here (in case we reactive epi->ws
		 * below).
		 *
		 * This could be rearranged to delay the deactivation of epi->ws
		 * instead, but then epi->ws would temporarily be out of sync
		 * with ep_is_linked().
		 */
		ws = ep_wakeup_source(epi);
		if (ws) {
			if (ws->active)
				__pm_stay_awake(ep->ws);
			__pm_relax(ws);
		}
		/* 然后从链表里面移除 */
		list_del_init(&epi->rdllink);
		 /* 读取events,
		* 注意events我们ep_poll_callback()里面已经取过一次了, 为啥还要再取?
		* 1. 我们当然希望能拿到此刻的最新数据, events是会变的~
		* 2. 不是所有的poll实现, 都通过等待队列传递了events, 有可能某些驱动压根没传
		* 必须主动去读取. */
		// 获取ready 事件掩码

		revents = ep_item_poll(epi, &pt);

		/*
		 * If the event mask intersect the caller-requested one,
		 * deliver the event to userspace. Again, ep_scan_ready_list()
		 * is holding "mtx", so no operations coming from userspace
		 * can change the item.
		 */
		if (revents) {
			 /* 将当前的事件和用户传入的数据都copy给用户空间,
             * 就是epoll_wait()后应用程序能读到的那一堆数据. */
             // 事件就绪, 复制到用户空间
			if (__put_user(revents, &uevent->events) ||
			    __put_user(epi->event.data, &uevent->data)) {
				list_add(&epi->rdllink, head);
				ep_pm_stay_awake(epi);
				return eventcnt ? eventcnt : -EFAULT;
			}
			eventcnt++;
			uevent++;
			if (epi->event.events & EPOLLONESHOT)
				epi->event.events &= EP_PRIVATE_BITS;
			else if (!(epi->event.events & EPOLLET)) {
				/*
				 * If this file has been added with Level
				 * Trigger mode, we need to insert back inside
				 * the ready list, so that the next call to
				 * epoll_wait() will check again the events
				 * availability. At this point, no one can insert
				 * into ep->rdllist besides us. The epoll_ctl()
				 * callers are locked out by
				 * ep_scan_ready_list() holding "mtx" and the
				 * poll callback will queue them in ep->ovflist.
				 */

                /* 嘿嘿, EPOLLET和非ET的区别就在这一步之差呀~
                 * 如果是ET, epitem是不会再进入到readly list,
                 * 除非fd再次发生了状态改变, ep_poll_callback被调用.
                 * 如果是非ET, 不管你还有没有有效的事件或者数据,
                 * 都会被重新插入到ready list, 再下一次epoll_wait
                 * 时, 会立即返回, 并通知给用户空间. 当然如果这个
                 * 被监听的fds确实没事件也没数据了, epoll_wait会返回一个0,
                 * 空转一次.
                 */
                 // 不是边缘模式, 再次添加到ready list,
                 // 下次epoll_wait 时直接进入此函数检查ready list是否仍然继续
				list_add_tail(&epi->rdllink, &ep->rdllist);
				ep_pm_stay_awake(epi);
			}
			// 如果是边缘模式, 只有当文件状态发生改变时,
			// 才文件会再次触发wait_address 上wait_queue的回调函数, 
		}
	}

	return eventcnt;
}

static int ep_send_events(struct eventpoll *ep,
			  struct epoll_event __user *events, int maxevents)
{
	struct ep_send_events_data esed;

	esed.maxevents = maxevents;
	esed.events = events;

	return ep_scan_ready_list(ep, ep_send_events_proc, &esed, 0, false);
}

static inline struct timespec ep_set_mstimeout(long ms)
{
	struct timespec now, ts = {
		.tv_sec = ms / MSEC_PER_SEC,
		.tv_nsec = NSEC_PER_MSEC * (ms % MSEC_PER_SEC),
	};

	ktime_get_ts(&now);
	return timespec_add_safe(now, ts);
}

/**
 * ep_poll - Retrieves ready events, and delivers them to the caller supplied
 *           event buffer.
 *
 * @ep: Pointer to the eventpoll context.
 * @events: Pointer to the userspace buffer where the ready events should be
 *          stored.
 * @maxevents: Size (in terms of number of events) of the caller event buffer.
 * @timeout: Maximum timeout for the ready events fetch operation, in
 *           milliseconds. If the @timeout is zero, the function will not block,
 *           while if the @timeout is less than zero, the function will block
 *           until at least one event has been retrieved (or an error
 *           occurred).
 *
 * Returns: Returns the number of ready events which have been fetched, or an
 *          error code, in case of error.
 */
static int ep_poll(struct eventpoll *ep, struct epoll_event __user *events,
		   int maxevents, long timeout)
{
	int res = 0, eavail, timed_out = 0;
	unsigned long flags;
	long slack = 0;
	wait_queue_t wait;//等待队列
	ktime_t expires, *to = NULL;
	/* 计算睡觉时间, 毫秒要转换为HZ */
	if (timeout > 0) {
		// 转换为内核时间
		struct timespec end_time = ep_set_mstimeout(timeout);

		slack = select_estimate_accuracy(&end_time);
		to = &expires;
		*to = timespec_to_ktime(end_time);
	} else if (timeout == 0) {
		/*
		 * Avoid the unnecessary trip to the wait queue loop, if the
		 * caller specified a non blocking operation.
		 */
		 // 已经超时直接检查readylist
		timed_out = 1;
		spin_lock_irqsave(&ep->lock, flags);
		goto check_events;
	}

fetch_events:
	spin_lock_irqsave(&ep->lock, flags);
	/* 如果ready list不为空, 就不睡了, 直接干活... */
	// 没有可用的事件，ready list 和ovflist 都为空
	if (!ep_events_available(ep)) {
		/*
		 * We don't have any available event to return to the caller.
		 * We need to sleep here, and we will be wake up by
		 * ep_poll_callback() when events will become available.
		 */
		 /* OK, 初始化一个等待队列, 准备直接把自己挂起,
         * 注意current是一个宏, 代表当前进程 */
         // 添加当前进程的唤醒函数
		init_waitqueue_entry(&wait, current);//初始化等待队列,wait表示当前进程
		__add_wait_queue_exclusive(&ep->wq, &wait);//挂载到ep结构的等待队列

		for (;;) {
			/*
			 * We don't want to sleep if the ep_poll_callback() sends us
			 * a wakeup in between. That's why we set the task state
			 * to TASK_INTERRUPTIBLE before doing the checks.
			 */
			  /* 将当前进程设置位睡眠, 但是可以被信号唤醒的状态,
             * 注意这个设置是"将来时", 我们此刻还没睡! */
			set_current_state(TASK_INTERRUPTIBLE);
			/* 如果这个时候, ready list里面有成员了,
             * 或者睡眠时间已经过了, 就直接不睡了... */
			if (ep_events_available(ep) || timed_out)
				break;
			/* 如果有信号产生, 也起床... */
			if (signal_pending(current)) {
				res = -EINTR;
				break;
			}
			/* 啥事都没有,解锁, 睡觉... */

			spin_unlock_irqrestore(&ep->lock, flags);
            /* jtimeout这个时间后, 会被唤醒,
             * ep_poll_callback()如果此时被调用,
             * 那么我们就会直接被唤醒, 不用等时间了...
             * 再次强调一下ep_poll_callback()的调用时机是由被监听的fd
             * 的具体实现, 比如socket或者某个设备驱动来决定的,
             * 因为等待队列头是他们持有的, epoll和当前进程
             * 只是单纯的等待...
             **/
             // 挂起当前进程，等待唤醒或超时
			if (!schedule_hrtimeout_range(to, slack, HRTIMER_MODE_ABS))
				timed_out = 1;

			spin_lock_irqsave(&ep->lock, flags);
		}

		__remove_wait_queue(&ep->wq, &wait);
		 /* OK 我们醒来了... */
		__set_current_state(TASK_RUNNING);
	}
check_events:
	/* Is it worth to try to dig for events ? */
	// 再次检查是否有可用事件
	eavail = ep_events_available(ep);

	spin_unlock_irqrestore(&ep->lock, flags);

	/*
	 * Try to transfer events to user space. In case we get 0 events and
	 * there's still timeout left over, we go trying again in search of
	 * more luck.
	 */
	 /* 如果一切正常, 有event发生, 就开始准备数据copy给用户空间了... */
	if (!res && eavail &&
	    !(res = ep_send_events(ep, events, maxevents)) && !timed_out)// 复制事件到用户空间
		goto fetch_events;

	return res;
}

/**
 * ep_loop_check_proc - Callback function to be passed to the @ep_call_nested()
 *                      API, to verify that adding an epoll file inside another
 *                      epoll structure, does not violate the constraints, in
 *                      terms of closed loops, or too deep chains (which can
 *                      result in excessive stack usage).
 *
 * @priv: Pointer to the epoll file to be currently checked.
 * @cookie: Original cookie for this call. This is the top-of-the-chain epoll
 *          data structure pointer.
 * @call_nests: Current dept of the @ep_call_nested() call stack.
 *
 * Returns: Returns zero if adding the epoll @file inside current epoll
 *          structure @ep does not violate the constraints, or -1 otherwise.
 */
static int ep_loop_check_proc(void *priv, void *cookie, int call_nests)
{
	int error = 0;
	struct file *file = priv;
	struct eventpoll *ep = file->private_data;
	struct eventpoll *ep_tovisit;
	struct rb_node *rbp;
	struct epitem *epi;

	mutex_lock_nested(&ep->mtx, call_nests + 1);
	// 标记当前为已遍历
	ep->visited = 1;
	list_add(&ep->visited_list_link, &visited_list);
	// 遍历所有ep 监视的文件
	for (rbp = rb_first(&ep->rbr); rbp; rbp = rb_next(rbp)) {
		epi = rb_entry(rbp, struct epitem, rbn);
		if (unlikely(is_file_epoll(epi->ffd.file))) {
			ep_tovisit = epi->ffd.file->private_data;
			// 跳过先前已遍历的, 避免循环检查
			if (ep_tovisit->visited)
				continue;
			// 所有ep监视的未遍历的epoll
			error = ep_call_nested(&poll_loop_ncalls, EP_MAX_NESTS,
					ep_loop_check_proc, epi->ffd.file,
					ep_tovisit, current);
			if (error != 0)
				break;
		} else {
			/*
			 * If we've reached a file that is not associated with
			 * an ep, then we need to check if the newly added
			 * links are going to add too many wakeup paths. We do
			 * this by adding it to the tfile_check_list, if it's
			 * not already there, and calling reverse_path_check()
			 * during ep_insert().
			 */
			 // 文件不在tfile_check_list 中, 添加 
			 // 最外层的epoll 需要检查子epoll监视的文件 
			if (list_empty(&epi->ffd.file->f_tfile_llink))
				list_add(&epi->ffd.file->f_tfile_llink,
					 &tfile_check_list);
		}
	}
	mutex_unlock(&ep->mtx);

	return error;
}

/**
 * ep_loop_check - Performs a check to verify that adding an epoll file (@file)
 *                 another epoll file (represented by @ep) does not create
 *                 closed loops or too deep chains.
 *
 * @ep: Pointer to the epoll private data structure.
 * @file: Pointer to the epoll file to be checked.
 *
 * Returns: Returns zero if adding the epoll @file inside current epoll
 *          structure @ep does not violate the constraints, or -1 otherwise.
 */
 // 检查 file (epoll)和ep 之间是否有循环
static int ep_loop_check(struct eventpoll *ep, struct file *file)
{
	int ret;
	struct eventpoll *ep_cur, *ep_next;

	ret = ep_call_nested(&poll_loop_ncalls, EP_MAX_NESTS,
			      ep_loop_check_proc, file, ep, current);
	/* clear visited list */
	/* 清除链表和标志 */
	list_for_each_entry_safe(ep_cur, ep_next, &visited_list,
							visited_list_link) {
		ep_cur->visited = 0;
		list_del(&ep_cur->visited_list_link);
	}
	return ret;
}

static void clear_tfile_check_list(void)
{
	struct file *file;

	/* first clear the tfile_check_list */
	while (!list_empty(&tfile_check_list)) {
		file = list_first_entry(&tfile_check_list, struct file,
					f_tfile_llink);
		list_del_init(&file->f_tfile_llink);
	}
	INIT_LIST_HEAD(&tfile_check_list);
}

/*
 * Open an eventpoll file descriptor.
 */
SYSCALL_DEFINE1(epoll_create1, int, flags)
{
	int error, fd;
	struct eventpoll *ep = NULL; //主描述符
	struct file *file;

	/* Check the EPOLL_* constant for consistency.  */
	BUILD_BUG_ON(EPOLL_CLOEXEC != O_CLOEXEC);
	/* 对于epoll来讲, 目前唯一有效的FLAG就是CLOEXEC */
	if (flags & ~EPOLL_CLOEXEC)
		return -EINVAL;
	/*
	 * Create the internal data structure ("struct eventpoll").
	 */
	 /* 分配一个struct eventpoll, 分配和初始化细节我们随后深聊~ */
	error = ep_alloc(&ep);
	if (error < 0)
		return error;
	/*
	 * Creates all the items needed to setup an eventpoll file. That is,
	 * a file structure and a free file descriptor.
	 */
	fd = get_unused_fd_flags(O_RDWR | (flags & O_CLOEXEC));
	if (fd < 0) {
		error = fd;
		goto out_free_ep;
	}


    /* 这里是创建一个匿名fd, 说起来就话长了...长话短说:
     * epollfd本身并不存在一个真正的文件与之对应, 所以内核需要创建一个
     * "虚拟"的文件, 并为之分配真正的struct file结构, 而且有真正的fd.
     * 这里2个参数比较关键:
     * eventpoll_fops, fops就是file operations, 就是当你对这个文件(这里是虚拟的)进行操作(比如读)时,
     * fops里面的函数指针指向真正的操作实现, 类似C++里面虚函数和子类的概念.
     * epoll只实现了poll和release(就是close)操作, 其它文件系统操作都有VFS全权处理了.
     * ep, ep就是struct epollevent, 它会作为一个私有数据保存在struct file的private指针里面.
     * 其实说白了, 就是为了能通过fd找到struct file, 通过struct file能找到eventpoll结构.
     * 如果懂一点Linux下字符设备驱动开发, 这里应该是很好理解的,
     * 推荐阅读 <Linux device driver 3rd>
     */
      // 设置epfd的相关操作，由于epoll也是文件也提供了poll操作 
	file = anon_inode_getfile("[eventpoll]", &eventpoll_fops, ep,
				 O_RDWR | (flags & O_CLOEXEC));
	if (IS_ERR(file)) {
		error = PTR_ERR(file);
		goto out_free_fd;
	}
	ep->file = file;
	fd_install(fd, file);
	return fd;

out_free_fd:
	put_unused_fd(fd);
out_free_ep:
	ep_free(ep);
	return error;
}

SYSCALL_DEFINE1(epoll_create, int, size)
{
	if (size <= 0)
		return -EINVAL;

	return sys_epoll_create1(0);
}

/*
 * The following function implements the controller interface for
 * the eventpoll file that enables the insertion/removal/change of
 * file descriptors inside the interest set.
 */
SYSCALL_DEFINE4(epoll_ctl, int, epfd, int, op, int, fd,
		struct epoll_event __user *, event)
{
	int error;
	int full_check = 0;
	struct fd f, tf;
	struct eventpoll *ep;
	struct epitem *epi;
	struct epoll_event epds;
	struct eventpoll *tep = NULL;

	error = -EFAULT;
	/*
     * 错误处理以及从用户空间将epoll_event结构copy到内核空间.
     */
	if (ep_op_has_event(op) &&// 复制用户空间数据到内核
	    copy_from_user(&epds, event, sizeof(struct epoll_event)))
		goto error_return;
	// 取得 epfd 对应的文件
	error = -EBADF;
	f = fdget(epfd);
	if (!f.file)
		goto error_return;
		/* 取得struct file结构, epfd既然是真正的fd, 那么内核空间
		 * 就会有与之对于的一个struct file结构
		 * 这个结构在epoll_create1()中, 由函数anon_inode_getfd()分配 */
	/* Get the "struct file *" for the target file */
	// 取得目标文件
	tf = fdget(fd);
	if (!tf.file)
		goto error_fput;

	/* The target file descriptor must support poll */
	/* 如果监听的文件不支持poll, 那就没辙了.
     * 你知道什么情况下, 文件会不支持poll吗?
     */
     // 目标文件必须提供 poll 操作 
	error = -EPERM;
	if (!tf.file->f_op->poll)
		goto error_tgt_fput;

	/* Check if EPOLLWAKEUP is allowed */
	if (ep_op_has_event(op))
		ep_take_care_of_epollwakeup(&epds);

	/*
	 * We have to check that the file structure underneath the file descriptor
	 * the user passed to us _is_ an eventpoll file. And also we do not permit
	 * adding an epoll file descriptor inside itself.
	 */
	 /* epoll不能自己监听自己... */
	// 添加自身或epfd 不是epoll 句柄
	error = -EINVAL;
	if (f.file == tf.file || !is_file_epoll(f.file))
		goto error_tgt_fput;

	/*
	 * At this point it is safe to assume that the "private_data" contains
	 * our own data structure.
	 */
	 /* 取到我们的eventpoll结构, 来自与epoll_create1()中的分配 */
	// 取得内部结构eventpoll
	ep = f.file->private_data;

	/*
	 * When we insert an epoll file descriptor, inside another epoll file
	 * descriptor, there is the change of creating closed loops, which are
	 * better be handled here, than in more critical paths. While we are
	 * checking for loops we also determine the list of files reachable
	 * and hang them on the tfile_check_list, so we can check that we
	 * haven't created too many possible wakeup paths.
	 *
	 * We do not need to take the global 'epumutex' on EPOLL_CTL_ADD when
	 * the epoll file descriptor is attaching directly to a wakeup source,
	 * unless the epoll file descriptor is nested. The purpose of taking the
	 * 'epmutex' on add is to prevent complex toplogies such as loops and
	 * deep wakeup paths from forming in parallel through multiple
	 * EPOLL_CTL_ADD operations.
	 */
	 /* 接下来的操作有可能修改数据结构内容, 锁之~ */
	mutex_lock_nested(&ep->mtx, 0);
	if (op == EPOLL_CTL_ADD) {
		if (!list_empty(&f.file->f_ep_links) ||
						is_file_epoll(tf.file)) {
			full_check = 1;
			mutex_unlock(&ep->mtx);
			mutex_lock(&epmutex);
			if (is_file_epoll(tf.file)) {
				error = -ELOOP;
				// 目标文件也是epoll 检测是否有循环包含的问题
				if (ep_loop_check(ep, tf.file) != 0) {
					clear_tfile_check_list();
					goto error_tgt_fput;
				}
			} else
			// 将目标文件添加到 epoll 全局的tfile_check_list 中
				list_add(&tf.file->f_tfile_llink,
							&tfile_check_list);
			mutex_lock_nested(&ep->mtx, 0);
			if (is_file_epoll(tf.file)) {
				tep = tf.file->private_data;
				mutex_lock_nested(&tep->mtx, 1);
			}
		}
	}

	/*
	 * Try to lookup the file inside our RB tree, Since we grabbed "mtx"
	 * above, we can be sure to be able to use the item looked up by
	 * ep_find() till we release the mutex.
	 */


    */
    /* 对于每一个监听的fd, 内核都有分配一个epitem结构,
     * 而且我们也知道, epoll是不允许重复添加fd的,
     * 所以我们首先查找该fd是不是已经存在了.
     * ep_find()其实就是RBTREE查找, 跟C++STL的map差不多一回事, O(lgn)的时间复杂度.
     */
     // 以tfile 和fd 为key 在rbtree 中查找文件对应的epitem  
	epi = ep_find(ep, tf.file, fd);

	error = -EINVAL;
	switch (op) {
	case EPOLL_CTL_ADD:
		if (!epi) {
            /* 之前的find没有找到有效的epitem, 证明是第一次插入, 接受!
             * 这里我们可以知道, POLLERR和POLLHUP事件内核总是会关心的
             * */
             // 没找到, 添加额外添加ERR HUP 事件
			epds.events |= POLLERR | POLLHUP;
            /* rbtree插入, 详情见ep_insert()的分析
             * 其实我觉得这里有insert的话, 之前的find应该
             * 是可以省掉的... */
			error = ep_insert(ep, &epds, tf.file, fd, full_check);
		} else
			/* 找到了!? 重复添加! */
			error = -EEXIST;
		if (full_check)
			// 清空文件检查列表
			clear_tfile_check_list();
		break;
		/* 删除和修改操作都比较简单 */
	case EPOLL_CTL_DEL:
		if (epi)
			error = ep_remove(ep, epi);
		else
			error = -ENOENT;
		break;
	case EPOLL_CTL_MOD:
		if (epi) {
			epds.events |= POLLERR | POLLHUP;
			error = ep_modify(ep, epi, &epds);
		} else
			error = -ENOENT;
		break;
	}
	if (tep != NULL)
		mutex_unlock(&tep->mtx);
	mutex_unlock(&ep->mtx);

error_tgt_fput:
	if (full_check)
		mutex_unlock(&epmutex);

	fdput(tf);
error_fput:
	fdput(f);
error_return:

	return error;
}

/*
 * Implement the event wait interface for the eventpoll file. It is the kernel
 * part of the user space epoll_wait(2).
 */
SYSCALL_DEFINE4(epoll_wait, int, epfd, struct epoll_event __user *, events,
		int, maxevents, int, timeout)
{
	int error;
	struct fd f;
	struct eventpoll *ep;

	/* The maximum number of event must be greater than zero */
	// 检查输入数据有效性
	if (maxevents <= 0 || maxevents > EP_MAX_EVENTS)
		return -EINVAL;

	/* Verify that the area passed by the user is writeable */
    /* 这个地方有必要说明一下:
     * 内核对应用程序采取的策略是"绝对不信任",
     * 所以内核跟应用程序之间的数据交互大都是copy, 不允许(也时候也是不能...)指针引用.
     * epoll_wait()需要内核返回数据给用户空间, 内存由用户程序提供,
     * 所以内核会用一些手段来验证这一段内存空间是不是有效的.
     */
	if (!access_ok(VERIFY_WRITE, events, maxevents * sizeof(struct epoll_event)))
		return -EFAULT;

	/* Get the "struct file *" for the eventpoll file */
	/* 获取epollfd的struct file, epollfd也是文件嘛 */
	f = fdget(epfd);
	if (!f.file)
		return -EBADF;

	/*
	 * We have to check that the file structure underneath the fd
	 * the user passed to us _is_ an eventpoll file.
	 */
	  /* 检查一下它是不是一个真正的epollfd... */
	error = -EINVAL;
	if (!is_file_epoll(f.file))
		goto error_fput;

	/*
	 * At this point it is safe to assume that the "private_data" contains
	 * our own data structure.
	 */
	 /* 获取eventpoll结构 */
	// 取得ep 结构
	ep = f.file->private_data;

	/* Time to fish for events ... */
	/* OK, 睡觉, 等待事件到来~~ */
	// 等待事件 
	error = ep_poll(ep, events, maxevents, timeout);

error_fput:
	fdput(f);
	return error;
}

/*
 * Implement the event wait interface for the eventpoll file. It is the kernel
 * part of the user space epoll_pwait(2).
 */
SYSCALL_DEFINE6(epoll_pwait, int, epfd, struct epoll_event __user *, events,
		int, maxevents, int, timeout, const sigset_t __user *, sigmask,
		size_t, sigsetsize)
{
	int error;
	sigset_t ksigmask, sigsaved;

	/*
	 * If the caller wants a certain signal mask to be set during the wait,
	 * we apply it here.
	 */
	if (sigmask) {
		if (sigsetsize != sizeof(sigset_t))
			return -EINVAL;
		if (copy_from_user(&ksigmask, sigmask, sizeof(ksigmask)))
			return -EFAULT;
		sigsaved = current->blocked;
		set_current_blocked(&ksigmask);
	}

	error = sys_epoll_wait(epfd, events, maxevents, timeout);

	/*
	 * If we changed the signal mask, we need to restore the original one.
	 * In case we've got a signal while waiting, we do not restore the
	 * signal mask yet, and we allow do_signal() to deliver the signal on
	 * the way back to userspace, before the signal mask is restored.
	 */
	if (sigmask) {
		if (error == -EINTR) {
			memcpy(&current->saved_sigmask, &sigsaved,
			       sizeof(sigsaved));
			set_restore_sigmask();
		} else
			set_current_blocked(&sigsaved);
	}

	return error;
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE6(epoll_pwait, int, epfd,
			struct epoll_event __user *, events,
			int, maxevents, int, timeout,
			const compat_sigset_t __user *, sigmask,
			compat_size_t, sigsetsize)
{
	long err;
	compat_sigset_t csigmask;
	sigset_t ksigmask, sigsaved;

	/*
	 * If the caller wants a certain signal mask to be set during the wait,
	 * we apply it here.
	 */
	if (sigmask) {
		if (sigsetsize != sizeof(compat_sigset_t))
			return -EINVAL;
		if (copy_from_user(&csigmask, sigmask, sizeof(csigmask)))
			return -EFAULT;
		sigset_from_compat(&ksigmask, &csigmask);
		sigsaved = current->blocked;
		set_current_blocked(&ksigmask);
	}

	err = sys_epoll_wait(epfd, events, maxevents, timeout);

	/*
	 * If we changed the signal mask, we need to restore the original one.
	 * In case we've got a signal while waiting, we do not restore the
	 * signal mask yet, and we allow do_signal() to deliver the signal on
	 * the way back to userspace, before the signal mask is restored.
	 */
	if (sigmask) {
		if (err == -EINTR) {
			memcpy(&current->saved_sigmask, &sigsaved,
			       sizeof(sigsaved));
			set_restore_sigmask();
		} else
			set_current_blocked(&sigsaved);
	}

	return err;
}
#endif
// epoll 文件系统的相关实现  
// epoll 文件系统初始化, 在系统启动时会调用

static int __init eventpoll_init(void)
{
	struct sysinfo si;

	si_meminfo(&si);
	/*
	 * Allows top 4% of lomem to be allocated for epoll watches (per user).
	 */
	 // 限制可添加到epoll的最多的描述符数量
	max_user_watches = (((si.totalram - si.totalhigh) / 25) << PAGE_SHIFT) /
		EP_ITEM_COST;
	BUG_ON(max_user_watches < 0);
	// 初始化递归检查队列	

	/*
	 * Initialize the structure used to perform epoll file descriptor
	 * inclusion loops checks.
	 */
	ep_nested_calls_init(&poll_loop_ncalls);

	/* Initialize the structure used to perform safe poll wait head wake ups */
	ep_nested_calls_init(&poll_safewake_ncalls);

	/* Initialize the structure used to perform file's f_op->poll() calls */
	ep_nested_calls_init(&poll_readywalk_ncalls);

	/*
	 * We can have many thousands of epitems, so prevent this from
	 * using an extra cache line on 64-bit (and smaller) CPUs
	 */
	BUILD_BUG_ON(sizeof(void *) <= 8 && sizeof(struct epitem) > 128);
	// epoll 使用的slab分配器分别用来分配epitem和eppoll_entry  
	/* Allocates slab cache used to allocate "struct epitem" items */
	epi_cache = kmem_cache_create("eventpoll_epi", sizeof(struct epitem),
			0, SLAB_HWCACHE_ALIGN | SLAB_PANIC, NULL);

	/* Allocates slab cache used to allocate "struct eppoll_entry" */
	pwq_cache = kmem_cache_create("eventpoll_pwq",
			sizeof(struct eppoll_entry), 0, SLAB_PANIC, NULL);

	return 0;
}
fs_initcall(eventpoll_init);
