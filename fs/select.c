/*
 * This file contains the procedures for the handling of select and poll
 *
 * Created for Linux based loosely upon Mathius Lattner's minix
 * patches by Peter MacDonald. Heavily edited by Linus.
 *
 *  4 February 1994
 *     COFF/ELF binary emulation. If the process has the STICKY_TIMEOUTS
 *     flag set in its personality we do *not* modify the given timeout
 *     parameter to reflect time remaining.
 *
 *  24 January 2000
 *     Changed sys_poll()/do_poll() to use PAGE_SIZE chunk-based allocation 
 *     of fds to overcome nfds < 16390 descriptors limit (Tigran Aivazian).
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/personality.h> /* for STICKY_TIMEOUTS */
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/rcupdate.h>
#include <linux/hrtimer.h>
#include <linux/sched/rt.h>
#include <linux/freezer.h>
#include <net/busy_poll.h>
#include <linux/vmalloc.h>

#include <asm/uaccess.h>


/*
 * Estimate expected accuracy in ns from a timeval.
 *
 * After quite a bit of churning around, we've settled on
 * a simple thing of taking 0.1% of the timeout as the
 * slack, with a cap of 100 msec.
 * "nice" tasks get a 0.5% slack instead.
 *
 * Consider this comment an open invitation to come up with even
 * better solutions..
 */

#define MAX_SLACK	(100 * NSEC_PER_MSEC)

static long __estimate_accuracy(struct timespec *tv)
{
	long slack;
	int divfactor = 1000;

	if (tv->tv_sec < 0)
		return 0;

	if (task_nice(current) > 0)
		divfactor = divfactor / 5;

	if (tv->tv_sec > MAX_SLACK / (NSEC_PER_SEC/divfactor))
		return MAX_SLACK;

	slack = tv->tv_nsec / divfactor;
	slack += tv->tv_sec * (NSEC_PER_SEC/divfactor);

	if (slack > MAX_SLACK)
		return MAX_SLACK;

	return slack;
}

long select_estimate_accuracy(struct timespec *tv)
{
	unsigned long ret;
	struct timespec now;

	/*
	 * Realtime tasks get a slack of 0 for obvious reasons.
	 */

	if (rt_task(current))
		return 0;

	ktime_get_ts(&now);
	now = timespec_sub(*tv, now);
	ret = __estimate_accuracy(&now);
	if (ret < current->timer_slack_ns)
		return current->timer_slack_ns;
	return ret;
}


// 申请的物理页都会将起始地址强制转换成该结构体指针
struct poll_table_page {
	// 指向下一个申请的物理页
	struct poll_table_page * next;
	 // 指向entries[]中首个待分配(空的) poll_table_entry地址
	struct poll_table_entry * entry;
	 // 该page页后面剩余的空间都是待分配的
	struct poll_table_entry entries[0];
	 //  poll_table_entry结构体
};

#define POLL_TABLE_FULL(table) \
	((unsigned long)((table)->entry+1) > PAGE_SIZE + (unsigned long)(table))

/*
 * Ok, Peter made a complicated, but straightforward multiple_wait() function.
 * I have rewritten this, taking some shortcuts: This code may not be easy to
 * follow, but it should be free of race-conditions, and it's practical. If you
 * understand what I'm doing here, then you understand how the linux
 * sleep/wakeup mechanism works.
 *
 * Two very simple procedures, poll_wait() and poll_freewait() make all the
 * work.  poll_wait() is an inline-function defined in <linux/poll.h>,
 * as all select/poll functions have to call it to add an entry to the
 * poll table.
 */
static void __pollwait(struct file *filp, wait_queue_head_t *wait_address,
		       poll_table *p);
// poll_wqueues 的初始化:  
// 初始化 poll_wqueues , __pollwait会在文件就绪时被调用  
void poll_initwait(struct poll_wqueues *pwq)
{
	// 初始化poll_table, 相当于调用基类的构造函数  
	init_poll_funcptr(&pwq->pt, __pollwait);
	pwq->polling_task = current;//将当前进程记录在pwq结构体
	pwq->triggered = 0;
	pwq->error = 0;
	pwq->table = NULL;
	pwq->inline_index = 0;
}
EXPORT_SYMBOL(poll_initwait);

static void free_poll_entry(struct poll_table_entry *entry)
{
	// 从等待队列中删除, 释放文件引用计数
	remove_wait_queue(entry->wait_address, &entry->wait);
	fput(entry->filp);
}
// 清理poll_wqueues 占用的资源
void poll_freewait(struct poll_wqueues *pwq)
{
	struct poll_table_page * p = pwq->table;
	int i;
	 // 遍历所有已分配的inline poll_table_entry
	for (i = 0; i < pwq->inline_index; i++)
		free_poll_entry(pwq->inline_entries + i);
	// 遍历在poll_table_page上分配的inline poll_table_entry 
	// 并释放poll_table_page
	while (p) {
		struct poll_table_entry * entry;
		struct poll_table_page *old;

		entry = p->entry;
		do {
			entry--;
			free_poll_entry(entry);
		} while (entry > p->entries);
		old = p;
		p = p->next;
		free_page((unsigned long) old);
	}
}
EXPORT_SYMBOL(poll_freewait);
// 分配或使用已先前申请的 poll_table_entry,
static struct poll_table_entry *poll_get_entry(struct poll_wqueues *p)
{
	struct poll_table_page *table = p->table;

	if (p->inline_index < N_INLINE_POLL_ENTRIES)
		return p->inline_entries + p->inline_index++;

	if (!table || POLL_TABLE_FULL(table)) {
		struct poll_table_page *new_table;

		new_table = (struct poll_table_page *) __get_free_page(GFP_KERNEL);
		if (!new_table) {
			p->error = -ENOMEM;
			return NULL;
		}
		new_table->entry = new_table->entries;
		new_table->next = table;
		p->table = new_table;
		table = new_table;
	}

	return table->entry++;
}

static int __pollwake(wait_queue_t *wait, unsigned mode, int sync, void *key)
{
	struct poll_wqueues *pwq = wait->private;
	// 将调用进程 pwq->polling_task 关联到 dummy_wait  
	DECLARE_WAITQUEUE(dummy_wait, pwq->polling_task);

	/*
	 * Although this function is called under waitqueue lock, LOCK
	 * doesn't imply write barrier and the users expect write
	 * barrier semantics on wakeup functions.  The following
	 * smp_wmb() is equivalent to smp_wmb() in try_to_wake_up()
	 * and is paired with smp_store_mb() in poll_schedule_timeout.
	 */
	smp_wmb();
	// select()用户进程只要有被唤醒过，就不可能再次进入睡眠，因为这个标志在睡眠的时候有用
	pwq->triggered = 1;

	/*
	 * Perform the default wake up operation using a dummy
	 * waitqueue.
	 *
	 * TODO: This is hacky but there currently is no interface to
	 * pass in @sync.  @sync is scheduled to be removed and once
	 * that happens, wake_up_process() can be used directly.
	 */
	 // 默认通用的唤醒函数
	return default_wake_function(&dummy_wait, mode, sync, key);
}
// 在等待队列(wait_queue_t)上回调函数(func)  
// 文件就绪后被调用，唤醒调用进程，其中key是文件提供的当前状态掩码
static int pollwake(wait_queue_t *wait, unsigned mode, int sync, void *key)
{
	struct poll_table_entry *entry;
	// 取得poll_table_entry结构体指针
	entry = container_of(wait, struct poll_table_entry, wait);
	/*这里的条件判断至关重要，避免应用进程被误唤醒*/
	if (key && !((unsigned long)key & entry->key))
		return 0;
	// 唤醒
	return __pollwake(wait, mode, sync, key);
}

/* Add a new entry */
// wait_queue设置函数  
// poll/select 向文件wait_queue中添加节点的方法

static void __pollwait(struct file *filp, wait_queue_head_t *wait_address,
				poll_table *p)
{
	//根据poll_wqueues的成员pt指针p找到所在的poll_wqueues结构指针
	struct poll_wqueues *pwq = container_of(p, struct poll_wqueues, pt);
	struct poll_table_entry *entry = poll_get_entry(pwq);
	if (!entry)
		return;
	entry->filp = get_file(filp);   // 保存对应的file结构体
	entry->wait_address = wait_address;  // 保存来自设备驱动程序的等待队列头
	entry->key = p->_key;  // 保存对该fd关心的事件掩码
	  // 初始化等待队列项，pollwake是唤醒该等待队列项时候调用的函数
	init_waitqueue_func_entry(&entry->wait, pollwake);
	      // 将poll_wqueues作为该等待队列项的私有数据，后面使用
	entry->wait.private = pwq;
		   // 将该等待队列项添加到从驱动程序中传递过来的等待队列头中去
	add_wait_queue(wait_address, &entry->wait);
}

int poll_schedule_timeout(struct poll_wqueues *pwq, int state,
			  ktime_t *expires, unsigned long slack)
{
	int rc = -EINTR;
	//设置进程状态

	set_current_state(state);
	 // 这个triggered在什么时候被置1的呢?只要有一个fd
	 // 对应的设备将当前应用进程唤醒后将会把它设置成1
	if (!pwq->triggered)
		rc = schedule_hrtimeout_range(expires, slack, HRTIMER_MODE_ABS);
	__set_current_state(TASK_RUNNING);

	/*
	 * Prepare for the next iteration.
	 *
	 * The following smp_store_mb() serves two purposes.  First, it's
	 * the counterpart rmb of the wmb in pollwake() such that data
	 * written before wake up is always visible after wake up.
	 * Second, the full barrier guarantees that triggered clearing
	 * doesn't pass event check of the next iteration.  Note that
	 * this problem doesn't exist for the first iteration as
	 * add_wait_queue() has full barrier semantics.
	 */
	smp_store_mb(pwq->triggered, 0);

	return rc;
}
EXPORT_SYMBOL(poll_schedule_timeout);

/**
 * poll_select_set_timeout - helper function to setup the timeout value
 * @to:		pointer to timespec variable for the final timeout
 * @sec:	seconds (from user space)
 * @nsec:	nanoseconds (from user space)
 *
 * Note, we do not use a timespec for the user space value here, That
 * way we can use the function for timeval and compat interfaces as well.
 *
 * Returns -EINVAL if sec/nsec are not normalized. Otherwise 0.
 */
int poll_select_set_timeout(struct timespec *to, long sec, long nsec)
{
	struct timespec ts = {.tv_sec = sec, .tv_nsec = nsec};

	if (!timespec_valid(&ts))
		return -EINVAL;

	/* Optimize for the zero timeout value here */
	if (!sec && !nsec) {
		to->tv_sec = to->tv_nsec = 0;
	} else {
		ktime_get_ts(to);
		*to = timespec_add_safe(*to, ts);
	}
	return 0;
}

static int poll_select_copy_remaining(struct timespec *end_time, void __user *p,
				      int timeval, int ret)
{
	struct timespec rts;
	struct timeval rtv;

	if (!p)
		return ret;

	if (current->personality & STICKY_TIMEOUTS)
		goto sticky;

	/* No update for zero timeout */
	if (!end_time->tv_sec && !end_time->tv_nsec)
		return ret;

	ktime_get_ts(&rts);
	rts = timespec_sub(*end_time, rts);
	if (rts.tv_sec < 0)
		rts.tv_sec = rts.tv_nsec = 0;

	if (timeval) {
		if (sizeof(rtv) > sizeof(rtv.tv_sec) + sizeof(rtv.tv_usec))
			memset(&rtv, 0, sizeof(rtv));
		rtv.tv_sec = rts.tv_sec;
		rtv.tv_usec = rts.tv_nsec / NSEC_PER_USEC;

		if (!copy_to_user(p, &rtv, sizeof(rtv)))
			return ret;

	} else if (!copy_to_user(p, &rts, sizeof(rts)))
		return ret;

	/*
	 * If an application puts its timeval in read-only memory, we
	 * don't want the Linux-specific update to the timeval to
	 * cause a fault after the select has completed
	 * successfully. However, because we're not updating the
	 * timeval, we can't restart the system call.
	 */

sticky:
	if (ret == -ERESTARTNOHAND)
		ret = -EINTR;
	return ret;
}

#define FDS_IN(fds, n)		(fds->in + n)
#define FDS_OUT(fds, n)		(fds->out + n)
#define FDS_EX(fds, n)		(fds->ex + n)

#define BITS(fds, n)	(*FDS_IN(fds, n)|*FDS_OUT(fds, n)|*FDS_EX(fds, n))

static int max_select_fd(unsigned long n, fd_set_bits *fds)
{
	unsigned long *open_fds;
	unsigned long set;
	int max;
	struct fdtable *fdt;

	/* handle last in-complete long-word first */
	set = ~(~0UL << (n & (BITS_PER_LONG-1)));
	n /= BITS_PER_LONG;
	fdt = files_fdtable(current->files);
	open_fds = fdt->open_fds + n;
	max = 0;
	if (set) {
		set &= BITS(fds, n);
		if (set) {
			if (!(set & ~*open_fds))
				goto get_max;
			return -EBADF;
		}
	}
	while (n) {
		open_fds--;
		n--;
		set = BITS(fds, n);
		if (!set)
			continue;
		if (set & ~*open_fds)
			return -EBADF;
		if (max)
			continue;
get_max:
		do {
			max++;
			set >>= 1;
		} while (set);
		max += n * BITS_PER_LONG;
	}

	return max;
}

#define POLLIN_SET (POLLRDNORM | POLLRDBAND | POLLIN | POLLHUP | POLLERR)
#define POLLOUT_SET (POLLWRBAND | POLLWRNORM | POLLOUT | POLLERR)
#define POLLEX_SET (POLLPRI)

static inline void wait_key_set(poll_table *wait, unsigned long in,
				unsigned long out, unsigned long bit,
				unsigned int ll_flag)
{
	wait->_key = POLLEX_SET | ll_flag;
	if (in & bit)
		wait->_key |= POLLIN_SET;
	if (out & bit)
		wait->_key |= POLLOUT_SET;
}

int do_select(int n, fd_set_bits *fds, struct timespec *end_time)
{
	ktime_t expire, *to = NULL;
	struct poll_wqueues table;
	poll_table *wait;
	int retval, i, timed_out = 0;
	unsigned long slack = 0;
	unsigned int busy_flag = net_busy_loop_on() ? POLL_BUSY_LOOP : 0;
	unsigned long busy_end = 0;

	rcu_read_lock();
	  // 根据已经设置好的fd位图检查用户打开的fd, 要求对应fd必须打开, 并且返回
	  // 最大的fd
	retval = max_select_fd(n, fds);  //获取最大文件描述
	rcu_read_unlock();

	if (retval < 0)
		return retval;
	n = retval;
	// 一些重要的初始化:
	  // poll_wqueues.poll_table.qproc函数指针初始化，该函数是驱动程序中poll函数实
	    // 现中必须要调用的poll_wait()中使用的函数
	    // 设置函数指针_qproc    为__pollwait
	poll_initwait(&table); //初始化用于等待的数据，当文件描述符就绪时回调 //初始化等待队列
	wait = &table.pt;
	if (end_time && !end_time->tv_sec && !end_time->tv_nsec) {
		wait->_qproc = NULL;
		 // 如果系统调用带进来的超时时间为0，那么设置
		   // timed_out = 1，表示不阻塞，直接返回。
		timed_out = 1;
	}
	 // 超时时间转换
	if (end_time && !timed_out)
		slack = select_estimate_accuracy(end_time);

	retval = 0;
	for (;;) {
		unsigned long *rinp, *routp, *rexp, *inp, *outp, *exp;
		bool can_busy_loop = false;

		inp = fds->in; outp = fds->out; exp = fds->ex;
		rinp = fds->res_in; routp = fds->res_out; rexp = fds->res_ex;
		//遍历每个描述符
		 // 所有n个fd的循环
		for (i = 0; i < n; ++rinp, ++routp, ++rexp) {
			unsigned long in, out, ex, all_bits, bit = 1, mask, j;
			unsigned long res_in = 0, res_out = 0, res_ex = 0;
			 // 先取出当前循环周期中的字长个文件描述符对应的bitmaps
			in = *inp++; out = *outp++; ex = *exp++;
			 // 组合一下，有的fd可能只监测读，或者写，
			 // 或者err，或者同时都监测
			all_bits = in | out | ex;
			 // 这32个描述符没有任何状态被监测，就跳入
			 // 下一个32个fd的循环中
			if (all_bits == 0) {
				i += BITS_PER_LONG; //每字长个文件描述符一个循环，正好一个long型数
				continue;
			}
			//遍历每个位
			// 初始bit = 1
			for (j = 0; j < BITS_PER_LONG; ++j, ++i, bit <<= 1) {
				struct fd f;
				if (i >= n)
					break;
				if (!(bit & all_bits))
					continue;
				//从文件描述符(fd)获取文件结构
				f = fdget(i);//找到目标fd
				if (f.file) {
					const struct file_operations *f_op;
					f_op = f.file->f_op;
				// 没有 f_op 的话就认为一直处于就绪状态
					mask = DEFAULT_POLLMASK;
					//调用相应的poll操作
					if (f_op->poll) {
						// 设置当前fd待监测的事件掩码
						wait_key_set(wait, in, out,
							     bit, busy_flag);
						
						/*
						调用驱动程序中的poll函数，以evdev驱动中的
						evdev_poll()为例该函数会调用函数poll_wait(file, &evdev->wait, wait)，继续调用__pollwait()回调来分配一个poll_table_entry结构体，该结构体有一个内嵌的等待队列项，
						设置好wake时调用的回调函数后将其添加到驱动程序中的等待队列头中。
						*/
						 // 获取当前的就绪状态, 并添加到文件的对应等待队列中
						  //执行文件系统的poll函数，检测IO事件
						mask = (*f_op->poll)(f.file, wait);
					}
					 // 释放file结构指针，实际就是减小他的一个引用计数字段f_count。
					fdput(f);
					  // mask是每一个fop->poll()程序返回的设备状态掩码。
					if ((mask & POLLIN_SET) && (in & bit)) {
						res_in |= bit;	  // fd对应的设备可读
						retval++;
					// 如果已有就绪事件就不再向其他文件的
					 // 等待队列中添加回调函数
						wait->_qproc = NULL;	   // 后续有用，避免重复执行__pollwait()
					}
					if ((mask & POLLOUT_SET) && (out & bit)) {
						res_out |= bit;	 // fd对应的设备可写
						retval++;
						wait->_qproc = NULL;
					}
					if ((mask & POLLEX_SET) && (ex & bit)) {
						res_ex |= bit;
						retval++;
						wait->_qproc = NULL;
					}
					/* got something, stop busy polling */
					//当返回值不为零，则停止循环轮询
					if (retval) {
						can_busy_loop = false;
						busy_flag = 0;

					/*
					 * only remember a returned
					 * POLL_BUSY_LOOP if we asked for it
					 */
					} else if (busy_flag & mask)
						can_busy_loop = true;

				}
			}
			 // 根据poll的结果写回到输出位图里,返回给上级函数
			if (res_in)
				*rinp = res_in;
			if (res_out)
				*routp = res_out;
			if (res_ex)
				*rexp = res_ex;
			/*
这里的目的纯粹是为了增加一个抢占点。
在支持抢占式调度的内核中（定义了CONFIG_PREEMPT），cond_resched是空操作。
 */
			cond_resched();  //调度新程序运行
		}
		wait->_qproc = NULL;
		/*跳出这个大循环的条件有: 有设备就绪或有异常(retval!=0), 超时(timed_out= 1), 或者有待处理信号出现*/
		if (retval || timed_out || signal_pending(current))
			break;
		if (table.error) {
			retval = table.error;
			break;
		}

		/* only if found POLL_BUSY_LOOP sockets && not out of time */
		if (can_busy_loop && !need_resched()) {
			if (!busy_end) {
				busy_end = busy_loop_end_time();
				continue;
			}
			if (!busy_loop_timeout(busy_end))
				continue;
		}
		busy_flag = 0;

		/*
		 * If this is the first loop and we have a timeout
		 * given, then we convert to ktime_t and set the to
		 * pointer to the expiry value.
		 */
		 //首轮循环设置超时
		if (end_time && !to) {
			expire = timespec_to_ktime(*end_time);
			to = &expire;
		}
		 // 第一次循环中，当前用户进程从这里进入休眠，
		 // 上面传下来的超时时间只是为了用在睡眠超时这里而已
		   // 超时，poll_schedule_timeout()返回0；被唤醒时返回-EINTR
		    //设置当前进程状态为TASK_INTERRUPTIBLE，进入睡眠直到超时
		if (!poll_schedule_timeout(&table, TASK_INTERRUPTIBLE,
					   to, slack))
			timed_out = 1;/* 超时后，将其设置成1，方便后面退出循环返回到上层 */
	}
	// 清理各个驱动程序的等待队列头，同时释放掉所有空出来
	// 的page页(poll_table_entry)

	poll_freewait(&table);

	return retval;
}

/*
 * We can actually return ERESTARTSYS instead of EINTR, but I'd
 * like to be certain this leads to no problems. So I return
 * EINTR just for safety.
 *
 * Update: ERESTARTSYS breaks at least the xview clock binary, so
 * I'm trying ERESTARTNOHAND which restart only when you want to.
 */
int core_sys_select(int n, fd_set __user *inp, fd_set __user *outp,
			   fd_set __user *exp, struct timespec *end_time)
{
	fd_set_bits fds;
	void *bits;
	int ret, max_fds;
	size_t size, alloc_size;
	struct fdtable *fdt;
	/* Allocate small arguments on the stack to save memory and be faster */
	 // 256/64 = 4, stack中分配的空间
	long stack_fds[SELECT_STACK_ALLOC/sizeof(long)];

	ret = -EINVAL;
	if (n < 0)
		goto out_nofds;

	/* max_fds can increase, so grab it once to avoid race */
	rcu_read_lock();
	 // RCU ref, 获取当前进程的文件描述符表
	fdt = files_fdtable(current->files);
	max_fds = fdt->max_fds;
	rcu_read_unlock();
	//不能大于最大描述符限制
	//select可监控个数小于等于进程可打开的文件描述上限
	if (n > max_fds)
		n = max_fds;

	/*
	 * We need 6 bitmaps (in/out/ex for both incoming and outgoing),
	 * since we used fdset we need to allocate memory in units of
	 * long-words. 
	 */
	// 以一个文件描述符占一bit来计算，传递进来的这些fd_set需要用掉多少个字
	//根据n来计算需要多少个字节, 展开为size=4*(n+32-1)/32
	size = FDS_BYTES(n);
	bits = stack_fds;
	//需要6个bitmaps (int/out/ex 以及其对应的3个结果集)
	// 除6，因为每个文件描述符需要6个bitmaps
	if (size > sizeof(stack_fds) / 6) {
		// 栈上的空间不够, 申请内存, 全部使用堆上的空间
		/* Not enough space in on-stack array; must use kmalloc */
		ret = -ENOMEM;
		if (size > (SIZE_MAX / 6))
			goto out_nofds;

		alloc_size = 6 * size;
		 // stack中分配的太小，直接kmalloc
		bits = kmalloc(alloc_size, GFP_KERNEL|__GFP_NOWARN);
		 //失败了的话继续vmalloc
		if (!bits && alloc_size > PAGE_SIZE)
			bits = vmalloc(alloc_size);

		if (!bits)
			goto out_nofds;
	}
	fds.in      = bits;
	fds.out     = bits +   size;
	fds.ex      = bits + 2*size;
	fds.res_in  = bits + 3*size;
	fds.res_out = bits + 4*size;
	fds.res_ex  = bits + 5*size;
	// get_fd_set仅仅调用copy_from_user从用户空间拷贝了fd_set
	if ((ret = get_fd_set(n, inp, fds.in)) ||
	    (ret = get_fd_set(n, outp, fds.out)) ||
	    (ret = get_fd_set(n, exp, fds.ex)))
		goto out;
	// 对这些存放返回状态的字段清0
	zero_fd_set(n, fds.res_in);
	zero_fd_set(n, fds.res_out);
	zero_fd_set(n, fds.res_ex);

	ret = do_select(n, &fds, end_time);

	if (ret < 0)  // 有错误
		goto out;
	if (!ret) {  // 超时返回，无设备就绪
		ret = -ERESTARTNOHAND;
		if (signal_pending(current))
			goto out;
		ret = 0;
	}
	// 把结果集,拷贝回用户空间
	if (set_fd_set(n, inp, fds.res_in) ||
	    set_fd_set(n, outp, fds.res_out) ||
	    set_fd_set(n, exp, fds.res_ex))
		ret = -EFAULT;

out:
	if (bits != stack_fds)
		kvfree(bits);	// 如果有申请空间，那么释放fds对应的空间
out_nofds:
	return ret; // 返回就绪的文件描述符的个数
}

SYSCALL_DEFINE5(select, int, n, fd_set __user *, inp, fd_set __user *, outp,
		fd_set __user *, exp, struct timeval __user *, tvp)
{
	struct timespec end_time, *to = NULL;
	struct timeval tv;
	int ret;
	// 如果超时值非NULL
	if (tvp) {
		// 从用户空间取数据到内核空间
		if (copy_from_user(&tv, tvp, sizeof(tv)))
			return -EFAULT;
		// 计算超时时间
		to = &end_time;
		 // 得到timespec格式的未来超时时间
		if (poll_select_set_timeout(to,
				tv.tv_sec + (tv.tv_usec / USEC_PER_SEC),
				(tv.tv_usec % USEC_PER_SEC) * NSEC_PER_USEC))
			return -EINVAL;
	}

	ret = core_sys_select(n, inp, outp, exp, to);
	   /*如果有超时值, 并拷贝离超时时刻还剩的时间到用户空间的timeval中*/
	ret = poll_select_copy_remaining(&end_time, tvp, 1, ret);
	// 返回就绪的文件描述符的个数
	return ret;
}

static long do_pselect(int n, fd_set __user *inp, fd_set __user *outp,
		       fd_set __user *exp, struct timespec __user *tsp,
		       const sigset_t __user *sigmask, size_t sigsetsize)
{
	sigset_t ksigmask, sigsaved;
	struct timespec ts, end_time, *to = NULL;
	int ret;

	if (tsp) {
		if (copy_from_user(&ts, tsp, sizeof(ts)))
			return -EFAULT;

		to = &end_time;
		if (poll_select_set_timeout(to, ts.tv_sec, ts.tv_nsec))
			return -EINVAL;
	}

	if (sigmask) {
		/* XXX: Don't preclude handling different sized sigset_t's.  */
		if (sigsetsize != sizeof(sigset_t))
			return -EINVAL;
		if (copy_from_user(&ksigmask, sigmask, sizeof(ksigmask)))
			return -EFAULT;

		sigdelsetmask(&ksigmask, sigmask(SIGKILL)|sigmask(SIGSTOP));
		sigprocmask(SIG_SETMASK, &ksigmask, &sigsaved);
	}

	ret = core_sys_select(n, inp, outp, exp, to);
	ret = poll_select_copy_remaining(&end_time, tsp, 0, ret);

	if (ret == -ERESTARTNOHAND) {
		/*
		 * Don't restore the signal mask yet. Let do_signal() deliver
		 * the signal on the way back to userspace, before the signal
		 * mask is restored.
		 */
		if (sigmask) {
			memcpy(&current->saved_sigmask, &sigsaved,
					sizeof(sigsaved));
			set_restore_sigmask();
		}
	} else if (sigmask)
		sigprocmask(SIG_SETMASK, &sigsaved, NULL);

	return ret;
}

/*
 * Most architectures can't handle 7-argument syscalls. So we provide a
 * 6-argument version where the sixth argument is a pointer to a structure
 * which has a pointer to the sigset_t itself followed by a size_t containing
 * the sigset size.
 */
SYSCALL_DEFINE6(pselect6, int, n, fd_set __user *, inp, fd_set __user *, outp,
		fd_set __user *, exp, struct timespec __user *, tsp,
		void __user *, sig)
{
	size_t sigsetsize = 0;
	sigset_t __user *up = NULL;

	if (sig) {
		if (!access_ok(VERIFY_READ, sig, sizeof(void *)+sizeof(size_t))
		    || __get_user(up, (sigset_t __user * __user *)sig)
		    || __get_user(sigsetsize,
				(size_t __user *)(sig+sizeof(void *))))
			return -EFAULT;
	}

	return do_pselect(n, inp, outp, exp, tsp, up, sigsetsize);
}

#ifdef __ARCH_WANT_SYS_OLD_SELECT
struct sel_arg_struct {
	unsigned long n;
	fd_set __user *inp, *outp, *exp;
	struct timeval __user *tvp;
};

SYSCALL_DEFINE1(old_select, struct sel_arg_struct __user *, arg)
{
	struct sel_arg_struct a;

	if (copy_from_user(&a, arg, sizeof(a)))
		return -EFAULT;
	return sys_select(a.n, a.inp, a.outp, a.exp, a.tvp);
}
#endif

struct poll_list {
	struct poll_list *next;
	int len;
	struct pollfd entries[0];
};

#define POLLFD_PER_PAGE  ((PAGE_SIZE-sizeof(struct poll_list)) / sizeof(struct pollfd))

/*
 * Fish for pollable events on the pollfd->fd file descriptor. We're only
 * interested in events matching the pollfd->events mask, and the result
 * matching that mask is both recorded in pollfd->revents and returned. The
 * pwait poll_table will be used by the fd-provided poll handler for waiting,
 * if pwait->_qproc is non-NULL.
 */
static inline unsigned int do_pollfd(struct pollfd *pollfd, poll_table *pwait,
				     bool *can_busy_poll,
				     unsigned int busy_flag)
{
	unsigned int mask;
	int fd;

	mask = 0;
	fd = pollfd->fd;
	if (fd >= 0) {
		// 取得fd对应的文件结构体
		struct fd f = fdget(fd);
		mask = POLLNVAL;
		if (f.file) {
			// 如果没有 f_op 或 f_op->poll 则认为文件始终处于就绪状态. 
			mask = DEFAULT_POLLMASK;
			if (f.file->f_op->poll) {
				// 设置关注的事件掩码
				pwait->_key = pollfd->events|POLLERR|POLLHUP;
				pwait->_key |= busy_flag;
			// 注册回调函数，并返回当前就绪状态，就绪后会调用pollwake  
				mask = f.file->f_op->poll(f.file, pwait);
				if (mask & busy_flag)
					*can_busy_poll = true;
			}
			/* Mask out unneeded events. */
			// 移除不需要的状态掩码
			mask &= pollfd->events | POLLERR | POLLHUP;
			// 释放文件
			fdput(f);
		}
	}
	// 更新事件状态
	pollfd->revents = mask;

	return mask;
}
// 释放申请的内存
static int do_poll(unsigned int nfds,  struct poll_list *list,
		   struct poll_wqueues *wait, struct timespec *end_time)
{
	poll_table* pt = &wait->pt;
	ktime_t expire, *to = NULL;
	int timed_out = 0, count = 0;
	unsigned long slack = 0;
	unsigned int busy_flag = net_busy_loop_on() ? POLL_BUSY_LOOP : 0;
	unsigned long busy_end = 0;

	/* Optimise the no-wait case */
	// 优化非阻塞的情形
	if (end_time && !end_time->tv_sec && !end_time->tv_nsec) {
		// 已经超时,直接遍历所有文件描述符, 然后返回
		pt->_qproc = NULL;
		timed_out = 1;
	}

	if (end_time && !timed_out)
		// 估计进程等待时间，纳秒
		slack = select_estimate_accuracy(end_time);
	// 遍历文件，为每个文件的等待队列添加唤醒函数(pollwake)
	for (;;) {
		struct poll_list *walk;
		bool can_busy_loop = false;

		for (walk = list; walk != NULL; walk = walk->next) {
			struct pollfd * pfd, * pfd_end;

			pfd = walk->entries;
			pfd_end = pfd + walk->len;
			for (; pfd != pfd_end; pfd++) {
				/*
				 * Fish for events. If we found one, record it
				 * and kill poll_table->_qproc, so we don't
				 * needlessly register any other waiters after
				 * this. They'll get immediately deregistered
				 * when we break out and return.
				 */
				 // do_pollfd 会向文件对应的wait queue 中添加节点  
                // 和回调函数(如果 pt 不为空)  
                // 并检查当前文件状态并设置返回的掩码 
				if (do_pollfd(pfd, pt, &can_busy_loop,
					      busy_flag)) {
					// 该文件已经准备好了.  
					// 不需要向后面文件的wait queue 中添加唤醒函数了.
					count++;
					pt->_qproc = NULL;
					/* found something, stop busy polling */
					busy_flag = 0;//找到目标事件，可跳出循环
					can_busy_loop = false;
				}
			}
		}
		/*
		 * All waiters have already been registered, so don't provide
		 * a poll_table->_qproc to them on the next loop iteration.
		 */
		 // 下次循环的时候不需要向文件的wait queue 中添加节点,  
		  // 因为前面的循环已经把该添加的都添加了
		pt->_qproc = NULL;
		// 第一次遍历没有发现ready的文件
		if (!count) {
			count = wait->error;
			// 有信号产生
			if (signal_pending(current))
				count = -EINTR;
		}
		// 有ready的文件或已经超时 
		if (count || timed_out)
			break;

		/* only if found POLL_BUSY_LOOP sockets && not out of time */
		if (can_busy_loop && !need_resched()) {
			if (!busy_end) {
				busy_end = busy_loop_end_time();
				continue;
			}
			if (!busy_loop_timeout(busy_end))
				continue;
		}
		busy_flag = 0;

		/*
		 * If this is the first loop and we have a timeout
		 * given, then we convert to ktime_t and set the to
		 * pointer to the expiry value.
		 */
		 // 转换为内核时间
		if (end_time && !to) {
			expire = timespec_to_ktime(*end_time);
			to = &expire;
		}
		// 等待事件就绪, 如果有事件发生或超时，就再循  
		// 环一遍，取得事件状态掩码并计数,  
		// 注意此次循环中, 文件 wait queue 中的节点依然存在  

		if (!poll_schedule_timeout(wait, TASK_INTERRUPTIBLE, to, slack))
			timed_out = 1;
	}
	return count;
}

#define N_STACK_PPS ((sizeof(stack_pps) - sizeof(struct poll_list))  / \
			sizeof(struct pollfd))

int do_sys_poll(struct pollfd __user *ufds, unsigned int nfds,
		struct timespec *end_time)
{
	struct poll_wqueues table;
 	int err = -EFAULT, fdcount, len, size;
	/* Allocate small arguments on the stack to save memory and be
	   faster - use long to make sure the buffer is aligned properly
	   on 64 bit archs to avoid unaligned access */
	   /* 首先使用栈上的空间，节约内存，加速访问 */
	long stack_pps[POLL_STACK_ALLOC/sizeof(long)];
	struct poll_list *const head = (struct poll_list *)stack_pps;
 	struct poll_list *walk = head;
 	unsigned long todo = nfds;

	if (nfds > rlimit(RLIMIT_NOFILE))
		 // 文件描述符数量超过当前进程限制 
		return -EINVAL;
	// 复制用户空间数据到内核  
	len = min_t(unsigned int, nfds, N_STACK_PPS);
	for (;;) {
		walk->next = NULL;
		walk->len = len;
		if (!len)
			break;
		// 复制到当前的 entries
		if (copy_from_user(walk->entries, ufds + nfds-todo,
					sizeof(struct pollfd) * walk->len))
			goto out_fds;

		todo -= walk->len;
		if (!todo)
			break;
		// 栈上空间不足，在堆上申请剩余部分
		len = min(todo, POLLFD_PER_PAGE);
		size = sizeof(struct poll_list) + sizeof(struct pollfd) * len;
		walk = walk->next = kmalloc(size, GFP_KERNEL);
		if (!walk) {
			err = -ENOMEM;
			goto out_fds;
		}
	}
	// 初始化 poll_wqueues 结构, 设置函数指针_qproc  为__pollwait
	poll_initwait(&table);
	// poll
	fdcount = do_poll(nfds, head, &table, end_time);
	// 从文件wait queue 中移除对应的节点, 释放entry.
	poll_freewait(&table);
	// 复制结果到用户空间
	for (walk = head; walk; walk = walk->next) {
		struct pollfd *fds = walk->entries;
		int j;

		for (j = 0; j < walk->len; j++, ufds++)
			//将revents值拷贝到用户空间ufds
			if (__put_user(fds[j].revents, &ufds->revents))
				goto out_fds;
  	}

	err = fdcount;
	// 释放申请的内存  
out_fds:
	walk = head->next;
	while (walk) {
		struct poll_list *pos = walk;
		walk = walk->next;
		kfree(pos);
	}

	return err;
}

static long do_restart_poll(struct restart_block *restart_block)
{
	struct pollfd __user *ufds = restart_block->poll.ufds;
	int nfds = restart_block->poll.nfds;
	struct timespec *to = NULL, end_time;
	int ret;

	if (restart_block->poll.has_timeout) {
		// 获取先前的超时时间 
		end_time.tv_sec = restart_block->poll.tv_sec;
		end_time.tv_nsec = restart_block->poll.tv_nsec;
		to = &end_time;
	}
	// 重新调用 do_sys_poll
	ret = do_sys_poll(ufds, nfds, to);

	if (ret == -EINTR) {
		// 又被信号中断了, 再次重启
		restart_block->fn = do_restart_poll;
		ret = -ERESTART_RESTARTBLOCK;
	}
	return ret;
}

SYSCALL_DEFINE3(poll, struct pollfd __user *, ufds, unsigned int, nfds,
		int, timeout_msecs)
{
	struct timespec end_time, *to = NULL;
	int ret;

	if (timeout_msecs >= 0) {
		to = &end_time;
		// 将相对超时时间msec 转化为绝对时间
		poll_select_set_timeout(to, timeout_msecs / MSEC_PER_SEC,
			NSEC_PER_MSEC * (timeout_msecs % MSEC_PER_SEC));
	}

	ret = do_sys_poll(ufds, nfds, to);
	// do_sys_poll 被信号中断, 重新调用, 对使用者来说 poll 是不会被信号中断的.	
	if (ret == -EINTR) {
		struct restart_block *restart_block;

		restart_block = &current->restart_block;
	// 设置重启的函数
		restart_block->fn = do_restart_poll;
		restart_block->poll.ufds = ufds;
		restart_block->poll.nfds = nfds;

		if (timeout_msecs >= 0) {
			restart_block->poll.tv_sec = end_time.tv_sec;
			restart_block->poll.tv_nsec = end_time.tv_nsec;
			restart_block->poll.has_timeout = 1;
		} else
			restart_block->poll.has_timeout = 0;
        // ERESTART_RESTARTBLOCK 不会返回给用户进程,  
        // 而是会被系统捕获, 然后调用 do_restart_poll,  
		ret = -ERESTART_RESTARTBLOCK;
	}
	return ret;
}

SYSCALL_DEFINE5(ppoll, struct pollfd __user *, ufds, unsigned int, nfds,
		struct timespec __user *, tsp, const sigset_t __user *, sigmask,
		size_t, sigsetsize)
{
	sigset_t ksigmask, sigsaved;
	struct timespec ts, end_time, *to = NULL;
	int ret;

	if (tsp) {
		if (copy_from_user(&ts, tsp, sizeof(ts)))
			return -EFAULT;

		to = &end_time;
		if (poll_select_set_timeout(to, ts.tv_sec, ts.tv_nsec))
			return -EINVAL;
	}

	if (sigmask) {
		/* XXX: Don't preclude handling different sized sigset_t's.  */
		if (sigsetsize != sizeof(sigset_t))
			return -EINVAL;
		if (copy_from_user(&ksigmask, sigmask, sizeof(ksigmask)))
			return -EFAULT;

		sigdelsetmask(&ksigmask, sigmask(SIGKILL)|sigmask(SIGSTOP));
		sigprocmask(SIG_SETMASK, &ksigmask, &sigsaved);
	}

	ret = do_sys_poll(ufds, nfds, to);

	/* We can restart this syscall, usually */
	if (ret == -EINTR) {
		/*
		 * Don't restore the signal mask yet. Let do_signal() deliver
		 * the signal on the way back to userspace, before the signal
		 * mask is restored.
		 */
		if (sigmask) {
			memcpy(&current->saved_sigmask, &sigsaved,
					sizeof(sigsaved));
			set_restore_sigmask();
		}
		ret = -ERESTARTNOHAND;
	} else if (sigmask)
		sigprocmask(SIG_SETMASK, &sigsaved, NULL);

	ret = poll_select_copy_remaining(&end_time, tsp, 0, ret);

	return ret;
}
