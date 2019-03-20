
#include <linux/sched.h>
#include <linux/sched/sysctl.h>
#include <linux/sched/rt.h>
#include <linux/sched/deadline.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/stop_machine.h>
#include <linux/irq_work.h>
#include <linux/tick.h>
#include <linux/slab.h>

#include "cpupri.h"
#include "cpudeadline.h"
#include "cpuacct.h"

struct rq;
struct cpuidle_state;

/* task_struct::on_rq states: */
#define TASK_ON_RQ_QUEUED	1
#define TASK_ON_RQ_MIGRATING	2

extern __read_mostly int scheduler_running;

extern unsigned long calc_load_update;
extern atomic_long_t calc_load_tasks;

extern void calc_global_load_tick(struct rq *this_rq);
extern long calc_load_fold_active(struct rq *this_rq);

#ifdef CONFIG_SMP
extern void update_cpu_load_active(struct rq *this_rq);
#else
static inline void update_cpu_load_active(struct rq *this_rq) { }
#endif

/*
 * Helpers for converting nanosecond timing to jiffy resolution
 */
#define NS_TO_JIFFIES(TIME)	((unsigned long)(TIME) / (NSEC_PER_SEC / HZ))

/*
 * Increase resolution of nice-level calculations for 64-bit architectures.
 * The extra resolution improves shares distribution and load balancing of
 * low-weight task groups (eg. nice +19 on an autogroup), deeper taskgroup
 * hierarchies, especially on larger systems. This is not a user-visible change
 * and does not change the user-interface for setting shares/weights.
 *
 * We increase resolution only if we have enough bits to allow this increased
 * resolution (i.e. BITS_PER_LONG > 32). The costs for increasing resolution
 * when BITS_PER_LONG <= 32 are pretty high and the returns do not justify the
 * increased costs.
 */
#if 0 /* BITS_PER_LONG > 32 -- currently broken: it increases power usage under light load  */
# define SCHED_LOAD_RESOLUTION	10
# define scale_load(w)		((w) << SCHED_LOAD_RESOLUTION)
# define scale_load_down(w)	((w) >> SCHED_LOAD_RESOLUTION)
#else
# define SCHED_LOAD_RESOLUTION	0
# define scale_load(w)		(w)
# define scale_load_down(w)	(w)
#endif

#define SCHED_LOAD_SHIFT	(10 + SCHED_LOAD_RESOLUTION)
#define SCHED_LOAD_SCALE	(1L << SCHED_LOAD_SHIFT)

#define NICE_0_LOAD		SCHED_LOAD_SCALE
#define NICE_0_SHIFT		SCHED_LOAD_SHIFT

/*
 * Single value that decides SCHED_DEADLINE internal math precision.
 * 10 -> just above 1us
 * 9  -> just above 0.5us
 */
#define DL_SCALE (10)

/*
 * These are the 'tuning knobs' of the scheduler:
 */

/*
 * single value that denotes runtime == period, ie unlimited time.
 */
#define RUNTIME_INF	((u64)~0ULL)

static inline int idle_policy(int policy)
{
	return policy == SCHED_IDLE;
}
static inline int fair_policy(int policy)
{
	return policy == SCHED_NORMAL || policy == SCHED_BATCH;
}

static inline int rt_policy(int policy)
{
	return policy == SCHED_FIFO || policy == SCHED_RR;
}

static inline int dl_policy(int policy)
{
	return policy == SCHED_DEADLINE;
}
static inline bool valid_policy(int policy)
{
	return idle_policy(policy) || fair_policy(policy) ||
		rt_policy(policy) || dl_policy(policy);
}

static inline int task_has_rt_policy(struct task_struct *p)
{
	return rt_policy(p->policy);
}

static inline int task_has_dl_policy(struct task_struct *p)
{
	return dl_policy(p->policy);
}

/*
 * Tells if entity @a should preempt entity @b.
 */
static inline bool
dl_entity_preempt(struct sched_dl_entity *a, struct sched_dl_entity *b)
{
	return dl_time_before(a->deadline, b->deadline);
}

/*
 * This is the priority-queue data structure of the RT scheduling class:
 */
struct rt_prio_array {
	DECLARE_BITMAP(bitmap, MAX_RT_PRIO+1); /* include 1 bit for delimiter */
	struct list_head queue[MAX_RT_PRIO];
};

struct rt_bandwidth {
	/* nests inside the rq lock: */
	raw_spinlock_t		rt_runtime_lock;
	ktime_t			rt_period;
	u64			rt_runtime;
	struct hrtimer		rt_period_timer;
	unsigned int		rt_period_active;
};

void __dl_clear_params(struct task_struct *p);

/*
 * To keep the bandwidth of -deadline tasks and groups under control
 * we need some place where:
 *  - store the maximum -deadline bandwidth of the system (the group);
 *  - cache the fraction of that bandwidth that is currently allocated.
 *
 * This is all done in the data structure below. It is similar to the
 * one used for RT-throttling (rt_bandwidth), with the main difference
 * that, since here we are only interested in admission control, we
 * do not decrease any runtime while the group "executes", neither we
 * need a timer to replenish it.
 *
 * With respect to SMP, the bandwidth is given on a per-CPU basis,
 * meaning that:
 *  - dl_bw (< 100%) is the bandwidth of the system (group) on each CPU;
 *  - dl_total_bw array contains, in the i-eth element, the currently
 *    allocated bandwidth on the i-eth CPU.
 * Moreover, groups consume bandwidth on each CPU, while tasks only
 * consume bandwidth on the CPU they're running on.
 * Finally, dl_total_bw_cpu is used to cache the index of dl_total_bw
 * that will be shown the next time the proc or cgroup controls will
 * be red. It on its turn can be changed by writing on its own
 * control.
 */
struct dl_bandwidth {
	raw_spinlock_t dl_runtime_lock;
	u64 dl_runtime;
	u64 dl_period;
};

static inline int dl_bandwidth_enabled(void)
{
	return sysctl_sched_rt_runtime >= 0;
}

extern struct dl_bw *dl_bw_of(int i);

struct dl_bw {
	raw_spinlock_t lock;
	u64 bw, total_bw;
};

static inline
void __dl_clear(struct dl_bw *dl_b, u64 tsk_bw)
{
	dl_b->total_bw -= tsk_bw;
}

static inline
void __dl_add(struct dl_bw *dl_b, u64 tsk_bw)
{
	dl_b->total_bw += tsk_bw;
}

static inline
bool __dl_overflow(struct dl_bw *dl_b, int cpus, u64 old_bw, u64 new_bw)
{
	return dl_b->bw != -1 &&
	       dl_b->bw * cpus < dl_b->total_bw - old_bw + new_bw;
}

extern struct mutex sched_domains_mutex;

#ifdef CONFIG_CGROUP_SCHED

#include <linux/cgroup.h>

struct cfs_rq;
struct rt_rq;

extern struct list_head task_groups;

struct cfs_bandwidth {
#ifdef CONFIG_CFS_BANDWIDTH
	raw_spinlock_t lock;
//设定的定时器周期时间
	ktime_t period;
//限额时间
//runtime 剩余可运行时间，在每次定时器回调函数中更新值为quota
	u64 quota, runtime;
	s64 hierarchical_quota;
	u64 runtime_expires;

	int idle, period_active;
	//上面一直提到的高精度定时器
	struct hrtimer period_timer, slack_timer;
	//所有被throttle的cfs_rq挂入此链表，在定时器的回调函数中便利链表执行unthrottle cfs_rq操作
	struct list_head throttled_cfs_rq;

	/* statistics */
	int nr_periods, nr_throttled;
	u64 throttled_time;
#endif
};

/* task group related information */
/* 进程组，用于实现组调度 */
struct task_group {
	/* 用于进程找到其所属进程组结构 */

	struct cgroup_subsys_state css;

#ifdef CONFIG_FAIR_GROUP_SCHED
	/* CFS调度器的进程组变量，在 alloc_fair_sched_group() 中进程初始化及分配内存 */
	/* 该进程组在每个CPU上都有对应的一个调度实体，因为有可能此进程组同时在两个CPU上运行(它的A进程在CPU0上运行，B进程在CPU1上运行) */
	/*
	指针数组，数组大小等于CPU数量。现在假设只有一个CPU的系统。
	我们将一个用户组也用一个调度实体代替，插入对应的红黑树。
	例如，上面用户组A和用户组B就是两个调度实体se，挂在顶层的就绪队列cfs_rq中。
	用户组A管理9个可运行的进程，这9个调度实体se作为用户组A调度实体的child。
	通过se->parent成员建立关系。用户组A也维护一个就绪队列cfs_rq，暂且称之为group cfs_rq，管理的9个进程的调度实体挂在group cfs_rq上。
	当我们选择进程运行的时候，首先从根就绪队列cfs_rq上选择用户组A，再从用户组A的group cfs_rq上选择其中一个进程运行。
	现在考虑多核CPU的情况，用户组中的进程可以在多个CPU上运行。因此，我们需要CPU个数的调度实体se，分别挂在每个CPU的根cfs_rq上。
	*/
	/* schedulable entities of this group on each cpu */
	struct sched_entity **se;
	/* runqueue "owned" by this group on each cpu */
	/* 进程组在每个CPU上都有一个CFS运行队列(为什么需要，稍后解释) */
	//上面提到的group cfs_rq，同样是指针数组，大小是CPU的数量。因为每一个CPU上都可以运行进程，因此需要维护CPU个数的group cfs_rq。
	struct cfs_rq **cfs_rq;
	/* 用于保存优先级默认为NICE 0的优先级 */
	//调度实体有权重的概念，以权重的比例分配CPU时间。用户组同样有权重的概念，share就是task_group的权重。
	unsigned long shares;

#ifdef	CONFIG_SMP
//整个用户组的负载贡献总和。
	atomic_long_t load_avg;
#endif
#endif

#ifdef CONFIG_RT_GROUP_SCHED
	/* 实时进程调度器的进程组变量，同 CFS */

	struct sched_rt_entity **rt_se;
	//实时进程调度队列

	struct rt_rq **rt_rq;
	//实时进程占用CPU时间的带宽（或者说比例）
	struct rt_bandwidth rt_bandwidth;
#endif

	struct rcu_head rcu;
	/* 用于建立进程链表(属于此调度组的进程链表) */

	struct list_head list;
	/* 指向其上层的进程组，每一层的进程组都是它上一层进程组的运行队列的一个调度实体，在同一层中，进程组和进程被同等对待 */

	struct task_group *parent;
	/* 进程组的兄弟结点链表 */
	struct list_head siblings;
	/* 进程组的儿子结点链表 */
	struct list_head children;

#ifdef CONFIG_SCHED_AUTOGROUP
	struct autogroup *autogroup;
#endif

	struct cfs_bandwidth cfs_bandwidth;
};

#ifdef CONFIG_FAIR_GROUP_SCHED
#define ROOT_TASK_GROUP_LOAD	NICE_0_LOAD

/*
 * A weight of 0 or 1 can cause arithmetics problems.
 * A weight of a cfs_rq is the sum of weights of which entities
 * are queued on this cfs_rq, so a weight of a entity should not be
 * too large, so as the shares value of a task group.
 * (The default weight is 1024 - so there's no practical
 *  limitation from this.)
 */
#define MIN_SHARES	(1UL <<  1)
#define MAX_SHARES	(1UL << 18)
#endif

typedef int (*tg_visitor)(struct task_group *, void *);

extern int walk_tg_tree_from(struct task_group *from,
			     tg_visitor down, tg_visitor up, void *data);

/*
 * Iterate the full tree, calling @down when first entering a node and @up when
 * leaving it for the final time.
 *
 * Caller must hold rcu_lock or sufficient equivalent.
 */
static inline int walk_tg_tree(tg_visitor down, tg_visitor up, void *data)
{
	return walk_tg_tree_from(&root_task_group, down, up, data);
}

extern int tg_nop(struct task_group *tg, void *data);

extern void free_fair_sched_group(struct task_group *tg);
extern int alloc_fair_sched_group(struct task_group *tg, struct task_group *parent);
extern void unregister_fair_sched_group(struct task_group *tg, int cpu);
extern void init_tg_cfs_entry(struct task_group *tg, struct cfs_rq *cfs_rq,
			struct sched_entity *se, int cpu,
			struct sched_entity *parent);
extern void init_cfs_bandwidth(struct cfs_bandwidth *cfs_b);
extern int sched_group_set_shares(struct task_group *tg, unsigned long shares);

extern void __refill_cfs_bandwidth_runtime(struct cfs_bandwidth *cfs_b);
extern void start_cfs_bandwidth(struct cfs_bandwidth *cfs_b);
extern void unthrottle_cfs_rq(struct cfs_rq *cfs_rq);

extern void free_rt_sched_group(struct task_group *tg);
extern int alloc_rt_sched_group(struct task_group *tg, struct task_group *parent);
extern void init_tg_rt_entry(struct task_group *tg, struct rt_rq *rt_rq,
		struct sched_rt_entity *rt_se, int cpu,
		struct sched_rt_entity *parent);

extern struct task_group *sched_create_group(struct task_group *parent);
extern void sched_online_group(struct task_group *tg,
			       struct task_group *parent);
extern void sched_destroy_group(struct task_group *tg);
extern void sched_offline_group(struct task_group *tg);

extern void sched_move_task(struct task_struct *tsk);

#ifdef CONFIG_FAIR_GROUP_SCHED
extern int sched_group_set_shares(struct task_group *tg, unsigned long shares);
#endif

#else /* CONFIG_CGROUP_SCHED */

struct cfs_bandwidth { };

#endif	/* CONFIG_CGROUP_SCHED */

/* CFS-related fields in a runqueue */
/* CFS调度的运行队列，每个CPU的rq会包含一个cfs_rq，而每个组调度的sched_entity也会有自己的一个cfs_rq队列 */

struct cfs_rq {
	/* CFS运行队列中所有进程的总负载 */
	struct load_weight load;  /*运行负载*/
	/*
	* nr_running: cfs_rq中调度实体数量
	* h_nr_running: 只对进程组有效，其下所有进程组中cfs_rq的nr_running之和
	*/
	unsigned int nr_running, h_nr_running;  ;/*运行进程个数*/

	u64 exec_clock; //运行的时钟
	/* 当前CFS队列上最小运行时间，单调递增
	* 两种情况下更新该值:
	* 1、更新当前运行任务的累计运行时间时
	* 2、当任务从队列删除去，如任务睡眠或退出，这时候会查看剩下的任务的vruntime是否大于min_vruntime，如果是则更新该值。
	*/
	u64 min_vruntime; //该cpu运行队列的vruntime推进值, 一般是红黑树中最小的vruntime值
#ifndef CONFIG_64BIT
	u64 min_vruntime_copy;
#endif
	/* 该红黑树的root */
	struct rb_root tasks_timeline;//红黑树的根结点
	/* 下一个调度结点(红黑树最左边结点，最左边结点就是下个调度实体) */
	struct rb_node *rb_leftmost; /*保存的红黑树最左边的
	节点，这个为最小运行时间的节点，当进程
	选择下一个来运行时，直接选择这个*/

	/*
	 * 'curr' points to currently running entity on this cfs_rq.
	 * It is set to NULL otherwise (i.e when none are currently running).
	 */
	 /*
	 * curr: 当前正在运行的sched_entity（对于组虽然它不会在cpu上运行，但是当它的下层有一个task在cpu上运行，那么它所在的cfs_rq就把它当做是该cfs_rq上当前正在运行的sched_entity）
	 * next: 表示有些进程急需运行，即使不遵从CFS调度也必须运行它，调度时会检查是否next需要调度，有就调度next
	 *
	 * skip: 略过进程(不会选择skip指定的进程调度)
	 */
	 //当前运行进程, 下一个将要调度的进程, 马上要抢占的进程, 
	struct sched_entity *curr, *next, *last, *skip;

#ifdef	CONFIG_SCHED_DEBUG
	unsigned int nr_spread_over;
#endif

#ifdef CONFIG_SMP
	/*
	 * CFS load tracking
	 */
	struct sched_avg avg;
	u64 runnable_load_sum;
	unsigned long runnable_load_avg;
#ifdef CONFIG_FAIR_GROUP_SCHED
	unsigned long tg_load_avg_contrib;
#endif
	atomic_long_t removed_load_avg, removed_util_avg;
#ifndef CONFIG_64BIT
	u64 load_last_update_time_copy;
#endif

#ifdef CONFIG_FAIR_GROUP_SCHED
	/*
	 *   h_load = weight * f(tg)
	 *
	 * Where f(tg) is the recursive weight fraction assigned to
	 * this group.
	 */
	unsigned long h_load;
	u64 last_h_load_update;
	struct sched_entity *h_load_next;
#endif /* CONFIG_FAIR_GROUP_SCHED */
#endif /* CONFIG_SMP */

#ifdef CONFIG_FAIR_GROUP_SCHED
	//系统中有普通进程的运行队列, 实时进程的运行队列, 这些队列都包含在rq运行队列中  
	/* 所属于的CPU rq */
	struct rq *rq;	/* cpu runqueue to which this cfs_rq is attached */

	/*
	 * leaf cfs_rqs are those that hold tasks (lowest schedulable entity in
	 * a hierarchy). Non-leaf lrqs hold other higher schedulable entities
	 * (like users, containers etc.)
	 *
	 * leaf_cfs_rq_list ties together list of leaf cfs_rq's in a cpu. This
	 * list is used during load balance.
	 */
	int on_list;
	struct list_head leaf_cfs_rq_list;
	/* 拥有该CFS运行队列的进程组 */
	struct task_group *tg;	/* group that "owns" this runqueue */

#ifdef CONFIG_CFS_BANDWIDTH
//该就绪队列是否已经开启带宽限制，默认带宽限制是关闭的，如果带宽限制使能，runtime_enabled的值为1
	int runtime_enabled;
	u64 runtime_expires;
	//cfs_rq从全局时间池申请的时间片剩余时间，当剩余时间小于等于0的时候，就需要重新申请时间片
	s64 runtime_remaining;
	//当cfs_rq被throttle的时候，方便统计被throttle的时间，需要记录throttle开始的时间
	u64 throttled_clock, throttled_clock_task;
	u64 throttled_clock_task_time;
	/*
	throttled：如果cfs_rq被throttle后，throttled变量置1，unthrottle的时候，throttled变量置0；throttle_count：由于task_group支持嵌套，
	当parent task_group的cfs_rq被throttle的时候，其chaild task_group对应的cfs_rq的throttle_count成员计数增加。
	*/
	int throttled, throttle_count, throttle_uptodate;
	//被throttle的cfs_rq挂入cfs_bandwidth->throttled_cfs_rq链表
	struct list_head throttled_list;
#endif /* CONFIG_CFS_BANDWIDTH */
#endif /* CONFIG_FAIR_GROUP_SCHED */
};

static inline int rt_bandwidth_enabled(void)
{
	return sysctl_sched_rt_runtime >= 0;
}

/* RT IPI pull logic requires IRQ_WORK */
#if defined(CONFIG_IRQ_WORK) && defined(CONFIG_SMP)
# define HAVE_RT_PUSH_IPI
#endif

/* Real-Time classes' related field in a runqueue: */
struct rt_rq {
	struct rt_prio_array active;
	unsigned int rt_nr_running;
#if defined CONFIG_SMP || defined CONFIG_RT_GROUP_SCHED
	struct {
		int curr; /* highest queued rt task prio */
#ifdef CONFIG_SMP
		int next; /* next highest */
#endif
	} highest_prio;
#endif
#ifdef CONFIG_SMP
	unsigned long rt_nr_migratory;
	unsigned long rt_nr_total;
	int overloaded;
	struct plist_head pushable_tasks;
#endif /* CONFIG_SMP */
	int rt_queued;
	//当前队列的实时调度是否受限

	int rt_throttled;
	//当前队列的累计运行时间
	u64 rt_time;
	//当前队列的最大运行时间
	u64 rt_runtime;
	/* Nests inside the rq lock: */
	raw_spinlock_t rt_runtime_lock;

#ifdef CONFIG_RT_GROUP_SCHED
	unsigned long rt_nr_boosted;
	//当前实时调度队列归属调度队列
	struct rq *rq;
	//当前实时调度队列归属的调度单元
	struct task_group *tg;
#endif
};

/* Deadline class' related fields in a runqueue */
struct dl_rq {
	/* runqueue is an rbtree, ordered by deadline */
	struct rb_root rb_root;
	struct rb_node *rb_leftmost;

	unsigned long dl_nr_running;

#ifdef CONFIG_SMP
	/*
	 * Deadline values of the currently executing and the
	 * earliest ready task on this rq. Caching these facilitates
	 * the decision wether or not a ready but not running task
	 * should migrate somewhere else.
	 */
	struct {
		u64 curr;
		u64 next;
	} earliest_dl;

	unsigned long dl_nr_migratory;
	int overloaded;

	/*
	 * Tasks on this rq that can be pushed away. They are kept in
	 * an rb-tree, ordered by tasks' deadlines, with caching
	 * of the leftmost (earliest deadline) element.
	 */
	struct rb_root pushable_dl_tasks_root;
	struct rb_node *pushable_dl_tasks_leftmost;
#else
	struct dl_bw dl_bw;
#endif
};

#ifdef CONFIG_SMP

/*
 * We add the notion of a root-domain which will be used to define per-domain
 * variables. Each exclusive cpuset essentially defines an island domain by
 * fully partitioning the member cpus from any other cpuset. Whenever a new
 * exclusive cpuset is created, we also create and attach a new root-domain
 * object.
 *
 */
struct root_domain {
	atomic_t refcount;
	atomic_t rto_count;
	struct rcu_head rcu;
	cpumask_var_t span;
	cpumask_var_t online;

	/* Indicate more than one runnable task for any CPU */
	bool overload;

	/*
	 * The bit corresponding to a CPU gets set here if such CPU has more
	 * than one runnable -deadline task (as it is below for RT tasks).
	 */
	cpumask_var_t dlo_mask;
	atomic_t dlo_count;
	struct dl_bw dl_bw;
	struct cpudl cpudl;

#ifdef HAVE_RT_PUSH_IPI
	/*
	 * For IPI pull requests, loop across the rto_mask.
	 */
	struct irq_work rto_push_work;
	raw_spinlock_t rto_lock;
	/* These are only updated and read within rto_lock */
	int rto_loop;
	int rto_cpu;
	/* These atomics are updated outside of a lock */
	atomic_t rto_loop_next;
	atomic_t rto_loop_start;
#endif
	/*
	 * The "RT overload" flag: it gets set if a CPU has more than
	 * one runnable RT task.
	 */
	cpumask_var_t rto_mask;
	struct cpupri cpupri;
};

extern struct root_domain def_root_domain;
extern void sched_get_rd(struct root_domain *rd);
extern void sched_put_rd(struct root_domain *rd);

#ifdef HAVE_RT_PUSH_IPI
extern void rto_push_irq_work_func(struct irq_work *work);
#endif
#endif /* CONFIG_SMP */

/*
 * This is the main, per-CPU runqueue data structure.
 *
 * Locking rule: those places that want to lock multiple runqueues
 * (such as the load balancing or the thread migration code), lock
 * acquire operations must be ordered by ascending &runqueue.
 */
 /* CPU运行队列，每个CPU包含一个struct rq */
struct rq {
	/* runqueue lock: */
	raw_spinlock_t lock;

	/*
	 * nr_running and cpu_load should be in the same cacheline because
	 * remote CPUs use both these fields when doing load calculation.
	 */
	 /* 此CPU上总共就绪的进程数，包括cfs，rt和正在运行的 */
	unsigned int nr_running;
#ifdef CONFIG_NUMA_BALANCING
	unsigned int nr_numa_running;
	unsigned int nr_preferred_running;
#endif
	#define CPU_LOAD_IDX_MAX 5
	/* 根据CPU历史情况计算的负载，cpu_load[0]一直等于load.weight，当达到负载平衡时，cpu_load[1]和cpu_load[2]都应该等于load.weight */
	unsigned long cpu_load[CPU_LOAD_IDX_MAX];
	/* 最后一次更新 cpu_load 的时间 */
	unsigned long last_load_update_tick;
#ifdef CONFIG_NO_HZ_COMMON
	u64 nohz_stamp;
	unsigned long nohz_flags;
#endif
#ifdef CONFIG_NO_HZ_FULL
	unsigned long last_sched_tick;
#endif
	/* capture load from *all* tasks on this cpu: */
	/* CPU负载，该CPU上所有可运行进程的load之和，nr_running更新时这个值也必须更新 */

	struct load_weight load;
	unsigned long nr_load_updates;
	/* 进行上下文切换次数，只有proc会使用这个 */
	u64 nr_switches;
	/* cfs调度运行队列，包含红黑树的根 */
	struct cfs_rq cfs;
	/* 实时调度运行队列 */
	struct rt_rq rt;
	struct dl_rq dl;

#ifdef CONFIG_FAIR_GROUP_SCHED
	/* list of leaf cfs_rq on this cpu: */
	struct list_head leaf_cfs_rq_list;
#endif /* CONFIG_FAIR_GROUP_SCHED */

	/*
	 * This is part of a global counter where only the total sum
	 * over all CPUs matters. A task can increase this counter on
	 * one CPU and if it got migrated afterwards it may decrease
	 * it on another CPU. Always updated under the runqueue lock:
	 */
	 /* 曾经处于队列但现在处于TASK_UNINTERRUPTIBLE状态的进程数量 */
	unsigned long nr_uninterruptible;
	/*
	* curr: 当前正在此CPU上运行的进程
	* idle: 当前CPU上idle进程的指针，idle进程用于当CPU没事做的时候调用，它什么都不执行
	*/

	struct task_struct *curr, *idle, *stop;
	/* 下次进行负载平衡执行时间 */
	unsigned long next_balance;
	/* 在进程切换时用来存放换出进程的内存描述符地址 */
	struct mm_struct *prev_mm;
	/* 是否需要更新rq的运行时间 */
	unsigned int clock_skip_update;
	/* rq运行时间 */
	u64 clock;
	u64 clock_task;

	atomic_t nr_iowait;

#ifdef CONFIG_SMP
	struct root_domain *rd;
	/* 当前CPU所在基本调度域，每个调度域包含一个或多个CPU组，每个CPU组包含该调度域中一个或多个CPU子集，负载均衡都是在调度域中的组之间完成的，不能跨域进行负载均衡 */

	struct sched_domain *sd;

	unsigned long cpu_capacity;
	unsigned long cpu_capacity_orig;

	struct callback_head *balance_callback;

	unsigned char idle_balance;
	/* For active balancing */
	/* 如果需要把进程迁移到其他运行队列，就需要设置这个位 */
	int active_balance;  //用于主动均衡
	int push_cpu;
	struct cpu_stop_work active_balance_work;
	/* cpu of this runqueue: */
	/* 该运行队列所属CPU */
	int cpu;  //该就绪队列的CPU
	int online;

	struct list_head cfs_tasks;

	u64 rt_avg;
	/* 该运行队列存活时间 */
	u64 age_stamp;
	u64 idle_stamp;
	u64 avg_idle;

	/* This is used to determine avg_idle's max value */
	u64 max_idle_balance_cost;
#endif

#ifdef CONFIG_IRQ_TIME_ACCOUNTING
	u64 prev_irq_time;
#endif
#ifdef CONFIG_PARAVIRT
	u64 prev_steal_time;
#endif
#ifdef CONFIG_PARAVIRT_TIME_ACCOUNTING
	u64 prev_steal_time_rq;
#endif

	/* calc_load related fields */
	/* 用于负载均衡 */

	unsigned long calc_load_update;
	long calc_load_active;

#ifdef CONFIG_SCHED_HRTICK
#ifdef CONFIG_SMP
	int hrtick_csd_pending;
	struct call_single_data hrtick_csd;
#endif
	/* 调度使用的高精度定时器 */
	struct hrtimer hrtick_timer;
#endif

#ifdef CONFIG_SCHEDSTATS
	/* latency stats */
	struct sched_info rq_sched_info;
	unsigned long long rq_cpu_time;
	/* could above be rq->cfs_rq.exec_clock + rq->rt_rq.rt_runtime ? */

	/* sys_sched_yield() stats */
	unsigned int yld_count;

	/* schedule() stats */
	unsigned int sched_count;
	unsigned int sched_goidle;

	/* try_to_wake_up() stats */
	unsigned int ttwu_count;
	unsigned int ttwu_local;
#endif

#ifdef CONFIG_SMP
	struct llist_head wake_list;
#endif

#ifdef CONFIG_CPU_IDLE
	/* Must be inspected within a rcu lock section */
	struct cpuidle_state *idle_state;
#endif
};

static inline int cpu_of(struct rq *rq)
{
#ifdef CONFIG_SMP
	return rq->cpu;
#else
	return 0;
#endif
}

DECLARE_PER_CPU_SHARED_ALIGNED(struct rq, runqueues);

#define cpu_rq(cpu)		(&per_cpu(runqueues, (cpu)))
#define this_rq()		this_cpu_ptr(&runqueues)
#define task_rq(p)		cpu_rq(task_cpu(p))
#define cpu_curr(cpu)		(cpu_rq(cpu)->curr)
#define raw_rq()		raw_cpu_ptr(&runqueues)

static inline u64 __rq_clock_broken(struct rq *rq)
{
	return READ_ONCE(rq->clock);
}

static inline u64 rq_clock(struct rq *rq)
{
	lockdep_assert_held(&rq->lock);
	return rq->clock;
}

static inline u64 rq_clock_task(struct rq *rq)
{
	lockdep_assert_held(&rq->lock);
	return rq->clock_task;
}

#define RQCF_REQ_SKIP	0x01
#define RQCF_ACT_SKIP	0x02

static inline void rq_clock_skip_update(struct rq *rq, bool skip)
{
	lockdep_assert_held(&rq->lock);
	if (skip)
		rq->clock_skip_update |= RQCF_REQ_SKIP;
	else
		rq->clock_skip_update &= ~RQCF_REQ_SKIP;
}

#ifdef CONFIG_NUMA
enum numa_topology_type {
	NUMA_DIRECT,
	NUMA_GLUELESS_MESH,
	NUMA_BACKPLANE,
};
extern enum numa_topology_type sched_numa_topology_type;
extern int sched_max_numa_distance;
extern bool find_numa_distance(int distance);
#endif

#ifdef CONFIG_NUMA_BALANCING
/* The regions in numa_faults array from task_struct */
enum numa_faults_stats {
	NUMA_MEM = 0,
	NUMA_CPU,
	NUMA_MEMBUF,
	NUMA_CPUBUF
};
extern void sched_setnuma(struct task_struct *p, int node);
extern int migrate_task_to(struct task_struct *p, int cpu);
extern int migrate_swap(struct task_struct *, struct task_struct *);
#endif /* CONFIG_NUMA_BALANCING */

#ifdef CONFIG_SMP

static inline void
queue_balance_callback(struct rq *rq,
		       struct callback_head *head,
		       void (*func)(struct rq *rq))
{
	lockdep_assert_held(&rq->lock);

	if (unlikely(head->next))
		return;

	head->func = (void (*)(struct callback_head *))func;
	head->next = rq->balance_callback;
	rq->balance_callback = head;
}

extern void sched_ttwu_pending(void);

#define rcu_dereference_check_sched_domain(p) \
	rcu_dereference_check((p), \
			      lockdep_is_held(&sched_domains_mutex))

/*
 * The domain tree (rq->sd) is protected by RCU's quiescent state transition.
 * See detach_destroy_domains: synchronize_sched for details.
 *
 * The domain tree of any CPU may only be accessed from within
 * preempt-disabled sections.
 */
#define for_each_domain(cpu, __sd) \
	for (__sd = rcu_dereference_check_sched_domain(cpu_rq(cpu)->sd); \
			__sd; __sd = __sd->parent)

#define for_each_lower_domain(sd) for (; sd; sd = sd->child)

/**
 * highest_flag_domain - Return highest sched_domain containing flag.
 * @cpu:	The cpu whose highest level of sched domain is to
 *		be returned.
 * @flag:	The flag to check for the highest sched_domain
 *		for the given cpu.
 *
 * Returns the highest sched_domain of a cpu which contains the given flag.
 */
static inline struct sched_domain *highest_flag_domain(int cpu, int flag)
{
	struct sched_domain *sd, *hsd = NULL;

	for_each_domain(cpu, sd) {
		if (!(sd->flags & flag))
			break;
		hsd = sd;
	}

	return hsd;
}

static inline struct sched_domain *lowest_flag_domain(int cpu, int flag)
{
	struct sched_domain *sd;

	for_each_domain(cpu, sd) {
		if (sd->flags & flag)
			break;
	}

	return sd;
}

DECLARE_PER_CPU(struct sched_domain *, sd_llc);
DECLARE_PER_CPU(int, sd_llc_size);
DECLARE_PER_CPU(int, sd_llc_id);
DECLARE_PER_CPU(struct sched_domain *, sd_numa);
DECLARE_PER_CPU(struct sched_domain *, sd_busy);
DECLARE_PER_CPU(struct sched_domain *, sd_asym);

struct sched_group_capacity {
	atomic_t ref;
	/*
	 * CPU capacity of this group, SCHED_LOAD_SCALE being max capacity
	 * for a single CPU.
	 */
	unsigned int capacity;
	unsigned long next_update;
	int imbalance; /* XXX unrelated to capacity but shared group state */
	/*
	 * Number of busy cpus in this group.
	 */
	atomic_t nr_busy_cpus;

	unsigned long cpumask[0]; /* iteration mask */
};

struct sched_group {
	struct sched_group *next;	/* Must be a circular list */
	atomic_t ref;

	unsigned int group_weight;
	struct sched_group_capacity *sgc;

	/*
	 * The CPUs this group covers.
	 *
	 * NOTE: this field is variable length. (Allocated dynamically
	 * by attaching extra space to the end of the structure,
	 * depending on how many CPUs the kernel has booted up with)
	 */
	unsigned long cpumask[0];
};

static inline struct cpumask *sched_group_cpus(struct sched_group *sg)
{
	return to_cpumask(sg->cpumask);
}

/*
 * cpumask masking which cpus in the group are allowed to iterate up the domain
 * tree.
 */
static inline struct cpumask *sched_group_mask(struct sched_group *sg)
{
	return to_cpumask(sg->sgc->cpumask);
}

/**
 * group_first_cpu - Returns the first cpu in the cpumask of a sched_group.
 * @group: The group whose first cpu is to be returned.
 */
static inline unsigned int group_first_cpu(struct sched_group *group)
{
	return cpumask_first(sched_group_cpus(group));
}

extern int group_balance_cpu(struct sched_group *sg);

#else

static inline void sched_ttwu_pending(void) { }

#endif /* CONFIG_SMP */

#include "stats.h"
#include "auto_group.h"

#ifdef CONFIG_CGROUP_SCHED

/*
 * Return the group to which this tasks belongs.
 *
 * We cannot use task_css() and friends because the cgroup subsystem
 * changes that value before the cgroup_subsys::attach() method is called,
 * therefore we cannot pin it and might observe the wrong value.
 *
 * The same is true for autogroup's p->signal->autogroup->tg, the autogroup
 * core changes this before calling sched_move_task().
 *
 * Instead we use a 'copy' which is updated from sched_move_task() while
 * holding both task_struct::pi_lock and rq::lock.
 */
static inline struct task_group *task_group(struct task_struct *p)
{
	return p->sched_task_group;
}

/* Change a task's cfs_rq and parent entity if it moves across CPUs/groups */
static inline void set_task_rq(struct task_struct *p, unsigned int cpu)
{
#if defined(CONFIG_FAIR_GROUP_SCHED) || defined(CONFIG_RT_GROUP_SCHED)
	struct task_group *tg = task_group(p);
#endif

#ifdef CONFIG_FAIR_GROUP_SCHED
	p->se.cfs_rq = tg->cfs_rq[cpu];
	p->se.parent = tg->se[cpu];
#endif

#ifdef CONFIG_RT_GROUP_SCHED
	p->rt.rt_rq  = tg->rt_rq[cpu];
	p->rt.parent = tg->rt_se[cpu];
#endif
}

#else /* CONFIG_CGROUP_SCHED */

static inline void set_task_rq(struct task_struct *p, unsigned int cpu) { }
static inline struct task_group *task_group(struct task_struct *p)
{
	return NULL;
}

#endif /* CONFIG_CGROUP_SCHED */

static inline void __set_task_cpu(struct task_struct *p, unsigned int cpu)
{
	set_task_rq(p, cpu);
#ifdef CONFIG_SMP
	/*
	 * After ->cpu is set up to a new value, task_rq_lock(p, ...) can be
	 * successfuly executed on another CPU. We must ensure that updates of
	 * per-task data have been completed by this moment.
	 */
	smp_wmb();
	task_thread_info(p)->cpu = cpu;
	p->wake_cpu = cpu;
#endif
}

/*
 * Tunables that become constants when CONFIG_SCHED_DEBUG is off:
 */
#ifdef CONFIG_SCHED_DEBUG
# include <linux/static_key.h>
# define const_debug __read_mostly
#else
# define const_debug const
#endif

extern const_debug unsigned int sysctl_sched_features;

#define SCHED_FEAT(name, enabled)	\
	__SCHED_FEAT_##name ,

enum {
#include "features.h"
	__SCHED_FEAT_NR,
};

#undef SCHED_FEAT

#if defined(CONFIG_SCHED_DEBUG) && defined(HAVE_JUMP_LABEL)
#define SCHED_FEAT(name, enabled)					\
static __always_inline bool static_branch_##name(struct static_key *key) \
{									\
	return static_key_##enabled(key);				\
}

#include "features.h"

#undef SCHED_FEAT

extern struct static_key sched_feat_keys[__SCHED_FEAT_NR];
#define sched_feat(x) (static_branch_##x(&sched_feat_keys[__SCHED_FEAT_##x]))
#else /* !(SCHED_DEBUG && HAVE_JUMP_LABEL) */
#define sched_feat(x) (sysctl_sched_features & (1UL << __SCHED_FEAT_##x))
#endif /* SCHED_DEBUG && HAVE_JUMP_LABEL */

extern struct static_key_false sched_numa_balancing;

static inline u64 global_rt_period(void)
{
	return (u64)sysctl_sched_rt_period * NSEC_PER_USEC;
}

static inline u64 global_rt_runtime(void)
{
	if (sysctl_sched_rt_runtime < 0)
		return RUNTIME_INF;

	return (u64)sysctl_sched_rt_runtime * NSEC_PER_USEC;
}

static inline int task_current(struct rq *rq, struct task_struct *p)
{
	return rq->curr == p;
}

static inline int task_running(struct rq *rq, struct task_struct *p)
{
#ifdef CONFIG_SMP
	return p->on_cpu;
#else
	return task_current(rq, p);
#endif
}

static inline int task_on_rq_queued(struct task_struct *p)
{
	return p->on_rq == TASK_ON_RQ_QUEUED;
}

static inline int task_on_rq_migrating(struct task_struct *p)
{
	return p->on_rq == TASK_ON_RQ_MIGRATING;
}

#ifndef prepare_arch_switch
# define prepare_arch_switch(next)	do { } while (0)
#endif
#ifndef finish_arch_post_lock_switch
# define finish_arch_post_lock_switch()	do { } while (0)
#endif

static inline void prepare_lock_switch(struct rq *rq, struct task_struct *next)
{
#ifdef CONFIG_SMP
	/*
	 * We can optimise this out completely for !SMP, because the
	 * SMP rebalancing from interrupt is the only thing that cares
	 * here.
	 */
	next->on_cpu = 1;
#endif
}

static inline void finish_lock_switch(struct rq *rq, struct task_struct *prev)
{
#ifdef CONFIG_SMP
	/*
	 * After ->on_cpu is cleared, the task can be moved to a different CPU.
	 * We must ensure this doesn't happen until the switch is completely
	 * finished.
	 *
	 * In particular, the load of prev->state in finish_task_switch() must
	 * happen before this.
	 *
	 * Pairs with the control dependency and rmb in try_to_wake_up().
	 */
	smp_store_release(&prev->on_cpu, 0);
#endif
#ifdef CONFIG_DEBUG_SPINLOCK
	/* this is a valid case when another task releases the spinlock */
	rq->lock.owner = current;
#endif
	/*
	 * If we are tracking spinlock dependencies then we have to
	 * fix up the runqueue lock - which gets 'carried over' from
	 * prev into current:
	 */
	spin_acquire(&rq->lock.dep_map, 0, 0, _THIS_IP_);

	raw_spin_unlock_irq(&rq->lock);
}

/*
 * wake flags
 */
#define WF_SYNC		0x01		/* waker goes to sleep after wakeup */
#define WF_FORK		0x02		/* child wakeup after fork */
#define WF_MIGRATED	0x4		/* internal use, task got migrated */

/*
 * To aid in avoiding the subversion of "niceness" due to uneven distribution
 * of tasks with abnormal "nice" values across CPUs the contribution that
 * each task makes to its run queue's load is weighted according to its
 * scheduling class and "nice" value. For SCHED_NORMAL tasks this is just a
 * scaled version of the new time slice allocation that they receive on time
 * slice expiry etc.
 */

#define WEIGHT_IDLEPRIO                3
#define WMULT_IDLEPRIO         1431655765

/*
 * Nice levels are multiplicative, with a gentle 10% change for every
 * nice level changed. I.e. when a CPU-bound task goes from nice 0 to
 * nice 1, it will get ~10% less CPU time than another CPU-bound task
 * that remained on nice 0.
 *
 * The "10% effect" is relative and cumulative: from _any_ nice level,
 * if you go up 1 level, it's -10% CPU usage, if you go down 1 level
 * it's +10% CPU usage. (to achieve that we use a multiplier of 1.25.
 * If a task goes up by ~10% and another task goes down by ~10% then
 * the relative distance between them is ~25%.)
 */
static const int prio_to_weight[40] = {
 /* -20 */     88761,     71755,     56483,     46273,     36291,
 /* -15 */     29154,     23254,     18705,     14949,     11916,
 /* -10 */      9548,      7620,      6100,      4904,      3906,
 /*  -5 */      3121,      2501,      1991,      1586,      1277,
 /*   0 */      1024,       820,       655,       526,       423,
 /*   5 */       335,       272,       215,       172,       137,
 /*  10 */       110,        87,        70,        56,        45,
 /*  15 */        36,        29,        23,        18,        15,
};

/*
 * Inverse (2^32/x) values of the prio_to_weight[] array, precalculated.
 *
 * In cases where the weight does not change often, we can use the
 * precalculated inverse to speed up arithmetics by turning divisions
 * into multiplications:
 */
static const u32 prio_to_wmult[40] = {
 /* -20 */     48388,     59856,     76040,     92818,    118348,
 /* -15 */    147320,    184698,    229616,    287308,    360437,
 /* -10 */    449829,    563644,    704093,    875809,   1099582,
 /*  -5 */   1376151,   1717300,   2157191,   2708050,   3363326,
 /*   0 */   4194304,   5237765,   6557202,   8165337,  10153587,
 /*   5 */  12820798,  15790321,  19976592,  24970740,  31350126,
 /*  10 */  39045157,  49367440,  61356676,  76695844,  95443717,
 /*  15 */ 119304647, 148102320, 186737708, 238609294, 286331153,
};

#define ENQUEUE_WAKEUP		0x01
#define ENQUEUE_HEAD		0x02
#ifdef CONFIG_SMP
#define ENQUEUE_WAKING		0x04	/* sched_class::task_waking was called */
#else
#define ENQUEUE_WAKING		0x00
#endif
#define ENQUEUE_REPLENISH	0x08
#define ENQUEUE_RESTORE	0x10

#define DEQUEUE_SLEEP		0x01
#define DEQUEUE_SAVE		0x02

#define RETRY_TASK		((void *)-1UL)

struct sched_class {
	/* 下一优先级的调度类
	* 调度类优先级顺序: stop_sched_class -> dl_sched_class -> rt_sched_class -> fair_sched_class -> idle_sched_class
	*/
	const struct sched_class *next;
	/* 将进程加入到运行队列中，即将调度实体（进程）放入红黑树中，并对 nr_running 变量加1 */
	//当某个任务进入可运行状态时，该函数将得到调用。它将调度实体（进程）放入红黑树中，并对 nr_running 变量加 1。
	void (*enqueue_task) (struct rq *rq, struct task_struct *p, int flags);
	//当某个任务退出可运行状态时调用该函数，它将从红黑树中去掉对应的调度实体，并从 nr_running 变量中减 1。
	void (*dequeue_task) (struct rq *rq, struct task_struct *p, int flags);
	//在 compat_yield sysctl 关闭的情况下，该函数实际上执行先出队后入队；在这种情况下，它将调度实体放在红黑树的最右端
	void (*yield_task) (struct rq *rq);
	bool (*yield_to_task) (struct rq *rq, struct task_struct *p, bool preempt);
	//该函数将检查当前运行的任务是否被抢占。在实际抢占正在运行的任务之前，CFS 调度程序模块将执行公平性测试。这将驱动唤醒式（wakeup）抢占。
	void (*check_preempt_curr) (struct rq *rq, struct task_struct *p, int flags);
	/*
	 * It is the responsibility of the pick_next_task() method that will
	 * return the next task to call put_prev_task() on the @prev task or
	 * something equivalent.
	 *
	 * May return RETRY_TASK when it finds a higher prio class has runnable
	 * tasks.
	 */
	 //该函数选择接下来要运行的最合适的进程。
	struct task_struct * (*pick_next_task) (struct rq *rq,
						struct task_struct *prev);
	/* 将进程放回运行队列 */
	void (*put_prev_task) (struct rq *rq, struct task_struct *p);

#ifdef CONFIG_SMP
	/* 为进程选择一个合适的CPU */
	int  (*select_task_rq)(struct task_struct *p, int task_cpu, int sd_flag, int flags);
	/* 迁移任务到另一个CPU */
	void (*migrate_task_rq)(struct task_struct *p);
	/* 用于进程唤醒 */
	void (*task_waking) (struct task_struct *task);
	void (*task_woken) (struct rq *this_rq, struct task_struct *task);
	/* 修改进程的CPU亲和力(affinity) */
	void (*set_cpus_allowed)(struct task_struct *p,
				 const struct cpumask *newmask);
	/* 启动运行队列 */
	void (*rq_online)(struct rq *rq);
	/* 禁止运行队列 */
	void (*rq_offline)(struct rq *rq);
#endif
	/* 当进程改变它的调度类或进程组时被调用 */
	void (*set_curr_task) (struct rq *rq);
	/* 该函数通常调用自 time tick 函数；它可能引起进程切换。这将驱动运行时（running）抢占 */
	void (*task_tick) (struct rq *rq, struct task_struct *p, int queued);
	/* 在进程创建时调用，不同调度策略的进程初始化不一样 */
	void (*task_fork) (struct task_struct *p);
	/* 在进程退出时会使用 */
	void (*task_dead) (struct task_struct *p);

	/*
	 * The switched_from() call is allowed to drop rq->lock, therefore we
	 * cannot assume the switched_from/switched_to pair is serliazed by
	 * rq->lock. They are however serialized by p->pi_lock.
	 */
	 /* 用于进程切换 */
	void (*switched_from) (struct rq *this_rq, struct task_struct *task);
	void (*switched_to) (struct rq *this_rq, struct task_struct *task);
	/* 改变优先级 */
	void (*prio_changed) (struct rq *this_rq, struct task_struct *task,
			     int oldprio);

	unsigned int (*get_rr_interval) (struct rq *rq,
					 struct task_struct *task);

	void (*update_curr) (struct rq *rq);

#ifdef CONFIG_FAIR_GROUP_SCHED
	void (*task_move_group) (struct task_struct *p);
#endif
};

static inline void put_prev_task(struct rq *rq, struct task_struct *prev)
{
//put_prev_task_fair
	prev->sched_class->put_prev_task(rq, prev);
}

#define sched_class_highest (&stop_sched_class)
#define for_each_class(class) \
   for (class = sched_class_highest; class; class = class->next)

extern const struct sched_class stop_sched_class;
extern const struct sched_class dl_sched_class;
extern const struct sched_class rt_sched_class;
extern const struct sched_class fair_sched_class;
extern const struct sched_class idle_sched_class;


#ifdef CONFIG_SMP

extern void update_group_capacity(struct sched_domain *sd, int cpu);

extern void trigger_load_balance(struct rq *rq);

extern void idle_enter_fair(struct rq *this_rq);
extern void idle_exit_fair(struct rq *this_rq);

extern void set_cpus_allowed_common(struct task_struct *p, const struct cpumask *new_mask);

#else

static inline void idle_enter_fair(struct rq *rq) { }
static inline void idle_exit_fair(struct rq *rq) { }

#endif

#ifdef CONFIG_CPU_IDLE
static inline void idle_set_state(struct rq *rq,
				  struct cpuidle_state *idle_state)
{
	rq->idle_state = idle_state;
}

static inline struct cpuidle_state *idle_get_state(struct rq *rq)
{
	WARN_ON(!rcu_read_lock_held());
	return rq->idle_state;
}
#else
static inline void idle_set_state(struct rq *rq,
				  struct cpuidle_state *idle_state)
{
}

static inline struct cpuidle_state *idle_get_state(struct rq *rq)
{
	return NULL;
}
#endif

extern void sysrq_sched_debug_show(void);
extern void sched_init_granularity(void);
extern void update_max_interval(void);

extern void init_sched_dl_class(void);
extern void init_sched_rt_class(void);
extern void init_sched_fair_class(void);

extern void resched_curr(struct rq *rq);
extern void resched_cpu(int cpu);

extern struct rt_bandwidth def_rt_bandwidth;
extern void init_rt_bandwidth(struct rt_bandwidth *rt_b, u64 period, u64 runtime);

extern struct dl_bandwidth def_dl_bandwidth;
extern void init_dl_bandwidth(struct dl_bandwidth *dl_b, u64 period, u64 runtime);
extern void init_dl_task_timer(struct sched_dl_entity *dl_se);

unsigned long to_ratio(u64 period, u64 runtime);

extern void init_entity_runnable_average(struct sched_entity *se);

static inline void add_nr_running(struct rq *rq, unsigned count)
{
	unsigned prev_nr = rq->nr_running;

	rq->nr_running = prev_nr + count;

	if (prev_nr < 2 && rq->nr_running >= 2) {
#ifdef CONFIG_SMP
		if (!rq->rd->overload)
			rq->rd->overload = true;
#endif

#ifdef CONFIG_NO_HZ_FULL
		if (tick_nohz_full_cpu(rq->cpu)) {
			/*
			 * Tick is needed if more than one task runs on a CPU.
			 * Send the target an IPI to kick it out of nohz mode.
			 *
			 * We assume that IPI implies full memory barrier and the
			 * new value of rq->nr_running is visible on reception
			 * from the target.
			 */
			tick_nohz_full_kick_cpu(rq->cpu);
		}
#endif
	}
}

static inline void sub_nr_running(struct rq *rq, unsigned count)
{
	rq->nr_running -= count;
}

static inline void rq_last_tick_reset(struct rq *rq)
{
#ifdef CONFIG_NO_HZ_FULL
	rq->last_sched_tick = jiffies;
#endif
}

extern void update_rq_clock(struct rq *rq);

extern void activate_task(struct rq *rq, struct task_struct *p, int flags);
extern void deactivate_task(struct rq *rq, struct task_struct *p, int flags);

extern void check_preempt_curr(struct rq *rq, struct task_struct *p, int flags);

extern const_debug unsigned int sysctl_sched_time_avg;
extern const_debug unsigned int sysctl_sched_nr_migrate;
extern const_debug unsigned int sysctl_sched_migration_cost;

static inline u64 sched_avg_period(void)
{
	return (u64)sysctl_sched_time_avg * NSEC_PER_MSEC / 2;
}

#ifdef CONFIG_SCHED_HRTICK

/*
 * Use hrtick when:
 *  - enabled by features
 *  - hrtimer is actually high res
 */
static inline int hrtick_enabled(struct rq *rq)
{
	if (!sched_feat(HRTICK))
		return 0;
	if (!cpu_active(cpu_of(rq)))
		return 0;
	return hrtimer_is_hres_active(&rq->hrtick_timer);
}

void hrtick_start(struct rq *rq, u64 delay);

#else

static inline int hrtick_enabled(struct rq *rq)
{
	return 0;
}

#endif /* CONFIG_SCHED_HRTICK */

#ifdef CONFIG_SMP
extern void sched_avg_update(struct rq *rq);

#ifndef arch_scale_freq_capacity
static __always_inline
unsigned long arch_scale_freq_capacity(struct sched_domain *sd, int cpu)
{
	return SCHED_CAPACITY_SCALE;
}
#endif

#ifndef arch_scale_cpu_capacity
static __always_inline
unsigned long arch_scale_cpu_capacity(struct sched_domain *sd, int cpu)
{
	if (sd && (sd->flags & SD_SHARE_CPUCAPACITY) && (sd->span_weight > 1))
		return sd->smt_gain / sd->span_weight;

	return SCHED_CAPACITY_SCALE;
}
#endif

static inline void sched_rt_avg_update(struct rq *rq, u64 rt_delta)
{
	rq->rt_avg += rt_delta * arch_scale_freq_capacity(NULL, cpu_of(rq));
	sched_avg_update(rq);
}
#else
static inline void sched_rt_avg_update(struct rq *rq, u64 rt_delta) { }
static inline void sched_avg_update(struct rq *rq) { }
#endif

/*
 * __task_rq_lock - lock the rq @p resides on.
 */
static inline struct rq *__task_rq_lock(struct task_struct *p)
	__acquires(rq->lock)
{
	struct rq *rq;

	lockdep_assert_held(&p->pi_lock);

	for (;;) {
		rq = task_rq(p);
		raw_spin_lock(&rq->lock);
		if (likely(rq == task_rq(p) && !task_on_rq_migrating(p))) {
			lockdep_pin_lock(&rq->lock);
			return rq;
		}
		raw_spin_unlock(&rq->lock);

		while (unlikely(task_on_rq_migrating(p)))
			cpu_relax();
	}
}

/*
 * task_rq_lock - lock p->pi_lock and lock the rq @p resides on.
 */
static inline struct rq *task_rq_lock(struct task_struct *p, unsigned long *flags)
	__acquires(p->pi_lock)
	__acquires(rq->lock)
{
	struct rq *rq;

	for (;;) {
		raw_spin_lock_irqsave(&p->pi_lock, *flags);
		rq = task_rq(p);
		raw_spin_lock(&rq->lock);
		/*
		 *	move_queued_task()		task_rq_lock()
		 *
		 *	ACQUIRE (rq->lock)
		 *	[S] ->on_rq = MIGRATING		[L] rq = task_rq()
		 *	WMB (__set_task_cpu())		ACQUIRE (rq->lock);
		 *	[S] ->cpu = new_cpu		[L] task_rq()
		 *					[L] ->on_rq
		 *	RELEASE (rq->lock)
		 *
		 * If we observe the old cpu in task_rq_lock, the acquire of
		 * the old rq->lock will fully serialize against the stores.
		 *
		 * If we observe the new cpu in task_rq_lock, the acquire will
		 * pair with the WMB to ensure we must then also see migrating.
		 */
		if (likely(rq == task_rq(p) && !task_on_rq_migrating(p))) {
			lockdep_pin_lock(&rq->lock);
			return rq;
		}
		raw_spin_unlock(&rq->lock);
		raw_spin_unlock_irqrestore(&p->pi_lock, *flags);

		while (unlikely(task_on_rq_migrating(p)))
			cpu_relax();
	}
}

static inline void __task_rq_unlock(struct rq *rq)
	__releases(rq->lock)
{
	lockdep_unpin_lock(&rq->lock);
	raw_spin_unlock(&rq->lock);
}

static inline void
task_rq_unlock(struct rq *rq, struct task_struct *p, unsigned long *flags)
	__releases(rq->lock)
	__releases(p->pi_lock)
{
	lockdep_unpin_lock(&rq->lock);
	raw_spin_unlock(&rq->lock);
	raw_spin_unlock_irqrestore(&p->pi_lock, *flags);
}

#ifdef CONFIG_SMP
#ifdef CONFIG_PREEMPT

static inline void double_rq_lock(struct rq *rq1, struct rq *rq2);

/*
 * fair double_lock_balance: Safely acquires both rq->locks in a fair
 * way at the expense of forcing extra atomic operations in all
 * invocations.  This assures that the double_lock is acquired using the
 * same underlying policy as the spinlock_t on this architecture, which
 * reduces latency compared to the unfair variant below.  However, it
 * also adds more overhead and therefore may reduce throughput.
 */
static inline int _double_lock_balance(struct rq *this_rq, struct rq *busiest)
	__releases(this_rq->lock)
	__acquires(busiest->lock)
	__acquires(this_rq->lock)
{
	raw_spin_unlock(&this_rq->lock);
	double_rq_lock(this_rq, busiest);

	return 1;
}

#else
/*
 * Unfair double_lock_balance: Optimizes throughput at the expense of
 * latency by eliminating extra atomic operations when the locks are
 * already in proper order on entry.  This favors lower cpu-ids and will
 * grant the double lock to lower cpus over higher ids under contention,
 * regardless of entry order into the function.
 */
static inline int _double_lock_balance(struct rq *this_rq, struct rq *busiest)
	__releases(this_rq->lock)
	__acquires(busiest->lock)
	__acquires(this_rq->lock)
{
	int ret = 0;

	if (unlikely(!raw_spin_trylock(&busiest->lock))) {
		if (busiest < this_rq) {
			raw_spin_unlock(&this_rq->lock);
			raw_spin_lock(&busiest->lock);
			raw_spin_lock_nested(&this_rq->lock,
					      SINGLE_DEPTH_NESTING);
			ret = 1;
		} else
			raw_spin_lock_nested(&busiest->lock,
					      SINGLE_DEPTH_NESTING);
	}
	return ret;
}

#endif /* CONFIG_PREEMPT */

/*
 * double_lock_balance - lock the busiest runqueue, this_rq is locked already.
 */
static inline int double_lock_balance(struct rq *this_rq, struct rq *busiest)
{
	if (unlikely(!irqs_disabled())) {
		/* printk() doesn't work good under rq->lock */
		raw_spin_unlock(&this_rq->lock);
		BUG_ON(1);
	}

	return _double_lock_balance(this_rq, busiest);
}

static inline void double_unlock_balance(struct rq *this_rq, struct rq *busiest)
	__releases(busiest->lock)
{
	raw_spin_unlock(&busiest->lock);
	lock_set_subclass(&this_rq->lock.dep_map, 0, _RET_IP_);
}

static inline void double_lock(spinlock_t *l1, spinlock_t *l2)
{
	if (l1 > l2)
		swap(l1, l2);

	spin_lock(l1);
	spin_lock_nested(l2, SINGLE_DEPTH_NESTING);
}

static inline void double_lock_irq(spinlock_t *l1, spinlock_t *l2)
{
	if (l1 > l2)
		swap(l1, l2);

	spin_lock_irq(l1);
	spin_lock_nested(l2, SINGLE_DEPTH_NESTING);
}

static inline void double_raw_lock(raw_spinlock_t *l1, raw_spinlock_t *l2)
{
	if (l1 > l2)
		swap(l1, l2);

	raw_spin_lock(l1);
	raw_spin_lock_nested(l2, SINGLE_DEPTH_NESTING);
}

/*
 * double_rq_lock - safely lock two runqueues
 *
 * Note this does not disable interrupts like task_rq_lock,
 * you need to do so manually before calling.
 */
static inline void double_rq_lock(struct rq *rq1, struct rq *rq2)
	__acquires(rq1->lock)
	__acquires(rq2->lock)
{
	BUG_ON(!irqs_disabled());
	if (rq1 == rq2) {
		raw_spin_lock(&rq1->lock);
		__acquire(rq2->lock);	/* Fake it out ;) */
	} else {
		if (rq1 < rq2) {
			raw_spin_lock(&rq1->lock);
			raw_spin_lock_nested(&rq2->lock, SINGLE_DEPTH_NESTING);
		} else {
			raw_spin_lock(&rq2->lock);
			raw_spin_lock_nested(&rq1->lock, SINGLE_DEPTH_NESTING);
		}
	}
}

/*
 * double_rq_unlock - safely unlock two runqueues
 *
 * Note this does not restore interrupts like task_rq_unlock,
 * you need to do so manually after calling.
 */
static inline void double_rq_unlock(struct rq *rq1, struct rq *rq2)
	__releases(rq1->lock)
	__releases(rq2->lock)
{
	raw_spin_unlock(&rq1->lock);
	if (rq1 != rq2)
		raw_spin_unlock(&rq2->lock);
	else
		__release(rq2->lock);
}

#else /* CONFIG_SMP */

/*
 * double_rq_lock - safely lock two runqueues
 *
 * Note this does not disable interrupts like task_rq_lock,
 * you need to do so manually before calling.
 */
static inline void double_rq_lock(struct rq *rq1, struct rq *rq2)
	__acquires(rq1->lock)
	__acquires(rq2->lock)
{
	BUG_ON(!irqs_disabled());
	BUG_ON(rq1 != rq2);
	raw_spin_lock(&rq1->lock);
	__acquire(rq2->lock);	/* Fake it out ;) */
}

/*
 * double_rq_unlock - safely unlock two runqueues
 *
 * Note this does not restore interrupts like task_rq_unlock,
 * you need to do so manually after calling.
 */
static inline void double_rq_unlock(struct rq *rq1, struct rq *rq2)
	__releases(rq1->lock)
	__releases(rq2->lock)
{
	BUG_ON(rq1 != rq2);
	raw_spin_unlock(&rq1->lock);
	__release(rq2->lock);
}

#endif

extern struct sched_entity *__pick_first_entity(struct cfs_rq *cfs_rq);
extern struct sched_entity *__pick_last_entity(struct cfs_rq *cfs_rq);

#ifdef	CONFIG_SCHED_DEBUG
extern void print_cfs_stats(struct seq_file *m, int cpu);
extern void print_rt_stats(struct seq_file *m, int cpu);
extern void print_dl_stats(struct seq_file *m, int cpu);
extern void
print_cfs_rq(struct seq_file *m, int cpu, struct cfs_rq *cfs_rq);

#ifdef CONFIG_NUMA_BALANCING
extern void
show_numa_stats(struct task_struct *p, struct seq_file *m);
extern void
print_numa_stats(struct seq_file *m, int node, unsigned long tsf,
	unsigned long tpf, unsigned long gsf, unsigned long gpf);
#endif /* CONFIG_NUMA_BALANCING */
#endif /* CONFIG_SCHED_DEBUG */

extern void init_cfs_rq(struct cfs_rq *cfs_rq);
extern void init_rt_rq(struct rt_rq *rt_rq);
extern void init_dl_rq(struct dl_rq *dl_rq);

extern void cfs_bandwidth_usage_inc(void);
extern void cfs_bandwidth_usage_dec(void);

#ifdef CONFIG_NO_HZ_COMMON
enum rq_nohz_flag_bits {
	NOHZ_TICK_STOPPED,
	NOHZ_BALANCE_KICK,
};

#define nohz_flags(cpu)	(&cpu_rq(cpu)->nohz_flags)
#endif

#ifdef CONFIG_IRQ_TIME_ACCOUNTING

DECLARE_PER_CPU(u64, cpu_hardirq_time);
DECLARE_PER_CPU(u64, cpu_softirq_time);

#ifndef CONFIG_64BIT
DECLARE_PER_CPU(seqcount_t, irq_time_seq);

static inline void irq_time_write_begin(void)
{
	__this_cpu_inc(irq_time_seq.sequence);
	smp_wmb();
}

static inline void irq_time_write_end(void)
{
	smp_wmb();
	__this_cpu_inc(irq_time_seq.sequence);
}

static inline u64 irq_time_read(int cpu)
{
	u64 irq_time;
	unsigned seq;

	do {
		seq = read_seqcount_begin(&per_cpu(irq_time_seq, cpu));
		irq_time = per_cpu(cpu_softirq_time, cpu) +
			   per_cpu(cpu_hardirq_time, cpu);
	} while (read_seqcount_retry(&per_cpu(irq_time_seq, cpu), seq));

	return irq_time;
}
#else /* CONFIG_64BIT */
static inline void irq_time_write_begin(void)
{
}

static inline void irq_time_write_end(void)
{
}

static inline u64 irq_time_read(int cpu)
{
	return per_cpu(cpu_softirq_time, cpu) + per_cpu(cpu_hardirq_time, cpu);
}
#endif /* CONFIG_64BIT */
#endif /* CONFIG_IRQ_TIME_ACCOUNTING */
