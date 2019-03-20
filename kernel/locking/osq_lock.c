#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/osq_lock.h>

/*
 * An MCS like lock especially tailored for optimistic spinning for sleeping
 * lock implementations (mutex, rwsem, etc).
 *
 * Using a single mcs node per CPU is safe because sleeping locks should not be
 * called from interrupt context and we have preemption disabled while
 * spinning.
 */
static DEFINE_PER_CPU_SHARED_ALIGNED(struct optimistic_spin_node, osq_node);

/*
 * We use the value 0 to represent "no CPU", thus the encoded value
 * will be the CPU number incremented by 1.
 */
static inline int encode_cpu(int cpu_nr)
{
	return cpu_nr + 1;
}

static inline struct optimistic_spin_node *decode_cpu(int encoded_cpu_val)
{
	int cpu_nr = encoded_cpu_val - 1;

	return per_cpu_ptr(&osq_node, cpu_nr);
}

/*
 * Get a stable @node->next pointer, either for unlock() or unqueue() purposes.
 * Can return NULL in case we were the last queued and we updated @lock instead.
 */
static inline struct optimistic_spin_node *
osq_wait_next(struct optimistic_spin_queue *lock,
	      struct optimistic_spin_node *node,
	      struct optimistic_spin_node *prev)
{
	struct optimistic_spin_node *next = NULL;
	int curr = encode_cpu(smp_processor_id());
	int old;

	/*
	 * If there is a prev node in queue, then the 'old' value will be
	 * the prev node's CPU #, else it's set to OSQ_UNLOCKED_VAL since if
	 * we're currently last in queue, then the queue will then become empty.
	 */
	old = prev ? prev->cpu : OSQ_UNLOCKED_VAL;

	for (;;) {
		if (atomic_read(&lock->tail) == curr &&
		    atomic_cmpxchg_acquire(&lock->tail, curr, old) == curr) {
			/*
			 * We were the last queued, we moved @lock back. @prev
			 * will now observe @lock and will complete its
			 * unlock()/unqueue().
			 */
			break;
		}

		/*
		 * We must xchg() the @node->next value, because if we were to
		 * leave it in, a concurrent unlock()/unqueue() from
		 * @node->next might complete Step-A and think its @prev is
		 * still valid.
		 *
		 * If the concurrent unlock()/unqueue() wins the race, we'll
		 * wait for either @lock to point to us, through its Step-B, or
		 * wait for a new @node->next from its Step-C.
		 */
		if (node->next) {
			next = xchg(&node->next, NULL);
			if (next)
				break;
		}

		cpu_relax_lowlatency();
	}

	return next;
}

bool osq_lock(struct optimistic_spin_queue *lock)
{
	//当前cpu的node
	struct optimistic_spin_node *node = this_cpu_ptr(&osq_node);
	struct optimistic_spin_node *prev, *next;
	//curr = smp_processor_id + 1
	int curr = encode_cpu(smp_processor_id());
	int old;

	node->locked = 0;
	node->next = NULL;
	node->cpu = curr;

	/*
	 * We need both ACQUIRE (pairs with corresponding RELEASE in
	 * unlock() uncontended, or fastpath) and RELEASE (to publish
	 * the node fields we just initialised) semantics when updating
	 * the lock tail.
	 */
	 //把lock->tail设置成curr，旧值返回给old
	old = atomic_xchg(&lock->tail, curr);
	 //如果之前是没有CPU获取到锁的，获取锁成功，返回true
	if (old == OSQ_UNLOCKED_VAL)
		return true;
	 //获取到上个cpu的node
	prev = decode_cpu(old);
	//设置当前node->prev为上一个cpu的node
	node->prev = prev;
	//上一个cpu的node->next设置为当前cpu的node
	WRITE_ONCE(prev->next, node);

	/*
	 * Normally @prev is untouchable after the above store; because at that
	 * moment unlock can proceed and wipe the node element from stack.
	 *
	 * However, since our nodes are static per-cpu storage, we're
	 * guaranteed their existence -- this allows us to apply
	 * cmpxchg in an attempt to undo our queueing.
	 */
	//一直查询当前node的locked是否为1，相当于自旋等待
	while (!READ_ONCE(node->locked)) {
		/*
		 * If we need to reschedule bail... so we can block.
		 */
		 //在等待的过程中，如果有优先级更高的进程抢占或者被调度器要求调度出去，那就应该放弃自旋等待。
		if (need_resched())
			goto unqueue;

		cpu_relax_lowlatency();
	}
	return true;

unqueue:
	/*
	 * Step - A  -- stabilize @prev
	 *
	 * Undo our @prev->next assignment; this will make @prev's
	 * unlock()/unqueue() wait for a next pointer since @lock points to us
	 * (or later).
	 */

	for (;;) {
		//无锁操作，把prev->next设置成null
		if (prev->next == node &&
		    cmpxchg(&prev->next, node, NULL) == node)
			break;

		/*
		 * We can only fail the cmpxchg() racing against an unlock(),
		 * in which case we should observe @node->locked becomming
		 * true.
		 */
		 //如果当前的locked被置成1，说明上一个cpu释放了锁，自己获取到了锁
		if (smp_load_acquire(&node->locked))
			return true;

		cpu_relax_lowlatency();

		/*
		 * Or we race against a concurrent unqueue()'s step-B, in which
		 * case its step-C will write us a new @node->prev pointer.
		 */
		 //重新获prev，防止其他地方修改链表
		prev = READ_ONCE(node->prev);
	}

	/*
	 * Step - B -- stabilize @next
	 *
	 * Similar to unlock(), wait for @node->next or move @lock from @node
	 * back to @prev.
	 */

	next = osq_wait_next(lock, node, prev);
	if (!next)
		return false;

	/*
	 * Step - C -- unlink
	 *
	 * @prev is stable because its still waiting for a new @prev->next
	 * pointer, @next is stable because our @node->next pointer is NULL and
	 * it will wait in Step-A.
	 */

	WRITE_ONCE(next->prev, prev);
	WRITE_ONCE(prev->next, next);

	return false;
}

void osq_unlock(struct optimistic_spin_queue *lock)
{
	struct optimistic_spin_node *node, *next;
	int curr = encode_cpu(smp_processor_id());

	/*
	 * Fast path for the uncontended case.
	 */
	 //如果tail为0，说明没有人竞争该锁，直接把tail设置成0，返回
	if (likely(atomic_cmpxchg_release(&lock->tail, curr,
					  OSQ_UNLOCKED_VAL) == curr))
		return;

	/*
	 * Second most likely case.
	 */
	 //反之有人竞争锁，获取当前node
	node = this_cpu_ptr(&osq_node);
	//把当前node的next设置成0，并返回之前next
	next = xchg(&node->next, NULL);
	//如果next不为0，说明有cpu在自旋等待锁
	if (next) {
		//把next->locked置为1，让他获取锁
		WRITE_ONCE(next->locked, 1);
		return;
	}
	//把当前node移除队列，设置next的prev，并返回next
	next = osq_wait_next(lock, node, NULL);
	//这时再判断一下next是否有值，有值得话说明有cpu在自选等待，
    //设置next的Locked
	if (next)
		WRITE_ONCE(next->locked, 1);
}
