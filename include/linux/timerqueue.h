#ifndef _LINUX_TIMERQUEUE_H
#define _LINUX_TIMERQUEUE_H

#include <linux/rbtree.h>
#include <linux/ktime.h>


struct timerqueue_node {
	// 红黑树的节点
	struct rb_node node;
	// 该节点代表队hrtimer的到期时间，与hrtimer结构中的_softexpires稍有不同
	// 该字段和hrtimer中的_softexpires字段一起，设定了hrtimer的到期时间的一个范围，
	// hrtimer可以在hrtimer._softexpires至timerqueue_node.expires之间的任何时刻到期，
	// 我们也称timerqueue_node.expires为硬过期时间(hard)
	ktime_t expires;
};

struct timerqueue_head {
	// 红黑树的根节点
	struct rb_root head;
	// 该红黑树中最早到期的节点，也就是最左下的节点
	struct timerqueue_node *next;
};


extern bool timerqueue_add(struct timerqueue_head *head,
			   struct timerqueue_node *node);
extern bool timerqueue_del(struct timerqueue_head *head,
			   struct timerqueue_node *node);
extern struct timerqueue_node *timerqueue_iterate_next(
						struct timerqueue_node *node);

/**
 * timerqueue_getnext - Returns the timer with the earliest expiration time
 *
 * @head: head of timerqueue
 *
 * Returns a pointer to the timer node that has the
 * earliest expiration time.
 */
static inline
struct timerqueue_node *timerqueue_getnext(struct timerqueue_head *head)
{
	return head->next;
}

static inline void timerqueue_init(struct timerqueue_node *node)
{
	RB_CLEAR_NODE(&node->node);
}

static inline void timerqueue_init_head(struct timerqueue_head *head)
{
	head->head = RB_ROOT;
	head->next = NULL;
}
#endif /* _LINUX_TIMERQUEUE_H */
