#ifndef _TICK_SCHED_H
#define _TICK_SCHED_H

#include <linux/hrtimer.h>

enum tick_device_mode {
	TICKDEV_MODE_PERIODIC,
	TICKDEV_MODE_ONESHOT,
};

struct tick_device {
	struct clock_event_device *evtdev;
	enum tick_device_mode mode;
};

enum tick_nohz_mode {
	NOHZ_MODE_INACTIVE,
	NOHZ_MODE_LOWRES,
	NOHZ_MODE_HIGHRES,
};

/**
 * struct tick_sched - sched tick emulation and no idle tick control/stats
 * @sched_timer:	hrtimer to schedule the periodic tick in high
 *			resolution mode
 * @last_tick:		Store the last tick expiry time when the tick
 *			timer is modified for nohz sleeps. This is necessary
 *			to resume the tick timer operation in the timeline
 *			when the CPU returns from nohz sleep.
 * @tick_stopped:	Indicator that the idle tick has been stopped
 * @idle_jiffies:	jiffies at the entry to idle for idle time accounting
 * @idle_calls:		Total number of idle calls
 * @idle_sleeps:	Number of idle calls, where the sched tick was stopped
 * @idle_entrytime:	Time when the idle call was entered
 * @idle_waketime:	Time when the idle was interrupted
 * @idle_exittime:	Time when the idle state was left
 * @idle_sleeptime:	Sum of the time slept in idle with sched tick stopped
 * @iowait_sleeptime:	Sum of the time slept in idle with sched tick stopped, with IO outstanding
 * @sleep_length:	Duration of the current idle sleep
 * @do_timer_lst:	CPU was the last one doing do_timer before going idle
 */
struct tick_sched {
//sched_timer表示用于实现时钟的定时器。
	struct hrtimer			sched_timer;
//用于notify系统通知hrtimer系统需要检查是否切换到高精度模式
	unsigned long			check_clocks;
	enum tick_nohz_mode		nohz_mode;
	//禁用周期时钟之前，上一个时钟信号的到期时间
	ktime_t				last_tick;
	int				inidle;
	//如果周期时钟已经停用，则tick_stopped为1
	int				tick_stopped;
	//idle_jiffies存储了周期时钟禁用时的jiffies值
	unsigned long			idle_jiffies;
	//idle_calls统计了内核试图停用周期时钟的次数
	unsigned long			idle_calls;
	//统计了实际上成功停用周期时钟的次数
	unsigned long			idle_sleeps;
	int				idle_active;
	ktime_t				idle_entrytime;
	ktime_t				idle_waketime;
	ktime_t				idle_exittime;
	//周期时钟上一次禁用的准确时间
	ktime_t				idle_sleeptime;
	ktime_t				iowait_sleeptime;
	//周期时钟将禁用的时间长度，即从时钟禁用起，到预定将发生的下一个时钟信号为止，这一段时间的长度。
	ktime_t				sleep_length;
	unsigned long			last_jiffies;
	//下一个定时器到期时间的jiffy值
	u64				next_timer;
	//下一个将到期的经典定时器的到期时间
	ktime_t				idle_expires;
	int				do_timer_last;
};

extern struct tick_sched *tick_get_tick_sched(int cpu);

extern void tick_setup_sched_timer(void);
#if defined CONFIG_NO_HZ_COMMON || defined CONFIG_HIGH_RES_TIMERS
extern void tick_cancel_sched_timer(int cpu);
#else
static inline void tick_cancel_sched_timer(int cpu) { }
#endif

#ifdef CONFIG_GENERIC_CLOCKEVENTS_BROADCAST
extern int __tick_broadcast_oneshot_control(enum tick_broadcast_state state);
#else
static inline int
__tick_broadcast_oneshot_control(enum tick_broadcast_state state)
{
	return -EBUSY;
}
#endif

#endif
