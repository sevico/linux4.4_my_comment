/*
 * kobject.h - generic kernel object infrastructure.
 *
 * Copyright (c) 2002-2003 Patrick Mochel
 * Copyright (c) 2002-2003 Open Source Development Labs
 * Copyright (c) 2006-2008 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (c) 2006-2008 Novell Inc.
 *
 * This file is released under the GPLv2.
 *
 * Please read Documentation/kobject.txt before using the kobject
 * interface, ESPECIALLY the parts about reference counts and object
 * destructors.
 */

#ifndef _KOBJECT_H_
#define _KOBJECT_H_

#include <linux/types.h>
#include <linux/list.h>
#include <linux/sysfs.h>
#include <linux/compiler.h>
#include <linux/spinlock.h>
#include <linux/kref.h>
#include <linux/kobject_ns.h>
#include <linux/kernel.h>
#include <linux/wait.h>
#include <linux/atomic.h>
#include <linux/workqueue.h>

#define UEVENT_HELPER_PATH_LEN		256
#define UEVENT_NUM_ENVP			32	/* number of env pointers */
#define UEVENT_BUFFER_SIZE		2048	/* buffer for the variables */

#ifdef CONFIG_UEVENT_HELPER
/* path to the userspace helper executed on an event */
extern char uevent_helper[];
#endif

/* counter to tag the uevent, read only except for the kobject core */
extern u64 uevent_seqnum;

/*
 * The actions here must match the index to the string array
 * in lib/kobject_uevent.c
 *
 * Do not add new actions here without checking with the driver-core
 * maintainers. Action strings are not meant to express subsystem
 * or device specific properties. In most cases you want to send a
 * kobject_uevent_env(kobj, KOBJ_CHANGE, env) with additional event
 * specific variables added to the event environment.
 */
enum kobject_action {
	KOBJ_ADD,// 添加
	KOBJ_REMOVE,// 移除
	//Kobject（或上层数据结构）的状态或者内容发生改变
	KOBJ_CHANGE,// 状态变化
	KOBJ_MOVE,// 更改名称或者更改 Parent
	//ONLINE/OFFLINE，Kobject（或上层数据结构）的上线/下线事件，其实是是否使能。
	KOBJ_ONLINE,// 上线
	KOBJ_OFFLINE,// 下线
	KOBJ_MAX
};

struct kobject {
	/*name，该Kobject的名称，同时也是sysfs中的目录名称。由于Kobject添加到Kernel时，需要根据名字注册到sysfs中，之后就不能再直接修改该字段。如果需要修改Kobject的名字，需要调用kobject_rename接口，该接口会主动处理sysfs的相关事宜。*/
	const char		*name;
	struct list_head	entry; //用于将Kobject加入到Kset中的list_head。
	struct kobject		*parent; //指向parent kobject，以此形成层次结构（在sysfs就表现为目录结构）。	
	//kobject属于的Kset。可以为NULL。如果存在，且没有指定parent，则会把Kset作为parent（别忘了Kset是一个特殊的Kobject）。
	struct kset		*kset;	
	//该Kobject属于的kobj_type。每个Kobject必须有一个ktype，或者Kernel会提示错误。
	struct kobj_type	*ktype;
	//对应sysfs对象。在3.14以后的内核中，sysfs基于kernfs来实现
	struct kernfs_node	*sd; /* sysfs directory entry */
	//该Kobject在sysfs中的表示。
	struct kref		kref;  //一个可用于原子操作的引用计数。
#ifdef CONFIG_DEBUG_KOBJECT_RELEASE
	struct delayed_work	release;
#endif
//记录初始化与否。调用kobject_init()后，会置位。
	unsigned int state_initialized:1;  //示该Kobject是否已经初始化，以在Kobject的Init，Put，Add等操作时进行异常校验。
	//记录kobj是否注册到sysfs，在kobject_add_internal()中置位
	unsigned int state_in_sysfs:1;  //指示该Kobject是否已在sysfs中呈现，以便在自动注销时从sysfs中移除。
	//当发送KOBJ_ADD消息时，置位。提示已经向用户空间发送ADD消息
	unsigned int state_add_uevent_sent:1;
	//当发送KOBJ_REMOVE消息时，置位。提示已经向用户空间发送REMOVE消息
	unsigned int state_remove_uevent_sent:1;
	// 如果该字段为1，则表示忽略所有上报的uevent事件。
	unsigned int uevent_suppress:1;
};

extern __printf(2, 3)
int kobject_set_name(struct kobject *kobj, const char *name, ...);
extern __printf(2, 0)
int kobject_set_name_vargs(struct kobject *kobj, const char *fmt,
			   va_list vargs);

static inline const char *kobject_name(const struct kobject *kobj)
{
	return kobj->name;
}

extern void kobject_init(struct kobject *kobj, struct kobj_type *ktype);
extern __printf(3, 4) __must_check
int kobject_add(struct kobject *kobj, struct kobject *parent,
		const char *fmt, ...);
extern __printf(4, 5) __must_check
int kobject_init_and_add(struct kobject *kobj,
			 struct kobj_type *ktype, struct kobject *parent,
			 const char *fmt, ...);

extern void kobject_del(struct kobject *kobj);

extern struct kobject * __must_check kobject_create(void);
extern struct kobject * __must_check kobject_create_and_add(const char *name,
						struct kobject *parent);

extern int __must_check kobject_rename(struct kobject *, const char *new_name);
extern int __must_check kobject_move(struct kobject *, struct kobject *);

extern struct kobject *kobject_get(struct kobject *kobj);
extern void kobject_put(struct kobject *kobj);

extern const void *kobject_namespace(struct kobject *kobj);
extern char *kobject_get_path(struct kobject *kobj, gfp_t flag);

struct kobj_type {
	//处理对象终结的回调函数。该接口应该由具体对象负责填充
	void (*release)(struct kobject *kobj);  //通过该回调函数，可以将包含该种类型kobject的数据结构的内存空间释放掉。
	const struct sysfs_ops *sysfs_ops;  //该种类型的Kobject的sysfs文件系统接口。
	struct attribute **default_attrs;  //该种类型的Kobject的atrribute列表（所谓attribute，就是sysfs文件系统中的一个文件）。将会在Kobject添加到内核时，一并注册到sysfs中。
	// namespace 操作函数
	const struct kobj_ns_type_operations *(*child_ns_type)(struct kobject *kobj);
	const void *(*namespace)(struct kobject *kobj);
};

struct kobj_uevent_env {
	char *argv[3];
	// 用于保存环境变量地址的指针数组，最多 32 个
	char *envp[UEVENT_NUM_ENVP];
	// 访问环境变量指针数组的索引
	int envp_idx;
	// 保存环境变量的 buffer，最大为 2048
	char buf[UEVENT_BUFFER_SIZE];
	// 当前 buf 长度
	int buflen;
};
//kset_uevent_ops是为kset量身订做的一个数据结构，里面包含filter和uevent两个回调函数
struct kset_uevent_ops {
//当任何Kobject需要上报uevent时，它所属的kset可以通过该接口过滤，阻止不希望上报的event，从而达到从整体上管理的目的。
	int (* const filter)(struct kset *kset, struct kobject *kobj);
	const char *(* const name)(struct kset *kset, struct kobject *kobj);
	int (* const uevent)(struct kset *kset, struct kobject *kobj,
		      struct kobj_uevent_env *env);
	//当任何Kobject需要上报uevent时，它所属的kset可以通过该接口统一为这些event添加环境变量。因为很多时候上报uevent时的环境变量都是相同的，因此可以由kset统一处理，就不需要让每个Kobject独自添加了。
};

struct kobj_attribute {
	struct attribute attr;
	ssize_t (*show)(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf);
	ssize_t (*store)(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count);
};

extern const struct sysfs_ops kobj_sysfs_ops;

struct sock;

/**
 * struct kset - a set of kobjects of a specific type, belonging to a specific subsystem.
 *
 * A kset defines a group of kobjects.  They can be individually
 * different "types" but overall these kobjects all want to be grouped
 * together and operated on in the same manner.  ksets are used to
 * define the attribute callbacks and other common events that happen to
 * a kobject.
 *
 * @list: the list of all kobjects for this kset
 * @list_lock: a lock for iterating over the kobjects
 * @kobj: the embedded kobject for this kset (recursion, isn't it fun...)
 * @uevent_ops: the set of uevent operations for this kset.  These are
 * called whenever a kobject has something happen to it so that the kset
 * can add new environment variables, or filter out the uevents if so
 * desired.
 */
 //kobj_type 的关联，kobject 会利用成员 kset 找到自已所属的 kset，设置自身的 ktype 为 kset.kobj.ktype 。当没有指定 kset 成员时，才会用 ktype 来建立关系
struct kset {
	// kobject 链表头
	//与kobj->entry对应，用来组织本kset管理的kobj
	struct list_head list;
	// 自旋锁，保障操作安全
	spinlock_t list_lock;
	// 自身的 kobject
	struct kobject kobj;
	// uevent 操作函数集。kobject 发送 uevent 时会调用所属 kset 的 uevent_ops
	const struct kset_uevent_ops *uevent_ops;
};

extern void kset_init(struct kset *kset);
extern int __must_check kset_register(struct kset *kset);
extern void kset_unregister(struct kset *kset);
extern struct kset * __must_check kset_create_and_add(const char *name,
						const struct kset_uevent_ops *u,
						struct kobject *parent_kobj);

static inline struct kset *to_kset(struct kobject *kobj)
{
	return kobj ? container_of(kobj, struct kset, kobj) : NULL;
}

static inline struct kset *kset_get(struct kset *k)
{
	return k ? to_kset(kobject_get(&k->kobj)) : NULL;
}

static inline void kset_put(struct kset *k)
{
	kobject_put(&k->kobj);
}

static inline struct kobj_type *get_ktype(struct kobject *kobj)
{
	return kobj->ktype;
}

extern struct kobject *kset_find_obj(struct kset *, const char *);

/* The global /sys/kernel/ kobject for people to chain off of */
extern struct kobject *kernel_kobj;
/* The global /sys/kernel/mm/ kobject for people to chain off of */
extern struct kobject *mm_kobj;
/* The global /sys/hypervisor/ kobject for people to chain off of */
extern struct kobject *hypervisor_kobj;
/* The global /sys/power/ kobject for people to chain off of */
extern struct kobject *power_kobj;
/* The global /sys/firmware/ kobject for people to chain off of */
extern struct kobject *firmware_kobj;

int kobject_uevent(struct kobject *kobj, enum kobject_action action);
int kobject_uevent_env(struct kobject *kobj, enum kobject_action action,
			char *envp[]);

__printf(2, 3)
int add_uevent_var(struct kobj_uevent_env *env, const char *format, ...);

int kobject_action_type(const char *buf, size_t count,
			enum kobject_action *type);

#endif /* _KOBJECT_H_ */
