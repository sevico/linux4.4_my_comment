#include <linux/mount.h>
#include <linux/seq_file.h>
#include <linux/poll.h>
#include <linux/ns_common.h>
#include <linux/fs_pin.h>

struct mnt_namespace {
	/*使用计数*/
	atomic_t		count;
	struct ns_common	ns;
	/*根目录的挂载点对象*/
	struct mount *	root;
	/*挂载点链表*/
	struct list_head	list;
	struct user_namespace	*user_ns;
	u64			seq;	/* Sequence number to prevent loops */
	/*轮询的等待队列*/
	wait_queue_head_t poll;
	/*事件计数*/
	u64 event;
	unsigned int		mounts; /* # of mounts in the namespace */
	unsigned int		pending_mounts;
};

struct mnt_pcp {
	int mnt_count;
	int mnt_writers;
};

struct mountpoint {
	struct hlist_node m_hash;
	struct dentry *m_dentry;
	struct hlist_head m_list;
	int m_count;
};

struct mount {
	/* 用于链接到全局已挂载文件系统的链表 */
//mount_hashtable
	struct hlist_node mnt_hash;
	/* 装载点所在的父文件系统 */
	struct mount *mnt_parent;
	//指向挂载点
	/* 装载点在父文件系统中的dentry */
	//了父文件系统的一个dentry，这个dentry也就是子文件系统的真正挂载点
	struct dentry *mnt_mountpoint;
	/* 指向此文件系统的vfsmount实例 */
	struct vfsmount mnt;
	union {
		/* 用于rcu锁 */
		struct rcu_head mnt_rcu;
		struct llist_node mnt_llist;
	};
#ifdef CONFIG_SMP
	/* 用于多核 */
	struct mnt_pcp __percpu *mnt_pcp;
#else
	//每当一个vfsmount实例不再需要时，都必须用mntput将计数器减1
	/* 使用计数 */
	int mnt_count;
	int mnt_writers;
#endif
	/* 子文件系统链表 */
	/* 挂载在此文件系统下的所有子文件系统的链表的表头，下面的节点都是mnt_child */
	struct list_head mnt_mounts;	/* list of children, anchored here */
	/* 链表元素，用于父文件系统中的mnt_mounts链表 */
	struct list_head mnt_child;	/* and going through their mnt_child */
	/* 链接到sb->s_mounts上的一个mount实例 */
	struct list_head mnt_instance;	/* mount instance on sb->s_mounts */
	/* 64位体系结构上，是一个4字节的空洞 */
	/* 设备名，如 /dev/dsk/hda1 */
	const char *mnt_devname;	/* Name of device e.g. /dev/dsk/hda1 */
	/* 链接到进程namespace中已挂载文件系统中，表头为mnt_namespace的list域 */
	struct list_head mnt_list;
	/* 链表元素，用于特定于文件系统的到期链表中 */
	struct list_head mnt_expire;	/* link in fs-specific expiry list */
	/* 链表元素，用于共享装载的循环链表 */
	/* 链接到共享挂载的循环链表中 */
	struct list_head mnt_share;	/* circular list of shared mounts */
	/* 从属装载的链表 */
	/* 此文件系统的slave mount链表的表头 */
	struct list_head mnt_slave_list;/* list of slave mounts */
	/* 链表元素，用于从属装载的链表 */
	/* 连接到master文件系统的mnt_slave_list */
	struct list_head mnt_slave;	/* slave list entry */
	/* 指向主装载，从属装载位于master->mnt_slave_list*/
	/* 指向此文件系统的master文件系统，slave is on master->mnt_slave_list */
	struct mount *mnt_master;	/* slave is on master->mnt_slave_list */
	/* 所属的命名空间 */
	/* 指向包含这个文件系统的进程的name space */
	struct mnt_namespace *mnt_ns;	/* containing namespace */
	struct mountpoint *mnt_mp;	/* where is it mounted */
	struct hlist_node mnt_mp_list;	/* list mounts with the same mountpoint */
	struct list_head mnt_umounting; /* list entry for umount propagation */
#ifdef CONFIG_FSNOTIFY
	struct hlist_head mnt_fsnotify_marks;
	__u32 mnt_fsnotify_mask;
#endif
	int mnt_id;			/* mount identifier */
	int mnt_group_id;		/* peer group identifier */
	/*
* 我们把mnt_count和mnt_expiry_mark放置在struct vfsmount的末尾，
* 以便让这些频繁修改的字段与结构的主体处于两个不同的缓存行中
* （这样在SMP机器上读取mnt_flags不会造成高速缓存的颠簸）
*/
	int mnt_expiry_mark;		/* true if marked for expiry */
	struct hlist_head mnt_pins;
	struct fs_pin mnt_umount;
	struct dentry *mnt_ex_mountpoint;
};

#define MNT_NS_INTERNAL ERR_PTR(-EINVAL) /* distinct from any mnt_namespace */

static inline struct mount *real_mount(struct vfsmount *mnt)
{
	return container_of(mnt, struct mount, mnt);
}

static inline int mnt_has_parent(struct mount *mnt)
{
	return mnt != mnt->mnt_parent;
}

static inline int is_mounted(struct vfsmount *mnt)
{
	/* neither detached nor internal? */
	return !IS_ERR_OR_NULL(real_mount(mnt)->mnt_ns);
}

extern struct mount *__lookup_mnt(struct vfsmount *, struct dentry *);

extern int __legitimize_mnt(struct vfsmount *, unsigned);
extern bool legitimize_mnt(struct vfsmount *, unsigned);

extern void __detach_mounts(struct dentry *dentry);

static inline void detach_mounts(struct dentry *dentry)
{
	if (!d_mountpoint(dentry))
		return;
	__detach_mounts(dentry);
}

static inline void get_mnt_ns(struct mnt_namespace *ns)
{
	atomic_inc(&ns->count);
}

extern seqlock_t mount_lock;

static inline void lock_mount_hash(void)
{
	write_seqlock(&mount_lock);
}

static inline void unlock_mount_hash(void)
{
	write_sequnlock(&mount_lock);
}

struct proc_mounts {
	struct mnt_namespace *ns;
	struct path root;
	int (*show)(struct seq_file *, struct vfsmount *);
	void *cached_mount;
	u64 cached_event;
	loff_t cached_index;
};

extern const struct seq_operations mounts_op;

extern bool __is_local_mountpoint(struct dentry *dentry);
static inline bool is_local_mountpoint(struct dentry *dentry)
{
	if (!d_mountpoint(dentry))
		return false;

	return __is_local_mountpoint(dentry);
}
