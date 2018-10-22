#ifndef _LINUX_SLUB_DEF_H
#define _LINUX_SLUB_DEF_H

/*
 * SLUB : A Slab allocator without object queues.
 *
 * (C) 2007 SGI, Christoph Lameter
 */
#include <linux/kobject.h>

enum stat_item {
	ALLOC_FASTPATH,		/* Allocation from cpu slab */
	ALLOC_SLOWPATH,		/* Allocation by getting a new cpu slab */
	FREE_FASTPATH,		/* Free to cpu slab */
	FREE_SLOWPATH,		/* Freeing not to cpu slab */
	FREE_FROZEN,		/* Freeing to frozen slab */
	FREE_ADD_PARTIAL,	/* Freeing moves slab to partial list */
	FREE_REMOVE_PARTIAL,	/* Freeing removes last object */
	ALLOC_FROM_PARTIAL,	/* Cpu slab acquired from node partial list */
	ALLOC_SLAB,		/* Cpu slab acquired from page allocator */
	ALLOC_REFILL,		/* Refill cpu slab from slab freelist */
	ALLOC_NODE_MISMATCH,	/* Switching cpu slab */
	FREE_SLAB,		/* Slab freed to the page allocator */
	CPUSLAB_FLUSH,		/* Abandoning of the cpu slab */
	DEACTIVATE_FULL,	/* Cpu slab was full when deactivated */
	DEACTIVATE_EMPTY,	/* Cpu slab was empty when deactivated */
	DEACTIVATE_TO_HEAD,	/* Cpu slab was moved to the head of partials */
	DEACTIVATE_TO_TAIL,	/* Cpu slab was moved to the tail of partials */
	DEACTIVATE_REMOTE_FREES,/* Slab contained remotely freed objects */
	DEACTIVATE_BYPASS,	/* Implicit deactivation */
	ORDER_FALLBACK,		/* Number of times fallback was necessary */
	CMPXCHG_DOUBLE_CPU_FAIL,/* Failure of this_cpu_cmpxchg_double */
	CMPXCHG_DOUBLE_FAIL,	/* Number of times that cmpxchg double did not match */
	CPU_PARTIAL_ALLOC,	/* Used cpu partial on alloc */
	CPU_PARTIAL_FREE,	/* Refill cpu partial on free */
	CPU_PARTIAL_NODE,	/* Refill cpu partial from node partial */
	CPU_PARTIAL_DRAIN,	/* Drain cpu partial to node partial */
	NR_SLUB_STAT_ITEMS };

struct kmem_cache_cpu {
	 /* 指向下一个空闲对象，用于快速找到对象 */
	void **freelist;	/* Pointer to next available object */
	  /* 用于保证cmpxchg_double计算发生在正确的CPU上，并且可作为一个锁保证不会同时申请这个kmem_cache_cpu的对象 */
	unsigned long tid;	/* Globally unique transaction id */
	  /* CPU当前所使用的slab缓冲区描述符，freelist会指向此slab的下一个空闲对象 */
	struct page *page;	/* The slab from which we are allocating */
 /* CPU的部分空slab链表，放到CPU的部分空slab链表中的slab会被冻结，而放入node中的部分空slab链表则解冻，冻结标志在slab缓冲区描述符中 */
	struct page *partial;	/* Partially allocated frozen slabs */
#ifdef CONFIG_SLUB_STATS
	unsigned stat[NR_SLUB_STAT_ITEMS];
#endif
};

/*
 * Word size structure that can be atomically updated or read and that
 * contains both the order and the number of objects that a slab of the
 * given order would contain.
 */
struct kmem_cache_order_objects {
	unsigned long x;
};

/*
 * Slab cache management.
 */
struct kmem_cache {
	struct kmem_cache_cpu __percpu *cpu_slab;
	/* Used for retriving partial slabs etc */
	/* 标志 */
	unsigned long flags;
	/* 每个node结点中部分空slab缓冲区数量不能低于这个值 */
	unsigned long min_partial;
	/* 分配给对象的内存大小(大于对象的实际大小，大小包括对象后边的下个空闲对象指针) */
	int size;		/* The size of an object including meta data */
	/* 对象的实际大小 */
	int object_size;	/* The size of an object without meta data */
	/* 存放空闲对象指针的偏移量 */
	int offset;		/* Free pointer offset. */
	/* cpu的可用objects数量范围最大值 */
	int cpu_partial;	/* Number of per cpu partial objects to keep around */
	/* 保存slab缓冲区需要的页框数量的order值和objects数量的值，通过这个值可以计算出需要多少页框，这个是默认值，初始化时会根据经验计算这个值 */
	struct kmem_cache_order_objects oo;

	/* Allocation and freeing of slabs */
	/* 保存slab缓冲区需要的页框数量的order值和objects数量的值，这个是最大值 */
	struct kmem_cache_order_objects max;
	 /* 保存slab缓冲区需要的页框数量的order值和objects数量的值，这个是最小值，当默认值oo分配失败时，会尝试用最小值去分配连续页框 */
	struct kmem_cache_order_objects min;
	 /* 每一次分配时所使用的标志 */
	gfp_t allocflags;	/* gfp flags to use on each alloc */
	 /* 重用计数器，当用户请求创建新的SLUB种类时，SLUB 分配器重用已创建的相似大小的SLUB，从而减少SLUB种类的个数。 */
	int refcount;		/* Refcount for slab cache destroy */
	  /* 创建slab时的构造函数 */
	void (*ctor)(void *);
	   /* 元数据的偏移量 */
	int inuse;		/* Offset to metadata */
	   /* 对齐 */
	int align;		/* Alignment */
	int reserved;		/* Reserved bytes at the end of slabs */
	 /* 高速缓存名字 */
	const char *name;	/* Name (only for display!) */
	  /* 所有的 kmem_cache 结构都会链入这个链表，链表头是 slab_caches */
	struct list_head list;	/* List of slab caches */
#ifdef CONFIG_SYSFS
	/* 用于sysfs文件系统，在/sys中会有个slub的专用目录 */

	struct kobject kobj;	/* For sysfs */
#endif
#ifdef CONFIG_MEMCG_KMEM
	/* 这两个主要用于memory cgroup的*/
	struct memcg_cache_params memcg_params;
	int max_attr_size; /* for propagation, maximum size of a stored attr */
#ifdef CONFIG_SYSFS
	struct kset *memcg_kset;
#endif
#endif

#ifdef CONFIG_NUMA
	/*
	 * Defragmentation by allocating from a remote node.
	 */
	  /* 用于NUMA架构，该值越小，越倾向于在本结点分配对象 */
	int remote_node_defrag_ratio;
#endif
	/* 此高速缓存的SLAB链表，每个NUMA结点有一个，有可能该高速缓存有些SLAB处于其他结点上 */
	struct kmem_cache_node *node[MAX_NUMNODES];
};

#ifdef CONFIG_SYSFS
#define SLAB_SUPPORTS_SYSFS
void sysfs_slab_remove(struct kmem_cache *);
#else
static inline void sysfs_slab_remove(struct kmem_cache *s)
{
}
#endif


/**
 * virt_to_obj - returns address of the beginning of object.
 * @s: object's kmem_cache
 * @slab_page: address of slab page
 * @x: address within object memory range
 *
 * Returns address of the beginning of object
 */
static inline void *virt_to_obj(struct kmem_cache *s,
				const void *slab_page,
				const void *x)
{
	return (void *)x - ((x - slab_page) % s->size);
}

void object_err(struct kmem_cache *s, struct page *page,
		u8 *object, char *reason);

#endif /* _LINUX_SLUB_DEF_H */
