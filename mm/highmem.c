/*
 * High memory handling common code and variables.
 *
 * (C) 1999 Andrea Arcangeli, SuSE GmbH, andrea@suse.de
 *          Gerhard Wichert, Siemens AG, Gerhard.Wichert@pdb.siemens.de
 *
 *
 * Redesigned the x86 32-bit VM architecture to deal with
 * 64-bit physical space. With current x86 CPUs this
 * means up to 64 Gigabytes physical RAM.
 *
 * Rewrote high memory support to move the page cache into
 * high memory. Implemented permanent (schedulable) kmaps
 * based on Linus' idea.
 *
 * Copyright (C) 1999 Ingo Molnar <mingo@redhat.com>
 */

#include <linux/mm.h>
#include <linux/export.h>
#include <linux/swap.h>
#include <linux/bio.h>
#include <linux/pagemap.h>
#include <linux/mempool.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/hash.h>
#include <linux/highmem.h>
#include <linux/kgdb.h>
#include <asm/tlbflush.h>


#if defined(CONFIG_HIGHMEM) || defined(CONFIG_X86_32)
DEFINE_PER_CPU(int, __kmap_atomic_idx);
#endif

/*
 * Virtual_count is not a pure "count".
 *  0 means that it is not mapped, and has not been mapped
 *    since a TLB flush - it is usable.
 *  1 means that there are no users, but it has been mapped
 *    since the last TLB flush - so we can't use it.
 *  n means that there are (n-1) current users of it.
 */
#ifdef CONFIG_HIGHMEM

/*
 * Architecture with aliasing data cache may define the following family of
 * helper functions in its asm/highmem.h to control cache color of virtual
 * addresses where physical memory pages are mapped by kmap.
 */
#ifndef get_pkmap_color

/*
 * Determine color of virtual address where the page should be mapped.
 */
static inline unsigned int get_pkmap_color(struct page *page)
{
	return 0;
}
#define get_pkmap_color get_pkmap_color

/*
 * Get next index for mapping inside PKMAP region for page with given color.
 */
static inline unsigned int get_next_pkmap_nr(unsigned int color)
{
	static unsigned int last_pkmap_nr;

	last_pkmap_nr = (last_pkmap_nr + 1) & LAST_PKMAP_MASK;
	return last_pkmap_nr;
}

/*
 * Determine if page index inside PKMAP region (pkmap_nr) of given color
 * has wrapped around PKMAP region end. When this happens an attempt to
 * flush all unused PKMAP slots is made.
 */
static inline int no_more_pkmaps(unsigned int pkmap_nr, unsigned int color)
{
	return pkmap_nr == 0;
}

/*
 * Get the number of PKMAP entries of the given color. If no free slot is
 * found after checking that many entries, kmap will sleep waiting for
 * someone to call kunmap and free PKMAP slot.
 */
static inline int get_pkmap_entries_count(unsigned int color)
{
	return LAST_PKMAP;
}

/*
 * Get head of a wait queue for PKMAP entries of the given color.
 * Wait queues for different mapping colors should be independent to avoid
 * unnecessary wakeups caused by freeing of slots of other colors.
 */
static inline wait_queue_head_t *get_pkmap_wait_queue_head(unsigned int color)
{
	static DECLARE_WAIT_QUEUE_HEAD(pkmap_map_wait);

	return &pkmap_map_wait;
}
#endif

unsigned long totalhigh_pages __read_mostly;
EXPORT_SYMBOL(totalhigh_pages);


EXPORT_PER_CPU_SYMBOL(__kmap_atomic_idx);

unsigned int nr_free_highpages (void)
{
	pg_data_t *pgdat;
	unsigned int pages = 0;

	for_each_online_pgdat(pgdat) {
		pages += zone_page_state(&pgdat->node_zones[ZONE_HIGHMEM],
			NR_FREE_PAGES);
		if (zone_movable_is_highmem())
			pages += zone_page_state(
					&pgdat->node_zones[ZONE_MOVABLE],
					NR_FREE_PAGES);
	}

	return pages;
}
/* 
高端映射区逻辑页面的分配结构用分配表(pkmap_count)来描述，它有1024项， 
对应于映射区内不同的逻辑页面。当分配项的值等于零时为自由项，等于1时为 
缓冲项，大于1时为映射项。映射页面的分配基于分配表的扫描，当所有的自由 
项都用完时，系统将清除所有的缓冲项，如果连缓冲项都用完时，系 
统将进入等待状态。 
*/ 
static int pkmap_count[LAST_PKMAP];
static  __cacheline_aligned_in_smp DEFINE_SPINLOCK(kmap_lock);

pte_t * pkmap_page_table;

/*
 * Most architectures have no use for kmap_high_get(), so let's abstract
 * the disabling of IRQ out of the locking in that case to save on a
 * potential useless overhead.
 */
#ifdef ARCH_NEEDS_KMAP_HIGH_GET
#define lock_kmap()             spin_lock_irq(&kmap_lock)
#define unlock_kmap()           spin_unlock_irq(&kmap_lock)
#define lock_kmap_any(flags)    spin_lock_irqsave(&kmap_lock, flags)
#define unlock_kmap_any(flags)  spin_unlock_irqrestore(&kmap_lock, flags)
#else
#define lock_kmap()             spin_lock(&kmap_lock)
#define unlock_kmap()           spin_unlock(&kmap_lock)
#define lock_kmap_any(flags)    \
		do { spin_lock(&kmap_lock); (void)(flags); } while (0)
#define unlock_kmap_any(flags)  \
		do { spin_unlock(&kmap_lock); (void)(flags); } while (0)
#endif

struct page *kmap_to_page(void *vaddr)
{
	unsigned long addr = (unsigned long)vaddr;

	if (addr >= PKMAP_ADDR(0) && addr < PKMAP_ADDR(LAST_PKMAP)) {
		int i = PKMAP_NR(addr);
		return pte_page(pkmap_page_table[i]);
	}

	return virt_to_page(addr);
}
EXPORT_SYMBOL(kmap_to_page);

static void flush_all_zero_pkmaps(void)
{
	int i;
	int need_flush = 0;

	flush_cache_kmaps();

	for (i = 0; i < LAST_PKMAP; i++) {
		struct page *page;

		/*
		 * zero means we don't have anything to do,
		 * >1 means that it is still in use. Only
		 * a count of 1 means that it is free but
		 * needs to be unmapped
		 */
		if (pkmap_count[i] != 1)
			continue;
		pkmap_count[i] = 0;

		/* sanity check */
		BUG_ON(pte_none(pkmap_page_table[i]));

		/*
		 * Don't need an atomic fetch-and-clear op here;
		 * no-one has the page mapped, and cannot get at
		 * its virtual address (and hence PTE) without first
		 * getting the kmap_lock (which is held here).
		 * So no dangers, even with speculative execution.
		 */
		page = pte_page(pkmap_page_table[i]);
		pte_clear(&init_mm, PKMAP_ADDR(i), &pkmap_page_table[i]);

		set_page_address(page, NULL);
		need_flush = 1;
	}
	if (need_flush)
		flush_tlb_kernel_range(PKMAP_ADDR(0), PKMAP_ADDR(LAST_PKMAP));
}

/**
 * kmap_flush_unused - flush all unused kmap mappings in order to remove stray mappings
 */
void kmap_flush_unused(void)
{
	lock_kmap();
	flush_all_zero_pkmaps();
	unlock_kmap();
}
/*
1.从最后使用的位置（保存在全局变量last_pkmap_nr中）开始，反向扫描pkmap_count数组, 直至找到一个空闲位置. 如果没有空闲位置，该函数进入睡眠状态，直至内核的另一部分执行解除映射操作腾出空位. 在到达pkmap_count的最大索引值时,  搜索从位置0开始. 在这种情况下,  还调用flush_all_zero_pkmaps函数刷出CPU高速缓存（读者稍后会看到这一点）。
2.修改内核的页表，将该页映射在指定位置。但尚未更新TLB.
3.新位置的使用计数器设置为1。如上所述，这意味着该页已分配但无法使用，因为TLB项未更新.
4.set_page_address将该页添加到持久内核映射的数据结构。 
该函数返回新映射页的虚拟地址. 在不需要高端内存页的体系结构上（或没有设置CONFIG_HIGHMEM），则使用通用版本的kmap返回页的地址，且不修改虚拟内存
*/

static inline unsigned long map_new_virtual(struct page *page)
{
	unsigned long vaddr;
	int count;
	unsigned int last_pkmap_nr;
	unsigned int color = get_pkmap_color(page);

start:
	count = get_pkmap_entries_count(color);
	/* Find an empty entry */
	for (;;) {
		last_pkmap_nr = get_next_pkmap_nr(color);/*加1，防止越界*/ 
		/* 接下来判断什么时候last_pkmap_nr等于０，等于０就表示1023（LAST_PKMAP(1024)-1）个页表项已经被分配了 
        ,这时候就需要调用flush_all_zero_pkmaps()函数,把所有pkmap_count[] 计数为1的页表项在TLB里面的entry给flush掉 
        ，并重置为0，这就表示该页表项又可以用了，可能会有疑惑为什么不在把pkmap_count置为1的时候也 
        就是解除映射的同时把TLB也flush呢？ 
        个人感觉有可能是为了效率的问题吧，毕竟等到不够的时候再刷新，效率要好点吧。*/ 
		if (no_more_pkmaps(last_pkmap_nr, color)) {
			flush_all_zero_pkmaps();
			count = get_pkmap_entries_count(color);
		}
		if (!pkmap_count[last_pkmap_nr])
			break;	/* Found a usable entry */
		if (--count)
			continue;

		/*
		 * Sleep for somebody else to unmap their entries
		 */
		{
			DECLARE_WAITQUEUE(wait, current);
			wait_queue_head_t *pkmap_map_wait =
				get_pkmap_wait_queue_head(color);
			  //睡眠等待
			__set_current_state(TASK_UNINTERRUPTIBLE);
			add_wait_queue(pkmap_map_wait, &wait);
			unlock_kmap();
			schedule();
			remove_wait_queue(pkmap_map_wait, &wait);
			lock_kmap();

			/* Somebody else might have mapped it while we slept */
			if (page_address(page))
				return (unsigned long)page_address(page);

			/* Re-start */
			goto start;
		}
	}
	/*返回这个页表项对应的线性地址vaddr.*/  
	vaddr = PKMAP_ADDR(last_pkmap_nr);
	/*设置页表项*/ 
	set_pte_at(&init_mm, vaddr,
		   &(pkmap_page_table[last_pkmap_nr]), mk_pte(page, kmap_prot));
		/*接下来把pkmap_count[last_pkmap_nr]置为1，1不是表示不可用吗， 
		既然映射已经建立好了，应该赋值为2呀，其实这个操作 
		是在他的上层函数kmap_high里面完成的(pkmap_count[PKMAP_NR(vaddr)]++).*/  
	pkmap_count[last_pkmap_nr] = 1;
		    /*到此为止，整个映射就完成了，再把page和对应的线性地址 
    加入到page_address_htable哈希链表里面就可以了*/ 
	set_page_address(page, (void *)vaddr);

	return vaddr;
}

/**
 * kmap_high - map a highmem page into memory
 * @page: &struct page to map
 *
 * Returns the page's virtual memory address.
 *
 * We cannot call this from interrupts, as it may block.
 */
void *kmap_high(struct page *page)
{
	unsigned long vaddr;

	/*
	 * For highmem pages, we can't trust "virtual" until
	 * after we have the lock.
	 */
	lock_kmap();/*保护页表免受多处理器系统上的并发访问*/  
	/*检查是否已经被映射*/
	vaddr = (unsigned long)page_address(page);
	/*  如果没有被映射  */ 
	if (!vaddr)
		/*把页框的物理地址插入到pkmap_page_table的 
        一个项中并在page_address_htable散列表中加入一个 
        元素*/
		vaddr = map_new_virtual(page);
	 /*分配计数加一，此时流程都正确应该是2了*/ 
	pkmap_count[PKMAP_NR(vaddr)]++;
	BUG_ON(pkmap_count[PKMAP_NR(vaddr)] < 2);
	unlock_kmap();
	return (void*) vaddr;/*返回地址*/ 
}

EXPORT_SYMBOL(kmap_high);

#ifdef ARCH_NEEDS_KMAP_HIGH_GET
/**
 * kmap_high_get - pin a highmem page into memory
 * @page: &struct page to pin
 *
 * Returns the page's current virtual memory address, or NULL if no mapping
 * exists.  If and only if a non null address is returned then a
 * matching call to kunmap_high() is necessary.
 *
 * This can be called from any context.
 */
void *kmap_high_get(struct page *page)
{
	unsigned long vaddr, flags;

	lock_kmap_any(flags);
	vaddr = (unsigned long)page_address(page);
	if (vaddr) {
		BUG_ON(pkmap_count[PKMAP_NR(vaddr)] < 1);
		pkmap_count[PKMAP_NR(vaddr)]++;
	}
	unlock_kmap_any(flags);
	return (void*) vaddr;
}
#endif

/**
 * kunmap_high - unmap a highmem page into memory
 * @page: &struct page to unmap
 *
 * If ARCH_NEEDS_KMAP_HIGH_GET is not defined then this may be called
 * only from user context.
 */
void kunmap_high(struct page *page)
{
	unsigned long vaddr;
	unsigned long nr;
	unsigned long flags;
	int need_wakeup;
	unsigned int color = get_pkmap_color(page);
	wait_queue_head_t *pkmap_map_wait;

	lock_kmap_any(flags);
	vaddr = (unsigned long)page_address(page);
	BUG_ON(!vaddr);
	nr = PKMAP_NR(vaddr);/*永久内存区域开始的第几个页面*/  

	/*
	 * A count must never go down to zero
	 * without a TLB flush!
	 */
	need_wakeup = 0;
	switch (--pkmap_count[nr]) { /*减小这个值，因为在映射的时候对其进行了加2*/ 
	case 0:
		BUG();
	case 1:
		/*
		 * Avoid an unnecessary wake_up() function call.
		 * The common case is pkmap_count[] == 1, but
		 * no waiters.
		 * The tasks queued in the wait-queue are guarded
		 * by both the lock in the wait-queue-head and by
		 * the kmap_lock.  As the kmap_lock is held here,
		 * no need for the wait-queue-head's lock.  Simply
		 * test if the queue is empty.
		 */
		pkmap_map_wait = get_pkmap_wait_queue_head(color);
		need_wakeup = waitqueue_active(pkmap_map_wait);
	}
	unlock_kmap_any(flags);

	/* do wake-up, if needed, race-free outside of the spin lock */
	if (need_wakeup)
		wake_up(pkmap_map_wait);
}

EXPORT_SYMBOL(kunmap_high);
#endif

#if defined(HASHED_PAGE_VIRTUAL)

#define PA_HASH_ORDER	7

/*
 * Describes one page->virtual association
 */
struct page_address_map {
	struct page *page;
	void *virtual;
	struct list_head list; //散列表
};

static struct page_address_map page_address_maps[LAST_PKMAP];

/*
 * Hash table bucket
 */
static struct page_address_slot {
	struct list_head lh;			/* List of page_address_maps */
	spinlock_t lock;			/* Protect this bucket's list */
} ____cacheline_aligned_in_smp page_address_htable[1<<PA_HASH_ORDER];

static struct page_address_slot *page_slot(const struct page *page)
{
	return &page_address_htable[hash_ptr(page, PA_HASH_ORDER)];
}

/**
 * page_address - get the mapped virtual address of a page
 * @page: &struct page to get the virtual address of
 *
 * Returns the page's virtual address.
 */
void *page_address(const struct page *page)
{
	unsigned long flags;
	void *ret;
	struct page_address_slot *pas;
	/*如果页框不在高端内存中*/  
	if (!PageHighMem(page))
		/*线性地址总是存在，通过计算页框下标 
            然后将其转换成物理地址，最后根据相应的 
            /物理地址得到线性地址*/
		return lowmem_page_address(page);
	/*从page_address_htable散列表中得到pas*/
	pas = page_slot(page);
	ret = NULL;
	spin_lock_irqsave(&pas->lock, flags);
	if (!list_empty(&pas->lh)) {
		/*如果对应的链表不空， 
    该链表中存放的是page_address_map结构*/
		struct page_address_map *pam;
		/*对每个链表中的元素*/
		list_for_each_entry(pam, &pas->lh, list) {
			if (pam->page == page) {
				/*返回线性地址*/
				ret = pam->virtual;
				goto done;
			}
		}
	}
done:
	spin_unlock_irqrestore(&pas->lock, flags);
	return ret;
}

EXPORT_SYMBOL(page_address);

/**
 * set_page_address - set a page's virtual address
 * @page: &struct page to set
 * @virtual: virtual address to use
 */
void set_page_address(struct page *page, void *virtual)
{
	unsigned long flags;
	struct page_address_slot *pas;
	struct page_address_map *pam;

	BUG_ON(!PageHighMem(page));

	pas = page_slot(page);
	if (virtual) {		/* Add */
		pam = &page_address_maps[PKMAP_NR((unsigned long)virtual)];
		pam->page = page;
		pam->virtual = virtual;

		spin_lock_irqsave(&pas->lock, flags);
		list_add_tail(&pam->list, &pas->lh);
		spin_unlock_irqrestore(&pas->lock, flags);
	} else {		/* Remove */
		spin_lock_irqsave(&pas->lock, flags);
		list_for_each_entry(pam, &pas->lh, list) {
			if (pam->page == page) {
				list_del(&pam->list);
				spin_unlock_irqrestore(&pas->lock, flags);
				goto done;
			}
		}
		spin_unlock_irqrestore(&pas->lock, flags);
	}
done:
	return;
}

void __init page_address_init(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(page_address_htable); i++) {
		INIT_LIST_HEAD(&page_address_htable[i].lh);
		spin_lock_init(&page_address_htable[i].lock);
	}
}

#endif	/* defined(CONFIG_HIGHMEM) && !defined(WANT_PAGE_VIRTUAL) */
