#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/swap.h> /* for totalram_pages */
#include <linux/bootmem.h>

void *kmap(struct page *page)
{
	might_sleep();
	if (!PageHighMem(page))
		return page_address(page);
	return kmap_high(page);
}
EXPORT_SYMBOL(kmap);

void kunmap(struct page *page)
{
	if (in_interrupt())
		BUG();
	if (!PageHighMem(page))
		return;
	kunmap_high(page);
}
EXPORT_SYMBOL(kunmap);

/*
 * kmap_atomic/kunmap_atomic is significantly faster than kmap/kunmap because
 * no global lock is needed and because the kmap code must perform a global TLB
 * invalidation when the kmap pool wraps.
 *
 * However when holding an atomic kmap it is not legal to sleep, so atomic
 * kmaps are appropriate for short, tight code paths only.
 */
void *kmap_atomic_prot(struct page *page, pgprot_t prot)
{
	unsigned long vaddr;
	int idx, type;

	preempt_disable();
	pagefault_disable();

	if (!PageHighMem(page))
		return page_address(page);

	type = kmap_atomic_idx_push();
	idx = type + KM_TYPE_NR*smp_processor_id();
	vaddr = __fix_to_virt(FIX_KMAP_BEGIN + idx);
	BUG_ON(!pte_none(*(kmap_pte-idx)));
	set_pte(kmap_pte-idx, mk_pte(page, prot));
	arch_flush_lazy_mmu_mode();

	return (void *)vaddr;
}
EXPORT_SYMBOL(kmap_atomic_prot);

void *kmap_atomic(struct page *page)
{
	return kmap_atomic_prot(page, kmap_prot);
}
EXPORT_SYMBOL(kmap_atomic);

/*
 * This is the same as kmap_atomic() but can map memory that doesn't
 * have a struct page associated with it.
 */
void *kmap_atomic_pfn(unsigned long pfn)
{
	return kmap_atomic_prot_pfn(pfn, kmap_prot);
}
EXPORT_SYMBOL_GPL(kmap_atomic_pfn);

void __kunmap_atomic(void *kvaddr)
{
	unsigned long vaddr = (unsigned long) kvaddr & PAGE_MASK;

	if (vaddr >= __fix_to_virt(FIX_KMAP_END) &&
	    vaddr <= __fix_to_virt(FIX_KMAP_BEGIN)) {
		int idx, type;

		type = kmap_atomic_idx();
		idx = type + KM_TYPE_NR * smp_processor_id();

#ifdef CONFIG_DEBUG_HIGHMEM
		WARN_ON_ONCE(vaddr != __fix_to_virt(FIX_KMAP_BEGIN + idx));
#endif
		/*
		 * Force other mappings to Oops if they'll try to access this
		 * pte without first remap it.  Keeping stale mappings around
		 * is a bad idea also, in case the page changes cacheability
		 * attributes or becomes a protected page in a hypervisor.
		 */
		kpte_clear_flush(kmap_pte-idx, vaddr);
		kmap_atomic_idx_pop();
		arch_flush_lazy_mmu_mode();
	}
#ifdef CONFIG_DEBUG_HIGHMEM
	else {
		BUG_ON(vaddr < PAGE_OFFSET);
		BUG_ON(vaddr >= (unsigned long)high_memory);
	}
#endif

	pagefault_enable();
	preempt_enable();
}
EXPORT_SYMBOL(__kunmap_atomic);
/* 所有高端内存管理区初始化，将所有node的所有zone的managed_pages置为0，并将他们的页框回收到页框分配器中 */

void __init set_highmem_pages_init(void)
{
	struct zone *zone;
	int nid;

	/*
	 * Explicitly reset zone->managed_pages because set_highmem_pages_init()
	 * is invoked before free_all_bootmem()
	 */
	 /* 将所有node的所有zone的managed_pages置为0，即将所有管理区的所管理页数量设置为0 */
	reset_all_zones_managed_pages();
	/* 遍历所有管理区，这里只初始化高端内存区 */
	for_each_zone(zone) {
		unsigned long zone_start_pfn, zone_end_pfn;
		/* 如果不是高端内存区，则下一个 */
		/* 判断方法: 当前zone描述符地址 - 所属node的zone描述符数组基地址 == 高端内存区偏移量 */

		if (!is_highmem(zone))
			continue;
		/* 该管理区开始页框号 */

		zone_start_pfn = zone->zone_start_pfn;
		/* 该管理区结束页框号 */
		zone_end_pfn = zone_start_pfn + zone->spanned_pages;
		/* 该管理区所属的node结点号 */

		nid = zone_to_nid(zone);
		printk(KERN_INFO "Initializing %s for node %d (%08lx:%08lx)\n",
				zone->name, nid, zone_start_pfn, zone_end_pfn);
		/* 将start_pfn到end_pfn中所有页框回收，并放入页框分配器 */

		add_highpages_with_active_regions(nid, zone_start_pfn,
				 zone_end_pfn);
	}
}
