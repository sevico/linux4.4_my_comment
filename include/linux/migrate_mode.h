#ifndef MIGRATE_MODE_H_INCLUDED
#define MIGRATE_MODE_H_INCLUDED
/*
 * MIGRATE_ASYNC means never block
 * MIGRATE_SYNC_LIGHT in the current implementation means to allow blocking
 *	on most operations but not ->writepage as the potential stall time
 *	is too significant
 * MIGRATE_SYNC will block when migrating pages
 */
enum migrate_mode {
    /* 
     * 异步模式的意思是禁止阻塞，遇到阻塞和需要调度的时候直接返回，返回前会把隔离出来的页框放回去
     * 在内存不足以分配连续页框时进行内存压缩，默认初始是异步模式，如果异步模式后还不能分配连续内存，则会转为轻同步模式(当明确表示不处理透明大页，或者当前进程是内核线程时，就会转为请同步模式)
     * 而kswapd内核线程中只使用异步模式，不会使用同步模式
     * 所以异步不处理MIRGATE_RECLAIMABLE类型的页框，因为这部分页框很大可能导致回写然后阻塞，只处理MIGRATE_MOVABLE和MIGRATE_CMA类型中的页
     * 即使匿名页加入到了swapcache，被标记为了脏页，这里也不会进行回写，只有匿名页被内存回收换出时，才会进行回写
     * 异步模式不会增加推迟计数器阀值
     */

	MIGRATE_ASYNC,
	MIGRATE_SYNC_LIGHT,
	MIGRATE_SYNC,
};

#endif		/* MIGRATE_MODE_H_INCLUDED */
