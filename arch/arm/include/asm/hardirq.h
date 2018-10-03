#ifndef __ASM_HARDIRQ_H
#define __ASM_HARDIRQ_H

#include <linux/cache.h>
#include <linux/threads.h>
#include <asm/irq.h>

#define NR_IPI	8

typedef struct {
	/* 表示挂起的软中断，每一位表示一个软中断，为1表示挂起 */
	unsigned int __softirq_pending;
	/* 硬中断统计. */
#ifdef CONFIG_SMP
	unsigned int ipi_irqs[NR_IPI];
#endif
} ____cacheline_aligned irq_cpustat_t;

#include <linux/irq_cpustat.h>	/* Standard mappings for irq_cpustat_t above */

#define __inc_irq_stat(cpu, member)	__IRQ_STAT(cpu, member)++
#define __get_irq_stat(cpu, member)	__IRQ_STAT(cpu, member)

#ifdef CONFIG_SMP
u64 smp_irq_stat_cpu(unsigned int cpu);
#else
#define smp_irq_stat_cpu(cpu)	0
#endif

#define arch_irq_stat_cpu	smp_irq_stat_cpu

#define __ARCH_IRQ_EXIT_IRQS_DISABLED	1

#endif /* __ASM_HARDIRQ_H */
