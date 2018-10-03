#include <linux/linkage.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/ioport.h>
#include <linux/interrupt.h>
#include <linux/timex.h>
#include <linux/random.h>
#include <linux/kprobes.h>
#include <linux/init.h>
#include <linux/kernel_stat.h>
#include <linux/device.h>
#include <linux/bitops.h>
#include <linux/acpi.h>
#include <linux/io.h>
#include <linux/delay.h>

#include <linux/atomic.h>
#include <asm/timer.h>
#include <asm/hw_irq.h>
#include <asm/pgtable.h>
#include <asm/desc.h>
#include <asm/apic.h>
#include <asm/setup.h>
#include <asm/i8259.h>
#include <asm/traps.h>
#include <asm/prom.h>

/*
 * ISA PIC or low IO-APIC triggered (INTA-cycle or APIC) interrupts:
 * (these are usually mapped to vectors 0x30-0x3f)
 */

/*
 * The IO-APIC gives us many more interrupt sources. Most of these
 * are unused but an SMP system is supposed to have enough memory ...
 * sometimes (mostly wrt. hw bugs) we get corrupted vectors all
 * across the spectrum, so we really want to be prepared to get all
 * of these. Plus, more powerful systems might have more than 64
 * IO-APIC registers.
 *
 * (these are usually mapped into the 0x30-0xff vector range)
 */

/*
 * IRQ2 is cascade interrupt to second interrupt controller
 */
static struct irqaction irq2 = {
	.handler = no_action,
	.name = "cascade",
	.flags = IRQF_NO_THREAD,
};

DEFINE_PER_CPU_USER_MAPPED(vector_irq_t, vector_irq) = {
	[0 ... NR_VECTORS - 1] = VECTOR_UNUSED,
};

int vector_used_by_percpu_irq(unsigned int vector)
{
	int cpu;

	for_each_online_cpu(cpu) {
		if (!IS_ERR_OR_NULL(per_cpu(vector_irq, cpu)[vector]))
			return 1;
	}

	return 0;
}

void __init init_ISA_irqs(void)
{
	/* CHIP默认是i8259A_chip */

	struct irq_chip *chip = legacy_pic->chip;
	int i;

#if defined(CONFIG_X86_64) || defined(CONFIG_X86_LOCAL_APIC)
	/* 使用了CPU本地中断控制器 */
	/* 开启virtual wire mode */
	init_bsp_APIC();
#endif
	/* 其实就是调用init_8259A()，进行8259A硬件的初始化 */

	legacy_pic->init(0);

	for (i = 0; i < nr_legacy_irqs(); i++)
		/* i为中断号，chip是irq_chip结构，最后是中断回调函数 
         * 设置了中断号i的中断描述符的irq_data.irq_chip = i8259A_chip
         * 设置了中断回调函数为handle_level_irq
         */
		irq_set_chip_and_handler(i, chip, handle_level_irq);
}

void __init init_IRQ(void)
{
	int i;

	/*
	 * On cpu 0, Assign ISA_IRQ_VECTOR(irq) to IRQ 0..15.
	 * If these IRQ's are handled by legacy interrupt-controllers like PIC,
	 * then this configuration will likely be static after the boot. If
	 * these IRQ's are handled by more mordern controllers like IO-APIC,
	 * then this vector space can be freed and re-used dynamically as the
	 * irq's migrate etc.
	 */
	 /* nr_legacy_irqs() 返回 legacy_pic->nr_legacy_irqs，为16
	 * vector_irq是一个int型的数组，长度为中断描述符表长，其保存的是中断向量对应的中断号(如果中断向量是异常则没有中断号)
	 * i8259A中断控制器使用IRQ0~IRQ15这16个中断号，这里将这16个中断号设置到CPU0的vector_irq数组的0x30~0x3f上。
     */
     
	for (i = 0; i < nr_legacy_irqs(); i++)
		per_cpu(vector_irq, 0)[ISA_IRQ_VECTOR(i)] = irq_to_desc(i);
	/* x86_init是一个结构体，里面定义了一组X86体系下的初始化函数 */
	x86_init.irqs.intr_init();
}

static void __init smp_intr_init(void)
{
#ifdef CONFIG_SMP
	/*
	 * The reschedule interrupt is a CPU-to-CPU reschedule-helper
	 * IPI, driven by wakeup.
	 */
	alloc_intr_gate(RESCHEDULE_VECTOR, reschedule_interrupt);

	/* IPI for generic function call */
	alloc_intr_gate(CALL_FUNCTION_VECTOR, call_function_interrupt);

	/* IPI for generic single function call */
	alloc_intr_gate(CALL_FUNCTION_SINGLE_VECTOR,
			call_function_single_interrupt);

	/* Low priority IPI to cleanup after moving an irq */
	set_intr_gate(IRQ_MOVE_CLEANUP_VECTOR, irq_move_cleanup_interrupt);
	set_bit(IRQ_MOVE_CLEANUP_VECTOR, used_vectors);

	/* IPI used for rebooting/stopping */
	alloc_intr_gate(REBOOT_VECTOR, reboot_interrupt);
#endif /* CONFIG_SMP */
}

static void __init apic_intr_init(void)
{
	smp_intr_init();

#ifdef CONFIG_X86_THERMAL_VECTOR
	alloc_intr_gate(THERMAL_APIC_VECTOR, thermal_interrupt);
#endif
#ifdef CONFIG_X86_MCE_THRESHOLD
	alloc_intr_gate(THRESHOLD_APIC_VECTOR, threshold_interrupt);
#endif

#ifdef CONFIG_X86_MCE_AMD
	alloc_intr_gate(DEFERRED_ERROR_VECTOR, deferred_error_interrupt);
#endif

#ifdef CONFIG_X86_LOCAL_APIC
	/* self generated IPI for local APIC timer */
	alloc_intr_gate(LOCAL_TIMER_VECTOR, apic_timer_interrupt);

	/* IPI for X86 platform specific use */
	alloc_intr_gate(X86_PLATFORM_IPI_VECTOR, x86_platform_ipi);
#ifdef CONFIG_HAVE_KVM
	/* IPI for KVM to deliver posted interrupt */
	alloc_intr_gate(POSTED_INTR_VECTOR, kvm_posted_intr_ipi);
	/* IPI for KVM to deliver interrupt to wake up tasks */
	alloc_intr_gate(POSTED_INTR_WAKEUP_VECTOR, kvm_posted_intr_wakeup_ipi);
#endif

	/* IPI vectors for APIC spurious and error interrupts */
	alloc_intr_gate(SPURIOUS_APIC_VECTOR, spurious_interrupt);
	alloc_intr_gate(ERROR_APIC_VECTOR, error_interrupt);

	/* IRQ work interrupts: */
# ifdef CONFIG_IRQ_WORK
	alloc_intr_gate(IRQ_WORK_VECTOR, irq_work_interrupt);
# endif

#endif
}

void __init native_init_IRQ(void)
{
	int i;

	/* Execute any quirks before the call gates are initialised: */
	/* 这里又是执行x86_init结构中的初始化函数，pre_vector_init()指向 init_ISA_irqs  */
	x86_init.irqs.pre_vector_init();
	/* 初始化中断描述符表中的中断控制器中默认的一些中断门初始化 */

	apic_intr_init();

	/*
	 * Cover the whole vector space, no vector can escape
	 * us. (some of these will be overridden and become
	 * 'special' SMP interrupts)
	 */
	 /* 第一个外部中断，默认是32 */
	i = FIRST_EXTERNAL_VECTOR;
#ifndef CONFIG_X86_LOCAL_APIC
#define first_system_vector NR_VECTORS
#endif
	/* 在used_vectors变量中找出所有没有置位的中断向量，我们知道，在trap_init()中对所有异常和陷阱和系统调用中断都置位了used_vectors，没有置位的都为中断
		 * 这里就是对所有中断设置门描述符
		 */
	for_each_clear_bit_from(i, used_vectors, first_system_vector) {
		/* IA32_SYSCALL_VECTOR could be used in trap_init already. */
	/* interrupt[]数组保存的是外部中断的中断门信息
         * 这里将中断描述符表中空闲的中断向量设置为中断门,interrupt是一个函数指针数组，其将31~255数组元素指向interrupt[i]函数
         */
		set_intr_gate(i, irq_entries_start +
				8 * (i - FIRST_EXTERNAL_VECTOR));
	}
#ifdef CONFIG_X86_LOCAL_APIC
	for_each_clear_bit_from(i, used_vectors, NR_VECTORS)
		set_intr_gate(i, spurious_interrupt);
#endif
	/* 如果外部中断控制器需要，则安装一个中断处理例程irq2到中断IRQ2上 */

	if (!acpi_ioapic && !of_ioapic && nr_legacy_irqs())
		setup_irq(2, &irq2);

#ifdef CONFIG_X86_32
	/* 在x86_32模式下，会为当前CPU分配一个中断使用的栈空间 */
	irq_ctx_init(smp_processor_id());
#endif
}
