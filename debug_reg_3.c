/*
 * Prototype of Debug Registers tapping
 * 
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/errno.h>
#include <linux/user.h>
#include <linux/security.h>
#include <linux/unistd.h>
#include <linux/notifier.h>
#include <linux/stop_machine.h>
#include <asm-x86/page.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
    #include <asm-i386/debugreg.h>
#else
    #include <asm-x86/debugreg.h>
#endif

#define __SYSENTER_ENABLE__

#include "sebek-lin26-3.2.0b/hooks.h"

/* define this if you want (very) verbose kern logs */
#define __DEBUG__

#ifdef __DEBUG__
    #define DEBUGLOG(a) printk a
#else
    #define DEBUGLOG(a) ""
#endif


/*
 *     Define our trap mask
 */

#define TRAP_GLOBAL_DR0 1<<1
#define TRAP_GLOBAL_DR1 1<<3
#define TRAP_GLOBAL_DR2 1<<5
#define TRAP_GLOBAL_DR3 1<<7

/* exact instruction detection not supported on P6 */
#define TRAP_LE         1<<8
#define TRAP_GE         1<<9

/* Global Detect flag */
#define GD_ACCESS       1<<13

/* 2 bits R/W and 2 bits len from these offsets */
#define DR0_RW      16
#define DR0_LEN     18
#define DR1_RW      20
#define DR1_LEN     22
#define DR2_RW      24
#define DR2_LEN     26
#define DR3_RW      28
#define DR3_LEN     30

/* needed in __uninit */
unsigned int h0x01_global    = 0;	

void (*__orig_do_debug)(struct pt_regs * regs, unsigned long error_code);

/*
 *     So that we can set our main watch on all cpu's
 *        in the actual handler we only care about THAT cpu
 *        so we don't have to set a smp watch there afaik
 */
struct watch {
    unsigned int dr0;
    unsigned int dr1;
    unsigned int dr2;
    unsigned int dr3;
    unsigned int stat;
    unsigned int ctrl;
};


static void __set_watch(struct watch *watches)
{
    if (watches->dr0)
        __asm__ __volatile__ (  "movl %0,%%dr0   \n\t"
                                :
                                : "r" (watches->dr0)    );

    if (watches->dr1)
        __asm__ __volatile__ (  "movl %0,%%dr1   \n\t"
                                :
                                : "r" (watches->dr1)    );

    if (watches->dr2)
        __asm__ __volatile__ (  "movl %0,%%dr2   \n\t"
                                :
                                : "r" (watches->dr2)    );

    if (watches->dr3)
        __asm__ __volatile__ (  "movl %0,%%dr2   \n\t"
                                :
                                : "r" (watches->dr3)    );

    /* set status */
    if (watches->stat)
        __asm__ __volatile__ (  "movl %0,%%dr6   \n\t"
                                :
                                : "r" (watches->stat)   );

    /* set ctrl */
    if (watches->ctrl)
        __asm__ __volatile__ (  "movl %0,%%dr7  \n\t"
                                :
                                : "r" (watches->ctrl)   );
}

/* regs in eax, error_code in edx .. static reg optimized is fine */
static void __my_do_debug(struct pt_regs * regs, unsigned long error_code)
{
    struct task_struct *tsk = current;
    siginfo_t info;

    int trap            = -1;
    int control         = 0;
    int s_control       = 0;
    int status          = 0;
    unsigned int dr2    = 0;
    void **sys_p        = (void **)sys_table_global;

    /* get dr6 */
    __asm__ __volatile__ (  "movl %%dr6,%0   \n\t"
                            : "=r" (status)  );

    /* enable irqs ? if (regs->eflags & X86_EFLAGS_IF) */

    /* check for trap on dr0 */
    if (status & DR_TRAP0)
    {
        trap = 0;
        status &= ~DR_TRAP0;
    }

    /* check for trap on dr1 */
    if (status & DR_TRAP1)
    {
        trap = 1;
        status &= ~DR_TRAP1;
    }

    /* check for trap on dr2 */
    if (status & DR_TRAP2)
    {
        trap = 2;
        status &= ~DR_TRAP2;
    }

    /* check for trap on dr3 */
    if (status & DR_TRAP3)
    {
        trap = 3;
        status &= ~DR_TRAP3;
    }

    /* we keep re-setting our control register after operation */

    /* DR0 is our int0x80 handler watch */
    control |= TRAP_GLOBAL_DR0;
    control |= DR_RW_EXECUTE << DR0_RW;
    control |= 0             << DR0_LEN;

#ifdef __SYSENTER_ENABLE__

    /* DR1 is our sysenter handler watch */
    control |= TRAP_GLOBAL_DR1;
    control |= DR_RW_EXECUTE << DR1_RW;
    control |= 0             << DR1_LEN;

#endif

    /* dr0-dr3 handlers */

    switch (trap)
    {
        /* dr0 handles int 0x80, dr1 handles sysenter */
        case 0:
        case 1:
	    
            /* if we dont have a hook for this call do nothing */
            if (!hook_table[regs->ax])
            {
                __asm__ __volatile__ (  "movl %0,%%dr6  \n\t"
                                        "movl %1,%%dr7  \n\t"
                                        :
                                        : "r" (status), "r" (control)   );
                break;
            }

            /* DR2 2nd watch on the syscall_table entry for this syscall */
            dr2 = sys_table_global + (unsigned int)regs->ax * sizeof(void *);
            /* enable exact breakpoint detection LE/GE */
            s_control   |= TRAP_GLOBAL_DR2;
            s_control   |= TRAP_LE;
            s_control   |= TRAP_GE;
            s_control   |= DR_RW_READ << DR2_RW;
            s_control   |= 3          << DR2_LEN;

            DEBUGLOG(("*** dr0/dr1 trap: setting read watch on syscall_NR of %d at %X\n", \
                    (unsigned int)regs->ax, dr2));

            /* set dr2 read watch on syscall_table */
            __asm__ __volatile__ (  "movl %0,%%dr2  \n\t"
                                    :
                                    : "r" (dr2) );

            /* set new control .. gives up syscall handler to avoid races */
            __asm__ __volatile__ (  "movl %0,%%dr6  \n\t"
                                    "movl %1,%%dr7  \n\t"
                                    :
                                    : "r" (status), "r" (s_control)   );

            /* if vm86 mode .. pass it on to orig */
            if (regs->flags & X86_VM_MASK)
                goto orig_do_debug;

            break;

        /* handle the watch on syscall_table .. return patched address */
        case 2:
            DEBUGLOG(("*** got dr2 trap (syscall_table watch)\n"));

            /* clear dr2 watch */
            __asm__ __volatile__ (  "xorl %eax,%eax \n\t"
                                    "movl %eax,%dr2 \n\t"   );

            /* restore old int0x80 handler control */
            __asm__ __volatile__ (  "movl %0,%%dr6  \n\t"
                                    "movl %1,%%dr7  \n\t"
                                    :
                                    : "r" (status), "r" (control)   );

            /*
             *   At the time of the trap1 eip is pointing at syscall
             *      so .. we just set the eip for the task to hook :P
             *
             *      NOTE:
             *           eax has our syscall number for both sysenter/int0x80
             */

            if ((regs->ax >= 0 && regs->ax < nr_syscalls) && hook_table[regs->ax])
            {
                /* double check .. verify eip matches original */
                unsigned int verify_hook = (unsigned int)sys_p[regs->ax];
                if (regs->ip == verify_hook)
                {
                    regs->ip = (unsigned int)hook_table[regs->ax];
                    DEBUGLOG(("*** hooked __NR_%ld at %X to %X\n", regs->ax, verify_hook, \
                                (unsigned int)hook_table[regs->ax]));
                } else {
                    DEBUGLOG(("regs->ip didnt match original: ip:%X sys_p: %X\n", regs->ip, verify_hook));
                }
            }

            if (regs->flags & X86_VM_MASK)
                goto orig_do_debug;

            break;

        case 3:
            DEBUGLOG(("*** got dr3 trap\n"));
            __asm__ __volatile__ (  "movl %0,%%dr6  \n\t"
                                    "movl %1,%%dr7  \n\t"
                                    :
                                    : "r" (status), "r" (control)   );
            break;

        default:
            DEBUGLOG(("*** unhandled trap"));

        orig_do_debug:

            /* call through to original int 1 handler */
            (*__orig_do_debug)(regs, error_code);

            /* restore our control just in case */
            __asm__ __volatile__ (  "movl %0,%%dr7  \n\t"
                                    :
                                    : "r" (control) );
    }

    /* set the resume flag after trap .. clear trap flag */
    if (trap >= 0)
    {
        regs->flags |= X86_EFLAGS_RF;
        regs->flags &= ~X86_EFLAGS_TF;
    }
}

/*
 *     __get_do_debug_2_6(int handler)
 *
 *         in:     address of INT1 handler
 *         out:    original do_debug address
 *
 *                 Finds the 'call do_debug' and patches the offset
 *                 to point to our patched handler.
 */

static unsigned char *pointer;

static int patch_debug_addr(void *data)
{

    unsigned char *opcode = (unsigned char *)data;
    memcpy((pointer+1), opcode, 4);
    
    return 0;
}

static int __get_and_set_do_debug_2_6(unsigned int handler, unsigned int my_do_debug)
{
    unsigned char *p        = (unsigned char *)handler;
    unsigned char buf[4]    = "\x00\x00\x00\x00";
    unsigned char opcode[4] = "\x00\x00\x00\x00";
    unsigned int offset     = 0;
    unsigned int orig       = 0;

    char *vaddr;
    int nr_pages = 2;
    struct page *pages[2];

    /* find a candidate for the call .. needs better heuristics */
    while (p[0] != 0xe8)
    {
        p ++;
    }
    DEBUGLOG(("*** found call do_debug %X\n", (unsigned int)p));
    buf[0]  = p[1];
    buf[1]  = p[2];
    buf[2]  = p[3];
    buf[3]  = p[4];

    offset  = *(unsigned int *)buf;
    DEBUGLOG(("*** found call do_debug offset %X\n", offset));

    orig    = offset + (unsigned int)p + 5;
    DEBUGLOG(("*** original do_debug %X\n", orig));

    offset  = my_do_debug - (unsigned int)p - 5;
    DEBUGLOG(("*** want call do_debug offset %X\n", offset));
   
    /* ========================================= */
    
    opcode[0]    = (offset & 0x000000ff);
    opcode[1]    = (offset & 0x0000ff00) >>  8;
    opcode[2]    = (offset & 0x00ff0000) >> 16;
    opcode[3]    = (offset & 0xff000000) >> 24;
    //DEBUGLOG(("Got opcode: %x%x%X%X\n", opcode[0], opcode[1], opcode[2], opcode[3]));

    // Get memory pages...
    pages[0] = virt_to_page(p);
    pages[1] = virt_to_page(p+PAGE_SIZE);
    
    if (pages[0] == NULL || pages[1] == NULL) 
    {
        DEBUGLOG(("NO PAGES!!!\n"));
        return orig;
    }

    //DEBUGLOG(("Got pages.\n"));
    
    // Map to kernel text section...
    vaddr = vmap(pages, nr_pages, VM_MAP, PAGE_KERNEL);
    if (!vaddr)
    {
        DEBUGLOG(("NO VMAP\n"));
        return orig;
    }

    //DEBUGLOG(("vmapped.\n"));

    pointer = vaddr + offset_in_page(p);
    //DEBUGLOG(("vaddr %X & pointer %X & p %X\n", (unsigned int)vaddr, (unsigned int)pointer, (unsigned int)p));
    //DEBUGLOG(("stuff at pointer: %X", (unsigned int)*(pointer+3)));
    stop_machine(patch_debug_addr, &opcode, NULL);
    
    vunmap(vaddr);

    DEBUGLOG(("*** patched in new do_debug offset\n"));

    return orig;
}


/*
 *     __get_sysenter_call
 *
 *         in:     syscall_call address
 *         in:     syscall_table address
 *         out:    sysenter_call address
 *
 *         NOTE:
 *
 *                 Alternatively there is also a cmpl to sysenter_entry in the
 *                   debug ENTRY .. but we want the direct offset to the syscall_table
 *                   call in sysenter_entry anyways, so this is just as valid.
 */

static unsigned int __get_sysenter_entry(unsigned int syscall_call, unsigned int table)
{
    /* do a backwards search from syscall_call for call *table(,%eax,4) */
    unsigned char *p        = (unsigned char *)syscall_call - 1;
    unsigned int verify     = 0;

    while(!((p[0] == 0xff) && (p[1] == 0x14) && (p[2] == 0x85)))
    {
        p --;
    }

    verify = *(unsigned int *)(p+3);
    if (verify == table)
        return (unsigned int) p;

    return 0;
}


/*
 *     __get_syscall_table(int idt_entry)
 *
 *         in:     Interrupt handler addr
 *         out:    syscall_call/syscall_table
 *
 *                 Return the syscall_table location based on an IDT entry addr
 *                     or the value of syscall_call pending on mode.
 */

#define RETURN_SYSCALL_TABLE    0
#define RETURN_SYSCALL_CALL     1

static unsigned int __get_syscall_table(int idt_entry, int mode)
{
    unsigned char *p = (unsigned char *)idt_entry;
    unsigned int table;
	
    // Searching for syscall_call...
    while (!((p[0] == 0xff) && (p[1] == 0x14) && (p[2] == 0x85)))
    {
        p ++;
    }

    table = *(unsigned int *)(p+3);

    /* returns sycall_table location from code */
    if (mode == RETURN_SYSCALL_TABLE)
        return table;

    /* returns syscall_call label loc to breakpoint on */
    if (mode == RETURN_SYSCALL_CALL)
        return (unsigned int)p;

    return 0;
}


/*
 *     __get_int_handler(int offset)
 *
 *         in:     interrupt # as an offset
 *         out:    address of interrupt handler
 */

static int __get_int_handler(int offset)
{
    int idt_entry   = 0;

                            /* off2 << 16 | off1 */
    __asm__ __volatile__ (  "xorl %%ebx,%%ebx               \n\t"
                            "pushl %%ebx                    \n\t" // Why to push ebx twice?
                            "pushl %%ebx                    \n\t"
                            "sidt (%%esp)                   \n\t" // Load idt into stack
                            "movl 2(%%esp),%%ebx            \n\t"
                            "movl %1,%%ecx                  \n\t" // Put offset into registry
                            "leal (%%ebx, %%ecx, 8),%%esi   \n\t"
                            "xorl %%eax,%%eax               \n\t" // - Next 3 instr. does off2 << 16 | off1 -
                            "movw 6(%%esi),%%ax             \n\t" // First 16 bits of idt addr.
                            "roll $0x10,%%eax               \n\t" // shift by 16 (off2 << 16)
                            "movw (%%esi),%%ax              \n\t" // Last 16 bits of idt addr.
                            "popl %%ebx                     \n\t"
                            "popl %%ebx                     \n\t"
                            : "=a" (idt_entry)
                            : "r" (offset)
                            : "ebx", "esi" );

    return idt_entry;
}


// Start from simple LKM routines
//

static int __init init_debug_reg(void)
{
    unsigned int h0x80          = 0;	// Address of INT 80 (syscall)
    unsigned int h0x01          = 0;	// Address of INT 1  (do_debug)
    unsigned int table          = 0;	// Address of syscall table
    unsigned int syscall_call   = 0;	// Address of syscall_call
    unsigned int sysenter_entry = 0;    // Alt way to make syscall
    struct watch watches        = { 0, 0, 0, 0, 0, 0 };

    DEBUGLOG(("******* LOADING IA32 DR HOOKING ENGINE *******\n"));

    h0x80 = __get_int_handler(0x80);

    DEBUGLOG(("*** loader: handler for INT 128 (0x80): %X\n", h0x80));

    table               = __get_syscall_table(h0x80, RETURN_SYSCALL_TABLE);
    syscall_call        = __get_syscall_table(h0x80, RETURN_SYSCALL_CALL);
    sys_table_global    = table;

    DEBUGLOG(("*** loader: syscall_table: %X\n", table));
    DEBUGLOG(("*** loader: syscall_call call *table(,eax,4): %X\n", syscall_call));

    h0x01 = __get_int_handler(0x1);

    DEBUGLOG(("*** loader: handler for INT 1: %X\n", h0x01));

    /* XXX: only for debug cleanup on unload */
    h0x01_global    = h0x01;

    /* patch the do_debug call offset in the INT 1 handler */
    __orig_do_debug = (void (*)())__get_and_set_do_debug_2_6(h0x01, \
                                (unsigned int)__my_do_debug);

    DEBUGLOG(("*** loader: INT 1 handler patched to use __my_do_debug\n"));

     __init_hook_table();
    
    DEBUGLOG(("*** loader: initialized hook_table\n"));

    /*
     *     Set a breakpoint on sycall handler in dr0 for 1 byte
     */

    /* for DR_RW_EXECUTE len has to be 0 (1 byte) (IA32_SDM_3B.pdf) */

    /* syscall_call watch into dr0 */
    
    watches.ctrl    |= TRAP_GLOBAL_DR0;
    watches.ctrl    |= DR_RW_EXECUTE << DR0_RW;
    watches.ctrl    |= 0             << DR0_LEN;
    watches.dr0     = syscall_call;

#ifdef __SYSENTER_ENABLE__

    /* we can find the 2nd addie by searching backwards for call *table(,%eax,4) ! :) */
    sysenter_entry = __get_sysenter_entry(syscall_call, table);
    DEBUGLOG(("*** loader: systenter_entry call *table(,eax,4): %X\n", sysenter_entry));

    /* if we were able to find the sysentry_entry syscall_table call .. hooray */
    if (sysenter_entry)
    {
        /* sysenter_entry watch into dr1 */
        watches.ctrl    |= TRAP_GLOBAL_DR1;
        watches.ctrl    |= DR_RW_EXECUTE << DR1_RW;
        watches.ctrl    |= 0             << DR1_LEN;
        watches.dr1     = sysenter_entry;
    }

#endif


    /* support smp */
    on_each_cpu((void (*)())__set_watch, &watches, 0);

    // Alloc decoy space...
    unsigned int core_addr = vmalloc(THIS_MODULE->core_size);
    
    // Now make module believe it...
    THIS_MODULE->module_core = core_addr;
    
    return -1;
}

static void __exit exit_debug_reg(void)
{
    struct watch watches = { 0, 0, 0, 0, 0, 0 };

    DEBUGLOG(("******* UNLOADING IA32 DR HOOKING ENGINE *******\n"));

    /* clear any breakpoints on all cpu's */
    on_each_cpu((void (*)())__set_watch, &watches, 0);

    __get_and_set_do_debug_2_6(h0x01_global, (unsigned int)__orig_do_debug);

    __uninit_hook_table();

    return;
}

/*
 *     main module init/exit
 */

module_init(init_debug_reg);
module_exit(exit_debug_reg);

/* taint-safe */
MODULE_LICENSE("GPL");

