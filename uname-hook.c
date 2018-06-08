#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <asm/uaccess.h>
#include <asm/cacheflush.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/utsname.h>

MODULE_DESCRIPTION("system call replace test module");
MODULE_LICENSE("Dual BSD/GPL");

/* following string SYSCALL_TABLE_ADDRESS will be replaced by set_syscall_table_address.sh */
static void **syscall_table = (void *) 0x80108244;

asmlinkage long (*orig_sys_uname)(struct old_utsname *buf);

asmlinkage long syscall_replace_sys_uname(struct old_utsname *buf)
{
    long ret;
    char str[] = "rangosta ";
    printk(KERN_INFO "rangosta %d", __NR_uname);
    ret = orig_sys_uname(buf);
    strncpy(buf->sysname, str, sizeof(str));
    
    return ret;
}

static void save_original_syscall_address(void)
{
    orig_sys_uname = syscall_table[__NR_uname];
}

static void change_page_attr_to_rw(pte_t *pte)
{
    set_pte_atomic(pte, pte_mkwrite(*pte));
}

static void change_page_attr_to_ro(pte_t *pte)
{
    set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));
}

static void replace_system_call(void *new)
{
    unsigned int level = 0;
    pte_t *pte;

    pte = lookup_address((unsigned long) syscall_table, &level);
    /* Need to set r/w to a page which syscall_table is in. */
    change_page_attr_to_rw(pte);

    syscall_table[__NR_uname] = new;
    /* set back to read only */
    change_page_attr_to_ro(pte);
}

static int syscall_replace_init(void)
{
    pr_info("sys_call_table address is 0x%p\n", syscall_table);
    
    save_original_syscall_address();
    pr_info("original sys_reboot's address is %p %p\n", syscall_table[0], syscall_table[__NR_write]);

    replace_system_call(syscall_replace_sys_uname);

    pr_info("system call replaced\n");
    return 0;
}

static void syscall_replace_cleanup(void)
{
    pr_info("cleanup");
    if (orig_sys_uname)
        replace_system_call(orig_sys_uname);
}

module_init(syscall_replace_init);
module_exit(syscall_replace_cleanup);