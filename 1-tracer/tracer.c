/*
 * Character device drivers lab
 *
 * All tasks
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/miscdevice.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/types.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>

#include "./tracer.h"

MODULE_DESCRIPTION("Tracer");
MODULE_AUTHOR("Theodor-Alin Oprea");
MODULE_LICENSE("GPL");

#define LOG_LEVEL	KERN_INFO

#define MESSAGE			"tracer hello\n"
#define IOCTL_MESSAGE		"tracer hello ioctl"

#ifndef BUFSIZ
#define BUFSIZ		4096
#endif

static int tracer_cdev_open(struct inode *inode, struct file *file)
{
	printk(LOG_LEVEL "open called!\n");

	return 0;
}

static int
tracer_cdev_release(struct inode *inode, struct file *file)
{
	printk(LOG_LEVEL "close called!\n");

	return 0;
}

static long
tracer_cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	int remains;
	pid_t arg_pid;

	switch (cmd) {
		case TRACER_ADD_PROCESS:
			if( copy_from_user(&arg_pid, (pid_t *) arg,
							sizeof(pid_t)) )
				return -EFAULT;
			
			printk(LOG_LEVEL "%s %d\n", IOCTL_MESSAGE, arg_pid);
			break;
		case TRACER_REMOVE_PROCESS:
			printk(LOG_LEVEL "%s %d\n", IOCTL_MESSAGE, arg_pid);
			break;
		default:
			ret = -EINVAL;
	}

	return ret;
}

static int tracer_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "Starts printing\n");

	return 0;
}

static int tracer_proc_read_open(struct inode *inode, struct  file *file)
{
	return single_open(file, tracer_proc_show, NULL);
}

struct proc_dir_entry *tracer_proc_read;

static const struct proc_ops tracer_pops = {
	.proc_open		= tracer_proc_read_open,
	.proc_read		= seq_read,
	.proc_release	= single_release,
};

static const struct file_operations tracer_fops = {
	.owner = THIS_MODULE,
	.open = tracer_cdev_open,
	.release = tracer_cdev_release,
	.unlocked_ioctl = tracer_cdev_ioctl,
};

static struct miscdevice tracer_miscdevice = {
	.minor = TRACER_DEV_MINOR,
	.name = TRACER_DEV_NAME,
	.fops = &tracer_fops
};

// Handlers section
static int up_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	printk("Handleing up func\n");
	return 0;
}

// Kretprobes section
static struct kretprobe up_probe = {
   .entry_handler = up_probe_handler,
   .maxactive = 32,
   .kp.symbol_name = "up"
};

static int tracer_cdev_init(void)
{
	int err;

	tracer_proc_read = proc_create(TRACER_DEV_NAME, 0000, NULL, &tracer_pops);
	if (!tracer_proc_read)
		return -ENOMEM;

	err = misc_register(&tracer_miscdevice);
	if (err != 0)
		goto error_misc_register;

	err = register_kretprobe(&up_probe);
	if (err) {
		pr_err("Failure on register_kretprobe up_probe\n");
		goto error_kretprobe_up;
	}

	return 0;

error_kretprobe_up:
	misc_deregister(&tracer_miscdevice);
error_misc_register:
	proc_remove(tracer_proc_read);

	return err;
}

static void tracer_cdev_exit(void)
{
	misc_deregister(&tracer_miscdevice);
	proc_remove(tracer_proc_read);
}

module_init(tracer_cdev_init);
module_exit(tracer_cdev_exit);
