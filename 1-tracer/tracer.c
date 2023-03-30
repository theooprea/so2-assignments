/*
 * Character device drivers lab
 *
 * All tasks
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/wait.h>

#include "./tracer.h"

MODULE_DESCRIPTION("Tracer");
MODULE_AUTHOR("Theodor-Alin Oprea");
MODULE_LICENSE("GPL");

#define LOG_LEVEL	KERN_INFO

#define MY_MAJOR		42
#define MY_MINOR		10
#define NUM_MINORS		1
#define MODULE_NAME		"tracer"
#define MESSAGE			"tracer hello\n"
#define IOCTL_MESSAGE		"tracer hello ioctl"

#ifndef BUFSIZ
#define BUFSIZ		4096
#endif


struct tracer_device_data {
	/* TODO 2/1: add cdev member */
	struct cdev cdev;
	/* TODO 4/2: add buffer with BUFSIZ elements */
	char buffer[BUFSIZ];
	size_t size;
	int flag;
	/* TODO 3/1: add atomic_t access variable to keep track if file is opened */
	atomic_t access;
};

struct tracer_device_data devs[NUM_MINORS];

static int tracer_cdev_open(struct inode *inode, struct file *file)
{
	struct tracer_device_data *data;

	/* TODO 2/1: print message when the device file is open. */
	printk(LOG_LEVEL "open called!\n");

	/* TODO 3/1: inode->i_cdev contains our cdev struct, use container_of to obtain a pointer to tracer_device_data */
	data = container_of(inode->i_cdev, struct tracer_device_data, cdev);

	file->private_data = data;

	/* TODO 3/2: return immediately if access is != 0, use atomic_cmpxchg */
	if (atomic_cmpxchg(&data->access, 0, 1) != 0)
		return -EBUSY;

	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(1 * HZ);

	return 0;
}

static int
tracer_cdev_release(struct inode *inode, struct file *file)
{
	/* TODO 2/1: print message when the device file is closed. */
	printk(LOG_LEVEL "close called!\n");

#ifndef EXTRA
	struct tracer_device_data *data =
		(struct tracer_device_data *) file->private_data;

	/* TODO 3/1: reset access variable to 0, use atomic_set */
	atomic_set(&data->access, 0);
#endif
	return 0;
}

static ssize_t
tracer_cdev_read(struct file *file,
		char __user *user_buffer,
		size_t size, loff_t *offset)
{
	struct tracer_device_data *data =
		(struct tracer_device_data *) file->private_data;
	size_t to_read;

	to_read = (size > data->size - *offset) ? (data->size - *offset) : size;
	if (copy_to_user(user_buffer, data->buffer + *offset, to_read) != 0)
		return -EFAULT;
	*offset += to_read;

	return to_read;
}

static ssize_t
tracer_cdev_write(struct file *file,
		const char __user *user_buffer,
		size_t size, loff_t *offset)
{
	struct tracer_device_data *data =
		(struct tracer_device_data *) file->private_data;

	size = (*offset + size > BUFSIZ) ? (BUFSIZ - *offset) : size;
	if (copy_from_user(data->buffer + *offset, user_buffer, size) != 0)
		return -EFAULT;
	*offset += size;
	data->size = *offset;

	return size;
}

static long
tracer_cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct tracer_device_data *data =
		(struct tracer_device_data *) file->private_data;
	int ret = 0;
	int remains;

	switch (cmd) {
	/* TODO 6/3: if cmd = MY_IOCTL_PRINT, display IOCTL_MESSAGE */
	case TRACER_ADD_PROCESS:
		printk(LOG_LEVEL "%s\n", IOCTL_MESSAGE);
		break;
	/* TODO 7/19: extra tasks, for home */
	case TRACER_REMOVE_PROCESS:
		printk(LOG_LEVEL "%s\n", IOCTL_MESSAGE);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

static const struct file_operations tracer_fops = {
	.owner = THIS_MODULE,
	.open = tracer_cdev_open,
	.release = tracer_cdev_release,
	.read = tracer_cdev_read,
	.write = tracer_cdev_write,
	.unlocked_ioctl = tracer_cdev_ioctl,
};

static int tracer_cdev_init(void)
{
	int err;
	int i;

	err = register_chrdev_region(MKDEV(MY_MAJOR, MY_MINOR),
			NUM_MINORS, MODULE_NAME);
	if (err != 0) {
		pr_info("register_chrdev_region");
		return err;
	}

	for (i = 0; i < NUM_MINORS; i++) {
		memcpy(devs[i].buffer, MESSAGE, sizeof(MESSAGE));
		devs[i].size = sizeof(MESSAGE);
		devs[i].flag = 0;
		atomic_set(&devs[i].access, 0);
		cdev_init(&devs[i].cdev, &tracer_fops);
		cdev_add(&devs[i].cdev, MKDEV(MY_MAJOR, MY_MINOR + i), 1);
	}

	return 0;
}

static void tracer_cdev_exit(void)
{
	int i;

	for (i = 0; i < NUM_MINORS; i++) {
		cdev_del(&devs[i].cdev);
	}

	unregister_chrdev_region(MKDEV(MY_MAJOR, MY_MINOR), NUM_MINORS);
}

module_init(tracer_cdev_init);
module_exit(tracer_cdev_exit);
