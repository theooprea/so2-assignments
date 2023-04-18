#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/cdev.h>
#include <linux/wait.h>
#include <linux/sched.h>

#include "uart16550.h"

#define MODULE_NAME		"uart16550"

#define COM1_ADDRESS 0x3f8
#define COM2_ADDRESS 0x2f8

#define COM_ADDRESSES_NO 8

static int com1_in_use = 0;
static int com2_in_use = 0;

static int major = 42;
static int option = OPTION_BOTH;

module_param(major, int, 0);
MODULE_PARM_DESC(major, "The major");
module_param(option, int, 0);
MODULE_PARM_DESC(option, "Option for serial port(s): 1 for COM1, 2 for COM2, 3 for both");

struct uart_com_device {
	struct cdev cdev;
} devs[2];

static int uart_cdev_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int
uart_cdev_release(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t
uart_cdev_read(struct file *file,
		char __user *user_buffer,
		size_t size, loff_t *offset)
{
    return size;
}

static ssize_t
uart_cdev_write(struct file *file,
		const char __user *user_buffer,
		size_t size, loff_t *offset)
{
    return size;
}

static long
uart_cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;

	switch (cmd) {
        case UART16550_IOCTL_SET_LINE:
            printk("Got ioctl\n");
            break;
        default:
            ret = -EINVAL;
	}

	return ret;
}

static const struct file_operations uart_fops = {
	.owner = THIS_MODULE,
	.open = uart_cdev_open,
	.release = uart_cdev_release,
	.read = uart_cdev_read,
	.write = uart_cdev_write,
	.unlocked_ioctl = uart_cdev_ioctl,
};

static int uart_init(void)
{
    int err;

    err = 0;

    if (option == OPTION_COM1) {
        err = register_chrdev_region(MKDEV(major, 0),
			1, MODULE_NAME);

        if (request_region(COM1_ADDRESS, COM_ADDRESSES_NO, MODULE_NAME) == NULL) {
            err = -EBUSY;
            goto request_region_error;
        }

        com1_in_use = 1;

        cdev_init(&devs[0].cdev, &uart_fops);
		cdev_add(&devs[0].cdev, MKDEV(major, 0), 1);

    } else if (option == OPTION_COM2) {
        err = register_chrdev_region(MKDEV(major, 1),
			1, MODULE_NAME);

        if (request_region(COM2_ADDRESS, COM_ADDRESSES_NO, MODULE_NAME) == NULL) {
            err = -EBUSY;
            goto request_region_error;
        }

        com2_in_use = 1;

        cdev_init(&devs[1].cdev, &uart_fops);
		cdev_add(&devs[1].cdev, MKDEV(major, 1), 1);

    } else if (option == OPTION_BOTH) {
        err = register_chrdev_region(MKDEV(major, 0),
			2, MODULE_NAME);

        if (request_region(COM1_ADDRESS, COM_ADDRESSES_NO, MODULE_NAME) == NULL) {
            err = -EBUSY;
            goto request_region_error;
        }

        com1_in_use = 1;

        cdev_init(&devs[0].cdev, &uart_fops);
		cdev_add(&devs[0].cdev, MKDEV(major, 0), 1);

        if (request_region(COM2_ADDRESS, COM_ADDRESSES_NO, MODULE_NAME) == NULL) {
            err = -EBUSY;
            goto request_region_error;
        }

        com2_in_use = 1;

        cdev_init(&devs[1].cdev, &uart_fops);
		cdev_add(&devs[1].cdev, MKDEV(major, 1), 1);
    } else {
        pr_err("Invalid option\n");
        err = -EINVAL;
    }

    if (err) {
        pr_err("Error at register chrdev region");
        goto register_chrdev_region_error;
    }

	return 0;

request_region_error:
    if (option == OPTION_COM1) {
        unregister_chrdev_region(MKDEV(major, 0), 1);
    } else if (option == OPTION_COM2) {
        unregister_chrdev_region(MKDEV(major, 1), 1);
    } else if (option == OPTION_BOTH) {
        unregister_chrdev_region(MKDEV(major, 0), 2);
    }

    if (com1_in_use) {
        release_region(COM1_ADDRESS, COM_ADDRESSES_NO);
    }

    if (com2_in_use) {
        release_region(COM2_ADDRESS, COM_ADDRESSES_NO);
    }

register_chrdev_region_error:

    return err;
}

static void uart_exit(void)
{
    if (option == OPTION_COM1) {
        unregister_chrdev_region(MKDEV(major, 0), 1);
        release_region(COM1_ADDRESS, COM_ADDRESSES_NO);
    } else if (option == OPTION_COM2) {
        release_region(COM2_ADDRESS, COM_ADDRESSES_NO);
        unregister_chrdev_region(MKDEV(major, 1), 1);
    } else if (option == OPTION_BOTH) {
        unregister_chrdev_region(MKDEV(major, 0), 2);
        release_region(COM1_ADDRESS, COM_ADDRESSES_NO);
        release_region(COM2_ADDRESS, COM_ADDRESSES_NO);
    }
}

module_init(uart_init);
module_exit(uart_exit);

MODULE_DESCRIPTION("UART 16550 driver");
MODULE_AUTHOR("Theodor-Alin Oprea <opreatheodor54@gmail.com>");
MODULE_LICENSE("GPL");
