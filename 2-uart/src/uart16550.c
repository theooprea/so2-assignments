#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/cdev.h>
#include <linux/wait.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/ioport.h>
#include <linux/uaccess.h>
#include <asm/io.h>
#include <linux/sched.h>

#include "uart16550.h"

#define MODULE_NAME		"uart16550"

#define COM1_ADDRESS 0x3f8
#define COM2_ADDRESS 0x2f8
#define COM1_IRQ_NO 4
#define COM2_IRQ_NO 3

#define RHR_OFFSET 0
#define THR_OFFSET 0
#define IER_OFFSET 1
#define FCR_OFFSET 2
#define ISR_OFFSET 2
#define LCR_OFFSET 3
#define MCR_OFFSET 4
#define MSR_OFFSET 6
#define SPR_OFFSET 7

#define DLAB_BIT 7

#define COM_ADDRESSES_NO 8

static int com1_requested_region = 0;
static int com2_requested_region = 0;
static int com1_requested_irq = 0;
static int com2_requested_irq = 0;

static int major = 42;
static int option = OPTION_BOTH;

module_param(major, int, 0);
MODULE_PARM_DESC(major, "The major");
module_param(option, int, 0);
MODULE_PARM_DESC(option, "Option for serial port(s): 1 for COM1, 2 for COM2, 3 for both");

struct uart_com_device {
	struct cdev cdev;

    int uart_com_no;
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
	int ret;
	int remains;
	struct uart16550_line_info uart_line_info;
    struct so2_device_data *data;

    ret = 0;

    remains = copy_from_user(&uart_line_info, (struct uart16550_line_info *)arg, sizeof(struct uart16550_line_info));
    if (remains) {
        return -EFAULT;
    }

    data = (struct so2_device_data *) file->private_data;

	switch (cmd) {
        case UART16550_IOCTL_SET_LINE:
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

irqreturn_t uart_interrupt_handle(int irq_no, void *dev_id)
{
	return IRQ_HANDLED;
}

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

        com1_requested_region = 1;

        devs[0].uart_com_no = 0;

        cdev_init(&devs[0].cdev, &uart_fops);
		cdev_add(&devs[0].cdev, MKDEV(major, 0), 1);

        err = request_irq(COM1_IRQ_NO,
			uart_interrupt_handle,
			IRQF_SHARED, MODULE_NAME, &devs[0]);

        if (err != 0) {
            pr_err("request_irq failed: %d\n", err);
            goto request_irq_error;
        }

        com1_requested_irq = 1;

    } else if (option == OPTION_COM2) {
        err = register_chrdev_region(MKDEV(major, 1),
			1, MODULE_NAME);

        if (request_region(COM2_ADDRESS, COM_ADDRESSES_NO, MODULE_NAME) == NULL) {
            err = -EBUSY;
            goto request_region_error;
        }

        com2_requested_region = 1;

        devs[1].uart_com_no = 1;

        cdev_init(&devs[1].cdev, &uart_fops);
		cdev_add(&devs[1].cdev, MKDEV(major, 1), 1);

        err = request_irq(COM2_IRQ_NO,
			uart_interrupt_handle,
			IRQF_SHARED, MODULE_NAME, &devs[1]);

        if (err != 0) {
            pr_err("request_irq failed: %d\n", err);
            goto request_irq_error;
        }

        com2_requested_irq = 1;

    } else if (option == OPTION_BOTH) {
        err = register_chrdev_region(MKDEV(major, 0),
			2, MODULE_NAME);

        if (request_region(COM1_ADDRESS, COM_ADDRESSES_NO, MODULE_NAME) == NULL) {
            err = -EBUSY;
            goto request_region_error;
        }

        com1_requested_region = 1;

        devs[0].uart_com_no = 0;

        cdev_init(&devs[0].cdev, &uart_fops);
		cdev_add(&devs[0].cdev, MKDEV(major, 0), 1);

        if (request_region(COM2_ADDRESS, COM_ADDRESSES_NO, MODULE_NAME) == NULL) {
            err = -EBUSY;
            goto request_region_error;
        }

        com2_requested_region = 1;

        devs[1].uart_com_no = 1;

        cdev_init(&devs[1].cdev, &uart_fops);
		cdev_add(&devs[1].cdev, MKDEV(major, 1), 1);

        err = request_irq(COM1_IRQ_NO,
			uart_interrupt_handle,
			IRQF_SHARED, MODULE_NAME, &devs[0]);

        if (err != 0) {
            pr_err("request_irq failed: %d\n", err);
            goto request_irq_error;
        }

        com1_requested_irq = 1;

        err = request_irq(COM2_IRQ_NO,
			uart_interrupt_handle,
			IRQF_SHARED, MODULE_NAME, &devs[1]);

        if (err != 0) {
            pr_err("request_irq failed: %d\n", err);
            goto request_irq_error;
        }

        com2_requested_irq = 1;
    } else {
        pr_err("Invalid option\n");
        err = -EINVAL;
    }

    if (err) {
        pr_err("Error at register chrdev region");
        goto register_chrdev_region_error;
    }

	return 0;

request_irq_error:
    if (com1_requested_irq) {
	    free_irq(COM1_IRQ_NO, &devs[0]);
    }

    if (com2_requested_irq) {
	    free_irq(COM2_IRQ_NO, &devs[1]);
    }

request_region_error:
    if (option == OPTION_COM1) {
        unregister_chrdev_region(MKDEV(major, 0), 1);
    } else if (option == OPTION_COM2) {
        unregister_chrdev_region(MKDEV(major, 1), 1);
    } else if (option == OPTION_BOTH) {
        unregister_chrdev_region(MKDEV(major, 0), 2);
    }

    if (com1_requested_region) {
        release_region(COM1_ADDRESS, COM_ADDRESSES_NO);
    }

    if (com2_requested_region) {
        release_region(COM2_ADDRESS, COM_ADDRESSES_NO);
    }

register_chrdev_region_error:

    return err;
}

static void uart_exit(void)
{
    if (option == OPTION_COM1) {
        cdev_del(&devs[0].cdev);
	    free_irq(COM1_IRQ_NO, &devs[0]);
        release_region(COM1_ADDRESS, COM_ADDRESSES_NO);
        unregister_chrdev_region(MKDEV(major, 0), 1);
    } else if (option == OPTION_COM2) {
        cdev_del(&devs[1].cdev);
	    free_irq(COM2_IRQ_NO, &devs[1]);
        release_region(COM2_ADDRESS, COM_ADDRESSES_NO);
        unregister_chrdev_region(MKDEV(major, 1), 1);
    } else if (option == OPTION_BOTH) {
        cdev_del(&devs[0].cdev);
        cdev_del(&devs[1].cdev);
	    free_irq(COM1_IRQ_NO, &devs[0]);
	    free_irq(COM2_IRQ_NO, &devs[1]);
        release_region(COM1_ADDRESS, COM_ADDRESSES_NO);
        release_region(COM2_ADDRESS, COM_ADDRESSES_NO);
        unregister_chrdev_region(MKDEV(major, 0), 2);
    }
}

module_init(uart_init);
module_exit(uart_exit);

MODULE_DESCRIPTION("UART 16550 driver");
MODULE_AUTHOR("Theodor-Alin Oprea <opreatheodor54@gmail.com>");
MODULE_LICENSE("GPL");
