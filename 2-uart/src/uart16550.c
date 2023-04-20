#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/cdev.h>
#include <linux/wait.h>
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/uaccess.h>
#include <asm/io.h>
#include <linux/kfifo.h>
#include <linux/sched.h>

#include "uart16550.h"

#define MODULE_NAME		"uart16550"

#define COM1_ADDRESS 0x3f8
#define COM2_ADDRESS 0x2f8
#define COM1_IRQ_NO 4
#define COM2_IRQ_NO 3

#define RHR_OFFSET 0
#define RBR_OFFSET 0
#define THR_OFFSET 0
#define DLL_OFFSET 0
#define IER_OFFSET 1
#define FCR_OFFSET 2
#define ISR_OFFSET 2
#define IIR_OFFSET 2
#define LCR_OFFSET 3
#define MCR_OFFSET 4
#define LSR_OFFSET 5
#define MSR_OFFSET 6
#define SPR_OFFSET 7

#define DR_BIT_INDEX 0
#define DLAB_BIT_INDEX 7
#define IIR_READ_BIT_INDEX 2
#define IIR_WRITE_BIT_INDEX 1
#define IER_RECEIVE_INTERRUPT_ENABLE_BIT_INDEX 0
#define IER_TRANSMIT_INTERRUPT_ENABLE_BIT_INDEX 1

#define COM_ADDRESSES_NO 8

#define BUFFER_SIZE 512

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
	int read_count, write_count;
	atomic_t read_access, write_access;

	wait_queue_head_t rx_work_queue, tx_work_queue;

    DECLARE_KFIFO(read_fifo_buffer, unsigned char, BUFFER_SIZE);
	DECLARE_KFIFO(write_fifo_buffer, unsigned char, BUFFER_SIZE);

    int uart_com_no;
} devs[2];

static int uart_cdev_open(struct inode *inode, struct file *file)
{
	struct uart_com_device *data;

    data = container_of(inode->i_cdev, struct uart_com_device, cdev);

	file->private_data = data;

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
	ssize_t to_read, available_in_kfifo;
    int com_address;
    char buff[BUFFER_SIZE];
    unsigned char ier_value;
    struct uart_com_device *data;

    data = (struct uart_com_device *) file->private_data;
    com_address = data->uart_com_no == 0 ? COM1_ADDRESS : COM2_ADDRESS;

    if (wait_event_interruptible(data->rx_work_queue,
        atomic_cmpxchg(&data->read_access, 1, 0)))
			return -ERESTARTSYS;

    available_in_kfifo = kfifo_len(&data->read_fifo_buffer);
    
    to_read = available_in_kfifo < size ? available_in_kfifo : size;

    kfifo_out(&data->read_fifo_buffer, buff, to_read);

    if (copy_to_user(user_buffer, buff, to_read)) {
		printk("Read - copy data to user error\n");
		return -EFAULT;
	}

    ier_value = inb(com_address + IER_OFFSET);
    ier_value |= (1 << IER_RECEIVE_INTERRUPT_ENABLE_BIT_INDEX);
    outb(ier_value, com_address + IER_OFFSET);

    return to_read;
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
	int ret, remains, com_address;
    unsigned char reg_value;
	struct uart16550_line_info uart_line_info;
    struct uart_com_device *data;

    ret = 0;

    data = (struct uart_com_device *) file->private_data;
    com_address = data->uart_com_no == 0 ? COM1_ADDRESS : COM2_ADDRESS;

	switch (cmd) {
        case UART16550_IOCTL_SET_LINE:
            remains = copy_from_user(&uart_line_info, (struct uart16550_line_info *)arg, sizeof(struct uart16550_line_info));
            if (remains) {
                return -EFAULT;
            }

            /* get LCR value and set DLAB bit */
            reg_value = inb(com_address + LCR_OFFSET);
            reg_value |= 1 << DLAB_BIT_INDEX;

            /* set new register value, with DLAB bit set */
            outb(reg_value, com_address + LCR_OFFSET);

            /* set baud rate at base COM address */
            outb(uart_line_info.baud, com_address + DLL_OFFSET);

            /* set len stop and par related info at LCR offset of COM address */
            reg_value = uart_line_info.len | uart_line_info.stop | uart_line_info.par;
            outb(reg_value, com_address + LCR_OFFSET);

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

irqreturn_t
uart_interrupt_handle(int irq_no, void *dev_id)
{
    int com_address;
    unsigned char iir_value, ier_value, lsr_value, read_bit_value,
        write_bit_value, data_ready, read_byte_value;
    struct uart_com_device *data;

    data = (struct uart_com_device *)dev_id;
    com_address = data->uart_com_no == 0 ? COM1_ADDRESS : COM2_ADDRESS;

    iir_value = inb(com_address + IIR_OFFSET);
    read_bit_value = iir_value & (1 << IIR_READ_BIT_INDEX);
    write_bit_value = iir_value & (1 << IIR_WRITE_BIT_INDEX);

    if (read_bit_value != 0) {
        /* turn interrupts off */
        ier_value = inb(com_address + IER_OFFSET);
        ier_value &= ~(1 << IER_RECEIVE_INTERRUPT_ENABLE_BIT_INDEX);
        outb(ier_value, com_address + IER_OFFSET);

        /* see if data is ready */
        lsr_value = inb(com_address + LSR_OFFSET);
        data_ready = lsr_value & (1 << DR_BIT_INDEX);

        /*
         * while fifo buffer not full and data is ready to be read, keep adding
         * the read bytes to the buffer
         */
        while (!kfifo_is_full(&data->read_fifo_buffer) && data_ready) {
            read_byte_value = inb(com_address + RBR_OFFSET);
            
            kfifo_in(&data->read_fifo_buffer, &read_byte_value, sizeof(unsigned char));
            
            lsr_value = inb(com_address + LSR_OFFSET);
            data_ready = lsr_value & (1 << DR_BIT_INDEX);
        }

        /* signal that data can be read */
        atomic_set(&data->read_access, 1);
        wake_up_interruptible(&data->rx_work_queue);
    } else if (write_bit_value != 0) {

    } else {
        printk("Neither read nor write on uart_interrupt_handle\n");
    }

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
        atomic_set(&devs[0].read_access, 0);
        atomic_set(&devs[0].write_access, 0);
        init_waitqueue_head(&devs[0].rx_work_queue);
        init_waitqueue_head(&devs[0].tx_work_queue);
        INIT_KFIFO(devs[0].read_fifo_buffer);
        INIT_KFIFO(devs[0].write_fifo_buffer);

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
        atomic_set(&devs[1].read_access, 0);
        atomic_set(&devs[1].write_access, 0);
        init_waitqueue_head(&devs[1].rx_work_queue);
        init_waitqueue_head(&devs[1].tx_work_queue);
        INIT_KFIFO(devs[1].read_fifo_buffer);
        INIT_KFIFO(devs[1].write_fifo_buffer);

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
        atomic_set(&devs[0].read_access, 0);
        atomic_set(&devs[0].write_access, 0);
        init_waitqueue_head(&devs[0].rx_work_queue);
        init_waitqueue_head(&devs[0].tx_work_queue);
        INIT_KFIFO(devs[0].read_fifo_buffer);
        INIT_KFIFO(devs[0].write_fifo_buffer);

        cdev_init(&devs[0].cdev, &uart_fops);
		cdev_add(&devs[0].cdev, MKDEV(major, 0), 1);

        if (request_region(COM2_ADDRESS, COM_ADDRESSES_NO, MODULE_NAME) == NULL) {
            err = -EBUSY;
            goto request_region_error;
        }

        com2_requested_region = 1;

        devs[1].uart_com_no = 1;
        atomic_set(&devs[1].read_access, 0);
        atomic_set(&devs[1].write_access, 0);
        init_waitqueue_head(&devs[1].rx_work_queue);
        init_waitqueue_head(&devs[1].tx_work_queue);
        INIT_KFIFO(devs[1].read_fifo_buffer);
        INIT_KFIFO(devs[1].write_fifo_buffer);

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
