// SPDX-License-Identifier: GPL-2.0+

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

/* module name */
#define MODULE_NAME		"uart16550"

/* com addresses and irq numbers */
#define COM1_ADDRESS 0x3f8
#define COM2_ADDRESS 0x2f8
#define COM1_IRQ_NO 4
#define COM2_IRQ_NO 3

/* registers offsets (offseted to base addresses, 0x3f8 and 0x2f8) */
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

/* bit indexes (as part of registers) */
#define DR_BIT_INDEX 0
#define ERDAI_BIT_INDEX 0
#define MCR_OUT_1_BIT_INDEX 2
#define THRE_BIT_INDEX 5
#define DLAB_BIT_INDEX 7
#define IIR_READ_BIT_INDEX 2
#define IIR_WRITE_BIT_INDEX 1
#define IER_RECEIVE_INTERRUPT_ENABLE_BIT_INDEX 0
#define IER_TRANSMIT_INTERRUPT_ENABLE_BIT_INDEX 1

/* 8 addresses per com, 0x2f8 - 0x2ff and 0x3f8 - 0x3ff*/
#define COM_ADDRESSES_NO 8

/*
 * chose this size to be able to fit inside the 1024 bits frame in functions
 * uart_cdev_read and uart_cdev_write
 */
#define BUFFER_SIZE 512

/* global variables to keep track of init progress (for error handling) */
static int com1_requested_region;
static int com2_requested_region;
static int com1_requested_irq;
static int com2_requested_irq;

/* major and option defaults */
static int major = 42;
static int option = OPTION_BOTH;

/* module param taking */
module_param(major, int, 0);
MODULE_PARM_DESC(major, "The major");
module_param(option, int, 0);
MODULE_PARM_DESC(option,
	"Option for serial port(s): 1 for COM1, 2 for COM2, 3 for both"
);

/* 2 uart com devices, one for each COM */
struct uart_com_device {
	/* cdev structure */
	struct cdev cdev;

	/* access atomic variables to coordinate the consumers-producers problem */
	atomic_t read_access, write_access;

	/*
	 * work queues to signal updates for when the kfifo queues are available to
	 * work with
	 */
	wait_queue_head_t rx_work_queue, tx_work_queue;

	/* kfifo queues buffers */
	DECLARE_KFIFO(read_fifo_buffer, unsigned char, BUFFER_SIZE);
	DECLARE_KFIFO(write_fifo_buffer, unsigned char, BUFFER_SIZE);

	/* 0 for COM1 and 1 for COM2*/
	int uart_com_no;
} devs[2];

/**
 * @brief The open callback when the dev is being opened
 *
 * @param inode
 * @param file Used to store the struct uart_com_device data
 * @return int The status - 0 for success
 */
static int uart_cdev_open(struct inode *inode, struct file *file)
{
	struct uart_com_device *data;

	/* getting refference to the struct uart_com_device variable */
	data = container_of(inode->i_cdev, struct uart_com_device, cdev);

	/* setting it for later usage (in uart_cdev_read and uart_cdev_write) */
	file->private_data = data;

	return 0;
}

/**
 * @brief The release callback for when the dev file is released
 *
 * @param inode
 * @param file
 * @return int The status - 0 for success
 */
static int
uart_cdev_release(struct inode *inode, struct file *file)
{
	return 0;
}

/**
 * @brief Read callback - called when a read is being attempted from a cdev
 * file. Extracts `size` number of bytes from the internal kfifo buffer of the
 * cdev file (or the number of available bytes, if the requested `size` bytes
 * are more than there are in the buffer) and copies them in the userspace.
 * This is done in a sunchronized manner, it first waits for data to be read by
 * the module from the uart device (which after the read is done, this function
 * is signaled to start sending the read data to the user). So in this workflow
 * the hardware is the producer, and the user is the consumer.
 *
 * @param file The file data from which we will get a referrence to the
 * uart_com_device data
 * @param user_buffer The user's buffer, in which we will send the data
 * @param size The number of bytes the user asks for (if the kfifo queue has
 * less bytes than what is requested, send only the amound of available bytes)
 * @param offset The offset in the file that the user wants to read from - not
 * aplicable in a cdev file context - not used
 * @return ssize_t The amount of bytes read and sent to the user
 */
static ssize_t
uart_cdev_read(struct file *file,
		char __user *user_buffer,
		size_t size, loff_t *offset)
{
	int com_address;
	char buffer_aux[BUFFER_SIZE];
	ssize_t read_count, available_in_kfifo;
	unsigned char ier_value;
	struct uart_com_device *data;

	/* extract the struct uart_com_device data from the file structure */
	data = (struct uart_com_device *) file->private_data;

	/* get the base COM address */
	com_address = data->uart_com_no == 0 ? COM1_ADDRESS : COM2_ADDRESS;

	/* wait for data to have been read from the hardware device */
	if (wait_event_interruptible(data->rx_work_queue,
		atomic_cmpxchg(&data->read_access, 1, 0)))
		return -ERESTARTSYS;

	/* see how many bytes are available in the kfifo buffer */
	available_in_kfifo = kfifo_len(&data->read_fifo_buffer);

	/*
	 * in case the user wants to read more than what is available, restrict
	 * the amount of bytes read to what is available
	 */
	read_count = available_in_kfifo < size ? available_in_kfifo : size;

	/* get read_count number of bytes from the kfifo buffer */
	kfifo_out(&data->read_fifo_buffer, buffer_aux, read_count);

	/* copy the bytes to the user buffer */
	if (copy_to_user(user_buffer, buffer_aux, read_count * sizeof(char)))
		return -EFAULT;

	/*
	 * restart the read interrupts, read the current IER register value,
	 * enable the RECEIVE_INTERRUPT_ENABLE bit and write the updated value
	 * back into IER register
	 */
	ier_value = inb(com_address + IER_OFFSET);
	ier_value |= (1 << IER_RECEIVE_INTERRUPT_ENABLE_BIT_INDEX);
	outb(ier_value, com_address + IER_OFFSET);

	/* state that read_count bytes have been read */
	return read_count;
}

/**
 * @brief Write callback - called when a write is being attempted to a cdev
 * file. Pushes `size` number of bytes into the internal kfifo buffer of the
 * cdev file (or the remaining number of free bytes - up until BUFFER_SIZE
 * bytes - the kfifo is full) from the userspace. This is done in a syncronized
 * manner, first the user writes the data into the internal kfifo buffer, and
 * only when the writing into the hardware device start do we signal user that
 * the bytes have been written. So in this workflow, the user is the produces
 * and the hardware is the consumer.
 *
 * @param file The file data from which we will get a referrence to the
 * uart_com_device data
 * @param user_buffer The user's buffer, from which we will get the data
 * @param size The number of bytes the user wants to write (if the kfifo queue
 * has less bytes available (BUFFER_SIZE - already_stored_bytes) than `size`,
 * only the available amount of bytes will be written)
 * @param offset The offset in the file that the user wants to read from - not
 * aplicable in a cdev file context - not used
 * @return ssize_t The amount of bytes read and sent to the user
 */
static ssize_t
uart_cdev_write(struct file *file,
		const char __user *user_buffer,
		size_t size, loff_t *offset)
{
	int com_address;
	char buffer_aux[BUFFER_SIZE];
	ssize_t write_count, available_in_kfifo;
	unsigned char ier_value;
	struct uart_com_device *data;

	/* extract the struct uart_com_device data from the file structure */
	data = (struct uart_com_device *) file->private_data;

	/* get the base COM address */
	com_address = data->uart_com_no == 0 ? COM1_ADDRESS : COM2_ADDRESS;

	/*
	 * see how many bytes are available in the kfifo buffer
	 * (BUFFER_SIZE - bytes_already_in_kfifo)
	 */
	available_in_kfifo = kfifo_avail(&data->write_fifo_buffer);

	/*
	 * in case the user wants to write more than how much is available,
	 * restrict the amount of bytes that will be written to what is available
	 */
	write_count = available_in_kfifo < size ? available_in_kfifo : size;

	/* copy the bytes from the user buffer to the auxiliary buffer */
	if (copy_from_user(buffer_aux, user_buffer,
			write_count * sizeof(char)) != 0)
		return -EFAULT;

	/* insert write_count number of bytes into the kfifo buffer */
	kfifo_in(&data->write_fifo_buffer, buffer_aux, write_count * sizeof(char));

	/*
	 * restart the write interrupts, read the current IER register value,
	 * enable the TRANSMIT_INTERRUPT_ENABLE bit and write the updated value
	 * back into IER register
	 */
	ier_value = inb(com_address + IER_OFFSET);
	ier_value |= (1 << IER_TRANSMIT_INTERRUPT_ENABLE_BIT_INDEX);
	outb(ier_value, com_address + IER_OFFSET);

	/*
	 * wait for the bytes to be actually written into the hardware before
	 * notifying the user that the write has been made
	 */
	if (wait_event_interruptible(data->tx_work_queue,
		atomic_cmpxchg(&data->write_access, 1, 0)))
		return -ERESTARTSYS;

	/* state that write_count bytes have been written */
	return write_count;
}

/**
 * @brief Ioctl function, receives a UART16550_IOCTL_SET_LINE command and
 * receives a struct uart16550_line_info variable, containing data about the
 * baud rate, the length bits the parity bits, stop bit.
 *
 * Sets the LCR register as 8b'10{xxx}{y}{zz} where the 7th bit (1) is the
 * Divisor Latch Access Bit - set as 1, the 6th bit is Set Break - set as 0,
 * the next 3 bits, bits 5 4 and 3 are the parity bits, the next bit, bit 2 is
 * the stop bit and the last (or first from little endian perspective) 2 bits,
 * bits 1 and 0 are the len bits
 *
 * @param file The file data from which we will get a referrence to the
 * uart_com_device data
 * @param cmd The command given to ioctl function, should only be
 * UART16550_IOCTL_SET_LINE, otherwise it won't be processed (since there is no
 * other one)
 * @param arg The struct uart16550_line_info argument
 * @return long The status of the operation, 0 for success, error otherwise
 */
static long
uart_cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret, remains, com_address;
	unsigned char lcr_value;
	struct uart16550_line_info uart_line_info;
	struct uart_com_device *data;

	ret = 0;

	/* extract the struct uart_com_device data from the file structure */
	data = (struct uart_com_device *) file->private_data;

	/* get the base COM address */
	com_address = data->uart_com_no == 0 ? COM1_ADDRESS : COM2_ADDRESS;

	switch (cmd) {
	case UART16550_IOCTL_SET_LINE:
		/* copy the struct uart16550_line_info argument from user space */
		remains = copy_from_user(
			&uart_line_info,
			(struct uart16550_line_info *)arg,
			sizeof(struct uart16550_line_info)
		);

		/* if the userspace -> kernelspace transfer fails, return error */
		if (remains)
			return -EFAULT;

		/* get LCR value and set the DLAB bit to 1 */
		lcr_value = inb(com_address + LCR_OFFSET);
		lcr_value |= 1 << DLAB_BIT_INDEX;

		/*
		 * set lcr register value, with DLAB bit set and given len, stop
		 * and par bits values
		 */
		outb(lcr_value, com_address + LCR_OFFSET);

		/* set baud rate at base COM address (DLL is actually at base) */
		outb(uart_line_info.baud, com_address + DLL_OFFSET);

		/* set len, stop and par bits */
		lcr_value = uart_line_info.len;
		lcr_value |= uart_line_info.stop;
		lcr_value |= uart_line_info.par;

		/*
		 * set lcr register value, with the given len, stop and par bits
		 * values AND with bits 7 and 6 set as 0 to correctly start
		 * communication
		 */
		outb(lcr_value, com_address + LCR_OFFSET);

		break;
	default:
		/* invalid operation */
		ret = -EINVAL;
	}

	return ret;
}

/* cdev fops structure */
static const struct file_operations uart_fops = {
	.owner = THIS_MODULE,
	.open = uart_cdev_open,
	.release = uart_cdev_release,
	.read = uart_cdev_read,
	.write = uart_cdev_write,
	.unlocked_ioctl = uart_cdev_ioctl,
};

/**
 * @brief UART interrupt handler - handles a UART interrupt, for both read and
 * write interrupts, disable the interrupts for that interrupt type, for read
 * disable read interrupts, get bytes from the hardware device while they are
 * available, and while the kfifo buffer is not full, when the read is done,
 * signal that the read from hardware has been finished and allow the user to
 * consume that data, and for the write case, disable write interrupts, get
 * bytes from the kfifo buffer (while it's not empty) and write them to the
 * device, and when the write is done, signal that the uart_cdev_write can
 * further signal the user that the write is handled
 *
 * @param irq_no The number of the interrupt, not used
 * @param dev_id The cdev device, used to get a referrence to out struct
 * uart_com_device data
 * @return irqreturn_t The status of the request, IRQ_HANDLED for when the
 * interrupt was handled correctly, and IRQ_NONE for error - not using IRQ_NONE
 * here since it's not applicaple
 */
irqreturn_t
uart_interrupt_handle(int irq_no, void *dev_id)
{
	int com_address;
	unsigned char iir_value, ier_value, lsr_value, read_bit_value,
		write_bit_value, data_ready, thre_value, rx_byte_value, tx_byte_value;
	struct uart_com_device *data;

	/* extract the struct uart_com_device data from the dev_id */
	data = (struct uart_com_device *)dev_id;

	/* get the base COM address */
	com_address = data->uart_com_no == 0 ? COM1_ADDRESS : COM2_ADDRESS;

	/*
	 * get the IIR register value, since it is the one containing the info
	 * as to if the interrupt is a read or write interrupt. this thing is set
	 * in the Interrupt ID (bits 1 and 2), if the Interrupt ID bit 0 (bit 1 of
	 * the IIR register) is set, it means that the interrupt is a write one,
	 * and if the Interrupt ID bit 1 (bit 2 of the IIR register) is set, it
	 * means that the interrupt is a read one
	 */
	iir_value = inb(com_address + IIR_OFFSET);
	read_bit_value = iir_value & (1 << IIR_READ_BIT_INDEX);
	write_bit_value = iir_value & (1 << IIR_WRITE_BIT_INDEX);

	if (read_bit_value != 0) {
		/* if the interrupt is a read interrupt*/

		/*
		 * turn read interrupts off, the IER register has the 0 bit as toggle
		 * for receive interrupt enabling - clear that bit
		 */
		ier_value = inb(com_address + IER_OFFSET);
		ier_value &= ~(1 << IER_RECEIVE_INTERRUPT_ENABLE_BIT_INDEX);
		outb(ier_value, com_address + IER_OFFSET);

		/*
		 * see if data is ready, get the LSR register value and check the
		 * Data Ready (DR) bit
		 */
		lsr_value = inb(com_address + LSR_OFFSET);
		data_ready = lsr_value & (1 << DR_BIT_INDEX);

		/*
		 * while kfifo buffer not full and data is ready to be read (Data Ready
		 * bit of the LSR register is continuously kept as set), keep adding
		 * the read bytes to the internal kfifo buffer
		 */
		while (!kfifo_is_full(&data->read_fifo_buffer) && data_ready) {
			/* read the actual byte from the UART device */
			rx_byte_value = inb(com_address + RBR_OFFSET);

			/* add the read byte into the kfifo buffer */
			kfifo_in(
				&data->read_fifo_buffer,
				&rx_byte_value,
				sizeof(unsigned char)
			);

			/* check that data is ready again */
			lsr_value = inb(com_address + LSR_OFFSET);
			data_ready = lsr_value & (1 << DR_BIT_INDEX);
		}

		/* signal that data is available to be read to the userspace */
		atomic_set(&data->read_access, 1);
		wake_up_interruptible(&data->rx_work_queue);
	} else if (write_bit_value != 0) {
		/* if the interrupt is a write interrupt*/

		/*
		 * turn write interrupts off, the IER register has the 1 bit as toggle
		 * for transmit interrupt enabling - clear that bit
		 */
		ier_value = inb(com_address + IER_OFFSET);
		ier_value &= ~(1 << IER_TRANSMIT_INTERRUPT_ENABLE_BIT_INDEX);
		outb(ier_value, com_address + IER_OFFSET);

		/*
		 * see if device is ready to be written into, get the LSR register
		 * value and check the Transmitter Holding Register (THRE) bit
		 */
		lsr_value = inb(com_address + LSR_OFFSET);
		thre_value = lsr_value & (1 << THRE_BIT_INDEX);

		/*
		 * while the kfifo buffer is not empty and the device is ready to be
		 * written into, pop data out from the kfifo buffer, byte by byte and
		 * write the poped value to the THR register, which is actually the
		 * base COM address
		 */
		while (!kfifo_is_empty(&data->write_fifo_buffer) && thre_value) {
			/* pop one byte from the kfifo buffer */
			kfifo_out(&data->write_fifo_buffer, &tx_byte_value, sizeof(unsigned char));

			/* write the byte to the device */
			outb(tx_byte_value, com_address + THR_OFFSET);

			/* check for availability again */
			lsr_value = inb(com_address + LSR_OFFSET);
			thre_value = lsr_value & (1 << THRE_BIT_INDEX);
		}

		/* signal that data was written and the user can be further signaled */
		atomic_set(&data->write_access, 1);
		wake_up_interruptible(&data->tx_work_queue);
	} else {
		pr_debug("%s Neither read nor write\n", __func__);
	}

	return IRQ_HANDLED;
}

/**
 * @brief Init function of the kernel module. Takes 2 arguments, the `major`
 * which will be used to register the char device, and the COM `option`, 1 for
 * using COM1, 2 for using COM2 and 3 for using both
 *
 * @return int The status of the initialization, 0 for success, error code
 * otherwise
 */
static int uart_init(void)
{
	int err;
	unsigned int ier_value, mcr_value;

	err = 0;

	if (option == OPTION_COM1) {
		/* if the chosen option is 1 - COM1 */

		/* register a char dev with 1 minor, major `major` and minor 0 */
		err = register_chrdev_region(MKDEV(major, 0),
			1, MODULE_NAME);

		if (err) {
			err = -EBUSY;
			goto register_chrdev_region_error;
		}

		/* request the region starting at 0x3f8 with length 8 (0x3f8-0x3ff) */
		if (request_region(
			COM1_ADDRESS,
			COM_ADDRESSES_NO,
			MODULE_NAME
		) == NULL) {
			err = -EBUSY;
			goto request_region_error;
		}

		/* mark the COM1 region as requested */
		com1_requested_region = 1;

		/*
		 * initialize dev related data, set the com number to 0 (COM 1),
		 * initialize atomic variables for the consumers - producers problem,
		 * initialize the waitqueues and the kfifo buffers, for both reading
		 * and writing
		 */
		devs[0].uart_com_no = 0;
		atomic_set(&devs[0].read_access, 0);
		atomic_set(&devs[0].write_access, 0);
		init_waitqueue_head(&devs[0].rx_work_queue);
		init_waitqueue_head(&devs[0].tx_work_queue);
		INIT_KFIFO(devs[0].read_fifo_buffer);
		INIT_KFIFO(devs[0].write_fifo_buffer);

		/*
		 * request the interrupt for COM1 - 4 and use uart_interrupt_handle as
		 * the interrupt handler, and have it shared with any other device
		 */
		err = request_irq(COM1_IRQ_NO,
			uart_interrupt_handle,
			IRQF_SHARED, MODULE_NAME, &devs[0]);

		/* irq request error */
		if (err != 0) {
			pr_err("request_irq failed: %d\n", err);
			goto request_irq_error;
		}

		/* mark the COM1 interrupt as requested */
		com1_requested_irq = 1;

		/* initialize and add the cdev structure */
		cdev_init(&devs[0].cdev, &uart_fops);
		cdev_add(&devs[0].cdev, MKDEV(major, 0), 1);

		/*
		 * start the interrupts for COM1 - Enable Received Data Available
		 * Interrupt (ERDAI) bit of the Interupt Enable Register (IER) Register
		 * and the Out 1 bit of the Modem Control Register (MCR) Register
		 */
		ier_value = 1 << ERDAI_BIT_INDEX;
		outb(ier_value, COM1_ADDRESS + IER_OFFSET);
		mcr_value = 1 << MCR_OUT_1_BIT_INDEX;
		outb(mcr_value, COM1_ADDRESS + MCR_OFFSET);
	} else if (option == OPTION_COM2) {
		/* if the chosen option is 2 - COM2 */

		/* register a char dev with 1 minor, major `major` and minor 1 */
		err = register_chrdev_region(MKDEV(major, 1),
			1, MODULE_NAME);

		if (err) {
			err = -EBUSY;
			goto register_chrdev_region_error;
		}

		/* request the region starting at 0x2f8 with length 8 (0x2f8-0x2ff) */
		if (request_region(
			COM2_ADDRESS,
			COM_ADDRESSES_NO,
			MODULE_NAME
		) == NULL) {
			err = -EBUSY;
			goto request_region_error;
		}

		/* mark the COM2 region as requested */
		com2_requested_region = 1;

		/*
		 * initialize dev related data, set the com number to 1 (COM 2),
		 * initialize atomic variables for the consumers - producers problem,
		 * initialize the waitqueues and the kfifo buffers, for both reading
		 * and writing
		 */
		devs[1].uart_com_no = 1;
		atomic_set(&devs[1].read_access, 0);
		atomic_set(&devs[1].write_access, 0);
		init_waitqueue_head(&devs[1].rx_work_queue);
		init_waitqueue_head(&devs[1].tx_work_queue);
		INIT_KFIFO(devs[1].read_fifo_buffer);
		INIT_KFIFO(devs[1].write_fifo_buffer);

		/*
		 * request the interrupt for COM2 - 3 and use uart_interrupt_handle as
		 * the interrupt handler, and have it shared with any other device
		 */
		err = request_irq(COM2_IRQ_NO,
			uart_interrupt_handle,
			IRQF_SHARED, MODULE_NAME, &devs[1]);

		/* irq request error */
		if (err != 0) {
			pr_err("request_irq failed: %d\n", err);
			goto request_irq_error;
		}

		/* mark the COM2 interrupt as requested */
		com2_requested_irq = 1;

		/* initialize and add the cdev structure */
		cdev_init(&devs[1].cdev, &uart_fops);
		cdev_add(&devs[1].cdev, MKDEV(major, 1), 1);

		/*
		 * start the interrupts for COM2 - Enable Received Data Available
		 * Interrupt (ERDAI) bit of the Interupt Enable Register (IER) Register
		 * and the Out 1 bit of the Modem Control Register (MCR) Register
		 */
		ier_value = 1 << ERDAI_BIT_INDEX;
		outb(ier_value, COM2_ADDRESS + IER_OFFSET);
		mcr_value = 1 << MCR_OUT_1_BIT_INDEX;
		outb(mcr_value, COM2_ADDRESS + MCR_OFFSET);
	} else if (option == OPTION_BOTH) {
		/* if the chosen option is 3 - COM1 and COM2 */

		/*
		 * register a char dev with 2 minors, major `major` and minors starting
		 * at 0
		 */
		err = register_chrdev_region(MKDEV(major, 0),
			2, MODULE_NAME);

		if (err) {
			err = -EBUSY;
			goto register_chrdev_region_error;
		}

		/* request the region starting at 0x3f8 with length 8 (0x3f8-0x3ff) */
		if (request_region(
			COM1_ADDRESS,
			COM_ADDRESSES_NO,
			MODULE_NAME
		) == NULL) {
			err = -EBUSY;
			goto request_region_error;
		}

		/* mark the COM1 region as requested */
		com1_requested_region = 1;

		/*
		 * initialize dev related data, set the com number to 0 (COM 1),
		 * initialize atomic variables for the consumers - producers problem,
		 * initialize the waitqueues and the kfifo buffers, for both reading
		 * and writing
		 */
		devs[0].uart_com_no = 0;
		atomic_set(&devs[0].read_access, 0);
		atomic_set(&devs[0].write_access, 0);
		init_waitqueue_head(&devs[0].rx_work_queue);
		init_waitqueue_head(&devs[0].tx_work_queue);
		INIT_KFIFO(devs[0].read_fifo_buffer);
		INIT_KFIFO(devs[0].write_fifo_buffer);

		/*
		 * request the interrupt for COM1 - 4 and use uart_interrupt_handle as
		 * the interrupt handler, and have it shared with any other device
		 */
		err = request_irq(COM1_IRQ_NO,
			uart_interrupt_handle,
			IRQF_SHARED, MODULE_NAME, &devs[0]);

		/* irq request error */
		if (err != 0) {
			pr_err("request_irq failed: %d\n", err);
			goto request_irq_error;
		}

		/* mark the COM1 interrupt as requested */
		com1_requested_irq = 1;

		/* initialize and add the cdev structure */
		cdev_init(&devs[0].cdev, &uart_fops);
		cdev_add(&devs[0].cdev, MKDEV(major, 0), 1);

		/*
		 * start the interrupts for COM1 - Enable Received Data Available
		 * Interrupt (ERDAI) bit of the Interupt Enable Register (IER) Register
		 * and the Out 1 bit of the Modem Control Register (MCR) Register
		 */
		ier_value = 1 << ERDAI_BIT_INDEX;
		outb(ier_value, COM1_ADDRESS + IER_OFFSET);
		mcr_value = 1 << MCR_OUT_1_BIT_INDEX;
		outb(mcr_value, COM1_ADDRESS + MCR_OFFSET);

		/* request the region starting at 0x2f8 with length 8 (0x2f8-0x2ff) */
		if (request_region(
			COM2_ADDRESS,
			COM_ADDRESSES_NO,
			MODULE_NAME
		) == NULL) {
			err = -EBUSY;
			goto request_region_error;
		}

		/* mark the COM2 region as requested */
		com2_requested_region = 1;

		/*
		 * initialize dev related data, set the com number to 1 (COM 2),
		 * initialize atomic variables for the consumers - producers problem,
		 * initialize the waitqueues and the kfifo buffers, for both reading
		 * and writing
		 */
		devs[1].uart_com_no = 1;
		atomic_set(&devs[1].read_access, 0);
		atomic_set(&devs[1].write_access, 0);
		init_waitqueue_head(&devs[1].rx_work_queue);
		init_waitqueue_head(&devs[1].tx_work_queue);
		INIT_KFIFO(devs[1].read_fifo_buffer);
		INIT_KFIFO(devs[1].write_fifo_buffer);

		/*
		 * request the interrupt for COM2 - 3 and use uart_interrupt_handle as
		 * the interrupt handler, and have it shared with any other device
		 */
		err = request_irq(COM2_IRQ_NO,
			uart_interrupt_handle,
			IRQF_SHARED, MODULE_NAME, &devs[1]);

		/* irq request error */
		if (err != 0) {
			pr_err("request_irq failed: %d\n", err);
			goto request_irq_error;
		}

		/* mark the COM2 interrupt as requested */
		com2_requested_irq = 1;

		/* initialize and add the cdev structure */
		cdev_init(&devs[1].cdev, &uart_fops);
		cdev_add(&devs[1].cdev, MKDEV(major, 1), 1);

		/*
		 * start the interrupts for COM2 - Enable Received Data Available
		 * Interrupt (ERDAI) bit of the Interupt Enable Register (IER) Register
		 * and the Out 1 bit of the Modem Control Register (MCR) Register
		 */
		ier_value = 1 << ERDAI_BIT_INDEX;
		outb(ier_value, COM2_ADDRESS + IER_OFFSET);
		mcr_value = 1 << MCR_OUT_1_BIT_INDEX;
		outb(mcr_value, COM2_ADDRESS + MCR_OFFSET);
	} else {
		/* invalid option */
		pr_err("Invalid option\n");
		err = -EINVAL;
		goto invalid_option_error;
	}

	return 0;

request_irq_error:

request_region_error:
	/* unregister char devices depending on the option */
	if (option == OPTION_COM1)
		unregister_chrdev_region(MKDEV(major, 0), 1);

	else if (option == OPTION_COM2)
		unregister_chrdev_region(MKDEV(major, 1), 1);

	else if (option == OPTION_BOTH)
		unregister_chrdev_region(MKDEV(major, 0), 2);

register_chrdev_region_error:
	/* if region 0x3f8 - COM 1 - has been registered */
	if (com1_requested_region)
		release_region(COM1_ADDRESS, COM_ADDRESSES_NO);

	/* if region 0x2f8 - COM 2 - has been registered */
	if (com2_requested_region)
		release_region(COM2_ADDRESS, COM_ADDRESSES_NO);

	/* if interrupt 4 - COM 1 - has been requested */
	if (com1_requested_irq)
		free_irq(COM1_IRQ_NO, &devs[0]);

	/* if interrupt 3 has been requested */
	if (com2_requested_irq)
		free_irq(COM2_IRQ_NO, &devs[1]);

invalid_option_error:

	return err;
}

static void uart_exit(void)
{
	/* depending on the option given */
	if (option == OPTION_COM1) {
		/* unregister the cdev structure */
		cdev_del(&devs[0].cdev);

		/* release the interrupt 4 - COM 1 */
		free_irq(COM1_IRQ_NO, &devs[0]);

		/* release the region 0x3f8 - COM 1*/
		release_region(COM1_ADDRESS, COM_ADDRESSES_NO);

		/* unregister the char device */
		unregister_chrdev_region(MKDEV(major, 0), 1);
	} else if (option == OPTION_COM2) {
		/* unregister the cdev structure */
		cdev_del(&devs[1].cdev);

		/* release the interrupt 3 - COM 2 */
		free_irq(COM2_IRQ_NO, &devs[1]);

		/* release the region 0x2f8 - COM 2*/
		release_region(COM2_ADDRESS, COM_ADDRESSES_NO);

		/* unregister the char device */
		unregister_chrdev_region(MKDEV(major, 1), 1);
	} else if (option == OPTION_BOTH) {
		/* unregister both cdev structures */
		cdev_del(&devs[0].cdev);
		cdev_del(&devs[1].cdev);

		/* release both 4 - COM 1 and 3 - COM 2 interrupts */
		free_irq(COM1_IRQ_NO, &devs[0]);
		free_irq(COM2_IRQ_NO, &devs[1]);

		/* release both 0x3f8 - COM 1 and 0x2f8 - COM2 regions */
		release_region(COM1_ADDRESS, COM_ADDRESSES_NO);
		release_region(COM2_ADDRESS, COM_ADDRESSES_NO);

		/* unregister the char device */
		unregister_chrdev_region(MKDEV(major, 0), 2);
	}
}

module_init(uart_init);
module_exit(uart_exit);

MODULE_DESCRIPTION("UART 16550 driver");
MODULE_AUTHOR("Theodor-Alin Oprea <opreatheodor54@gmail.com>");
MODULE_LICENSE("GPL v2");
