#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/cdev.h>
#include <linux/sched.h>

#include "uart16550.h"

#define MODULE_NAME		"uart16550"

static int major = 42;
static int option = OPTION_BOTH;

module_param(major, int, 0);
MODULE_PARM_DESC(major, "The major");
module_param(option, int, 0);
MODULE_PARM_DESC(option, "Option for serial port(s): 1 for COM1, 2 for COM2, 3 for both");

static int uart_init(void)
{
    int err;

    if (option == OPTION_COM1) {
        err = register_chrdev_region(MKDEV(major, 0),
			1, MODULE_NAME);
    } else if (option == OPTION_COM2) {
        err = register_chrdev_region(MKDEV(major, 1),
			1, MODULE_NAME);
    } else if (option == OPTION_BOTH) {
        err = register_chrdev_region(MKDEV(major, 0),
			2, MODULE_NAME);
    } else {
        pr_err("Invalid option\n");
        err = -EINVAL;
    }

    if (err) {
        pr_err("Error at register chrdev region");
        goto register_chrdev_region_error;
    }

	return 0;

register_chrdev_region_error:

    return err;
}

static void uart_exit(void)
{
    if (option == OPTION_COM1) {
        unregister_chrdev_region(MKDEV(major, 0), 1);
    } else if (option == OPTION_COM2) {
        unregister_chrdev_region(MKDEV(major, 1), 1);
    } else if (option == OPTION_BOTH) {
        unregister_chrdev_region(MKDEV(major, 0), 2);
    }
}

module_init(uart_init);
module_exit(uart_exit);

MODULE_DESCRIPTION("UART 16550 driver");
MODULE_AUTHOR("Theodor-Alin Oprea <opreatheodor54@gmail.com>");
MODULE_LICENSE("GPL");
