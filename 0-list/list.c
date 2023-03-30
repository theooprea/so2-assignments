// SPDX-License-Identifier: GPL-2.0+

/*
 * list.c - Linux kernel list API
 *
 * Author: Theodor-Alin Oprea <opreatheodor54@gmail.com>
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>

#define PROCFS_MAX_SIZE		512

#define procfs_dir_name		"list"
#define procfs_file_read	"preview"
#define procfs_file_write	"management"

struct proc_dir_entry *proc_list;
struct proc_dir_entry *proc_list_read;
struct proc_dir_entry *proc_list_write;

/*
 * List node structure, contains a char* to store the string data and
 * a list_head field, to use it as a list
 */
struct list_node {
	char *data;
	struct list_head list_node;
};

/* Create the list head */
static LIST_HEAD(head);

static int list_proc_show(struct seq_file *m, void *v)
{
	struct list_node *node;
	struct list_head *iterator;

	/* Iterate through the list and print the data for each node */
	list_for_each(iterator, &head) {
		node = list_entry(iterator, struct list_node, list_node);

		seq_printf(m, "%s\n", node->data);
	}

	return 0;
}

static int list_read_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static int list_write_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

/**
 * @brief Creates a new node in the list
 *
 * @param data The string data that the node will contain
 * @return struct list_node* The newly created node
 */
static struct list_node *new_node(char *data)
{
	struct list_node *node;

	/* Allocate memory for the node, if there is not enough, return NULL*/
	node = kmalloc(sizeof(struct list_node), GFP_KERNEL);
	if (node == NULL)
		return NULL;

	/*
	 * Allocate memory for the char* data field, if there is not enough,
	 * free the already allocated node and return NULL
	 */
	node->data = kmalloc((strlen(data) + 1) * sizeof(char), GFP_KERNEL);
	if (node->data == NULL) {
		kfree(node);
		return NULL;
	}

	/* Add char array \0 terminator */
	memcpy(node->data, data, strlen(data));
	node->data[strlen(data)] = '\0';

	return node;
}

/**
 * @brief Adds a new node, created using the provided data, at the beginning
 * of the existing list
 *
 * @param data The string data that the new node will contain
 * @return int Return code, 0 for success and -ENOMEM for insufficient memory
 */
static int addf(char *data)
{
	struct list_node *node;

	/*
	 * Allocate a new node with the provided data, if there was not enough
	 * memory, return error
	 */
	node = new_node(data);
	if (node == NULL)
		return -ENOMEM;

	/* Add the new node at the beginning of the list */
	list_add(&node->list_node, &head);

	return 0;
}

/**
 * @brief Adds a new node, created using the provided data, at the end
 * of the existing list
 *
 * @param data The string data that the new node will contain
 * @return int Return code, 0 for success and -ENOMEM for insufficient memory
 */
static int adde(char *data)
{
	struct list_node *node;

	/*
	 * Allocate a new node with the provided data, if there was not enough
	 * memory, return error
	 */
	node = new_node(data);
	if (node == NULL)
		return -ENOMEM;

	/* Add the new node at the end (tail) of the list */
	list_add_tail(&node->list_node, &head);

	return 0;
}

/**
 * @brief Removes the first node that contains the provided 'data' string
 *
 * @param data The data that the node to be removed must contain
 */
static void delf(char *data)
{
	struct list_head *iterator, *backup;
	struct list_node *node;

	/*
	 * Iterate through the list in a safe manner, since a node will be removed
	 */
	list_for_each_safe(iterator, backup, &head) {
		/*
		 * Get the iterator as a list_node* variable to be able to access data
		 */
		node = list_entry(iterator, struct list_node, list_node);

		/* If the current node's data is equal to the provided data */
		if (!strcmp(node->data, data)) {
			/* Remove the node from the list */
			list_del(iterator);

			/* Free the node's memory */
			kfree(node->data);
			kfree(node);

			/* Since we only need the first appearance, exit the function */
			return;
		}
	}
}

/**
 * @brief Removes all nodes that contain the provided 'data' string
 *
 * @param data The data that the nodes to be removed must contain
 */
static void dela(char *data)
{
	struct list_head *iterator, *backup;
	struct list_node *node;

	/*
	 * Iterate through the list in a safe manner, since a node will be removed
	 */
	list_for_each_safe(iterator, backup, &head) {
		/*
		 * Get the iterator as a list_node* variable to be able to access data
		 */
		node = list_entry(iterator, struct list_node, list_node);

		if (!strcmp(node->data, data)) {
			/* Remove the node from the list */
			list_del(iterator);

			/* Free the node's memory */
			kfree(node->data);
			kfree(node);
		}
	}
}

static ssize_t list_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *offs)
{
	char local_buffer[PROCFS_MAX_SIZE];
	unsigned long local_buffer_size = 0;
	char *command, *argument;
	char *delimiter_pos;
	int command_size, r;

	local_buffer_size = count;
	if (local_buffer_size > PROCFS_MAX_SIZE)
		local_buffer_size = PROCFS_MAX_SIZE;

	memset(local_buffer, 0, PROCFS_MAX_SIZE);
	if (copy_from_user(local_buffer, buffer, local_buffer_size))
		return -EFAULT;

	/* Get the position of the first ' ' delimiter appearance */
	delimiter_pos = strchr(local_buffer, ' ');

	/* If the delimiter is not found, return error */
	if (delimiter_pos == NULL)
		return -EFAULT;

	/* Compute the size of the given command (addf | adde | delf | dela) */
	command_size = delimiter_pos - local_buffer;

	/* Allocate the memory for the command char array */
	command = kmalloc_array((command_size + 1), sizeof(char), GFP_KERNEL);

	/* If not enough memory, return error */
	if (command == NULL)
		return -ENOMEM;

	/* Copy the data from the local buffer in the command buffer and add \0 */
	memcpy(command, local_buffer, command_size);
	command[command_size] = '\0';

	/* Allocate the memory for the argument char array */
	argument = kmalloc_array(strlen(delimiter_pos), sizeof(char), GFP_KERNEL);

	/* If not enough memory, free the command array and return error */
	if (argument == NULL) {
		kfree(command);
		return -ENOMEM;
	}

	/*
	 * Copy the data from the remaining local buffer into the argument
	 * buffer and add \0
	 */
	memcpy(argument, delimiter_pos + 1, strlen(delimiter_pos) - 2);
	argument[strlen(delimiter_pos) - 2] = '\0';

	/* If no argument was provided, free used memory and return error */
	if (strlen(argument) == 0) {
		kfree(command);
		kfree(argument);
		return -EFAULT;
	}

	if (!strcmp(command, "addf")) {
		/* addf command */
		r = addf(argument);
		if (r != 0)
			return r;
	} else if (!strcmp(command, "adde")) {
		/* adde command */
		r = adde(argument);
		if (r != 0)
			return r;
	} else if (!strcmp(command, "delf")) {
		/* delf command */
		delf(argument);
	} else if (!strcmp(command, "dela")) {
		/* dela command */
		dela(argument);
	} else {
		/* unknown command */
		return -EFAULT;
	}

	/* Free used memory */
	kfree(command);
	kfree(argument);

	return local_buffer_size;
}

static const struct proc_ops r_pops = {
	.proc_open		= list_read_open,
	.proc_read		= seq_read,
	.proc_release	= single_release,
};

static const struct proc_ops w_pops = {
	.proc_open		= list_write_open,
	.proc_write		= list_write,
	.proc_release	= single_release,
};

static int list_init(void)
{
	proc_list = proc_mkdir(procfs_dir_name, NULL);
	if (!proc_list)
		return -ENOMEM;

	proc_list_read = proc_create(procfs_file_read, 0000, proc_list,
				     &r_pops);
	if (!proc_list_read)
		goto proc_list_cleanup;

	proc_list_write = proc_create(procfs_file_write, 0000, proc_list,
				      &w_pops);
	if (!proc_list_write)
		goto proc_list_read_cleanup;

	return 0;

proc_list_read_cleanup:
	proc_remove(proc_list_read);
proc_list_cleanup:
	proc_remove(proc_list);
	return -ENOMEM;
}

static void list_exit(void)
{
	struct list_head *iterator, *backup;
	struct list_node *node;

	/*
	 * Iterate through the list in a safe manner, since a node will be removed
	 */
	list_for_each_safe(iterator, backup, &head) {
		/*
		 * Get the iterator as a list_node* variable to be able to access data
		 */
		node = list_entry(iterator, struct list_node, list_node);

		/* Remove the node from the list */
		list_del(iterator);

		/* Free the node's memory */
		kfree(node->data);
		kfree(node);
	}
	proc_remove(proc_list);
}

module_init(list_init);
module_exit(list_exit);

MODULE_DESCRIPTION("Linux kernel list API");
MODULE_AUTHOR("Theodor-Alin Oprea <opreatheodor54@gmail.com>");
MODULE_LICENSE("GPL v2");
