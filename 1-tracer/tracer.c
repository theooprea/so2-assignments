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

/* spinlock to restrict access to process-context critical code */
DEFINE_SPINLOCK(procs_lock);

/* list to keep track of registered processes */
static LIST_HEAD(procs_list_head);

/* list to keep track of the allocated memory areas */
static LIST_HEAD(memory_areas_list_head);

/* a struct to keep allocated memory areas info */
struct memory_areas_list_node {
	/* pid of the proccess that the memory area belongs to */
	pid_t pid;

	/* the start address and size of the memory area */
	int address;
	int size;

	/* the list_head var to be able to use it as a list node */
	struct list_head memory_areas_list_node;
};

struct procs_list_node {
	/* the pid of the process */
	pid_t pid;

	/* kmalloc and kfree number of calls and memory amount */
	int kmalloc_no;
	int kfree_no;
	int kmalloc_mem;
	int kfree_mem;

	/* the number of schedule calls */
	int sched_no;

	/* the number of up and down calls */
	int up_no;
	int down_no;

	/* the number of mutex lock and mutex unlock calls */
	int lock_no;
	int unlock_no;

	/* the list_head var to be able to use it as a list node */
	struct list_head procs_list_node;
};

/**
 * @brief Alocates the memory for a new processor info node and initialize
 * all fields to 0, other than the pid
 *
 * @param pid The pid of the new process for which the new node is created
 * @return struct procs_list_node* The newly created node
 */
static struct procs_list_node *new_node(pid_t pid)
{
	struct procs_list_node *node;

	/* allocate a new node structure in process-context*/
	node = kmalloc(sizeof(struct procs_list_node), GFP_KERNEL);
	if (node == NULL)
		return NULL;

	node->pid = pid;

	node->kmalloc_no = 0;
	node->kfree_no = 0;
	node->kmalloc_mem = 0;
	node->kfree_mem = 0;

	node->sched_no = 0;
	
	node->up_no = 0;
	node->down_no = 0;

	node->lock_no = 0;
	node->unlock_no = 0;
	
	return node;
}

/**
 * @brief Adds a node to the processors list
 *
 * @param node The node to be added
 * @return int The status of the operation, 0 success, error code otherwise
 */
static int procs_list_add(struct procs_list_node *node) {
	struct procs_list_node *node_iterator;
	struct list_head *iterator;

	/*
	 * iterate through the list, if the pid is already in the list,
	 * don't add it again
	 */
	list_for_each(iterator, &procs_list_head) {
		/* get the procs_list_node* variable from a generic list node */
		node_iterator = list_entry(iterator, struct procs_list_node, procs_list_node);

		if (node_iterator->pid == node->pid)
			return -EFAULT;
	}

	/* add to the list in an rcu protected context */
	list_add_rcu(&node->procs_list_node, &procs_list_head);

	return 0;
}

/**
 * @brief Removes a proc from the procs list and get referrence to it
 *
 * @param pid The pid of the process to be removed from the list
 * @return struct procs_list_node* The referrence to the removed node
 */
static struct procs_list_node *procs_list_remove(pid_t pid) {
	struct list_head *iterator, *backup;
	struct procs_list_node *node;

	/*
	 * Iterate through the list safely and if the node with the given pid is
	 * found, remove it from the list
	 */
	list_for_each_safe(iterator, backup, &procs_list_head) {
		node = list_entry(iterator, struct procs_list_node, procs_list_node);

		/* remove in an rcu-guarded context */
		if (node->pid == pid) {
			list_del_rcu(iterator);

			return node;
		}
	}

	/* if the process was not found, return NULL */
	return NULL;
}

/**
 * @brief Gets a referrence to the process with the given pid from the list
 *
 * @param pid The pid of the node which is searched for
 * @return struct procs_list_node* 
 */
static struct procs_list_node *procs_list_get(pid_t pid) {
	struct procs_list_node *node;

	/* iterate in an rcu protected context for performance reasons */
	list_for_each_entry_rcu(node, &procs_list_head, procs_list_node) {
		if (node->pid == pid) {
			return node;
		}
	}

	return NULL;
}

static int tracer_cdev_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int
tracer_cdev_release(struct inode *inode, struct file *file)
{
	return 0;
}

/**
 * @brief The IOCTL command function, receives an IOCTL command and performs it
 *
 * @param file The dev file
 * @param cmd The given command
 * @param arg The argument given (in our case, the pid of the process to be
 * added / removed)
 * @return long The status of the function's success, 0 - success, failure
 * otherwise
 */
static long
tracer_cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct procs_list_node *aux;

	switch (cmd) {
		/* add process command */
		case TRACER_ADD_PROCESS:
			/* create new node with the given pid */
			aux = new_node(arg);

			/* get the lock to be able to properly insert the node */
			spin_lock(&procs_lock);

			/* add the process to the list and get the return code */
			ret = procs_list_add(aux);

			/* unlock the critical zone */
			spin_unlock(&procs_lock);

			break;
		/* remove process command */
		case TRACER_REMOVE_PROCESS:
			/* get the lock to be able to properly remove the node */
			spin_lock(&procs_lock);

			/*
			 * get referrence to the node to be later freed, and remove the
			 * node from the list
			 */
			aux = procs_list_remove(arg);

			/* unlock the critical zone */
			spin_unlock(&procs_lock);

			/*
			 * get exclusive access to the list, including the node to be
			 * freed, extra check in case the given pid was not added in the
			 * list
			 */
			synchronize_rcu();
			if (aux != NULL)
				kfree(aux);

			break;
		default:
			ret = -EINVAL;
	}

	return ret;
}

/**
 * @brief Shows the stats so far
 *
 * @param m Referrence to print the results
 * @param v
 * @return int status of the function, always 0 success
 */
static int tracer_proc_show(struct seq_file *m, void *v)
{
	struct procs_list_node *node;

	seq_printf(m, "PID kmalloc kfree kmalloc_mem kfree_mem sched up down lock unloc\n");

	/* get read exclusivity to the list */
	rcu_read_lock();

	/* iterate in an rcu protected zone */
	list_for_each_entry_rcu(node, &procs_list_head, procs_list_node) {

		seq_printf(m, "%d %d %d %d %d %d %d %d %d %d\n", node->pid,
			node->kmalloc_no, node->kfree_no, node->kmalloc_mem, node->kfree_mem,
			node->sched_no, node->up_no, node->down_no, node->lock_no, node->unlock_no);
	}

	/* unlock the critical read intensive zone */
	rcu_read_unlock();

	return 0;
}

static int tracer_proc_read_open(struct inode *inode, struct  file *file)
{
	return single_open(file, tracer_proc_show, NULL);
}

struct proc_dir_entry *tracer_proc_read;

/* proc fs ops, used to read the stats */
static const struct proc_ops tracer_pops = {
	.proc_open		= tracer_proc_read_open,
	.proc_read		= seq_read,
	.proc_release	= single_release,
};

/* char device ops, mainly used for ioctl operations */
static const struct file_operations tracer_fops = {
	.owner = THIS_MODULE,
	.open = tracer_cdev_open,
	.release = tracer_cdev_release,
	.unlocked_ioctl = tracer_cdev_ioctl,
};

/* the miscdevice struct for the char device, the name, the Minor
 * (since the major for miscdevice is 10 by default) and the ops for the
 * char device
 */
static struct miscdevice tracer_miscdevice = {
	.minor = TRACER_DEV_MINOR,
	.name = TRACER_DEV_NAME,
	.fops = &tracer_fops
};

/* handlers section */

/**
 * @brief Sched probe handler, increments the sched calls number
 * for the current pid
 *
 * @param ri The kretprobe instance
 * @param regs The registers used in the calling function
 * @return int The status, 0 - success, failure otherwise
 */
static int sched_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct procs_list_node *current_proc;

	/* get rcu exclusive access to the list - shared read exclusive write */
	rcu_read_lock();

	/* get current process node */
	current_proc = procs_list_get(current->pid);

	/* if the process is not among the monitored ones */
	if (current_proc == NULL) {
		/* free the lock before returning error */
		spin_unlock(&procs_lock);
		return -EINVAL;
	}

	/* increment the sched calls number */
	current_proc->sched_no = current_proc->sched_no + 1;

	/* free the rcu lock */
	rcu_read_unlock();

	return 0;
}

/**
 * @brief Up probe handler, increments the up calls number
 * for the current pid
 *
 * @param ri The kretprobe instance
 * @param regs The registers used in the calling function
 * @return int The status, 0 - success, failure otherwise
 */
static int up_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct procs_list_node *current_proc;

	/* get rcu exclusive access to the list - shared read exclusive write */
	rcu_read_lock();
	
	/* get current process node */
	current_proc = procs_list_get(current->pid);

	/* if the process is not among the monitored ones */
	if (current_proc == NULL) {
		/* free the lock before returning error */
		spin_unlock(&procs_lock);
		return -EINVAL;
	}

	/* increment the up calls number */
	current_proc->up_no = current_proc->up_no + 1;
	
	/* free the rcu lock */
	rcu_read_unlock();

	return 0;
}

/**
 * @brief Down probe handler, increments the down calls number
 * for the current pid
 *
 * @param ri The kretprobe instance
 * @param regs The registers used in the calling function
 * @return int The status, 0 - success, failure otherwise
 */
static int down_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct procs_list_node *current_proc;

	/* get rcu exclusive access to the list - shared read exclusive write */
	rcu_read_lock();
	
	/* get current process node */
	current_proc = procs_list_get(current->pid);

	/* if the process is not among the monitored ones */
	if (current_proc == NULL) {
		/* free the lock before returning error */
		spin_unlock(&procs_lock);
		return -EINVAL;
	}

	/* increment the down calls number */
	current_proc->down_no = current_proc->down_no + 1;
	
	/* free the rcu lock */
	rcu_read_unlock();

	return 0;
}

/**
 * @brief Lock probe handler, increments the lock calls number
 * for the current pid
 *
 * @param ri The kretprobe instance
 * @param regs The registers used in the calling function
 * @return int The status, 0 - success, failure otherwise
 */
static int lock_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct procs_list_node *current_proc;

	/* get rcu exclusive access to the list - shared read exclusive write */
	rcu_read_lock();
	
	/* get current process node */
	current_proc = procs_list_get(current->pid);

	/* if the process is not among the monitored ones */
	if (current_proc == NULL) {
		/* free the lock before returning error */
		spin_unlock(&procs_lock);
		return -EINVAL;
	}

	/* increment the lock calls number */
	current_proc->lock_no = current_proc->lock_no + 1;
	
	/* free the rcu lock */
	rcu_read_unlock();

	return 0;
}

/**
 * @brief Unlock probe handler, increments the unlock calls number
 * for the current pid
 *
 * @param ri The kretprobe instance
 * @param regs The registers used in the calling function
 * @return int The status, 0 - success, failure otherwise
 */
static int unlock_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct procs_list_node *current_proc;

	/* get rcu exclusive access to the list - shared read exclusive write */
	rcu_read_lock();
	
	/* get current process node */
	current_proc = procs_list_get(current->pid);

	/* if the process is not among the monitored ones */
	if (current_proc == NULL) {
		/* free the lock before returning error */
		spin_unlock(&procs_lock);
		return -EINVAL;
	}

	/* increment the unlock calls number */
	current_proc->unlock_no = current_proc->unlock_no + 1;
	
	/* free the rcu lock */
	rcu_read_unlock();

	return 0;
}

/**
 * @brief Kmalloc entry probe handler, increments the kmalloc calls number
 * for the current pid, and passes the wanted size for the to be allocated
 * memory area to the kmalloc exit probe
 *
 * @param ri The kretprobe instance - used to pass the wanted size to the
 * kmalloc exit probe
 * @param regs The registers used in the calling function, used to get the
 * wanted size of the to-be-allocated memory area
 * @return int The status, 0 - success, failure otherwise
 */
static int kmalloc_entry_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct procs_list_node *current_proc;

	/* get rcu exclusive access to the list - shared read exclusive write */
	rcu_read_lock();
	
	/* get current process node */
	current_proc = procs_list_get(current->pid);

	/* if the process is not among the monitored ones */
	if (current_proc == NULL) {
		/* free the lock before returning error */
		spin_unlock(&procs_lock);
		return -EINVAL;
	}

	/* increment the kmalloc calls number */
	current_proc->kmalloc_no = current_proc->kmalloc_no + 1;
	
	/* free the rcu lock */
	rcu_read_unlock();

	/*
	 * pass the wanted size for the to-be-allocated memory area to the
	 * kmalloc exit probe (to be able to track the allocated memory)
	 */
	*((int *)ri->data) = regs->ax;

	return 0;
}

/**
 * @brief Kmalloc exit probe handler, gets the passed data from the kmalloc
 * entry handler (the wanted size of the to-be-allocated memory area)
 *
 * @param ri The kretprobe instance, used to get the size of the memory area,
 * passed by the kmalloc entry probe handler
 * @param regs The registers used in the calling function, used to get the
 * starting address of the allocated memory, to be saved in the memory_area
 * list
 * @return int The status, 0 - success, failure otherwise
 */
static int kmalloc_exit_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int address;
	struct procs_list_node *current_proc;
	struct memory_areas_list_node *memory_area;

	/* get rcu exclusive access to the list - shared read exclusive write */
	rcu_read_lock();
	
	/* get current process node */
	current_proc = procs_list_get(current->pid);

	/* if the process is not among the monitored ones */
	if (current_proc == NULL) {
		/* free the lock before returning error */
		spin_unlock(&procs_lock);
		return -EINVAL;
	}

	/* get the starting address of the alocated memory area */
	address = regs_return_value(regs);
	
	/*
	 * allocate a memory_area node, to store the amount of memory that was
	 * allocated
	 */
	memory_area = kmalloc(sizeof(struct memory_areas_list_node), GFP_ATOMIC);
	
	/* in case of failure, unlock the lock and return error */
	if (memory_area == NULL) {
		spin_unlock(&procs_lock);
		return -ENOMEM;
	}

	/* populate the info for the new node */
	memory_area->pid = current->pid;
	memory_area->address = address;
	memory_area->size = *((int *)ri->data);

	/* add the allocated memory to the current proc's info node */
	current_proc->kmalloc_mem = current_proc->kmalloc_mem + *((int *)ri->data);

	/* add the memory_area node to the list */
	list_add(&memory_area->memory_areas_list_node, &memory_areas_list_head);
	
	/* free the rcu lock */
	rcu_read_unlock();

	return 0;
}

/**
 * @brief Kfree probe handler, increments the kfree calls number
 * for the current pid, and searches for the corresponding memory_area node,
 * which has the current process's pid, and has the starting address equal
 * to the value stored in ax register (the starting address for the to-be-freed
 * memory area)
 *
 * @param ri The kretprobe instance
 * @param regs The registers used in the calling function, used to get the
 * starting address of the to-be-freed memory_area
 * @return int The status, 0 - success, failure otherwise
 */
static int kfree_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct list_head *iterator;
	struct memory_areas_list_node *memory_area_node;
	struct procs_list_node *current_proc;

	/* get rcu exclusive access to the list - shared read exclusive write */
	rcu_read_lock();
	
	/* get current process node */
	current_proc = procs_list_get(current->pid);

	/* if the process is not among the monitored ones */
	if (current_proc == NULL) {
		/* free the lock before returning error */
		spin_unlock(&procs_lock);
		return -EINVAL;
	}

	/* increment the kfree calls number */
	current_proc->kfree_no = current_proc->kfree_no + 1;

	/*
	 * iterate through the memory_areas_list to find the one corresponding
	 * to the kree call starting address and current pid
	 */
	list_for_each(iterator, &memory_areas_list_head) {
		memory_area_node = list_entry(iterator, struct memory_areas_list_node, memory_areas_list_node);

		if (memory_area_node->pid == current->pid && memory_area_node->address == regs->ax) {
			/*
			 * if the memory_area node is found, add the size to the kfree
			 * memory for the current process
			 */
			current_proc->kfree_mem = current_proc->kfree_mem + memory_area_node->size;
			break;
		}
	}

	/* free the rcu lock */
	rcu_read_unlock();

	return 0;
}

/* kretprobes section */
static struct kretprobe sched_probe = {
   .entry_handler = sched_probe_handler,
   .maxactive = 32,
   .kp.symbol_name = "schedule"
};

static struct kretprobe up_probe = {
   .entry_handler = up_probe_handler,
   .maxactive = 32,
   .kp.symbol_name = "up"
};

static struct kretprobe down_probe = {
   .entry_handler = down_probe_handler,
   .maxactive = 32,
   .kp.symbol_name = "down_interruptible"
};

static struct kretprobe lock_probe = {
   .entry_handler = lock_probe_handler,
   .maxactive = 32,
   .kp.symbol_name = "mutex_lock_nested"
};

static struct kretprobe unlock_probe = {
   .entry_handler = unlock_probe_handler,
   .maxactive = 32,
   .kp.symbol_name = "mutex_unlock"
};

/*
 * use an entry handler and an exit handler to be able to get both starting
 * address and size for a kmalloc call
 */
static struct kretprobe kmalloc_probe = {
   .entry_handler = kmalloc_entry_probe_handler,
   .handler = kmalloc_exit_probe_handler,
   .data_size = sizeof(int),
   .maxactive = 32,
   .kp.symbol_name = "__kmalloc"
};

static struct kretprobe kfree_probe = {
   .entry_handler = kfree_probe_handler,
   .maxactive = 32,
   .kp.symbol_name = "kfree"
};

/**
 * @brief Init func to register the kernel module
 *
 * @return int The status of the init func, 0 - success, error otherwise
 */
static int tracer_init(void)
{
	int err;

	/* initialize the procs lock */
	spin_lock_init(&procs_lock);

	/* register the /proc/tracer proc_fs entry */
	tracer_proc_read = proc_create(TRACER_DEV_NAME, 0000, NULL, &tracer_pops);
	if (!tracer_proc_read)
		return -ENOMEM;

	/* register the /dev/tracer char device, with 10 as Major */
	err = misc_register(&tracer_miscdevice);
	if (err != 0)
		goto error_misc_register;

	/* register the sched calls responsible kretprobe */
	err = register_kretprobe(&sched_probe);
	if (err) {
		pr_err("Failure on register_kretprobe sched_probe\n");
		goto error_kretprobe_sched;
	}

	/* register the up calls responsible kretprobe */
	err = register_kretprobe(&up_probe);
	if (err) {
		pr_err("Failure on register_kretprobe up_probe\n");
		goto error_kretprobe_up;
	}

	/* register the down calls responsible kretprobe */
	err = register_kretprobe(&down_probe);
	if (err) {
		pr_err("Failure on register_kretprobe down_probe\n");
		goto error_kretprobe_down;
	}

	/* register the lock calls responsible kretprobe */
	err = register_kretprobe(&lock_probe);
	if (err) {
		pr_err("Failure on register_kretprobe lock_probe\n");
		goto error_kretprobe_lock;
	}

	/* register the unlock calls responsible kretprobe */
	err = register_kretprobe(&unlock_probe);
	if (err) {
		pr_err("Failure on register_kretprobe unlock_probe\n");
		goto error_kretprobe_unlock;
	}

	/* register the kmalloc calls responsible kretprobe */
	err = register_kretprobe(&kmalloc_probe);
	if (err) {
		pr_err("Failure on register_kretprobe kmalloc_probe\n");
		goto error_kretprobe_kmalloc;
	}

	/* register the kfree calls responsible kretprobe */
	err = register_kretprobe(&kfree_probe);
	if (err) {
		pr_err("Failure on register_kretprobe kfree_probe\n");
		goto error_kretprobe_kfree;
	}

	return 0;

error_kretprobe_kfree:
	unregister_kretprobe(&kmalloc_probe);

error_kretprobe_kmalloc:
	unregister_kretprobe(&unlock_probe);

error_kretprobe_unlock:
	unregister_kretprobe(&lock_probe);

error_kretprobe_lock:
	unregister_kretprobe(&down_probe);

error_kretprobe_down:
	unregister_kretprobe(&up_probe);

error_kretprobe_up:
	unregister_kretprobe(&sched_probe);

error_kretprobe_sched:
	misc_deregister(&tracer_miscdevice);

error_misc_register:
	proc_remove(tracer_proc_read);

	return err;
}

/**
 * @brief Exit function to tear the kernel module down
 *
 */
static void tracer_exit(void)
{
	struct list_head *iterator, *backup;
	struct procs_list_node *node_procs;
	struct memory_areas_list_node *node_memory_areas;

	/* unregister all kretprobes */
	unregister_kretprobe(&up_probe);
	unregister_kretprobe(&down_probe);
	unregister_kretprobe(&lock_probe);
	unregister_kretprobe(&unlock_probe);
	unregister_kretprobe(&sched_probe);
	unregister_kretprobe(&kmalloc_probe);
	unregister_kretprobe(&kfree_probe);

	/* unregister the char device */
	misc_deregister(&tracer_miscdevice);

	/* unregister the proc fs entry */
	proc_remove(tracer_proc_read);

	/* free all the remaining procs that were registered */
	list_for_each_safe(iterator, backup, &procs_list_head) {
		node_procs = list_entry(iterator, struct procs_list_node, procs_list_node);

		list_del(iterator);

		kfree(node_procs);
	}

	/* free all the remaining memory areas */
	list_for_each_safe(iterator, backup, &memory_areas_list_head) {
		node_memory_areas = list_entry(iterator, struct memory_areas_list_node, memory_areas_list_node);

		list_del(iterator);

		kfree(node_memory_areas);
	}
}

module_init(tracer_init);
module_exit(tracer_exit);

MODULE_DESCRIPTION("Linux kprobe based tracer");
MODULE_AUTHOR("Theodor-Alin Oprea <opreatheodor54@gmail.com>");
MODULE_LICENSE("GPL v2");

