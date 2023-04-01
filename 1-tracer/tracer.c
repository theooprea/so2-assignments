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

#ifndef BUFSIZ
#define BUFSIZ		4096
#endif

DEFINE_SPINLOCK(procs_lock);
static LIST_HEAD(procs_list_head);
static LIST_HEAD(memory_areas_list_head);

struct memory_areas_list_node {
	pid_t pid;

	int address;
	int size;

	struct list_head memory_areas_list_node;
};

struct procs_list_node {
	pid_t pid;

	int kmalloc_no;
	int kfree_no;
	int kmalloc_mem;
	int kfree_mem;

	int sched_no;

	int up_no;
	int down_no;

	int lock_no;
	int unlock_no;

	struct list_head procs_list_node;
};

static struct procs_list_node *new_node(pid_t pid)
{
	struct procs_list_node *node;

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

static int procs_list_add(struct procs_list_node *node) {
	struct procs_list_node *node_iterator;
	struct list_head *iterator;

	list_for_each(iterator, &procs_list_head) {
		node_iterator = list_entry(iterator, struct procs_list_node, procs_list_node);

		if (node_iterator->pid == node->pid)
			return -EFAULT;
	}

	list_add(&node->procs_list_node, &procs_list_head);

	return 0;
}

static struct procs_list_node *procs_list_remove(pid_t pid) {
	struct list_head *iterator, *backup;
	struct procs_list_node *node;

	list_for_each_safe(iterator, backup, &procs_list_head) {
		node = list_entry(iterator, struct procs_list_node, procs_list_node);

		if (node->pid == pid) {
			list_del(iterator);

			return node;
		}
	}

	return NULL;
}

static struct procs_list_node *procs_list_get(pid_t pid) {
	struct list_head *iterator, *backup;
	struct procs_list_node *node;

	list_for_each_safe(iterator, backup, &procs_list_head) {
		node = list_entry(iterator, struct procs_list_node, procs_list_node);

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

static long
tracer_cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct procs_list_node *aux;

	switch (cmd) {
		case TRACER_ADD_PROCESS:
			aux = new_node(arg);

			spin_lock(&procs_lock);
			ret = procs_list_add(aux);
			spin_unlock(&procs_lock);

			break;
		case TRACER_REMOVE_PROCESS:
			spin_lock(&procs_lock);
			aux = procs_list_remove(arg);
			spin_unlock(&procs_lock);

			if (aux != NULL)
				kfree(aux);

			break;
		default:
			ret = -EINVAL;
	}

	return ret;
}

static int tracer_proc_show(struct seq_file *m, void *v)
{
	struct procs_list_node *node;
	struct list_head *iterator;

	seq_printf(m, "PID kmalloc kfree kmalloc_mem kfree_mem sched up down lock unloc\n");

	spin_lock(&procs_lock);
	list_for_each(iterator, &procs_list_head) {
		node = list_entry(iterator, struct procs_list_node, procs_list_node);

		seq_printf(m, "%d %d %d %d %d %d %d %d %d %d\n", node->pid,
			node->kmalloc_no, node->kfree_no, node->kmalloc_mem, node->kfree_mem,
			node->sched_no, node->up_no, node->down_no, node->lock_no, node->unlock_no);
	}
	spin_unlock(&procs_lock);

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
static int sched_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct procs_list_node *current_proc;

	current_proc = procs_list_get(current->pid);

	if (current_proc == NULL)
		return -EINVAL;

	spin_lock(&procs_lock);
	current_proc->sched_no = current_proc->sched_no + 1;
	spin_unlock(&procs_lock);

	return 0;
}

static int up_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct procs_list_node *current_proc;

	current_proc = procs_list_get(current->pid);

	if (current_proc == NULL)
		return -EINVAL;

	spin_lock(&procs_lock);
	current_proc->up_no = current_proc->up_no + 1;
	spin_unlock(&procs_lock);

	return 0;
}

static int down_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct procs_list_node *current_proc;

	current_proc = procs_list_get(current->pid);

	if (current_proc == NULL)
		return -EINVAL;

	spin_lock(&procs_lock);
	current_proc->down_no = current_proc->down_no + 1;
	spin_unlock(&procs_lock);

	return 0;
}

static int lock_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct procs_list_node *current_proc;

	current_proc = procs_list_get(current->pid);

	if (current_proc == NULL)
		return -EINVAL;

	spin_lock(&procs_lock);
	current_proc->lock_no = current_proc->lock_no + 1;
	spin_unlock(&procs_lock);

	return 0;
}

static int unlock_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct procs_list_node *current_proc;

	current_proc = procs_list_get(current->pid);

	if (current_proc == NULL)
		return -EINVAL;

	spin_lock(&procs_lock);
	current_proc->unlock_no = current_proc->unlock_no + 1;
	spin_unlock(&procs_lock);

	return 0;
}

static int kmalloc_entry_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct procs_list_node *current_proc;

	current_proc = procs_list_get(current->pid);

	if (current_proc == NULL)
		return -EINVAL;

	spin_lock(&procs_lock);
	current_proc->kmalloc_no = current_proc->kmalloc_no + 1;
	spin_unlock(&procs_lock);

	*((int *)ri->data) = regs->ax;

	return 0;
}

static int kmalloc_exit_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int address;
	struct procs_list_node *current_proc;
	struct memory_areas_list_node *memory_area;

	current_proc = procs_list_get(current->pid);

	if (current_proc == NULL)
		return -EINVAL;

	address = regs_return_value(regs);
	memory_area = kmalloc(sizeof(struct memory_areas_list_node), GFP_ATOMIC);
	if (memory_area == NULL)
		return -ENOMEM;

	memory_area->pid = current->pid;
	memory_area->address = address;
	memory_area->size = *((int *)ri->data);

	spin_lock(&procs_lock);
	current_proc->kmalloc_mem = current_proc->kmalloc_mem + *((int *)ri->data);
	list_add(&memory_area->memory_areas_list_node, &memory_areas_list_head);
	spin_unlock(&procs_lock);

	return 0;
}

static int kfree_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct list_head *iterator;
	struct memory_areas_list_node *memory_area_node;
	struct procs_list_node *current_proc;

	current_proc = procs_list_get(current->pid);

	if (current_proc == NULL)
		return -EINVAL;

	spin_lock(&procs_lock);
	current_proc->kfree_no = current_proc->kfree_no + 1;

	list_for_each(iterator, &memory_areas_list_head) {
		memory_area_node = list_entry(iterator, struct memory_areas_list_node, memory_areas_list_node);

		if (memory_area_node->pid == current->pid && memory_area_node->address == regs->ax)
			current_proc->kfree_mem = current_proc->kfree_mem + memory_area_node->size;
	}

	spin_unlock(&procs_lock);

	return 0;
}

// Kretprobes section
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

static int tracer_init(void)
{
	int err;

	spin_lock_init(&procs_lock);

	tracer_proc_read = proc_create(TRACER_DEV_NAME, 0000, NULL, &tracer_pops);
	if (!tracer_proc_read)
		return -ENOMEM;

	err = misc_register(&tracer_miscdevice);
	if (err != 0)
		goto error_misc_register;

	err = register_kretprobe(&sched_probe);
	if (err) {
		pr_err("Failure on register_kretprobe sched_probe\n");
		goto error_kretprobe_sched;
	}

	err = register_kretprobe(&up_probe);
	if (err) {
		pr_err("Failure on register_kretprobe up_probe\n");
		goto error_kretprobe_up;
	}

	err = register_kretprobe(&down_probe);
	if (err) {
		pr_err("Failure on register_kretprobe down_probe\n");
		goto error_kretprobe_down;
	}

	err = register_kretprobe(&lock_probe);
	if (err) {
		pr_err("Failure on register_kretprobe lock_probe\n");
		goto error_kretprobe_lock;
	}

	err = register_kretprobe(&unlock_probe);
	if (err) {
		pr_err("Failure on register_kretprobe unlock_probe\n");
		goto error_kretprobe_unlock;
	}

	err = register_kretprobe(&kmalloc_probe);
	if (err) {
		pr_err("Failure on register_kretprobe kmalloc_probe\n");
		goto error_kretprobe_kmalloc;
	}

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
	misc_deregister(&tracer_miscdevice);
	unregister_kretprobe(&sched_probe);
error_kretprobe_sched:
	misc_deregister(&tracer_miscdevice);
error_misc_register:
	proc_remove(tracer_proc_read);

	return err;
}

static void tracer_exit(void)
{
	struct list_head *iterator, *backup;
	struct procs_list_node *node_procs;
	struct memory_areas_list_node *node_memory_areas;

	unregister_kretprobe(&up_probe);
	unregister_kretprobe(&down_probe);
	unregister_kretprobe(&lock_probe);
	unregister_kretprobe(&unlock_probe);
	unregister_kretprobe(&sched_probe);
	unregister_kretprobe(&kmalloc_probe);
	unregister_kretprobe(&kfree_probe);
	misc_deregister(&tracer_miscdevice);
	proc_remove(tracer_proc_read);

	list_for_each_safe(iterator, backup, &procs_list_head) {
		node_procs = list_entry(iterator, struct procs_list_node, procs_list_node);

		list_del(iterator);

		kfree(node_procs);
	}

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

