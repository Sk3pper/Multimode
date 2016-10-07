#define EXPORT_SYMTAB
#include <linux/errno.h> /* error codes */
#include <linux/module.h> /* try_module_get() and put_module() */
#include <linux/slab.h> /* kmalloc() */
#include <linux/types.h> /* size_t */
#include <linux/fs.h> /* struct file */
#include <linux/spinlock.h> /* spinlock */
#include <linux/sched.h> /*wait_event_interruptible */
#include <asm/atomic.h> /* atomic counter */
#define LINKED_LIST_IS_EMPTY(minor) (head[minor] == NULL)
#define O_PACKET 0x80000000
#define DEVICE_FILE_NAME "multimode"
#define DEVICE_NUMBERS 256
#define LINKED_LIST_SIZE 32    /* initial value */
#define MAX_PACKET_SIZE 8      /* initial value */
#define MIN_PACKET_SIZE 4      /* initial value */

/* size limits */
#define MAX_LIMIT_LINKED_LIST 1024
#define MIN_LIMIT_LINKED_LIST 16
#define MAX_LIMIT_PACKET 16
#define MIN_LIMIT_PACKET 2

/* buffer to store data */
typedef struct packet {
	char *buffer;
	int buffer_size;
	int read_pos;
	struct packet *next;
} packet;

/* queue of blocking processes */
typedef struct process_list{
	spinlock_t lock;
	struct process *head;
	struct process *tail;
} process_list;

typedef struct process{
	struct task_struct *the_task;
	struct process *next;
	struct process *previous;
}process;

