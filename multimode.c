#include "multimode.h"
#include "multimode_ioctl.h"

#include <linux/errno.h> /* error codes */
#include <linux/module.h> /* try_module_get() and put_module() */
#include <linux/slab.h> /* kmalloc() */
#include <linux/types.h> /* size_t */
#include <linux/fs.h> /* struct file */
#include <linux/spinlock.h> /* spinlock */
#include <linux/sched.h> /*wait_event_interruptible */
#include <asm/atomic.h> /* atomic counter */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Bissoli");

/* linked list of nodes */
static node* head[DEVICE_NUMBERS];
static node* tail[DEVICE_NUMBERS];
/* major number */
static int major;
/* lock for write,read and atomic_set/atomic_read */
static spinlock_t buffer_lock[DEVICE_NUMBERS];
/* buffer dynamic sizes */
static atomic_t buffer_size[DEVICE_NUMBERS];
/* node dynamic sizes */
static atomic_t max_node_size[DEVICE_NUMBERS];
static atomic_t min_node_size[DEVICE_NUMBERS];
/* number of bytes occupied within the buffer */
static atomic_t payload[DEVICE_NUMBERS];
/* 0=file not opened - 1=file opened */
static atomic_t is_open[DEVICE_NUMBERS];
/* wait queue for blocking mode */
static wait_process_list *write_wait_queue[DEVICE_NUMBERS];
static wait_process_list *read_wait_queue[DEVICE_NUMBERS];

static int free_head_process(struct wait_process_list* wait_list);
static int wakeup_head_queue(struct wait_process_list* wait_list);

/*insert the process in the proper wait queue*/
static process* set_blocking_process_in_the_list(wait_process_list * wait_list){
	/*insert the process in the list_wait_queue*/
	process* proc;
	proc = kmalloc( sizeof(process), GFP_KERNEL);
	proc->pcb = pid_task(find_vpid(current->pid),PIDTYPE_PID);
	proc->next = NULL;
	proc->previous = NULL;
	if(wait_list->head==NULL){ /* insert the process in the head of the list */
		printk("[set_blocking_process_in_the_list] %d       insert in wait_queue in the head\n",GET_PID); 
		wait_list->head = proc;
		wait_list->tail = proc;
	}else{	/* insert the process in the tail of the list */
		printk("[set_blocking_process_in_the_list] %d        insert in wait_queue in the tail\n",GET_PID); 
		proc->previous = wait_list->tail;
		wait_list->tail->next = proc;
		wait_list->tail = proc;
	}
	return proc;
}

/*remove the process in the proper wait queue*/
static void unset_process_in_the_list(wait_process_list * wait_list,process* proc){
    spin_lock(&wait_list->lock);
		if(proc->previous != NULL){	/* blocking_process is not the first process in the list */	
			(proc->previous)->next = proc->next;
			if(proc->next != NULL) /*blocking_process is the last process in the list*/	
				(proc->next)->previous = proc->previous;
		}
		else{ /*blocking_process is the first process in the list */
			wait_list->head = wait_list->head->next;
			if(wait_list->head != NULL)
				(wait_list->head)->previous = NULL;
		}
		/* once updated the pointers in the list it is possible to free blocking_process */
		kfree(proc); 
	spin_unlock(&wait_list->lock);
}

/*sleep funtion called when process is in blocking mode*/
static long sleep_on_queue(int minor,wait_process_list * wait_list,int flag,int count){
    process* proc;	
    DECLARE_WAIT_QUEUE_HEAD(the_queue); /*private wait queue for wake up process according FIFO semantic in a selectively way */
	
	spin_lock(&wait_list->lock);
		proc = set_blocking_process_in_the_list(wait_list);
	
	if(flag==0){ /* write_wait_queue case */
        printk("[sleep_on_queue] %d       write_wait_queue case\n",GET_PID); 
		spin_unlock(&wait_list->lock);
        printk("[sleep_on_queue] %d      blocking_process->pcb: %d metto a dormire\n",proc->pcb->pid,GET_PID); 		
		if(wait_event_interruptible(the_queue,
								   ( (atomic_read(&buffer_size[minor])-atomic_read(&payload[minor]) >= count) || /* if there is free space*/
									 (atomic_read(&buffer_size[minor])<count) || /* if the buffer size change and become less than what i want to write*/
									 (count <  atomic_read(&min_node_size[minor]) || count >atomic_read(&max_node_size[minor])) ))){/* if the min/max node size change and become less/greater than waht i want to write*/				
                /*a signal is received*/
                printk("[unset_blocking_process_in_the_list] %d    A signal is received. Exit\n",GET_PID);
                unset_process_in_the_list(wait_list,proc);
				return -ERESTARTSYS;
	 	}
        /*check what wake up me*/
        if( (atomic_read(&buffer_size[minor])<count) || 
            (count <  atomic_read(&min_node_size[minor]) || count >atomic_read(&max_node_size[minor]))) {
            printk("[sleep_on_queue] %d  atomic_read(&buffer_size[minor])<count) || (count <  atomic_read(&min_node_size[minor]) || count >atomic_read(&max_node_size[minor])) IT IS TRUE\n",GET_PID);
            /* free the blocking_process from the list*/
            unset_process_in_the_list(wait_list,proc);
            /*wake up the head*/
            wakeup_head_queue(wait_list);
            /*return error */
            return -ERESTARTSYS;
        }				
	}else{ /*read_wait_queue case*/
        printk("[sleep_on_queue] %d      read_wait_queue case\n",GET_PID); 
		spin_unlock(&wait_list->lock);
        printk("[sleep_on_queue] %d      blocking_process->pcb: %d metto a dormire\n",proc->pcb->pid,GET_PID); 
		if (wait_event_interruptible(the_queue, !LINKED_LIST_IS_EMPTY(minor))){//ENTRO nell'if quando mi arriva un segnale,
			//quindi un numero !=0 viene ritornato
			unset_process_in_the_list(wait_list,proc);
			return -ERESTARTSYS;
		}		
	}
	printk("[sleep_on_queue] %d      blocking_process->pcb: %d si e'  svegliato\n",proc->pcb->pid,GET_PID); 
	/* wait to leave the wait queue because we can do thaht only after we have got the buffer's lock(buffer_lock)*/
	return 0;
}

/*selective wake up of list's head*/
static int wakeup_head_queue(struct wait_process_list* wait_list){	
    int res=0;
    printk("[wakeup_head_queue] %d wake_up_queue called\n",GET_PID);
    spin_lock(&wait_list->lock);
	if(wait_list->head != NULL){  
        printk("[wakeup_head_queue] %d after list->head != NULL, c'e' qualcuno da svegliare in lista\n",GET_PID);    
		printk("[wakeup_head_queue] %d wakeup process: pid: %d\n",GET_PID,wait_list->head->pcb->pid);     
        res = wake_up_process(wait_list->head->pcb);
        spin_unlock(&wait_list->lock); 
      	return res;
    }else{
         printk("[wakeup_head_queue] %d after list->head == NULL, non c'e' nessuno in lista!\n",GET_PID);    
        spin_unlock(&wait_list->lock); 
		return 0;
    }
}

/*free the head: we have to free the head only when the process has got the buffer_lock*/
static int free_head_process(struct wait_process_list* wait_list){
    process* proc;
    printk("[free_head_process]  %d   free_head_process called\n",GET_PID);
	spin_lock(&wait_list->lock);
        proc = wait_list->head;
		if(wait_list->head != NULL){
            wait_list->head = wait_list->head->next; /* go to the next process blocked*/
            /*ther is the possibility that the list->head->next is null, so the new head is null. This occour when there is only one process in the list_queue*/
            if(wait_list->head != NULL){//this is THE NEW HEAD
                wait_list->head->previous = NULL; //it's the new head    
                printk("[free_head_process] %d    list->head != NULL\n",GET_PID);
            }else{ 
                wait_list->head = NULL;/*the new head is è null, there is nobody*/
                printk("[free_head_process] %d    list->head == NULL, la nuova testa e' null, non c'e' piu' nessuno\n",GET_PID);}   
        }
        printk("[free_head_process] %d, libero: %d\n",GET_PID,proc->pcb->pid);
        kfree(proc); /* remove blocking_process */		
	spin_unlock(&wait_list->lock); 
    return 0;
}

/*inizialize all variables*/
static int multimode_open(struct inode *inode, struct file *filp) {
	int minor;
	try_module_get(THIS_MODULE);
	minor = iminor(filp->f_path.dentry->d_inode);
	printk("[multimode_open] open operation on multimode device with minor %d is called\n", minor);
	if( minor >= 0 && minor < DEVICE_NUMBERS) {
		if(atomic_read(&is_open[minor]) == 0){
			spin_lock_init(&(buffer_lock[minor]));
			atomic_set(&is_open[minor], 1);
			atomic_set(&(buffer_size[minor]), BUFFER_SIZE);
			atomic_set(&(max_node_size[minor]), MAX_NODE_SIZE);
			atomic_set(&(min_node_size[minor]), MIN_NODE_SIZE);
			atomic_set(&(payload[minor]),0);
			/* initialize write queue */
			write_wait_queue[minor] = kmalloc(sizeof(struct wait_process_list), GFP_KERNEL);
			write_wait_queue[minor]->head=NULL;
			write_wait_queue[minor]->tail = NULL;
			spin_lock_init(&write_wait_queue[minor]->lock);
            
            /* initialize read queue*/
			read_wait_queue[minor] = kmalloc(sizeof(struct wait_process_list), GFP_KERNEL);
			read_wait_queue[minor]->head=NULL;
			read_wait_queue[minor]->tail = NULL;
			spin_lock_init(&read_wait_queue[minor]->lock);
		}
		return 0; 
    }else {
		printk("minor not allowed\n");
		return -ENODEV;
	}
}

/*release resources*/
static int multimode_release(struct inode *inode, struct file *filp) {
	int minor = iminor(filp->f_path.dentry->d_inode);
	module_put(THIS_MODULE);/* decrements the reference counter*/
	/* the FIFO queue will be freed when the module is unmounted */
	printk("[multimode_release] release operation on multimode device with minor %d is called\n",minor);
	return 0;
}

/*ioctl function*/
static long multimode_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
	int minor = iminor(filp->f_path.dentry->d_inode);
	int res;
	int size;	
	int old_size;
	printk("[multimode_ioctl] ioctl operation on multimode device with minor %d is called\n",minor);
	switch (cmd) {
        case MULTIMODE_SET_PACKET :
            printk("[multimode_ioctl] minor %d : node mode now is active\n",minor);
			//node_mode == 1 
            filp->private_data = (void *) ((unsigned long)filp->private_data | O_NODE);
            break;
        case MULTIMODE_SET_STREAM :
			//stream_mode == 1 
            printk("[multimode_ioctl] minor %d : stream mode now is active\n",minor);
            filp->private_data = (void *) ((unsigned long)filp->private_data & ~O_NODE);
            break;
        case MULTIMODE_SET_BLOCKING :
            printk("[multimode_ioctl] minor %d : blocking mode now is active\n",minor);
            filp->f_flags = filp->f_flags & ~O_NONBLOCK;
            break;
        case MULTIMODE_SET_NOTBLOCKING :
            printk("[multimode_ioctl] minor %d : not blocking mode now is active\n",minor);
            filp->f_flags = filp->f_flags | O_NONBLOCK;
            break;
        case MULTIMODE_GET_BUFFER_SIZE:
            printk("[multimode_ioctl] minor %d : get buffer size\n", minor);
            size = atomic_read(&(buffer_size[minor]));
			
	    res = copy_to_user((int *) arg, &size , sizeof(int));
	    if(res != 0)
	    	return -EINVAL;
            break;
			
        case MULTIMODE_SET_BUFFER_SIZE:
            printk("[multimode_ioctl] minor %d : set buffer size\n", minor);
			res = copy_from_user(&size, (int *) arg, sizeof(int));
			if(res != 0)
			return -EINVAL; 
			if( size < MIN_LIMIT_BUFFER_SIZE || size > MAX_LIMIT_BUFFER_SIZE )
				return -EINVAL;
			
			spin_lock(&(buffer_lock[minor]));
				old_size = atomic_read(&(buffer_size[minor]));
				atomic_set(&(buffer_size[minor]), size);
				if(size < old_size)/*if the new size is less that the old ones we have to check if the process in the list can write*/
					wakeup_head_queue(write_wait_queue[minor]);
				printk("[multimode_ioctl] maximum buffer size set to: %d", size);
			spin_unlock(&(buffer_lock[minor]));		
        break;
		
		case MULTIMODE_GET_NODE_MAX_SIZE:
            printk("[multimode_ioctl] minor %d : get node max size\n", minor);
	    size = atomic_read(&(max_node_size[minor]));
	    res = copy_to_user((int *) arg, &size , sizeof(int));
	    if(res != 0)
			return -EINVAL;
            break;
        
		case MULTIMODE_SET_NODE_MAX_SIZE:
            printk("[multimode_ioctl] minor %d : set node max size\n", minor);
            res = copy_from_user(&size, (int *) arg, sizeof(int));
			if(res != 0)
                return -EINVAL;
			if( size < MIN_LIMIT_NODE || size > MAX_LIMIT_NODE )
				return -EINVAL;
			
			spin_lock(&(buffer_lock[minor]));
				if( size < atomic_read(&(min_node_size[minor])) ){
                    printk("[multimode_ioctl] size < atomic_read(&(min_node_size[minor]))\n");
					spin_unlock(&(buffer_lock[minor]));
					return -EINVAL;
				}
				old_size = atomic_read(&(max_node_size[minor]));
				atomic_set(&(max_node_size[minor]), size);
                printk("[multimode_ioctl] old_size:%d, size:%d\n",old_size,size);
				if( size < old_size )					
					wakeup_head_queue(write_wait_queue[minor]);
				    				
				printk("[multimode_ioctl] maximum node size set to: %d\n", size);
			spin_unlock(&(buffer_lock[minor]));
				break;
				
        case MULTIMODE_GET_NODE_MIN_SIZE:
            printk("[multimode_ioctl] minor %d : get node min size\n", minor);
			size = atomic_read(&(min_node_size[minor]));
			res = copy_to_user((int *) arg, &size , sizeof(int));
			if(res != 0)
				return -EINVAL; 
            break;
        case MULTIMODE_SET_NODE_MIN_SIZE:
			printk("[multimode_ioctl] minor %d : set node min size\n", minor);
				res = copy_from_user(&size, (int *) arg, sizeof(int));
			if ( res != 0)
				return -EINVAL;
			if( size < MIN_LIMIT_NODE || size > MAX_LIMIT_NODE )
				return -EINVAL;
			spin_lock(&(buffer_lock[minor]));
				if( size > atomic_read(&max_node_size[minor]) ){
					spin_unlock(&(buffer_lock[minor]));
					return -EINVAL;
				}
				old_size = atomic_read(&(min_node_size[minor]));
				atomic_set(&(min_node_size[minor]), size);
                printk("[multimode_ioctl] old_size:%d, size:%d\n",old_size,size);
                /*if i raise the minumum_node_size i have to check if someone have the wrong request*/
				if( size > old_size )
					wakeup_head_queue(write_wait_queue[minor]);
				printk("[multimode_ioctl] minimum node size set to: %d\n", size);
			spin_unlock(&(buffer_lock[minor]));
				break;
        default:
            return -EINVAL;
    }
	return 0;
}

/*write function*/
static ssize_t multimode_write(struct file *filp, const char *buff, size_t count, loff_t *f_pos) {
	int minor = iminor(filp->f_path.dentry->d_inode);
	node* n;
	int res,size_buffer,bytes_occupied,free_space, min_size_p, max_size_p, wake_up_next =0;
	char *buffer_temp = NULL;
	
	printk("[multimode_write] %d  write operation on device with minor %d is called\n",GET_PID,minor);
	if(count <= 0) {
		printk("[multimode_write] %d   error : invalid count number of bytes.\n",GET_PID);
		return -EINVAL;
	}
	
	/*allocate here, out of spinlock, the tempory buffer and the copy_from_user for effencity purpose*/
	if(count > MAX_LIMIT_NODE){
		/*grater than MAX_LIMIT_node is not possible to satisfy the request*/
		printk("[multimode_write] %d   error : count>MAX_LIMIT_node, the driver not support writing over than %d bytes\n",GET_PID,MAX_LIMIT_NODE);
		return -EINVAL; 
	}else
		buffer_temp = kmalloc(count,GFP_KERNEL);
	res = copy_from_user(buffer_temp, buff, count);
	
	if(res != 0) {
		kfree(buffer_temp);
		return -EINVAL; 
	}
	/*get spinlock*/
	spin_lock(&(buffer_lock[minor])); 
		/* we have to check if the size of the new node is in the local boundary */
		min_size_p = atomic_read(&min_node_size[minor]);
		max_size_p = atomic_read(&max_node_size[minor]);		
		if(count < min_size_p || count >max_size_p ){
			printk("[multimode_write] %d   error : bytes lower/greater than the minimum/maxiumum node size, change the min_node_size/max_node_size and try again\n",GET_PID);
			spin_unlock(&(buffer_lock[minor]));
            kfree(buffer_temp);
			return -EINVAL;	
		}
		/*check if there is somedy in the write_wait_queue*/
		spin_lock(&(write_wait_queue[minor]->lock));
			if(write_wait_queue[minor]->head == NULL){ /*i'm the first*/
                printk("[multimode_write] %d    ther is nobody in the write_wait_queue[%d]\n",GET_PID,minor);
				spin_unlock(&(write_wait_queue[minor]->lock));
                /*we have to check if there is enough free space for count*/
                size_buffer = atomic_read(&buffer_size[minor]);
                bytes_occupied = atomic_read(&payload[minor]);
                free_space = size_buffer - bytes_occupied;
                
                 /*above we have cheacked if count>min_node_size, here we check if there is enough space*/
                if ( free_space < count) {
                    printk("[multimode_write]  %d  the buffer is not enough free. A minimum size node does not fit in the buffer\n",GET_PID);
                    /*release spinlock*/
                    spin_unlock(&(buffer_lock[minor]));
                    if (filp->f_flags & O_NONBLOCK) {
                            printk("[multimode_write] %d   mode is not-blocking therefore return\n",GET_PID);
                            return -EAGAIN; /* EGAIN:resource is temporarily unavailable */
                    }
                    printk(" [multimode_write] %d  mode is blocking therefore sleep on the write queue\n",GET_PID);
                    if( sleep_on_queue(minor,write_wait_queue[minor],0,count) < 0)
                        return -ERESTARTSYS;
                    wake_up_next=1;
                     /* if I reach this point means that 0 is returned by the wait_event_interruptible.
                     * Therefore the buffer has enough space for write data but first we have to get again the spinlock because 
					   somebody else can be into the write queue*/
                    spin_lock(&(buffer_lock[minor]));                               
                    /*we leave the write_wait_queue only after got the spinlock*/
                    free_head_process(write_wait_queue[minor]);
                    /*try to wakeup the next*/
                    /***** selective wake up*****/
                    wakeup_head_queue(write_wait_queue[minor]);                    
                }
            }else{/*put in the queue in anyway*/
                printk("[multimode_write] %d  ther is somebody in the write_wait_queue[%d]\n",GET_PID,minor);
				spin_unlock(&(buffer_lock[minor]));
				spin_unlock(&(write_wait_queue[minor]->lock));
                
                if (filp->f_flags & O_NONBLOCK) {
                    printk("[multimode_write] %d   mode is not-blocking therefore return\n",GET_PID);
                    return -EAGAIN; /* EGAIN:resource is temporarily unavailable */
                }
                printk(" [multimode_write] %d  mode is blocking therefore sleep on the write queue\n",GET_PID);
				
                if( sleep_on_queue(minor,write_wait_queue[minor],0,count) < 0)
                    return -ERESTARTSYS;				
				spin_lock(&(buffer_lock[minor]));
                     /*we leave the write_wait_queue only after got the spinlock*/
                    free_head_process(write_wait_queue[minor]);
                    wakeup_head_queue(write_wait_queue[minor]);
            }	
			
            /* from this point we have exclusive access to the buffer and it is not full
             * because if it is coming another write request if there are another processes in
             * the wait_queue it cannot write, it is put in the wait_queue */
            size_buffer = atomic_read(&buffer_size[minor]);
            bytes_occupied = atomic_read(&payload[minor]);
            free_space = size_buffer - bytes_occupied;
            if(free_space < count){ /* ALLorNOTHING WRITE */
                printk("[multimode_write]  %d  free_space < count after wake_up, ERRORE\n",GET_PID);
                return -EINVAL;	
            }
                
            /* allocating struct node */
            n = kmalloc(sizeof(node), GFP_KERNEL);
            n->node_buffer = kmalloc(count, GFP_KERNEL);
            n->node_size = count;
            n->pos = 0;
            n->next = NULL;
            
            /* add the node on the head of the linkedlist */
            if(LINKED_LIST_IS_EMPTY(minor)) {
                printk("[multimode_write] %d   the node is inserted at the head of the linked list\n",GET_PID);
                head[minor] = n;
                tail[minor] = n;
            }else {/*add the node on queue of the linkedlist*/
                printk("[multimode_write]  %d  the node is inserted at the tail of the linked list\n",GET_PID);
                tail[minor]->next = n;
                tail[minor] = tail[minor]->next;
            }		
            memcpy(n->node_buffer, buffer_temp, count);
            printk("[multimode_write] %d  written %d bytes\n",GET_PID,(int)count);
            atomic_add(count,&(payload[minor]));
            printk("[multimode_write]  %d buffer_size = %d payload = %d\n",GET_PID,size_buffer,(int)(bytes_occupied+count));
            printk("[multimode_write] %d   try to wakeup read_wait_queue\n",GET_PID);
            wakeup_head_queue(read_wait_queue[minor]);
        spin_unlock(&(buffer_lock[minor]));
        kfree(buffer_temp);
	return count;
}

/*read packet*/
static ssize_t multimode_read_packet(struct file *filp, char *out_buffer, size_t count, loff_t *f_pos) {
    int available_bytes,res,to_read;
	node* n;
    char * buffer_temp;
	int minor=iminor(filp->f_path.dentry->d_inode);
	/* first node in the buffer */
    n = head[minor];	
	/* checking how many bytes there are available*/
	available_bytes = n->node_size - n->pos;
	
	/* checking for bytes to be read effectively */
    if(count < available_bytes) 
		to_read = count;
	else
		to_read = available_bytes;
	
	/* copy to user using a temporary buffer */
	buffer_temp = kmalloc(to_read,GFP_KERNEL);
	memcpy((void*)(&(buffer_temp[0])), (void*)(&(n->node_buffer[n->pos])), to_read);
	
	/* update linked list and counter bytes*/
	head[minor] = head[minor]->next;
	atomic_sub(n->node_size, &payload[minor]);
	
	/* free the memory node*/
	kfree(n->node_buffer);
	kfree(n);
	printk("[multimode_read_node] %d  payload updated to %d\n",GET_PID, atomic_read(&payload[minor]));
	wakeup_head_queue(write_wait_queue[minor]);
	spin_unlock(&(buffer_lock[minor]));

	res = copy_to_user(out_buffer, (char*)buffer_temp, to_read);
	kfree(buffer_temp);
	if(res != 0)
		return -EINVAL;
	return to_read;
}

/*read stream*/
static ssize_t multimode_read_stream(struct file *filp, char *out_buffer, size_t count, loff_t *f_pos) {
	int minor=iminor(filp->f_path.dentry->d_inode);
    int res,total_byte_buffer, bytes_read = 0,temp_pos = 0,to_read,left,freed = 0;
	char* buffer_temp;
	node* n;
	node* temp;
	/* first node in the stream */
	n = head[minor];
	/* alloc temporary buff to keep output */
	total_byte_buffer = atomic_read(&(payload[minor]));
	
	/* READ BEST EFFORT = if we have not enough info we take what we have also if the request asks more */
	if(count > total_byte_buffer - n->pos)
		buffer_temp = kmalloc( total_byte_buffer - n->pos, GFP_KERNEL);
	else 
		buffer_temp = kmalloc(count, GFP_KERNEL);
	
	while(n != NULL && bytes_read != count) {
		/* left to read */
		left = count - bytes_read;
		/* how much to read in this iteration */
		if(left <= n->node_size - n->pos) {
			/* it is the last node to be read */
			to_read = left;	
		}else {
			/*it is not the last node to be read */
			to_read = n->node_size - n->pos; 
		}		
		memcpy((void*)(&(buffer_temp[temp_pos])), (void*)(&(n->node_buffer[n->pos])), to_read);
		/* update temp_pos in order to append the bytes read into the buffer_temp */
		temp_pos+=to_read;
		/* update bytes_read*/
		bytes_read += to_read;
		if(n->pos + to_read < n->node_size) {
			/* If we enter in the IF ==> bytes_read = count */
			n->pos += to_read;
			//freed += to_read;
		}else {  
			/*we read all the node. Therefore move on to the next node */
			temp = n;
			n = n->next;
			freed += temp->node_size;
			kfree(temp->node_buffer);
			kfree(temp);
		}		
	}
	/* updates the head of the linked list */
	head[minor]=n;
	/* updates counter bytes : read_pos bytes not counted*/
	atomic_sub(freed,&payload[minor]);
    printk("[multimode_read_stream] %d   payload updated to %d\n",GET_PID,atomic_read(&payload[minor]));
	printk("[multimode_read_stream]  %d  try to wakeup write_wait_queue\n",GET_PID);
	wakeup_head_queue(write_wait_queue[minor]);
	spin_unlock(&(buffer_lock[minor]));
	res = copy_to_user(out_buffer, (char *)(buffer_temp), bytes_read);
	
	kfree(buffer_temp);
	if(res != 0)
		return -EINVAL;
	return bytes_read;
}

/*read dispatcher*/
static ssize_t multimode_read(struct file *filp, char *buffer, size_t count, loff_t *f_pos) {
	int minor=iminor(filp->f_path.dentry->d_inode);
	int wake_up_next=0,res;
	if(count <= 0)
		return -EINVAL;
	
    /*acquire spinlock*/
    spin_lock(&(buffer_lock[minor]));
    spin_lock(&(read_wait_queue[minor]->lock));
        if(read_wait_queue[minor]->head == NULL){ /*i'm the first*/
            printk("[multimode_read]  %d   ther is nobody in the read_wait_queue[%d]\n",GET_PID,minor);
			
            if (LINKED_LIST_IS_EMPTY(minor)) {
				printk("[multimode_read] %d    the buffer is empty\n",GET_PID);
				/* release spinlock*/ 
				spin_unlock(&(buffer_lock[minor]));
                spin_unlock(&(read_wait_queue[minor]->lock));
				if (filp->f_flags & O_NONBLOCK) {
					printk("[multimode_read] %d   mode is not-blocking therefore return\n",GET_PID);
						return -EAGAIN;  /* EGAIN:resource is temporarily unavailable */
				}
				printk("[multimode_read]  %d   mode is blocking therefore sleep on the read queue\n",GET_PID);
				if( sleep_on_queue(minor,read_wait_queue[minor],1,0) < 0 ){
					return -ERESTARTSYS;
				}
				printk("[multimode_read] %d    wake up from read queue\n",GET_PID);
				/* if I reach this point means that 0 is returned by the wait_event_interruptible
				 * therefore the buffer is not empty but first we have to get again the spinlock because
				   somebody else can be into the read queue */
				wake_up_next = 1;
				spin_lock(&(buffer_lock[minor]));
                free_head_process(read_wait_queue[minor]);
                /*try to wakeup the next*/
                /***** selective wake up*****/
                printk("[multimode_read] %d cerco di svegliare il successivo in read_wait_queue\n",GET_PID);
				wakeup_head_queue(read_wait_queue[minor]);                			
			}
            if(!wake_up_next){
                /*i have to release because if in the buffer there is somenthing,
                 * in the while i don't enter and we don't release ever*/
                spin_unlock(&(read_wait_queue[minor]->lock));
            }		
		}else{
			printk("[multimode_read] %d   ther is somebody in the read_wait_queue[%d]\n",GET_PID,minor);
			spin_unlock(&(buffer_lock[minor]));
			spin_unlock(&(read_wait_queue[minor]->lock));
            
			if (filp->f_flags & O_NONBLOCK) {
                printk("[multimode_read] %d    mode is not-blocking therefore return\n",GET_PID);
				return -EAGAIN;  /* EGAIN:resource is temporarily unavailable */
            }
            
            printk("[multimode_read] %d   mode is blocking therefore sleep on the read queue\n",GET_PID);
			if( sleep_on_queue(minor,read_wait_queue[minor],1,0) < 0 ){
                return -ERESTARTSYS;
            }
            spin_lock(&(buffer_lock[minor]));
			free_head_process(read_wait_queue[minor]);
            printk("[multimode_read] %d cerco di svegliare il successivo in read_wait_queue\n",GET_PID);
			wakeup_head_queue(read_wait_queue[minor]);
        }
		
    /* if we get here, then data is in the buffer and we have exclusive access to it: we are ready to go. */
    
	if ((unsigned long)filp->private_data & O_NODE){
            //in multimode_read_node we unlock(&(buffer_lock[minor])
        	res = multimode_read_packet(filp, buffer, count, f_pos);
    }else{
        ////in multimode_read_stream we unlock(&(buffer_lock[minor])
        res = multimode_read_stream(filp, buffer, count, f_pos);
    }  
    return res;
}

/* file operations */
static struct file_operations fops = {
	.read = multimode_read,
	.write = multimode_write,
	.open = multimode_open,
	.release = multimode_release,
	.unlocked_ioctl = multimode_ioctl
};

int init_module(void){
    int i;
    printk("\n \n\n");
    printk("\n ------------- new module --------------\n");	
	/* with major==0 the function dinamically allocates a major and return corresponding number */
	major = register_chrdev(0, DEVICE_FILE_NAME, &fops); 
	if (major < 0) {
		printk("[init_module] registering multimode device failed\n");
		return major;
	}
	for(i = 0; i < DEVICE_NUMBERS; i++)
		atomic_set (&is_open[i], 0);
	printk("[init_module] multimode device registered, it is assigned major number %d\n", major);
	return 0;
}

void cleanup_module(void) {
	int i;
	unregister_chrdev(major, DEVICE_FILE_NAME);
	printk(KERN_INFO "[cleanup_module] multimode device unregistered, it was assigned major number %d\n", major);
	/*free the streams*/
	for(i = 0; i < DEVICE_NUMBERS; i++) {
		node* n = head[i];
		while(n != NULL) {
			node* temp = n;
			kfree(n->node_buffer);
			n = n->next;
			kfree(temp);
		}
		kfree(write_wait_queue[i]);
		kfree(read_wait_queue[i]);
	}
  	printk("[cleanup_module] removing memory module\n");
}
