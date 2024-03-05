#include <linux/init.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/sched.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/memory.h>
#include <linux/mm.h>

#include <paging.h>
#include <stdatomic.h>
#include <linux/types.h>

struct vm_pd { // vm private data
        atomic_t counter; // reference counter 
        struct list_node* head; // head of the list
        struct list_node* curr;
};

struct list_node {
        struct page* pa; // physical memory address
        struct list_node* next; // next node
};

static atomic_t pagesAllocated = ATOMIC_INIT(0);
static atomic_t pagesFreed = ATOMIC_INIT(0);

static unsigned int demand_paging = 1;
module_param(demand_paging, uint, 0644);

static int
do_fault(struct vm_area_struct * vma,
         unsigned long           fault_address)
{
	struct page* p;
	int res;
	struct vm_pd* ptr;
	struct list_node* n;

	p = alloc_page(GFP_KERNEL);
	if (p == NULL) {
		return VM_FAULT_OOM;
	}
	res = remap_pfn_range(vma, PAGE_ALIGN(fault_address), page_to_pfn(p), PAGE_SIZE, vma->vm_page_prot);
	if (res == 0) {
		// printk(KERN_INFO "paging_vma_fault() invoked: took a page fault at VA 0x%lx\n", fault_address);
		atomic_inc(&pagesAllocated);
		ptr = vma->vm_private_data;
		
		// insert the new node to the linked list
		n = kmalloc(sizeof(struct list_node), GFP_KERNEL);
		if (n) {
			n->pa = NULL;
			n->next = NULL;
		}
		if (ptr->head == NULL) {
			ptr->head = n;
			ptr->curr = ptr->head;
			ptr->curr->pa = p;
		} 
		else {
			ptr->curr->next = n;
			ptr->curr = ptr->curr->next;
			ptr->curr->pa = p;
		}
		

		return VM_FAULT_NOPAGE;
	}
	
	return VM_FAULT_SIGBUS;
}

static vm_fault_t
paging_vma_fault(struct vm_fault * vmf)
{
    struct vm_area_struct * vma = vmf->vma;
    unsigned long fault_address = (unsigned long)vmf->address;

    return do_fault(vma, fault_address);
}

static void
paging_vma_open(struct vm_area_struct * vma)
{
	struct vm_pd* ptr = vma->vm_private_data;
	atomic_inc(&ptr->counter);
    printk(KERN_INFO "paging_vma_open() invoked\n");
}

static void
paging_vma_close(struct vm_area_struct * vma)
{
	struct list_node* n;
	struct list_node* temp; // used to free the linked list
	struct vm_pd* ptr = vma->vm_private_data;
	atomic_dec(&ptr->counter);
	
	if (atomic_read(&ptr->counter) == 0) {
		n = ptr->head;
		// free all the pages we allocated
		while (n != NULL) {
			__free_page(n->pa);
			atomic_inc(&pagesFreed);
			n = n->next;
		}
		// printk(KERN_INFO "pages freed\n");
		// free the linked list 
		n = ptr->head;
		while (n != NULL) {
			temp = n;
			n = n->next;
			kfree(temp);
		}
		// printk(KERN_INFO "list freed\n");

		// free the struct we designed 
		kfree(ptr);
		// printk(KERN_INFO "struct freed\n");
	}
    printk(KERN_INFO "paging_vma_close() invoked\n");

}

static struct vm_operations_struct
paging_vma_ops = 
{
    .fault = paging_vma_fault,
    .open  = paging_vma_open,
    .close = paging_vma_close
};

// paging_mmap invokes pre_paging
static int
pre_paging(struct vm_area_struct* vma) {
	size_t len = vma->vm_end - vma->vm_start;
	int ret;
	unsigned int order = get_order(len);
	struct page* p = alloc_pages(GFP_KERNEL, order);
	if (!p) {
		return VM_FAULT_OOM;
	}
	ret = remap_pfn_range(vma, vma->vm_start, page_to_pfn(p), len, vma->vm_page_prot);
	if (!ret) {
		return VM_FAULT_NOPAGE;
	}
	return VM_FAULT_SIGBUS;
}


/* vma is the new virtual address segment for the process */
static int
paging_mmap(struct file           * filp,
            struct vm_area_struct * vma)
{
	
	if (demand_paging) {
	// allocate memory for our struct vm_pd and set counter to 1
	struct vm_pd* ptr = kmalloc(sizeof(struct vm_pd), GFP_KERNEL);
	vma->vm_private_data = ptr;
	atomic_set(&ptr->counter, 1);
	// initialize the pointers to NULL
	ptr->head = NULL;
	ptr->curr = NULL;

    /* prevent Linux from mucking with our VMA (expanding it, merging it 
     * with other VMAs, etc.)
     */
    vma->vm_flags |= VM_IO | VM_DONTCOPY | VM_DONTEXPAND | VM_NORESERVE
              | VM_DONTDUMP | VM_PFNMAP;

    /* setup the vma->vm_ops, so we can catch page faults */
    vma->vm_ops = &paging_vma_ops;

    printk(KERN_INFO "paging_mmap() invoked: new VMA for pid %d from VA 0x%lx to 0x%lx\n",
        current->pid, vma->vm_start, vma->vm_end);
	return 0;
	}
	else {
		int ret;
		ret = pre_paging(vma);	
		if (ret == VM_FAULT_NOPAGE) {
			return 0;
		}
		else if (ret == VM_FAULT_OOM) {
			return -ENOMEM;
		}
		else {
			return -EFAULT; 
		}
	}
}


static struct file_operations
dev_ops =
{
    .mmap = paging_mmap,
};

static struct miscdevice
dev_handle =
{
    .minor = MISC_DYNAMIC_MINOR,
    .name = PAGING_MODULE_NAME,
    .fops = &dev_ops,
};
/*** END device I/O **/

/*** Kernel module initialization and teardown ***/
static int
kmod_paging_init(void)
{
    int status;

    /* Create a character device to communicate with user-space via file I/O operations */
    status = misc_register(&dev_handle);
    if (status != 0) {
        printk(KERN_ERR "Failed to register misc. device for module\n");
        return status;
    }

    printk(KERN_INFO "Loaded kmod_paging module\n");

    return 0;
}

static void
kmod_paging_exit(void)
{
    /* Deregister our device file */
    misc_deregister(&dev_handle);

    printk(KERN_INFO "Unloaded kmod_paging module, pages allocated: %d, pages freed: %d\n", atomic_read(&pagesAllocated), atomic_read(&pagesFreed));
}

module_init(kmod_paging_init);
module_exit(kmod_paging_exit);

/* Misc module info */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jake Jing");
MODULE_DESCRIPTION("Memory management and paging.");
