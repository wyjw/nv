// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Yu Jian
 */

#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/moduleparam.h>
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/treenvme.h>
#include <linux/nvme_ioctl.h>
#include <trace/events/block.h>
#include "nvme.h"
#include "tokuspec.h"

#define DEBUG 1
//#define DEBUGMAX 0

static bool depthpath = true;
module_param(depthpath, bool, 0444);
MODULE_PARM_DESC(depthpath,
	"turn on native support for per subsystem");

static int depthcount = 4;
module_param(depthcount, int, 0644);
MODULE_PARM_DESC(depthcount, "number of rebound in the backpath");

struct nvme_dev;
struct nvme_completion;
struct block_table;
struct pivot_bounds;
struct DBT;

struct treenvme_ctx {
	struct nvme_dev *dev;
	struct block_table *bt;
};

struct block_table {
	int64_t check;
};

static struct treenvme_ctx *tctx;
static const struct file_operations treenvme_ctrl_fops;
static struct kmem_cache *node_cachep; 
static int page_match(char *page, int page_size);

void treenvme_set_name(char *disk_name, struct nvme_ns *ns, struct nvme_ctrl *ctrl, int *flags)
{
	sprintf(disk_name, "treenvme%d", ctrl->subsys->instance);
}

blk_qc_t treenvme_make_request(struct request_queue *q, struct bio *bio)
{
	struct nvme_ns *ns = q->queuedata;
	struct device *dev = disk_to_dev(ns->tdisk);

	blk_qc_t ret = BLK_QC_T_NONE;
	int srcu_idx;

	blk_queue_split(q, &bio);
	bio->bi_disk = ns->disk;
	bio->bi_opf |= REQ_TREENVME;
	ret = direct_make_request(bio);

	return ret;
}

// taken from io_uring
static void *treenvme_validate_mmap_request(struct file *file, loff_t pgoff, size_t sz)
{
	struct treenvme_ctx *_tctx = file->private_data;
	loff_t offset = pgoff << PAGE_SHIFT;
	struct page *page;
	void *ptr;

	switch(offset) {
	/*
	case TREENVME:
		ptr = _tctx->bt;
		break;
	*/
	default:
		return ERR_PTR(-EINVAL);
	}	

	page = virt_to_head_page(ptr);
	if (sz > page_size(page))
		return ERR_PTR(-EINVAL);

	return ptr;
}

static int treenvme_mmap(struct file *file, struct vm_area_struct *vma)
{
	size_t sz = vma->vm_end - vma->vm_start;
	unsigned long pfn;
	void *ptr;

	ptr = treenvme_validate_mmap_request(file, vma->vm_pgoff, sz);
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);

	pfn = virt_to_phys(ptr) >> PAGE_SHIFT;

}
/*
int treenvme_alloc_disk(struct nvme_ctrl *ctrl, struct treenvme_head *thead)
{
	printk(KERN_ERR "Alloc'ing disk\n");
	struct request_queue *q;
	bool wbc = false;

	mutex_init(&thead->lock);
	//INIT_WORK(&thead->requeue_work, nvme_requeue_work);

	q = blk_alloc_queue(treenvme_make_request, ctrl->numa_node);
	if (!q)
		goto out;
	q->queuedata = thead;
	blk_queue_flag_set(QUEUE_FLAG_NONROT, q);
	blk_queue_logical_block_size(q, 4096);

	blk_queue_write_cache(q, wbc, wbc);

	thead->disk = alloc_disk(0);
	thead->disk->fops = &treenvme_fops;
	thead->disk->private_data = thead;
	thead->disk->queue = q;
	thead->disk->flags = GENHD_FL_EXT_DEVT;

	sprintf(thead->disk->disk_name, "treenvmen%d", thead->instance);
	return 0;

out:
	return -ENOMEM;
}
*/

/*
int treenvme_resubmit_path(struct nvme_queue *nvmeq, struct request *rq, u16 idx)
{
	volatile struct nvme_completion *cqe = &nvmeq->cqes[idx];
}
*/

inline void add_treedisk(struct nvme_ctrl *ctrl, struct nvme_ns *ns, unsigned nsid) {
	struct gendisk *treedisk;
	char disk_name[DISK_NAME_LEN];
	struct nvme_id_ns *id;
	int node = ctrl->numa_node, flags = GENHD_FL_EXT_DEVT;
	int ret;

	ret = nvme_identify_ns(ctrl, nsid, &id);

	printk(KERN_ERR "Got into treenvme creation. \n");
	ns->tqueue = blk_alloc_queue(treenvme_make_request, ctrl->numa_node);
	ns->tqueue->queuedata = ns;
	blk_queue_logical_block_size(ns->tqueue, 1 << ns->lba_shift);
	nvme_set_queue_limits(ctrl, ns->tqueue);

	treenvme_set_name(disk_name, ns, ctrl, &flags);
	treedisk = alloc_disk_node(0, node);
	
	treedisk->fops = &treenvme_fops;
	treedisk->private_data = ns;
	treedisk->queue = ns->tqueue;
	treedisk->flags = flags;
	memcpy(treedisk->disk_name, disk_name, DISK_NAME_LEN);
	ns->tdisk = treedisk;

	__nvme_revalidate_disk(treedisk, id);
	nvme_get_ctrl(ctrl);
	printk(KERN_ERR "Disk name added is: %s\n", disk_name);
	device_add_disk(ctrl->device, ns->tdisk, nvme_ns_id_attr_groups);	

}	

static int treenvme_get_fd(struct treenvme_ctx *tctx)
{
	struct file *file;
	int ret;

	ret = get_unused_fd_flags( O_RDWR | O_CLOEXEC );
	if (ret < 0)
		goto err; 
	file = anon_inode_getfile("[treenvme]", &treenvme_ctrl_fops, tctx, O_RDWR | O_CLOEXEC);
	if (IS_ERR(file)){
		put_unused_fd(ret);
		ret = PTR_ERR(file);
		goto err;
	}
err:
	return -1;
}

// All the treenvme operations

static void *treenvme_add_user_metadata(struct bio *bio, void __user *ubuf,
		unsigned len, u32 seed, bool write)
{
	struct bio_integrity_payload *bip;
	int ret = -ENOMEM;
	void *buf;

	buf = kmalloc(len, GFP_KERNEL);
	if (!buf)
		goto out;

	ret = -EFAULT;
	if (write && copy_from_user(buf, ubuf, len))
		goto out_free_meta;

	bip = bio_integrity_alloc(bio, GFP_KERNEL, 1);
	if (IS_ERR(bip)) {
		ret = PTR_ERR(bip);
		goto out_free_meta;
	}

	bip->bip_iter.bi_size = len;
	bip->bip_iter.bi_sector = seed;
	ret = bio_integrity_add_page(bio, virt_to_page(buf), len,
			offset_in_page(buf));
	if (ret == len)
		return buf;
	ret = -ENOMEM;
out_free_meta:
	kfree(buf);
out:
	return ERR_PTR(ret);
}

static int treenvme_submit_user_cmd(struct request_queue *q,
		struct nvme_command *cmd, void __user *ubuffer,
		unsigned bufflen, void __user *meta_buffer, unsigned meta_len,
		u32 meta_seed, u64 *result, unsigned timeout)
{
	bool write = nvme_is_write(cmd);
	struct nvme_ns *ns = q->queuedata;
	struct gendisk *disk = ns ? ns->disk : NULL;
	struct request *req;
	struct bio *bio = NULL;
	void *meta = NULL;
	int ret;

	req = nvme_alloc_request(q, cmd, 0, NVME_QID_ANY);
	if (IS_ERR(req))
		return PTR_ERR(req);

	req->timeout = timeout ? timeout : ADMIN_TIMEOUT;
	nvme_req(req)->flags |= NVME_REQ_USERCMD;

	if (ubuffer && bufflen) {
		ret = blk_rq_map_user(q, req, NULL, ubuffer, bufflen,
				GFP_KERNEL);
		if (ret)
			goto out;
		bio = req->bio;
		bio->bi_disk = disk;
		if (disk && meta_buffer && meta_len) {
			meta = treenvme_add_user_metadata(bio, meta_buffer, meta_len,
					meta_seed, write);
			if (IS_ERR(meta)) {
				ret = PTR_ERR(meta);
				goto out_unmap;
			}
			req->cmd_flags |= REQ_INTEGRITY;
		}
	}

	blk_execute_rq(req->q, disk, req, 0);
	if (nvme_req(req)->flags & NVME_REQ_CANCELLED)
		ret = -EINTR;
	else
		ret = nvme_req(req)->status;
	if (result)
		*result = le64_to_cpu(nvme_req(req)->result.u64);
	if (meta && !ret && !write) {
		if (copy_to_user(meta_buffer, meta, meta_len))
			ret = -EFAULT;
	}
	kfree(meta);
 out_unmap:
	if (bio)
		blk_rq_unmap_user(bio);
 out:
	blk_mq_free_request(req);
	return ret;
}

static void __user *nvme_to_user_ptr(uintptr_t ptrval)
{
	if (in_compat_syscall())
		ptrval = (compat_uptr_t)ptrval;
	return (void __user *)ptrval;
}

static int treenvme_submit_io(struct nvme_ns *ns, struct nvme_user_io __user *uio)
{
	struct nvme_user_io io;
	struct nvme_command c;
	unsigned length, meta_len;
	void __user *metadata;

	if (copy_from_user(&io, uio, sizeof(io)))
		return -EFAULT;
	if (io.flags)
		return -EINVAL;

	switch (io.opcode) {
	case nvme_cmd_write:
	case nvme_cmd_read:
	case nvme_cmd_compare:
		break;
	default:
		return -EINVAL;
	}

	length = (io.nblocks + 1) << ns->lba_shift;
	meta_len = (io.nblocks + 1) * ns->ms;
	metadata = nvme_to_user_ptr(io.metadata);

	if (ns->ext) {
		length += meta_len;
		meta_len = 0;
	} else if (meta_len) {
		if ((io.metadata & 3) || !io.metadata)
			return -EINVAL;
	}

	memset(&c, 0, sizeof(c));
	c.rw.opcode = io.opcode;
	c.rw.flags = io.flags;
	c.rw.nsid = cpu_to_le32(ns->head->ns_id);
	c.rw.slba = cpu_to_le64(io.slba);
	c.rw.length = cpu_to_le16(io.nblocks);
	c.rw.control = cpu_to_le16(io.control);
	c.rw.dsmgmt = cpu_to_le32(io.dsmgmt);
	c.rw.reftag = cpu_to_le32(io.reftag);
	c.rw.apptag = cpu_to_le16(io.apptag);
	c.rw.appmask = cpu_to_le16(io.appmask);

	return treenvme_submit_user_cmd(ns->queue, &c,
			nvme_to_user_ptr(io.addr), length,
			metadata, meta_len, lower_32_bits(io.slba), NULL, 0);
}

static void nvme_put_ns_from_disk(struct nvme_ns_head *head, int idx)
{
	if (head)
		srcu_read_unlock(&head->srcu, idx);
}

int treenvme_ioctl(struct block_device *bdev, fmode_t mode,
		unsigned int cmd, unsigned long arg)
{
	struct nvme_ns_head *head = NULL;
	void __user *argp = (void __user *)arg;
	struct nvme_ns *ns;
	int srcu_idx, ret;

	ns = bdev->bd_disk->private_data;
	if (unlikely(!ns))
		return -EWOULDBLOCK;

	/*
	 * Handle ioctls that apply to the controller instead of the namespace
	 * seperately and drop the ns SRCU reference early.  This avoids a
	 * deadlock when deleting namespaces using the passthrough interface.
	 */
	
	/*
	 * if (is_ctrl_ioctl(cmd))
		return nvme_handle_ctrl_ioctl(ns, cmd, argp, head, srcu_idx);
	*/
	switch (cmd) {
	/*
	case NVME_IOCTL_ID:
		force_successful_syscall_return();
		ret = ns->head->ns_id;
		break;
	case NVME_IOCTL_IO_CMD:
		ret = nvme_user_cmd(ns->ctrl, ns, argp);
		break;
	*/
	case NVME_IOCTL_SUBMIT_IO:
		ret = treenvme_submit_io(ns, argp);
		break;
	/*
	case NVME_IOCTL_IO64_CMD:
		ret = nvme_user_cmd64(ns->ctrl, ns, argp);
		break;
	*/
	default:
		if (ns->ndev)
			ret = nvme_nvm_ioctl(ns, cmd, arg);
		else
			ret = -ENOTTY;
	}

	nvme_put_ns_from_disk(head, srcu_idx);
	return ret;
}

// end

static inline struct blk_mq_tags *nvme_queue_tagset(struct nvme_queue *nvmeq)
{
	if (!nvmeq->qid)
		return nvmeq->dev->admin_tagset.tags[0];
	return nvmeq->dev->tagset.tags[nvmeq->qid - 1];
}

inline void nvme_backpath(struct nvme_queue *nvmeq, u16 idx, struct request *req, struct nvme_completion *cqe)
{
	struct nvme_iod *iod = blk_mq_rq_to_pdu(req);
	//struct nvme_queue *nvmeq = iod->nvmeq;
	struct nvme_ns *ns = req->q->queuedata;
	struct nvme_dev *dev = iod->nvmeq->dev;
	struct nvme_command cmnd;
	blk_status_t ret;

	//printk(KERN_ERR "GOT HERE -- rebound \n");
	if (req->alter_count < depthcount && !op_is_write(req_op(req)))
	{
		req->alter_count += 1;
		// alter
		ret = nvme_setup_cmd(ns, req, &cmnd);
		if (ret)
			printk(KERN_ERR "submit error\n");
		//printk(KERN_ERR "Got here 2\n");x
		if (blk_rq_nr_phys_segments(req)) {
			ret = nvme_map_data(dev, req, &cmnd);
			if (ret)
				printk(KERN_ERR "mapping error\n");
		}
		if (blk_integrity_rq(req)) {
			ret = nvme_map_metadata(dev, req, &cmnd);
			if (ret)
				printk(KERN_ERR "meta error\n");
		}
		cmnd.rw.slba = cpu_to_le64(nvme_sect_to_lba(ns, blk_rq_pos(req)));
		//printk(KERN_ERR "SECTOR NUMBER IS %u\n", cmnd.rw.slba);

		int ret;
		struct bio_vec bvec;
		struct req_iterator iter;

		rq_for_each_segment(bvec, req, iter)
		{
			char *buffer = bio_data(req->bio);
			printk(KERN_ERR "char bio: %s \n", buffer);
			printk(KERN_ERR "char is: %c\n", buffer[2]);
		
			printk(KERN_ERR "size is: %u\n", req->bio->bi_iter.bi_size);
			// retry
			int next_page;
			next_page = page_match(buffer, 4096);
			if (next_page == 0)
				goto ERROR;
			printk(KERN_ERR "SECTOR NUMBER IS %u\n", cmnd.rw.slba);
			cmnd.rw.slba = cpu_to_le64(next_page);
			req->__sector = cmnd.rw.slba;
			/*
			if (buffer[a] == "a"){
				cmnd.rw.slba += cpu_to_le64(cmnd.rw.slba * 2);
				printk(KERN_ERR "SECTOR NUMBER IS %u\n", cmnd.rw.slba);
				printk(KERN_ERR "matched.\n");
				req->__sector = cmnd.rw.slba;
			}
			*/
		}
		nvme_req(req)->cmd = &cmnd;
		nvme_submit_cmd(nvmeq, &cmnd, true);
	}
	else
	{
ERROR:
		//printk(KERN_ERR "Final\n");
		req = blk_mq_tag_to_rq(nvme_queue_tagset(nvmeq), req->first_command_id);
		nvme_end_request(req, cqe->status, cqe->result);
	}

}

void init_pivot(struct pivot_bounds *pb, int num) {
	pb->num_pivots = num;
	pb->total_size = 0;
	pb->fixed_keys = NULL;
	pb->fixed_keylen_aligned = 0;
	pb->dbt_keys = NULL;
}

typedef int (*comparator)(char *a, char *b, int asize, int bsize);

enum search_direction {
	LEFT_TO_RIGHT,
	RIGHT_TO_LEFT
};

struct search_ctx {
	comparator compare;
	enum search_direction direction;
       	const struct DBT *k;
	void *user_data;
	struct DBT *pivot_bound;	
	const struct DBT *k_bound;
};

static void init_DBT(struct DBT *new)
{
	memset(new, 0, sizeof(*new));
	return new;
}

static int compare (struct search_ctx *srch, struct DBT *keya, struct DBT *keyb)
{
	char *keyadata = keya->data;
	char *keybdata = keyb->data;
	if (srch->compare(keyadata, keybdata, keya->size, keyb->size))
	{
		return 0;
	}
	else {
		return 1;
	}
}
int fill_pivot(struct pivot_bounds *pb, char *page, int n)
{
	int k = 0;
	int i = 0;

	pb->num_pivots = n;
	pb->total_size = 0;
	pb->fixed_keys = NULL;
	pb->fixed_keylen = 0;
	pb->dbt_keys = NULL;

	pb->dbt_keys = kmalloc(sizeof(struct DBT) * pb->num_pivots, GFP_KERNEL);
	for (i = 0; i < n; i++) {
		uint32_t size;
		memcmp(&size, page[k], 4);
		k += 4;
		memcmp(&pb->dbt_keys[i].data, page[k], size);
#ifdef DEBUG
	printk("Data is %s\n", &pb->dbt_keys[i].data);
#endif
		pb->total_size += size;
	       	k += size;	
	}
	return k;
}

struct block_data {
	uint32_t start;
	uint32_t end;
	uint32_t size;
};

struct subblock_data {
	void *ptr;
	uint32_t csize; // compressed size
	uint32_t usize; // uncompressed size
};

// Reference: toku_deserialize_bp_from_disk
static int deserialize(char *page, struct tokunode *node) 
{
	struct block_data *bd;
	// node->blocknum = blocknum;
	node->blocknum = 0;
	node->bp = NULL;
	node->ct_pair = NULL;
	int z = 0;

#ifdef DEBUGMAX	
	for (z = 0; z < 512; z++){
		if (page[z] != 0)
		{
			printk(KERN_ERR "we have %u @ %u", page[z], z);
		}	
	}
#endif

	int i = 0;
	int j; 
	int k;
	int l;
	int m = 0;

	char buffer[8];
	memcpy(buffer, &page[i], 8);
       	i += 8;
	if (memcmp(buffer, "tokuleaf", 8) != 0 
	   && memcmp(buffer, "tokunode", 8) != 0)
	{
		printk(KERN_WARNING "No leaf word in buffer.\n");
		goto ERROR;
	}
#ifdef DEBUG
	printk(KERN_ERR "BUFFER: %.*s\n", 8, buffer);
#endif

	uint32_t version;
	memcpy(&version, &page[i], 4);
	i += 4;

#ifdef DEBUG
	printk(KERN_ERR "VERSION_NUM: %u\n", version);
#endif

	i += 8; // skip layout version and build id
	
	uint32_t num_child;
	memcpy(&num_child, &page[i], 4);
	i += 4;
	node->n_children = num_child;

#ifdef DEBUG
	printk(KERN_ERR "NUM_CHILD: %u\n", num_child);
#endif

	// node->bp = kmalloc(sizeof(struct ftnode_partition) * num_child, GFP_KERNEL);
	bd = kmalloc(sizeof(struct block_data) * num_child, GFP_KERNEL);

	for (j = 0; j < node->n_children; j++) {
		//printk("PAGE HERE IS: %u\n", page[i]);
		memcpy(&bd[j].start, &page[i], 4);
		i += 4;
		memcpy(&bd[j].size, &page[i], 4);
		i += 4;
		bd[j].end = bd[j].start + bd[j].size;
#ifdef DEBUG
	printk("CHILD_NUM: %u\n", j);
	printk("BLOCK_START: %u\n", bd[j].start);
	printk("BLOCK_END: %u\n", bd[j].end);	
	printk("BLOCK_SIZE: %u\n", bd[j].size); 
#endif
	}

	i += 4; // skip checksumming

	struct subblock_data sb_data;
	sb_data.csize = 0;
	sb_data.usize = 0;
	
	// compressed size
	memcpy(&sb_data.csize, &page[i], 4);
	i += 4;

	// uncompressed size
	memcpy(&sb_data.usize, &page[i], 4);
	i += 4;	
	/*
	for (j = 0; i < 400; j++) {
		memcpy(&sb_data.usize, &page[i], 4);
		i += 4;
	}
	*/

#ifdef DEBUG
	printk("COMPRESSED_SIZE: %u\n", sb_data.csize);
	printk("UNCOMPRESSED_SIZE: %u\n", sb_data.usize);
	printk("COUNTER IS AT: %u\n", i);
#endif
	
	// skip compressing

	char *cp = kmalloc(sizeof(int) * sb_data.usize, GFP_KERNEL);
	memcpy(cp, &page[i], sb_data.usize);
	//memcpy(&cp, &page[i], 4);

	// get from subblock_data
	uint32_t data_size = 0;
	if (sb_data.usize != 0) 
		data_size = sb_data.usize - 4;

#ifdef DEBUG 
	printk("DATA_SIZE: %u\n", data_size);
#endif

#ifdef DEBUG	
	for (z = 0; z < data_size; z++){
		if (cp[z] != 0)
		{
			printk(KERN_ERR "we have %u @ %u in subblock", cp[z], z);
		}	
	}
#endif
	if (data_size != 0) 
	{
		char bufferd[data_size];
		memcpy(&bufferd, &cp[m], data_size);
		m += data_size;

		k = 0;
		memcpy(&node->flags, &bufferd[k], 8);

		k += 8;
		memcpy(&node->height, &bufferd[k], 4);

#ifdef DEBUG
	printk("Node flags of %u\n", node->flags);
	printk("Node height of %u\n", node->height);
#endif

		k += 8;
		node->pivotkeys = kmalloc(sizeof(struct pivot_bounds), GFP_KERNEL); 
		if (node->n_children > 1){
			k += fill_pivot(node->pivotkeys, &bufferd[k], node->n_children); 
		}	
		else {
			init_pivot(node->pivotkeys, 0);
		}

		// Block nums
		if (node->height > 0) {
			for (l = 0; l < node->n_children; l++) {
				memcpy(node->pivotkeys->dbt_keys[l].blocknum, &bufferd[k], 4);
				k += 4;
#ifdef DEBUG
	printk("CHILD_BLOCKNUM: %d\n", node->pivotkeys->dbt_keys[l].blocknum);
#endif			
			}
		}

		return 1; 
	}
	else {
		k += 16;
		goto ERROR;
	}
ERROR:
	return 0;	
}

static int page_match(char *page, int page_size)
{
	struct tokunode *node = kmem_cache_alloc(node_cachep, GFP_KERNEL);

	if (deserialize(page, node) == 0)
		return 0;

	int low = 0;
	int high = node->n_children - 1;
	int middle;
	struct DBT pivot_key;
	init_DBT(&pivot_key);

	struct search_ctx *search = kmalloc(sizeof(struct search_ctx), GFP_KERNEL);
	while (low < high)
	{
		middle = (low + high) / 2;
		/*	
		bool c = compare(search, &node->pivotkeys->dbt_keys[low], &node->pivotkeys->dbt_keys[high]);
		if (((search->direction == LEFT_TO_RIGHT) && c) || (search->direction == RIGHT_TO_LEFT && !c))
		{	
			high = middle;
		}
		else {
			low = middle + 1;
		}
		*/
		break;		
	}
#ifdef DEBUG
	if (!node)
		printk(KERN_ERR "Node is NULL\n");
#endif

	return (node)->pivotkeys->dbt_keys[low].blocknum;	
}

static int __init treenvme_init(void)
{
	tctx = kmalloc(sizeof(struct treenvme_ctx), GFP_NOWAIT);
	tctx->bt = kmalloc(sizeof(struct block_table), GFP_NOWAIT);	
	
	// this is how we keep the nodes in memory
	node_cachep = KMEM_CACHE(tokunode, SLAB_HWCACHE_ALIGN | SLAB_PANIC);	
}

static void __exit treenvme_exit(void)
{
	kfree(tctx);
}

static const struct file_operations treenvme_ctrl_fops = {
	.owner		= THIS_MODULE,
	.mmap		= treenvme_mmap,
};

/*
const struct block_device_operations treenvme_fops = {
	.owner		= THIS_MODULE,
	.open		= nvme_open,
	.release	= nvme_release,
	.ioctl		= treenvme_ioctl,
	.compat_ioctl	= nvme_compat_ioctl,
	.getgeo		= nvme_getgeo,
	.pr_ops		= &nvme_pr_ops,
};
*/

MODULE_AUTHOR("Yu Jian <yujian.wu1@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
module_init(treenvme_init);
module_exit(treenvme_exit);
