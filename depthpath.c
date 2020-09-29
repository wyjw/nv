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
#include <trace/events/block.h>
#include "nvme.h"

static bool depthpath = true;
module_param(depthpath, bool, 0444);
MODULE_PARM_DESC(depthpath,
	"turn on native support for per subsystem");

struct nvme_dev;
struct nvme_queue;
struct block_table;

struct treenvme_ctx {
	struct nvme_dev *dev;
	struct block_table *bt;
};

struct block_table {
	int64_t check;
};

static struct treenvme_ctx *tctx;

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
	device_add_disk(ctrl->device, ns->tdisk, nvme_ns_id_attr_groups);	

}	

static int treenvme_get_fd(struct treenvme_ctx *tctx)
{
	struct file *file;
	int ret;

	ret = get_unused_fd_flags( O_RDWR | O_CLOEXEC );
	if (ret < 0)
		goto err;

	file = anon_inode_getfile("[treenvme]", &treenvme_ctrl_fops, tctx, O_RWDR | O_CLOEXEC);

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

	return nvme_submit_user_cmd(ns->queue, &c,
			nvme_to_user_ptr(io.addr), length,
			metadata, meta_len, lower_32_bits(io.slba), NULL, 0);
}

static int treenvme_ioctl(struct block_device *bdev, fmode_t mode,
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
	if (is_ctrl_ioctl(cmd))
		return nvme_handle_ctrl_ioctl(ns, cmd, argp, head, srcu_idx);

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

static int __init treenvme_init(void)
{
	tctx = kmalloc(sizeof(struct treenvme_ctx), GFP_NOWAIT);
	tctx->bt = kmalloc(sizeof(struct block_table), GFP_NOWAIT);	
}

static void __exit treenvme_exit(void)
{
	kfree(tctx);
}

static const struct file_operations treenvme_ctrl_fops {
	.mmap = treenvme_mmap,
};

MODULE_AUTHOR("Yu Jian <yujian.wu1@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
module_init(treenvme_init);
module_exit(treenvme_exit);
