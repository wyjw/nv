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
#include <linux/treenvme_ioctl.h>
#include <trace/events/block.h>
#include "nvme.h"
#include "tokuspec.h"
#include "simplekvspec.h"

/*@ddp*/
#include <linux/bpf.h>
#include <linux/bpf_ddp.h>
#include <linux/filter.h>

//#define DEBUG 1
//#define DEBUGMAX 1
//#define DEBUGEX1 1
//#define TIME 1
#define SIMPLEBPF 1
#define DEBUG2 1
#define DEBUGS 1
#define FILE_MASK ((ptr__t)1 << 63)

// Hardcoded magic variables
#define TREENVME_OFF_BLOCKTABLE 0ULL
#define TREENVME_OFF_SQES	0x8000000ULL
#define SIMPLEKV 1
#ifdef SIMPLEKV
//#define SHORTCUT
#endif
//#define TOKUDB 1

#ifdef TOKUDB
#undef SIMPLEKV
#endif
#define KEYINBUF 1 

static int counter = 0;

static bool depthpath = true;
module_param(depthpath, bool, 0444);
MODULE_PARM_DESC(depthpath,
	"turn on native support for per subsystem");

static int depthcount = 4;
module_param(depthcount, int, 0644);
MODULE_PARM_DESC(depthcount, "number of rebound in the backpath");

struct nvme_dev;
struct nvme_completion;
struct block_translation_pair;
struct block_table;
struct pivot_bounds;
struct DBT;

struct key_entry{
	unsigned long a;
	struct list_head entry;
};

static int page_match(struct request *rq, char *page, int page_size);
static int page_match_tokudb(struct request *rq, char *page, int page_size);
static int treenvme_setup_ctx(struct nvme_ns *ns, void *argp);
//void nvme_backpath(struct nvme_queue *nvmeq, u16 idx, struct request *req, volatile struct nvme_completion *cqe);
int treenvme_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd, unsigned long arg);

//MTC
//inline void add_treedisk(struct nvme_ctrl *ctrl, struct nvme_ns *ns, unsigned nsid);

// MACROS


static inline void *bio_data_none(struct bio *bio)
{
	return page_address(bio_page(bio)) + bio_offset(bio);
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
void nvme_backpath(struct nvme_queue *nvmeq, u16 idx, struct request *req, volatile struct nvme_completion *cqe)
{
	struct nvme_iod *iod = blk_mq_rq_to_pdu(req);
	//struct nvme_queue *nvmeq = iod->nvmeq;
	struct nvme_ns *ns = req->q->queuedata;
	struct nvme_dev *dev = iod->nvmeq->dev;
	struct nvme_command cmnd;
	blk_status_t ret;

#ifdef SIMPLEBPF
	struct bpf_prog *attached;
	u32 result = 1;
	attached = tctx ? rcu_dereference(tctx->ddp_prog) : NULL;
	rcu_read_lock();
	if (attached) {
		printk("BPF Prog is being used!\n");
		result = BPF_PROG_RUN(attached, bio_data(req->bio));
		printk("Result of %d\n", result);
	}
	rcu_read_unlock();
#endif

	counter++;


#ifdef SIMPLEKV
	//if (req_op(req) && REQ_TREENVME)
	//if (!op_is_write(req_op(req)))
	if (req->bio->_imposter_count < req->bio->_imposter_level && !op_is_write(req_op(req)))
	{
	char *buffer = bio_data(req->bio);
	int next_page;
	next_page = page_match(req, buffer, 4096);
	if (next_page == 0)
	{
#ifdef DEBUGS
		printk(KERN_ERR "Got to leaf in %u with count %u\n", req->__sector, req->bio->_imposter_count);
#endif
		req = blk_mq_tag_to_rq(nvme_queue_tagset(nvmeq), req->first_command_id);
		nvme_end_request(req, cqe->status, cqe->result);
		return;
	}
	next_page = next_page & (~FILE_MASK);
	req->bio->_imposter_count += 1;
#ifdef DEBUGS
	printk(KERN_ERR "Alter count is %lu\n", req->bio->_imposter_count);
#endif
	
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
	
	nvme_req(req)->cmd = &cmnd;
	//cmnd.rw.slba = next_page / 2048;
	req->bio->bi_iter.bi_sector = next_page / 512;
	req->__sector = req->bio->bi_iter.bi_sector;
	req->_imposter_command.rw.slba = cpu_to_le64(nvme_sect_to_lba(req->q->queuedata, blk_rq_pos(req)));
	cmnd.rw.slba = cpu_to_le64(nvme_sect_to_lba(req->q->queuedata, blk_rq_pos(req)));
#ifdef DEBUGS
	printk(KERN_ERR "Next sector is %lu\n", req->__sector);
#endif
	//nvme_submit_cmd(nvmeq, &req->_imposter_command, true);
	nvme_submit_cmd(nvmeq, &cmnd, true);
	return; 
	}
	else {
		req = blk_mq_tag_to_rq(nvme_queue_tagset(nvmeq), req->first_command_id);
		printk(KERN_ERR "STATUS: %x\n", cqe->status);
		ret = nvme_setup_cmd(ns, req, &cmnd);
		//nvme_end_request(req, cqe->status, cqe->result);
		nvme_end_request(req, 0, cqe->result);
		return;
	}
#endif
#ifdef TOKUDB
	//if (req_op(req) && REQ_TREENVME)
	//if (!op_is_write(req_op(req)))
	if (req->bio->_imposter_count < req->bio->_imposter_level && !op_is_write(req_op(req)))
	{
	char *buffer = bio_data(req->bio);
	int next_page;
	next_page = page_match_tokudb(req, buffer, 4096);
	if (next_page == 0)
	{
		printk(KERN_ERR "Got to leaf in %u with count %u\n", req->__sector, req->bio->_imposter_count);
		req = blk_mq_tag_to_rq(nvme_queue_tagset(nvmeq), req->first_command_id);
		nvme_end_request(req, cqe->status, cqe->result);
		return;
	}
	next_page = next_page & (~FILE_MASK);
	req->bio->_imposter_count += 1;
#ifdef DEBUGS
	printk(KERN_ERR "Alter count is %lu\n", req->bio->_imposter_count);
#endif
	
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
	
	nvme_req(req)->cmd = &cmnd;
	//cmnd.rw.slba = next_page / 2048;
	req->bio->bi_iter.bi_sector = next_page / 512;
	req->__sector = req->bio->bi_iter.bi_sector;
	req->_imposter_command.rw.slba = cpu_to_le64(nvme_sect_to_lba(req->q->queuedata, blk_rq_pos(req)));
	cmnd.rw.slba = cpu_to_le64(nvme_sect_to_lba(req->q->queuedata, blk_rq_pos(req)));
#ifdef DEBUGS
	printk(KERN_ERR "Next sector is %lu\n", req->__sector);
#endif
	//nvme_submit_cmd(nvmeq, &req->_imposter_command, true);
	nvme_submit_cmd(nvmeq, &cmnd, true);
	return; 
	}
	else {
		req = blk_mq_tag_to_rq(nvme_queue_tagset(nvmeq), req->first_command_id);
		printk(KERN_ERR "STATUS: %x\n", cqe->status);
		ret = nvme_setup_cmd(ns, req, &cmnd);
		//nvme_end_request(req, cqe->status, cqe->result);
		nvme_end_request(req, 0, cqe->result);
		return;
	}
#endif
#if 0
	//printk(KERN_ERR "GOT HERE -- rebound \n");
	if (req->bio->_imposter_count < req->bio->_imposter_level && !op_is_write(req_op(req)))
	{
#ifdef DEBUG
		printk(KERN_ERR "alter count at: %u\n", req->alter_count);
		printk(KERN_ERR "total count at: %u\n", req->total_count);
#endif
		req->bio->_imposter_count += 1;
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

		uint64_t next_offset;
		rq_for_each_segment(bvec, req, iter)
		{
			char *buffer = bio_data(req->bio);
#ifdef DEBUG
			printk(KERN_ERR "char bio: %s \n", buffer);
			printk(KERN_ERR "char is: %c\n", buffer[2]);	
			printk(KERN_ERR "size is: %u\n", req->bio->bi_iter.bi_size);
#endif
			// retry
#ifdef TIME
			uint64_t time = ktime_get_ns();
#endif
			int next_page;
			next_page = page_match(req, buffer, 4096);
#ifdef TIME
			printk("Time of %llu\n", ktime_get_ns() - time);
#endif
#ifdef SIMPLEKV
			if (next_page == -1)
				goto LEAF;
			next_offset = next_page;
			goto ENDING;
#endif
#ifdef SHORTCUT
			goto LEAF;
#endif
			if (next_page == 0)
				goto ERROR;
#ifndef SIMPLEKV
			if (!tctx->bt || !tctx->bt->block_translation)
			{
				printk(KERN_ERR "No block table when we want to do lookup.\n");
				goto ERROR;
			}
			if (next_page > tctx->bt->length_of_array) {
				printk(KERN_ERR "Does not fit!\n");
				goto ERROR;
			}
			if (next_page == -2) {
				// we have a resulting leaf node
				goto LEAF;	
			}
#endif
#ifdef DEBUG
			printk(KERN_ERR "NEXT PAGE IS %u\n", next_page);
			printk(KERN_ERR "Length of array is: %llu \n", tctx->bt->length_of_array);
			printk(KERN_ERR "Smallest element is: %u \n", tctx->bt->smallest);
			printk(KERN_ERR "Next head is: %u \n", tctx->bt->next_head);

#endif


#ifdef DEBUG2
			printk(KERN_ERR "NEXT PAGE IS %lu\n", next_page);
#endif
#ifdef DEBUGMAX	
			int i = 0;
			for (i = 0; i < tctx->bt->length_of_array; i++)
			{
				// Free is used to signify empty entry
				if (tctx->bt->block_translation[i].size <= FREE && tctx->bt->block_translation[i].u.diskoff <= FREE && tctx->bt->block_translation[i].size != 0) {
				printk(KERN_ERR "For blocknum %u", i);
				printk(KERN_ERR "OFFSET: %llu", tctx->bt->block_translation[i].u.diskoff);
				printk(KERN_ERR "SIZE: %llu", tctx->bt->block_translation[i].size);
				}
			}
#endif
			if (next_page >= tctx->bt->length_of_array)
			{
				printk(KERN_ERR "Page is not in block array.");
				goto ERROR;
			}
			next_offset = tctx->bt->block_translation[next_page].u.diskoff;
			if (next_offset == -1) 
			{
				printk(KERN_ERR "Broken! Not right offset. ");
				goto ERROR;
			}
#ifdef DEBUG
			printk(KERN_ERR "The next offset is %llu\n", next_offset);
#endif
//ENDING:
			// cmnd.rw.slba = cpu_to_le64(nvme_lba_to_sect(ns, next_offset));
			cmnd.rw.slba = cpu_to_le64(next_offset / 512);
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
ENDING:
		//req->alter_count++;
		nvme_req(req)->cmd = &cmnd;
		cmnd.rw.slba = cpu_to_le64(next_offset / 512);
		req->__sector = cmnd.rw.slba;
		nvme_submit_cmd(nvmeq, &cmnd, true);
	}
	else
	{
ERROR:
		/*
		// What is going on here?
		if (req->alter_count < depthcount && !op_is_write(req_op(req)))
		{
			req->alter_count = depthcount;
		}
		*/
		// just some final sanity check
		//printk(KERN_ERR "Final count is %u\n", req->alter_count);
		//req = blk_mq_tag_to_rq(nvme_queue_tagset(nvmeq), req->first_command_id);
		nvme_end_request(req, cqe->status, cqe->result);
		return;
LEAF:
	printk(KERN_ERR "Got to leaf in %u with count %u\n", req->__sector, req->bio->_imposter_count);
	//req = blk_mq_tag_to_rq(nvme_queue_tagset(nvmeq), req->first_command_id);
	nvme_end_request(req, cqe->status, cqe->result);
	return;
//====
FINAL:
	printk(KERN_ERR "ERRNO reached!\n");
	//req = blk_mq_tag_to_rq(nvme_queue_tagset(nvmeq), req->first_command_id);
	nvme_end_request(req, cqe->status, cqe->result);
	return;
	}
#endif

}

void init_pivot(struct pivot_bounds *pb, int num) {
	pb->num_pivots = num;
	pb->total_size = 0;
	pb->fixed_keys = NULL;
	pb->fixed_keylen_aligned = 0;
	//pb->dbt_keys = NULL;
	pb->dbt_keys = kmalloc(sizeof(struct DBT) * pb->num_pivots, GFP_KERNEL);
}

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
		memcpy(&size, &page[k], 4);
		k += 4;
		memcpy(&pb->dbt_keys[i].data, &page[k], size);
#ifdef DEBUG
	printk("Size is %u\n", size);
	printk("Data is %u\n", pb->dbt_keys[i].data);
#endif
		pb->total_size += size;
	       	k += size;	
	}
	return k;
}

// Reference: https://github.com/percona/PerconaFT/blob/8ff18ff1d135a8a5d6e745cf2c4dbf5684fcebd9/ft/bndata.cc#L176
static int deserialize_basement(char *page, struct child_node_data *cnd) 
{
	int i = 0;
	uint32_t num_entries = 0;
	uint32_t key_data_size = 0;
	uint32_t val_data_size = 0;
	uint32_t fixed_klpair_length = 0;
	bool all_keys_same_len = false;
	bool key_vals_sep = false;

#ifdef DEBUG
	int z = 0;
	for (z = 0; z < 512; z++){
		if (page[z] != 0)
		{
			printk(KERN_ERR "we have %u @ %u", page[z], z);
		}	
	}
#endif
	i += 4;

	// starting offset should be 4 i think
	memcpy(&num_entries, &page[i], 4);
	i += 8;
		
#ifdef DEBUG
	printk(KERN_ERR "page val: %u\n", page[0]);
#endif

	memcpy(&key_data_size, &page[i], 4);
	i += 8;

	memcpy(&val_data_size, &page[i], 4);
	i += 8;

	memcpy(&fixed_klpair_length, &page[i], 4);
	i += 8;

	memcpy(&all_keys_same_len, &page[i], 1);
	i += 8;

	memcpy(&key_vals_sep, &page[i], 1);
	i += 8;

#ifdef DEBUG
	printk(KERN_ERR "NUM_ENTRIES: %u\n", num_entries);
	printk(KERN_ERR "KEY_DATA_SIZE: %u\n", key_data_size);
	printk(KERN_ERR "VAL_DATA_SIZE: %u\n", val_data_size);
	printk(KERN_ERR "KLPAIR_LEN: %u\n", fixed_klpair_length);
#endif

	char *bytes = kmalloc(sizeof(char) * key_data_size, GFP_KERNEL);
	memcpy(&bytes, &page[i], key_data_size);
	i += key_data_size;
}

static void print_simple_node(ptr__t ptr, Node *node) {
    size_t i = 0;
    printk(KERN_ERR "----------------\n");
    printk(KERN_ERR "ptr %lu num %lu type %lu\n", ptr, node->num, node->type);
    for (i = 0; i < NODE_CAPACITY; i++) {
	    printk(KERN_ERR "(%6lu, %8lu) ", node->key[i], node->ptr[i] & (~FILE_MASK));
    }
    printk(KERN_ERR "\n----------------\n");
} 

// Reference: toku_deserialize_bp_from_disk
static int deserialize(struct request *req, char *page, struct tokunode *node) 
{
	int i = 0;
#ifdef DEBUGMAX
	int z = 0;
	for (z = 0; z < 512; z++){
		if (page[z] != 0)
		{
			printk(KERN_ERR "we have %u @ %u", page[z], z);
		}	
	}
#ifdef DEBUGEX1
	printk(KERN_ERR "Stuff from Leaf Example 1:....... \n");
	printk(KERN_ERR	"VAL_SIZE: 10\n");
	printk(KERN_ERR "ELE_SIZE: 10\n");
	printk(KERN_ERR "\n");
#endif
#endif


#ifdef SIMPLEKV
	struct _Node *nd = (struct _Node*)page;
	
#ifdef DEBUGS
	print_simple_node(0, nd);
	/*
	printk(KERN_ERR "printing simple kv node:\n");
	printk(KERN_ERR "node num: %d\n", nd->num);
	printk(KERN_ERR "type: %d\n", nd->type);
	printk(KERN_ERR "KEYS:\n");
	for (i = 0; i < NODE_CAPACITY; i++) {
		printk(KERN_ERR "%d", nd->key[i]);
	}
	*/
#endif
#ifdef KEYINBUF
	unsigned long kk = req->bio->key;
	//printk(KERN_ERR "KEY HERE IS %lu\n", kk);
	if (nd->type != 1) {
		//struct key_entry *_k;
        	//_k = list_first_entry(&tctx->keys, struct key_entry, entry);	
		for (i = 0; i < nd->num; i++) {
			if(kk < nd->key[i]) {
				return nd->ptr[i-1];
			}
		}
		return nd->ptr[nd->num - 1];
	}
	else {
	if (nd->type == 1) {
#ifdef DEBUGS
		// this is a leaf
		printk(KERN_ERR "Got to leaf.\n");
#endif
		return 0;
	}
	else {
		printk(KERN_ERR "Busted\n");
		return 0;
	     }
	}
#else	
	if (nd->type != 1) {
		struct key_entry *_k;
        	_k = list_first_entry(&tctx->keys, struct key_entry, entry);	
		for (i = 0; i < nd->num; i++) {
			if(_k->a < nd->key[i]) {
				return nd->ptr[i-1];
			}
		}
		return nd->ptr[nd->num - 1];
	}
	else {
	if (nd->type == 1) {
#ifdef DEBUGS
		// this is a leaf
		printk(KERN_ERR "Got to leaf.\n");
#endif
		return 0;
	}
	else {
		printk(KERN_ERR "Busted\n");
		return 0;
	     }
	}
#endif
#else
	struct block_data *bd;
	// node->blocknum = blocknum;
	node->blocknum = 0;
	node->ct_pair = NULL;


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

	struct subblock_data *sb_data = kmalloc(sizeof(struct subblock_data), GFP_KERNEL);
	sb_data->csize = 0;
	sb_data->usize = 0;
	
	// compressed size
	memcpy(&sb_data->csize, &page[i], 4);
	i += 4;

	// uncompressed size
	memcpy(&sb_data->usize, &page[i], 4);
	i += 4;	
	/*
	for (j = 0; i < 400; j++) {
		memcpy(&sb_data.usize, &page[i], 4);
		i += 4;
	}
	*/

#ifdef DEBUG
	printk("COMPRESSED_SIZE: %u\n", sb_data->csize);
	printk("UNCOMPRESSED_SIZE: %u\n", sb_data->usize);
	printk("COUNTER IS AT: %u\n", i);
#endif
	
	// skip compressing

	char *cp = kmalloc(sizeof(int) * sb_data->csize, GFP_KERNEL);
	memcpy(cp, &page[i], sb_data->csize);
	
	// decompress by moving everything one to the left
	char *temp = kmalloc(sizeof(int) * sb_data->usize, GFP_KERNEL);
	memcpy(temp, cp + 1, sb_data->csize - 1);

	kfree(cp);
	cp = temp;
	// memcpy(&cp, &page[i], 4);

	// get from subblock_data
	uint32_t data_size = 0;
	if (sb_data->usize != 0) 
		data_size = sb_data->usize - 4;

#ifdef DEBUG 
	printk("DATA_SIZE: %u\n", data_size);
#endif

#ifdef DEBUGMAX
	for (z = 0; z < data_size; z++){
		if (cp[z] != 0)
		{
			printk(KERN_ERR "we have %u @ %u in subblock\n", cp[z], z);
		}	
	}
#endif
	if (data_size != 0) 
	{
		char bufferd[data_size];
		memcpy(&bufferd, &cp[m], data_size);
		m += data_size;

		k = 0;
		k += 12;
		memcpy(&node->flags, &bufferd[k], 4);

		k += 4;
		memcpy(&node->height, &bufferd[k], 4);

#ifdef DEBUG
	printk("Node flags of %u\n", node->flags);
	printk("Node height of %u\n", node->height);
#endif
		k += 12;
		node->pivotkeys = kmalloc(sizeof(struct pivot_bounds), GFP_KERNEL); 
		if (node->n_children > 1){
			k += fill_pivot(node->pivotkeys, &bufferd[k], node->n_children); 
		}	
		else {
			init_pivot(node->pivotkeys, 0);
		}

		// Block nums
#ifdef DEBUG
	printk("NUMBER OF CHILDREN IS %d\n", node->n_children);
#endif
		if (node->height > 0) {
			// puts into node stuff
			node->cnd = kmalloc(sizeof(struct child_node_data) * node->n_children, GFP_KERNEL);
			for (l = 0; l < node->n_children; l++) {
				memcpy(&node->cnd[l].blocknum, &bufferd[k], 4);
				k += 8;
#ifdef DEBUG
	printk("CHILD_BLOCKNUM: %d\n", node->cnd[l].blocknum);
#endif			
			}
		}
		else {
			// Gotten from: ?
			// hopefully this magic number doesn't break things.	
			// This is adding the uncompressed size
			i += sb_data->csize;
			i += 14;
#ifdef DEBUG
			printk("We are at counter %d\n", i);
#endif
			memcpy(&node->n_children, &page[i], 4);
			i += 22;
#ifdef DEBUG
			printk("NUMBER OF CHILDREN IS %d\n", node->n_children);
			printk("We are at counter %d\n", i);
#endif
			node->cnd = kmalloc(sizeof(struct child_node_data) * node->n_children, GFP_KERNEL);	
			
			// we have to re-do the pivot keys because number of children was wrong in first fill
			// fill_pivot(node->pivotkeys, &page[i], node->n_children); 
			// actually this does not work
		
			for (l = 0; l < node->n_children; l++) {
				memcpy(&node->cnd[l].blocknum, &page[i], 4);
				i += 12;
#ifdef DEBUG
	printk("LEAF_CHILD_BLOCKNUM: %d\n", node->cnd[l].blocknum);
#endif			
				//deserialize_basement(&bufferd[k], &node->cnd[l]);
			}
			return -2;
		}

		return 1; 
	}
	else {
		k += 16;
		goto ERROR;
	}
#endif
ERROR:
	return -1;	
}

// example function -- don't use
static int example_compare(char *a, char *b, int asize, int bsize)
{
	int i = 0;
	int j = 0;

	for (i = 0; i < asize; i++) {
		for (j = 0; j < bsize; j++) {
			if (a[i] > b[j])
				return i;
		}
	}
	return -1;	
}

static int page_match_tokudb(struct request *req, char *page, int page_size)
{
	struct tokunode *node = kmem_cache_alloc(node_cachep, GFP_KERNEL);
	int is_child = 0;
	int result;
	result = deserialize(req, page, node);
	if (result == -1)
		return -1;
	if (result == -2)
		is_child = 1;

	int low = 0;
	int high = node->n_children - 1;
	int middle;
	struct DBT pivot_key;
	init_DBT(&pivot_key);

	struct search_ctx *search = kmalloc(sizeof(struct search_ctx), GFP_KERNEL);

	if (is_child == 0) {	
		// this is only a test?
		search->compare = &example_compare;
		while (low < high)
		{
			middle = (low + high) / 2;	
			bool c = compare(search, &node->pivotkeys->dbt_keys[low], &node->pivotkeys->dbt_keys[high]);
			if (((search->direction == LEFT_TO_RIGHT) && c) || (search->direction == RIGHT_TO_LEFT && !c))
			{	
				high = middle;
			}
			else {
				low = middle + 1;
			}
			break;		
		}
	}
	else {
		// This means that we are dealing with a leaf node.
		return -2;
	}
#ifdef DEBUG
	if (!node)
		printk(KERN_ERR "Node is NULL\n");
#endif

	if (result == 1)
	{
		return (node)->cnd[low].blocknum;	
	}
	if (result == 0)
	{
		return 0;
	}
}

static int page_match(struct request *req, char *page, int page_size)
{
#ifdef DEBUG2
	printk(KERN_ERR "Got into page_match.\n");
#endif
	struct tokunode *node = kmem_cache_alloc(node_cachep, GFP_KERNEL);
	
	int is_child = 0;
	int result;
#ifdef TIME
	uint64_t dstime = ktime_get_ns();
#endif
	result = deserialize(req, page, node);
#ifdef SIMPLEKV
#ifdef DEBUG2
	printk(KERN_ERR "End result of %lu\n", result);
#endif
	return result;
#endif
#ifdef TIME
	printk(KERN_ERR "Deserialize time: %llu\n", ktime_get_ns() - dstime);
#endif
	if (result == -1)
		return -1;

	// is this a leaf node?
	if (result == -2)
		is_child = 1;

	int low = 0;
	int high = node->n_children - 1;
	int middle;
	struct DBT pivot_key;
	init_DBT(&pivot_key);

	struct search_ctx *search = kmalloc(sizeof(struct search_ctx), GFP_KERNEL);

	if (is_child == 0) {	
		// this is only a test?
		search->compare = &example_compare;
		while (low < high)
		{
			middle = (low + high) / 2;	
			bool c = compare(search, &node->pivotkeys->dbt_keys[low], &node->pivotkeys->dbt_keys[high]);
			if (((search->direction == LEFT_TO_RIGHT) && c) || (search->direction == RIGHT_TO_LEFT && !c))
			{	
				high = middle;
			}
			else {
				low = middle + 1;
			}
			break;		
		}
	}
	else {
		// This means that we are dealing with a leaf node.
		return -2;
	}
#ifdef DEBUG
	if (!node)
		printk(KERN_ERR "Node is NULL\n");
#endif

	if (result == 1)
	{
		return (node)->cnd[low].blocknum;	
	}
	if (result == 0)
	{
		return 0;
	}
}

/*
static int __init treenvme_init(void)
{
#ifdef DEBUG
	printk(KERN_ERR "Got into original treenvme init. \n");
#endif
	tctx = kmalloc(sizeof(struct treenvme_ctx), GFP_KERNEL);
	tctx->bt = kmalloc(sizeof(struct block_table), GFP_KERNEL);	
	
	// this is how we keep the nodes in memory
	node_cachep = KMEM_CACHE(tokunode, SLAB_HWCACHE_ALIGN | SLAB_PANIC);	
	INIT_LIST_HEAD(&tctx->keys);
	// DECLARE_HASHTABLE(tbl, 4);
}

static void __exit treenvme_exit(void)
{
	kfree(tctx);
}
*/

/*
static const struct file_operations treenvme_ctrl_fops = {
	.owner		= THIS_MODULE,
	.mmap		= treenvme_mmap,
// probably have to do release and flush
};
*/

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

/*@ddp*/
/*
 * struct ddp_info{
	struct bpf_prog __rcu *ddp_prog;
}
*/

MODULE_AUTHOR("Yu Jian <yujian.wu1@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
//module_init(treenvme_init);
//module_exit(treenvme_exit);
