#include "dbin.h"
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#ifndef RBUF
// rbuf methods
unsigned int _rbuf_int (struct rbuf *r) {
    //assert(r->ndone+4 <= r->size);
    uint32_t result = (*(uint32_t*)(r->buf+r->ndone));
    r->ndone+=4;
    return result;
}

inline void _rbuf_literal_bytes (struct rbuf *r, const void **bytes, unsigned int n_bytes) {
    *bytes =   &r->buf[r->ndone];
    r->ndone+=n_bytes;
    //assert(r->ndone<=r->size);
}

inline void _rbuf_init(struct rbuf *r, unsigned char *buf, unsigned int size) {
    r->buf = buf;
    r->size = size;
    r->ndone = 0;
}

#endif

#define _cast_voidp(name, val) name = (__typeof__(name))val

void *_mmalloc(int size) {
	void *p = kmalloc(size, GFP_KERNEL);
	return p;
}

#define MMALLOC(v) _cast_voidp(v, _mmalloc(sizeof(*v)))
#define MMALLOC_N(n,v) _cast_voidp(v, _mmalloc((n)*sizeof(*v)))
#define _BP_BLOCKNUM(node,i) ((node)->bp[i].blocknum)
#define _BP_STATE(node,i) ((node)->bp[i].state)
#define _BP_WORKDONE(node,i) ((node)->bp[i].workdone)

/*
 *
 * Functions are defined here
 */
struct _dbt *_fill_pivot(_pivot_keys *pk, int i, struct _dbt *a) {
	a->data = pk->_dbt_keys[i].data;
	a->size = pk->_dbt_keys[i].size;
	a->ulen = pk->_dbt_keys[i].ulen;
	a->flags = pk->_dbt_keys[i].flags;
	return a;
}

struct _dbt *_get_pivot(_pivot_keys *pk, int i) {
	// unless fixed format
	return &pk->_dbt_keys[i];
}

static long
ftnode_memory_size_cutdown(struct _ftnode *node)
// Effect: Estimate how much main memory a node requires.
{
    long retval = 0;
    int n_children = node->n_children;
    retval += sizeof(*node);
    retval += (n_children)*(sizeof(node->bp[0]));
    retval += node->pivotkeys._total_size;
	
    int i = 0;
    for (i = 0; i < n_children; i++) {
    	//struct _sub_block *sb = BSB(node, i);
    	struct _sub_block *sb = node->bp[i].ptr.u.subblock;
    	retval += sizeof(*sb);
    	retval += sb->compressed_size;
    }
    /*
    // now calculate the sizes of the partitions
    for (int i = 0; i < n_children; i++) {
        if (BP_STATE(node,i) == PT_INVALID || BP_STATE(node,i) == PT_ON_DISK) {
            continue;
        }
        else if (BP_STATE(node,i) == PT_COMPRESSED) {
            struct _sub_block *sb = BSB(node, i);
            retval += sizeof(*sb);
            retval += sb->compressed_size;
        }
        else if (BP_STATE(node,i) == PT_AVAIL) {
            if (node->height > 0) {
                retval += get_avail_internal_node_partition_size(node, i);
            }
            else {
                BASEMENTNODE bn = BLB(node, i);
                retval += sizeof(*bn);
                retval += BLB_DATA(node, i)->get_memory_size();
            }
        }
        else {
            abort();
        }
    }
    */
    return retval;
}

long ftnode_cachepressure_size_cutdown(struct _ftnode *node) {
    long retval = 0;
    bool totally_empty = true;
    int i = 0;
    if (node->height == 0) {
        goto exit;
    }
    else {
        for (i = 0; i < node->n_children; i++) {
    		struct _sub_block *sb = node->bp[i].ptr.u.subblock;
                totally_empty = false;
                retval += sb->compressed_size;
        }
    }
exit:
    if (totally_empty) {
        return 0;
    }
    return retval;
}

_PAIR_ATTR make_ftnode_pair_attr_cutdown(struct _ftnode *node) {
    long size = ftnode_memory_size_cutdown(node);
    long cachepressure_size = ftnode_cachepressure_size_cutdown(node);
    _PAIR_ATTR result={
        .size = size,
        .nonleaf_size = (node->height > 0) ? size : 0,
        .leaf_size = (node->height > 0) ? 0 : size,
        .rollback_size = 0,
        .cache_pressure_size = cachepressure_size,
        .is_valid = true
    };
    return result;
}

struct _dbt *_init_dbt(struct _dbt *dbt)
{
	memset(dbt, 0, sizeof(*dbt));
	return dbt;
}

/*
static inline struct _ftnode_nonleaf_childinfo _BNC(struct _ftnode* node, int i) {
	struct _ftnode_child_pointer fcptr = node->bp[i].ptr;
	return *fcptr.u.nonleaf; 
}
*/

static int ft_compare_pivot_cutdown(const struct _comparator *cmp, struct _dbt *key, struct _dbt *pivot) {
    return cmp->_cmp(key, pivot);
}

int toku_ftnode_which_child_cutdown(struct _ftnode *node, struct _dbt *k, struct _comparator *cmp);

int ftnode_which_child_cutdown(struct _ftnode *node, struct _dbt *k, struct _comparator *_cmp) {
    // a funny case of no pivots
    struct _comparator cmp;
    init_comparator(&cmp); 
    if (node->n_children <= 1) return 0;

    struct _dbt pivot;

    // check the last key to optimize seq insertions
    int n = node->n_children-1;
    int c = ft_compare_pivot_cutdown(&cmp, k, _fill_pivot(&node->pivotkeys, n - 1, &pivot));
    if (c > 0) return n;

    // binary search the pivots
    int lo = 0;
    int hi = n-1; // skip the last one, we checked it above
    int mi;
    while (lo < hi) {
        mi = (lo + hi) / 2;
        c = ft_compare_pivot_cutdown(&cmp, k, _fill_pivot(&node->pivotkeys, mi, &pivot));
        if (c > 0) {
            lo = mi+1;
            continue;
        }
        if (c < 0) {
            hi = mi;
            continue;
        }
        return mi;
    }
    return lo;
}

int read_compressed_sub_block_cutdown(struct rbuf *rb, struct _sub_block *sb)
{
	int r = 0;
	sb->compressed_size = _rbuf_int(rb);
	sb->uncompressed_size = _rbuf_int(rb);
	const void **cp = (const void **) &sb->compressed_ptr;
	_rbuf_literal_bytes(rb, cp, sb->compressed_size);
	sb->xsum = _rbuf_int(rb);
	
	// decompress; only no compression
	sb->uncompressed_ptr = _mmalloc(sb->uncompressed_size);
	memcpy(sb->uncompressed_ptr, sb->compressed_ptr + 1, sb->compressed_size -1);

	return r;
}

/*
int
read_compressed_sub_block_cutdown(struct rbuf *rb, struct _sub_block *sb)
{
    int r = 0;
    sb->compressed_size = _rbuf_int(rb);
    sb->uncompressed_size = _rbuf_int(rb);
    const void **cp = (const void **) &sb->compressed_ptr;
    _rbuf_literal_bytes(rb, cp, sb->compressed_size);
    sb->xsum = _rbuf_int(rb);
    return r;
}
*/

int read_and_decompress_sub_block_cutdown(struct rbuf *rb, struct _sub_block *sb)
{
    int r = 0;
    r = read_compressed_sub_block_cutdown(rb, sb);
    if (r != 0) {
        goto exit;
    }
exit:
    return r;
}

void just_decompress_sub_block_cutdown(struct _sub_block *sb)
{
    // <CER> TODO: Add assert that the subblock was read in.
    sb->uncompressed_ptr = _mmalloc(sb->uncompressed_size);

    decompress_cutdown(
        (_Bytef *) sb->uncompressed_ptr,
        sb->uncompressed_size,
        (_Bytef *) sb->compressed_ptr,
        sb->compressed_size
        );
}

void decompress_cutdown (_Bytef       *dest,   _uLongf destLen,
                      const _Bytef *source, _uLongf sourceLen)
{
    //assert(sourceLen>=1);
    memcpy(dest, source + 1, sourceLen - 1);
    return;
}
/*
struct _dbt *_get_pivot(_pivot_keys *pk, int a) {
	return pk->_dbt_keys[a];
}
*/

void _create_empty_pivot(_pivot_keys *pk) {
	pk = (__typeof__(pk))_mmalloc(sizeof(_pivot_keys));
	pk->_num_pivots = 0;
	pk->_total_size = 0;
	pk->_fixed_keys = NULL;
	pk->_fixed_keylen = 0;
	pk->_fixed_keylen_aligned = 0;
	pk->_dbt_keys = NULL;
}

void deserialize_from_rbuf_cutdown(_pivot_keys *pk, struct rbuf *rb, int n) {
	int i = 0;
	pk->_num_pivots = n;
	pk->_total_size = 0;
	pk->_fixed_keys = NULL;
	pk->_fixed_keylen = 0;
	pk->_dbt_keys = NULL;

	pk->_dbt_keys = (__typeof__(pk->_dbt_keys))_mmalloc(64 * n);
	for (i = 0; i < n; i++) {
		const void *pivotkeyptr;
		uint32_t size;
		size = _rbuf_int(rb);
		_rbuf_literal_bytes(rb, &pivotkeyptr, size);
		memcpy(&pk->_dbt_keys[i], pivotkeyptr, size);
		pk->_total_size += size;
	}
}

void dump_ftnode_cutdown(struct _ftnode *nd) {
	printk("============DUMPINGFTNODE=============\n");
	printk("Max msn of node %d\n", nd->max_msn_applied_to_node_on_disk.msn);
	printk("Flags: %u\n", nd->flags);
	printk("Blocknum: %u\n", nd->blocknum.b);
	printk("Layout version: %u\n", nd->layout_version);
	printk("Layout version original: %u\n", nd->layout_version_original);
	printk("Layout version read from disk: %u\n", nd->layout_version_read_from_disk);
	printk("Build ID: %u\n", nd->build_id);
	printk("Height: %u\n", nd->height);
	printk("Dirty: %u\n", nd->dirty_);
	printk("Fullhash: %u\n", nd->fullhash);
	printk("Number of children: %u\n", nd->n_children);
	printk("Pivot keys total size of: %u\n", nd->pivotkeys._total_size);
	printk("Oldest reference xid known: %u\n", nd->oldest_referenced_xid_known);
	printk("Ftnode partition of: %u\n", nd->bp->blocknum.b);
	if (nd->ct_pair) {
		printk("Ctpair count is: %u\n", nd->ct_pair->key.b);
		printk("Cache fd: %u\n", nd->ct_pair->count);
	}
	else {
		printk("Null ctpair.\n");
	}
	if (nd->bp)
		dump_ftnode_partition(nd->bp);
	printk("================DUMPED================\n");
}

void dump_ftnode_partition(struct _ftnode_partition *bp) {
	printk("===========DUMPINGFTNODEPARTITION========\n");
	printk("Blocknum is %u\n", bp->blocknum.b);
	printk("Workdone is %u\n", bp->workdone);
	printk("State is %u\n", bp->state);
	dump_ftnode_child_ptr_cutdown(&bp->ptr);
	printk("==================DUMPED==================\n");
}

void dump_sub_block(struct _sub_block *sb) {
	int i = 0;
	printk("=============DUMPINGSUBBLOCK==============\n");
	for (i = 0; i < sb->uncompressed_size; i++) {
		printk("%c", ((char *)(sb->uncompressed_ptr))[i]);
	}		
	printk("==========DUMPED=SUB=BLOCK================\n");	
}

void dump_ftnode_child_ptr_cutdown(_FTNODE_CHILD_POINTER *fcp) {
	printk("===========DUMPINGFTNODECHILDPTR========\n");
	printk("Subblock is at: %c\n", fcp->u.subblock->uncompressed_ptr);
	printk("Subblock unc size is: %u\n", fcp->u.subblock->uncompressed_size);
	printk("Compressed sz is at: %u\n", fcp->u.subblock->compressed_size);
	if (fcp->tag)
		printk("Child tag is: %u\n", fcp->tag);
	printk("================DUMPED===================\n");
}

int leftmost_child_wanted (struct ftnode_fetch_extra *ffe, struct _ftnode *node) {
	if (ffe->left_is_neg_infty) {
		return 0;
	}
	else if (ffe->range_lock_left_key.data == NULL) {
		return -1;
	}
	else {
		return ftnode_which_child_cutdown(node, &ffe->range_lock_left_key, NULL);
	}
}

int rightmost_child_wanted (struct ftnode_fetch_extra *ffe, struct _ftnode *node) {
	if (ffe->right_is_pos_infty) {
		return node->n_children - 1;
	}
	else if (ffe->range_lock_right_key.data == NULL) {
		return -1;
	}
	else {
		return ftnode_which_child_cutdown(node, &ffe->range_lock_right_key, NULL);
	}
}

int long_key_cmp(struct _dbt *a, struct _dbt *b);

inline void init_comparator(struct _comparator *cmp) {
	cmp->_cmp = &long_key_cmp;
	cmp->_memcpy_magic = 8;
}

inline struct _sub_block *BSB(struct _ftnode *node, int i) {
	struct _ftnode_child_pointer p = node->bp[i].ptr;
	return p.u.subblock;	
}

inline void set_BSB(struct _ftnode *node, int i, struct _sub_block *sb) {
	struct _ftnode_child_pointer *p = &node->bp[i].ptr;
	p->tag = _BCT_SUBBLOCK;
	p->u.subblock = sb; 
}

// Comparators
int long_key_cmp(struct _dbt *a, struct _dbt *b) {
	const long *_cast_voidp(x, a->data);
	const long *_cast_voidp(y, b->data);
	return (*x > *y) - (*x < *y);	
}

int _ft_compare(const struct _ft_search *a, const struct _dbt *b) {
	struct _comparator cmp;
	init_comparator(&cmp);
	return cmp._cmp(a->k, b) <= 0; 
}

void init_ft_search(struct _ft_search *a) {
	a->compare = _ft_compare;
	a->direction = _FT_SEARCH_RIGHT;
	_init_dbt(a->k);
	_init_dbt(&a->pivot_bound);
	_init_dbt(a->k_bound);	
}

int _search_which_child(struct _comparator *cmp, struct _ftnode *node, struct _ft_search *search) {
        struct _dbt a;
        _init_dbt(&a);

        int lo = 0;
        int hi = node->n_children - 1;
        int mi;
        while (lo < hi) {
                mi = (lo + hi) / 2;
                _fill_pivot(&node->pivotkeys, mi, &a);
                bool c = search->compare(search, &a);
                if (((search->direction == _FT_SEARCH_LEFT) && c) ||
                        ((search->direction == _FT_SEARCH_RIGHT) && !c)) {
                        hi = mi;
                }
                else {
                        lo = mi + 1;
                }
        }

        // ready to return something
        // https://github.com/percona/PerconaFT/blob/d627ac564ae11944a363e18749c9eb8291b8c0ac/ft/ft-ops.cc#L3674

        /*
        if (search->pivot_bound.data != nullptr) {
                if (search->direction == FT_SEARCH_LEFT) {
                        while (lo < node->n_children - 1 && search_which_child_cmp_with_bound(cmp, node, lo, search, &pivotkey) <= 0) {
                                lo++;
                        }
                }
                else {
                        while (lo > 0 && search_which_child_cmp_with_bound(cmp, node, lo - 1, search, &pivotkey) >= 0) {
                                lo--;
                        }
                }
        }
        */
        return lo;
}


/*
inline struct _sub_block *BSB(struct _ftnode *node, int i) {
	struct _ftnode_child_pointer *p = &node->bp[i].ptr;
	return p.u.subblock;
}

inline void set_BSB(struct _ftnode *node, int i, struct _sub_block *sb) {
	struct _ftnode_child_pointer *p = &node->bp[i].ptr;
	p->tag = _BCT_SUBBLOCK;
	p->u.subblock = sb;
}
*/

void init_ffe(struct ftnode_fetch_extra *fe) {
	fe->ft = 4;
	fe->type = ftnode_fetch_none;
	fe->search = NULL;
	_init_dbt(&fe->range_lock_left_key);
	_init_dbt(&fe->range_lock_right_key);
	fe->left_is_neg_infty = false;
	fe->right_is_pos_infty = false;
	fe->child_to_read = -1;
	fe->disable_prefetching = true;
	fe->read_all_partitions = false;
	fe->bytes_read = 0;
	fe->io_time = 0;
	fe->deserialize_time = 0;
	fe->decompress_time = 0;
}

void sub_block_init_cutdown(struct _sub_block *sb) {
        sb->uncompressed_ptr = 0;
        sb->uncompressed_size = 0;
        sb->compressed_ptr = 0;
        sb->compressed_size_bound = 0;
	sb->compressed_size = 0;
	sb->xsum = 0;
}

inline void _rbuf_MSN(struct rbuf *r) {
	_MSN msn = { .msn = rbuf_ulonglong(rb) };
	return msn;
}
