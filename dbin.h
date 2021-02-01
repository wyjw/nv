#ifndef DBIN_H
#define DBIN_H

//#include <stdint.h>
//#include <cstddef>
//#include <stdio.h>
//#include <cstring>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ctype.h>

//#include <pthread.h>
//#define printk printf

// node stuff
// preliminaries for node
typedef struct _msn { uint64_t msn; } _MSN;
typedef struct _blocknum_s { int64_t b; } _BLOCKNUM;
typedef uint64_t _TXNID;
typedef _BLOCKNUM _CACHEKEY;
struct _ftnode_partition;
struct _dbt;
struct __db_dbt;
struct __toku_dbt;
typedef struct __toku_dbt DBT;
struct _dbt{
	void *data;
	uint32_t size;
	uint32_t ulen;
	uint32_t flags;
};
struct cachefile;
typedef struct cachefile *CACHEFILE;
struct __toku_db;
typedef struct __toku_db DB;
struct ctpair;

#define RBUFDEF 1
struct rbuf {
    unsigned char *buf;
    unsigned int  size;
    unsigned int  ndone;
};
#define RBUF_INITIALIZER ((struct rbuf){.buf = NULL, .size=0, .ndone=0})
// pivot_keys
typedef struct _int_pivot_keys {
	char *_fixed_keys;
	size_t _fixed_keylen;
	size_t _fixed_keylen_aligned;
	struct _dbt *_dbt_keys;
	int _num_pivots;
	size_t _total_size;
} _pivot_keys;

struct _ftnode {
    _MSN max_msn_applied_to_node_on_disk;
    unsigned int flags;
    _BLOCKNUM blocknum;
    int layout_version;
    int layout_version_original;
    int layout_version_read_from_disk;
    uint32_t build_id;
    int height;
    int dirty_;
    uint32_t fullhash;
/*
    void set_dirty() {
        dirty_ = 1;
    }
    void clear_dirty() {
        dirty_ = 0;
    }
    bool dirty() {
        return dirty_;
    }
*/
    int n_children;
    _pivot_keys pivotkeys;
    _TXNID oldest_referenced_xid_known;

    struct _ftnode_partition *bp;
    struct _ctpair *ct_pair;
};
typedef char _Bytef;
typedef unsigned long int _uLongf;

void *_mmalloc(int size);

#define _cast_voidp(name, val) name = (__typeof__(name))val
#define MMALLOC(v) _cast_voidp(v, _mmalloc(sizeof(*v)))
#define MMALLOC_N(n,v) _cast_voidp(v, _mmalloc((n)*sizeof(*v)))
#define _BP_BLOCKNUM(node,i) ((node)->bp[i].blocknum)
#define _BP_STATE(node,i) ((node)->bp[i].state)
#define _BP_WORKDONE(node,i) ((node)->bp[i].workdone)
struct _sub_block {
	void *uncompressed_ptr;
	uint32_t uncompressed_size;
	void *compressed_ptr;
	uint32_t compressed_size;
	uint32_t compressed_size_bound;
	uint32_t xsum;
};
void sub_block_init_cutdown(struct _sub_block *sb);
//int _read_compressed_sub_block(struct rbuf *rb, struct _sub_block *sb);
int deserialize_ftnode_info_cutdown(struct _sub_block *sb, struct _ftnode *ftnode);
struct _sbt;
struct _dbt *_init_dbt(struct _dbt *dbt);
struct _comparator;

// PAIR STUFF
struct _klpair_struct {
	uint32_t le_offset;
	uint8_t key[0];
};

enum _pt_state {
	_PT_INVALID = 0,
	_PT_ON_DISK = 1,
	_PT_COMPRESSED = 2,
	_PT_AVAIL = 3
};

struct ftnode_leaf_basement_node;

/*
struct _ftnode_leaf_basement_node {
	bn_data data_buffer;
};
*/

enum _ftnode_child_tag {
	_BCT_INVALID = 0,
	_BCT_NULL,
	_BCT_SUBBLOCK,
	_BCT_LEAF,
	_BCT_NONLEAF
};

typedef struct _ftnode_child_pointer {
	union {
		struct _sub_block *subblock;
		struct ftnode_nonleaf_childinfo *nonleaf;
		struct ftnode_leaf_basement_node *leaf;
	} u;
	enum _ftnode_child_tag tag;
} _FTNODE_CHILD_POINTER;

struct _ftnode_partition {
    _BLOCKNUM     blocknum; // blocknum of child 
    uint64_t     workdone;
    struct _ftnode_child_pointer ptr;
    enum _pt_state state; // make this an enum to make debugging easier.  
    uint8_t clock_count;
};

struct _ancestors {
	struct _ftnode *node;
	int childnum;
	struct _ancestors *next;
};

typedef struct _pair_attr_s {
	long size;
	long nonleaf_size;
	long leaf_size;
	long rollback_size;
	long cache_pressure_size;
	bool is_valid;
} _PAIR_ATTR;

// search structs
enum _ft_search_direction_e {
	_FT_SEARCH_LEFT = 1,
	_FT_SEARCH_RIGHT = 2,
};
struct _ft_search;

typedef int (*_ft_search_compare_func_t)(const struct _ft_search *a, const struct _dbt *b);

struct _ft_search {
	_ft_search_compare_func_t compare;
	enum _ft_search_direction_e direction;
	const struct _dbt *k;
	void *context;
	struct _dbt pivot_bound;
	const struct _dbt *k_bound;
};

/*
 * Function declarations begin here:
 */
struct _dbt *_fill_pivot(_pivot_keys* pk, int a, struct _dbt* k);
long int ftnode_cachepressure_size_cutdown(struct _ftnode* ftn);
_PAIR_ATTR make_ftnode_pair_cutdown(struct _ftnode* ftn);
void _convert_dbt_to_tokudbt(DBT *keya, struct _dbt* keyb);
void _convert_tokudbt_to_dbt(struct _dbt* keya, DBT *keyb);
_PAIR_ATTR make_ftnode_pair_attr_cutdown(struct _ftnode *node);
uint32_t toku_cachetable_hash_cutdown(CACHEFILE cf, _BLOCKNUM bn);
struct _dbt *_get_pivot(_pivot_keys *pk, int a);
void _create_empty_pivot(_pivot_keys *pk);
void deserialize_from_rbuf_cutdown(_pivot_keys *pk, struct rbuf *rb, int n);

typedef int (*_compare_func)(struct _dbt *a, struct _dbt *b); 
typedef int (*_old_compare_func)(DB *db, const DBT *a, const DBT *b);
struct _comparator{
	_compare_func _cmp;
	uint8_t _memcpy_magic;
};

inline void init_comparator (struct _comparator *cmp); 

/*void _convert_dbt_to_tokudbt(DBT *a, struct _dbt *b) {
	a->data = b->data;
	a->size = b->size;
	a->ulen= b->ulen;
	a->flags = b->flags;
}

void _convert_tokudbt_to_dbt(struct _dbt *a, DBT *b) {
	a->data = b->data;
	a->size = b->size;
	a->ulen = b->ulen;
	a->flags = b->flags;
}
*/

typedef uint64_t _TXNID;
struct __attribute__((__packed__)) _XIDS_S {
	uint8_t num_xids;
	_TXNID ids[];
};
typedef struct _XIDS_S *_XIDS;

struct _message_buffer {
	struct __attribute__((__packed__)) buffer_entry {
		unsigned int keylen;
		unsigned int vallen;
		unsigned char type;
		bool is_fresh;
		_MSN msn;
		
	};
	int _num_entries;
	char* memory;
	int _memory_size;
	int _memory_used;
	size_t memory_usable;
};

/*
struct __attribute__((__packed__)) buffer_entry {
	unsigned int keylen;
	unsigned int vallen;
	unsigned char type;
	bool is_fresh;
	_MSN msn;	 
};
*/
/*
typedef omtdata_t;

struct _omt_integer {
	struct _omt_array {
		uint32_t start_idx;
		uint32_t num_values;
		_omtdata_t *values;
	};

	struct _omt_tree {
		_subtree root;
		uint32_t free_idx;
		_omt_node *nodes;	
	};

	bool is_array;
	uint32_t capacity;
	union {
		struct _omt_array a;
		struct _omt_tree b;
	};
}

struct message_buffer;
namespace toku {
	template<typename omtdata_t,
        typename omtdataout_t=omtdata_t,
        bool supports_marks=false>
	class omt;
};
//class toku::omt;
typedef toku::omt<int32_t> off_omt_t;
typedef toku::omt<int32_t, int32_t, true> marked_off_omt_t;

struct _ftnode_nonleaf_childinfo {
	struct message_buffer msg_buffer;
	// all these are broken
	off_omt_t broadcast_list;
	marked_off_omt_t fresh_message_tree;
	off_omt_t stale_message_tree;
	uint64_t flow[2];
};
*/

// compression declarations 
int read_compressed_sub_block_cutdown(struct rbuf *rb, struct _sub_block *sb);
int read_and_decompress_sub_block_cutdown(struct rbuf *rb, struct _sub_block *sb);
void just_decompress_sub_block_cutdown(struct _sub_block *sb);
void decompress_cutdown (_Bytef *dest, _uLongf destLen, const _Bytef *source, _uLongf sourceLen);
void dump_ftnode_cutdown(struct _ftnode *nd);
void dump_ftnode_child_ptr_cutdown(_FTNODE_CHILD_POINTER *fcp);
void dump_ftnode_partition(struct _ftnode_partition *bp);
void dump_sub_block(struct _sub_block *sb);

struct _ctpair;
typedef struct _cachetable *_CACHETABLE;
typedef struct _cachefile *_CACHEFILE;
typedef struct _ctpair *_PAIR;

struct _FILENUM { 
	uint32_t fileid;
};

struct _psi_mutex {};

struct _mutex_t {
	//A pthread_mutex_t pmutex;
	struct mutex *pm;
	//A struct _psi_mutex *psi_mutex;
	struct mutex *psi_mutex;
};

// This is broken
struct _cond_t {	
	int pcond;
	//pthread_cond_t pcond;
};

struct _mutex_aligned {
	struct _mutex_t aligned_mutex __attribute__((__aligned__(64)));
};

//#include <sys/stat.h>
struct _fileid {
	dev_t st_dev;
	ino_t st_ino;	
};

typedef struct background_job_manager_struct {
	bool accepting_jobs;
	uint32_t num_jobs;
	//_cond_t jobs_wait;
	int jobs_wait;
	struct _mutex_t jobs_lock;
} _BACKGROUND_JOB_MANAGER;

typedef _BLOCKNUM _CACHEKEY;
typedef struct __lsn { uint64_t lsn; } _LSN;
struct cachetable;
typedef struct cachetable *CACHETABLE;
struct _evictor;

struct _cachefile {
    _PAIR cf_head;
    uint32_t num_pairs;
    bool for_checkpoint;
    bool unlink_on_close;
    bool skip_log_recover_on_close;
    int fd;
    CACHETABLE cachetable;
    struct _fileid fileid;
    struct _FILENUM filenum;
    uint32_t hash_id;
    char *fname_in_env;

    void *userdata;
    void (*log_fassociate_during_checkpoint)(CACHEFILE cf, void *userdata); 
    void (*close_userdata)(CACHEFILE cf, int fd, void *userdata, bool lsnvalid, _LSN);
    void (*free_userdata)(CACHEFILE cf, void *userdata);
    void (*begin_checkpoint_userdata)(_LSN lsn_of_checkpoint, void *userdata);
    void (*checkpoint_userdata)(CACHEFILE cf, int fd, void *userdata);
    void (*end_checkpoint_userdata)(CACHEFILE cf, int fd, void *userdata);
    void (*note_pin_by_checkpoint)(CACHEFILE cf, void *userdata);
    void (*note_unpin_by_checkpoint)(CACHEFILE cf, void *userdata);
    _BACKGROUND_JOB_MANAGER bjm;
};

// definitions of all the callbacks

enum _cachetable_dirty {
	_CACHETABLE_CLEAN = 0,
	_CACHETABLE_DIRTY = 1,
};

enum _context_id {
	_CTX_INVALID = -1,
	_CTX_DEFAULT = 0,
	_CTX_SEARCH,
	_CTX_PROMO,
	_CTX_FULL_FETCH,
	_CTX_PARTIAL_FETCH,
	_CTX_FULL_EVICTION,
	_CTX_PARTIAL_EVICTION,
	_CTX_MESSAGE_INJECTION,
	_CTX_MESSAGE_APPLICATION,
	_CTX_FLUSH,
	_CTX_CLEANER
};

struct _frwlock {
	struct queue_item {
		struct _cond_t *cond;
		struct queue_item *next;
	};
	struct _mutex_t *m_mutex;
	uint32_t m_num_readers;
	uint32_t m_num_writers;
	uint32_t m_num_want_write;
	uint32_t m_num_want_read;
	uint32_t m_num_signaled_readers;
	uint32_t m_num_expensive_want_write;
	bool m_current_writer_expensive;
	bool m_read_wait_experience;
	int m_current_writer_tid;
	enum _context_id m_blocking_writer_context_id;
	struct queue_item m_queue_item_read;
	bool m_wait_read_is_in_queue;
	struct _cond_t m_wait_read;
	struct queue_item *m_wait_head;
	struct queue_item *m_wait_tail;
};

enum _partial_eviction_cost {
	_PE_CHEAP = 0,
	_PE_EXPENSIVE = 1,
};

// Definition of all the callbacks
typedef void (*_CACHETABLE_FLUSH_CALLBACK)(CACHEFILE, int fd, _CACHEKEY key, void *value, void **disk_data, void *write_extraargs, _PAIR_ATTR size, _PAIR_ATTR* new_size, bool write_me, bool keep_me, bool for_checkpoint, bool is_clone);

typedef int (*_CACHETABLE_FETCH_CALLBACK)(CACHEFILE, _PAIR p, int fd, _CACHEKEY key, uint32_t fullhash, void **value_data, void **disk_data, _PAIR_ATTR *sizep, int *dirtyp, void *read_extraargs);

typedef void (*_CACHETABLE_PARTIAL_EVICTION_EST_CALLBACK)(void *ftnode_pv, void* disk_data, long* bytes_freed_estimate, enum _partial_eviction_cost *cost, void *write_extraargs);

typedef int (*_CACHETABLE_PARTIAL_EVICTION_CALLBACK)(void *ftnode_pv, _PAIR_ATTR old_attr, void *write_extraargs, void (*finalize)(_PAIR_ATTR new_attr, void *extra), void *finalize_extra);

typedef bool (*_CACHETABLE_PARTIAL_FETCH_REQUIRED_CALLBACK)(void *ftnode_pv, void *read_extraargs);

typedef int (*_CACHETABLE_PARTIAL_FETCH_CALLBACK)(void *value_data, void* disk_data, void *read_extraargs, int fd, _PAIR_ATTR *sizep);

typedef void (*_CACHETABLE_PUT_CALLBACK)(_CACHEKEY key, void *value_data, _PAIR p);

typedef int (*_CACHETABLE_CLEANER_CALLBACK)(void *ftnode_pv, _BLOCKNUM blocknum, uint32_t fullhash, void *write_extraargs);

typedef void (*_CACHETABLE_CLONE_CALLBACK)(void* value_data, void** cloned_value_data, long* clone_size, _PAIR_ATTR* new_attr, bool for_checkpoint, void* write_extraargs);

typedef void (*_CACHETABLE_CHECKPOINT_COMPLETE_CALLBACK)(void *value_data);

typedef struct {
	_CACHETABLE_FLUSH_CALLBACK flush_callback;
	_CACHETABLE_PARTIAL_EVICTION_EST_CALLBACK pe_est_callback;
	_CACHETABLE_PARTIAL_EVICTION_CALLBACK pe_callback;
	_CACHETABLE_CLEANER_CALLBACK cleaner_callback;
	_CACHETABLE_CLONE_CALLBACK clone_callback;
	_CACHETABLE_CHECKPOINT_COMPLETE_CALLBACK checkpoint_complete_callback;
	void *write_extraargs;
} _CACHETABLE_WRITE_CALLBACK;

struct _pthread_rwlock_t {
	int rwlock;
	//pthread_rwlock_t rwlock;
};

typedef struct _pair_list_cutdown {
	uint32_t m_n_in_table;
	uint32_t m_table_size;
	uint32_t m_num_locks;
	_PAIR *m_table;
	struct _mutex_aligned *m_mutexes;
	_PAIR m_clock_head;
	_PAIR m_cleaner_head;
	_PAIR m_checkpoint_head;
	_PAIR m_pending_head;

	struct _pthread_rwlock_t m_list_lock;
	struct _pthread_rwlock_t m_pending_lock_expensive;
	struct _pthread_rwlock_t m_pending_lock_cheap;	
} _pair_list;

struct _st_rwlock {
	int reader;
	int want_read;
	struct _cond_t wait_read;
	int writer;
	int want_write;
	struct _cond_t wait_write;
	struct _cond_t *wait_users_go_to_zero; 
};

struct _nb_mutex {
	struct _st_rwlock lock;
};

struct _ctpair {
    CACHEFILE cachefile;
    _CACHEKEY key;
    uint32_t fullhash;
    _CACHETABLE_FLUSH_CALLBACK flush_callback;
    _CACHETABLE_PARTIAL_EVICTION_EST_CALLBACK pe_est_callback;
    _CACHETABLE_PARTIAL_EVICTION_CALLBACK pe_callback;
    _CACHETABLE_CLEANER_CALLBACK cleaner_callback;
    _CACHETABLE_CLONE_CALLBACK clone_callback;
    _CACHETABLE_CHECKPOINT_COMPLETE_CALLBACK checkpoint_complete_callback;
    void *write_extraargs;
    void* cloned_value_data;
    long cloned_value_size;
    void* disk_data;
    void* value_data;
    _PAIR_ATTR attr;
    enum _cachetable_dirty dirty;
    uint32_t count;
    uint32_t refcount;
    uint32_t num_waiting_on_refs;
    struct _cond_t refcount_wait;
    struct _frwlock value_rwlock;
    struct _nb_mutex disk_nb_mutex;
    struct _mutex_t* mutex;
    bool checkpoint_pending;
    long size_evicting_estimate;
    struct _evictor* ev;
    _pair_list* list_;
    _PAIR clock_next, clock_prev;
    _PAIR hash_chain;
    _PAIR pending_next;
    _PAIR pending_prev;
    _PAIR cf_next;
    _PAIR cf_prev;
};

inline void _rbuf_init(struct rbuf *r, unsigned char *buf, unsigned int size);
unsigned int _rbuf_int (struct rbuf *r);
inline void _rbuf_literal_bytes(struct rbuf *r, const void **bytes, unsigned int n_bytes);
inline unsigned long long _rbuf_ulonglong(struct rbuf *r);
inline _MSN _rbuf_MSN(struct rbuf *r);
inline void _rbuf_TXNID(struct rbuf *r, _TXNID *txnid);
inline _BLOCKNUM _rbuf_blocknum(struct rbuf *rb);

#define BP_START(node_dd,i) ((node_dd)[i].start)
#define BP_SIZE(node_dd,i) ((node_dd)[i].size)
#define BP_BLOCKNUM(node,i) ((node)->bp[i].blocknum)
#define _BP_BLOCKNUM(node,i) ((node)->bp[i].blocknum)
#define BP_STATE(node,i) ((node)->bp[i].state)
#define BP_WORKDONE(node, i)((node)->bp[i].workdone)
#define BP_TOUCH_CLOCK(node, i) ((node)->bp[i].clock_count = 1)
#define BP_SWEEP_CLOCK(node, i) ((node)->bp[i].clock_count = 0)
#define BP_SHOULD_EVICT(node, i) ((node)->bp[i].clock_count == 0)
#define BP_INIT_TOUCHED_CLOCK(node, i) ((node)->bp[i].clock_count = 1)
#define BP_INIT_UNTOUCHED_CLOCK(node, i) ((node)->bp[i].clock_count = 0)
#define BLB_MAX_MSN_APPLIED(node,i) (BLB(node,i)->max_msn_applied) 
#define BLB_MAX_DSN_APPLIED(node,i) (BLB(node,i)->max_dsn_applied)
#define BLB_DATA(node,i) (&(BLB(node,i)->data_buffer))
#define BLB_NBYTESINDATA(node,i) (BLB_DATA(node,i)->get_disk_size())
#define BLB_SEQINSERT(node,i) (BLB(node,i)->seqinsert)
#define BLB_LRD(node, i) (BLB(node,i)->logical_rows_delta)

//inline void set_BNC_cutdown(struct _ftnode *node, int i, 

#define FT_LAYOUT_VERSION_14 14 

struct ftnode_disk_data {
	uint32_t start;
	uint32_t size;
};

typedef struct ftnode_disk_data *FTNODE_DISK_DATA;

enum ftnode_fetch_type {
	ftnode_fetch_none = 1,
	ftnode_fetch_subset,
	ftnode_fetch_prefetch,
	ftnode_fetch_all,
	ftnode_fetch_keymatch,	
};

struct ftnode_fetch_extra {
	uint8_t ft;
	enum ftnode_fetch_type type;
	struct _ft_search *search;
	struct _dbt range_lock_left_key, range_lock_right_key;
	bool left_is_neg_infty, right_is_pos_infty;
	bool disable_prefetching;
	int child_to_read;
	bool read_all_partitions;
	uint64_t bytes_read;
	uint64_t io_time;
	uint64_t decompress_time;
	uint64_t deserialize_time;
};

int leftmost_child_wanted(struct ftnode_fetch_extra *ffe, struct _ftnode *node);
int rightmost_child_wanted(struct ftnode_fetch_extra *ffe, struct _ftnode *node);

int _search_which_child(struct _comparator *cmp, struct _ftnode *node, struct _ft_search *search);

inline void set_BSB(struct _ftnode *node, int i, struct _sub_block *sb); 
inline struct _sub_block *BSB(struct _ftnode *node, int i); 

void init_ffe(struct ftnode_fetch_extra *fe);

#endif /* DBIN_H */
