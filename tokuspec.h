// This is a key-data structure..

#include <linux/hashtable.h>

//#define FREE 0xFFFFFFFFFFFFFFFF 
#define FREE 0xFFFF000000000000

struct DBT {
	void *data;		/* key value */
	uint32_t size;		/* key/data length */
	uint32_t ulen;		/* read-only: length of user buffer */
	uint32_t dlen;		/* read-only: get/put record length */
	uint32_t doff;		/* read-only: get/put record offset */
	void *app_data;
	uint32_t flags;
	uint32_t blocknum;
};

struct pivot_bounds {
	int num_pivots;
	int total_size;
	char *fixed_keys;
	int fixed_keylen;
	int fixed_keylen_aligned;
	struct DBT *dbt_keys;
};

struct block_data {
	uint32_t start;
	uint32_t end;
	uint32_t size;
};

enum child_tag {
	SUBBLOCK = 1,
	BASEMENT = 2,
};

struct subblock_data {
	void *ptr;
	uint32_t csize; // compressed size
	uint32_t usize; // uncompressed size
};

struct basement_data {
	uint32_t le_offset;
	uint8_t key[0];
	struct hlist_node node;
};

struct child_node_data {
	int blocknum;
	union {
		struct subblock_data *sublock;
		struct basement_data *leaf;
	} u;
	enum child_tag tag;
};

struct ctpair;

struct tokunode {
	int max_msn_applied_to_node_on_disk;
	unsigned int flags;
	uint64_t blocknum;
	int layout_version;
	int layout_version_original;
	int layout_version_read_from_disk;
	uint32_t build_id;
	int height;
	int dirty_;
	uint32_t fullhash;
	int n_children;
	struct pivot_bounds *pivotkeys;
	struct child_node_data *cnd;
	struct ctpair *ct_pair;
};

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

enum translation_type {
	TRANSLATION_NONE = 0,
	TRANSLATION_CURRENT,
	TRANSLATION_INPROGRESS,
	TRANSLATION_CHECKPOINTED,
	TRANSLATION_DEBUG
};

struct block_struct { int64_t b; };

struct block_translation_pair {
	union {
		uint64_t diskoff;
		struct block_struct free_blocknum;	
	} u;

	uint64_t size;
};

struct block_table {
	enum translation_type type;
	int64_t length_of_array;
	int64_t smallest;
	int64_t next_head;
	struct block_translation_pair *block_translation; 
};
