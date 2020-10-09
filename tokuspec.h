// This is a key-data structure..

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

struct ftnode_partition;
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
	struct ftnode_parititon *bp;
	struct ctpair *ct_pair;
};
