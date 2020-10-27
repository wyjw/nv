#ifndef _UAPI_LINUX_TREENVME_IOCTL_H
#define _UAPI_LINUX_TREENVME_IOCTL_H

#include <linux/types.h>

#define TREENVME_IOCTL '$'

// taken from the original NVME ioctl
struct treenvme_user_io {
	__u8	opcode;
	__u8	flags;
	__u16	control;
	__u16	nblocks;
	__u16	rsvd;
	__u64	metadata;
	__u64	addr;
	__u64	slba;
	__u32	dsmgmt;
	__u32	reftag;
	__u16	apptag;
	__u16	appmask;
};

struct treenvme_passthru_cmd {
	__u8	opcode;
	__u8	flags;
	__u16	rsvd1;
	__u32	nsid;
	__u32	cdw2;
	__u32	cdw3;
	__u64	metadata;
	__u64	addr;
	__u32	metadata_len;
	__u32	data_len;
	__u32	cdw10;
	__u32	cdw11;
	__u32	cdw12;
	__u32	cdw13;
	__u32	cdw14;
	__u32	cdw15;
	__u32	timeout_ms;
	__u32	result;
};

enum treenvme_translation_type {
	TREENVME_TRANSLATION_NONE = 0,
	TREENVME_TRANSLATION_CURRENT,
	TREENVME_TRANSLATION_INPROGRESS,
	TREENVME_TRANSLATION_CHECKPOINTED,
	TREENVME_TRANSLATION_DEBUG
};

struct treenvme_block_translation_pair {
	union {
		uint64_t diskoff;
		uint32_t free_blocknum;	
	} u;

	uint64_t size;
};

struct treenvme_block_table {
	enum treenvme_translation_type type;
	int64_t length_of_array;
	uint32_t smallest;
	uint32_t next_head;
	struct treenvme_block_translation_pair *block_translation; 
};

struct treenvme_params {
	uint32_t flags;
	uint32_t num;
};

// possible IOCTL commands
#define TREENVME_IOCTL_ID			_IO('$', 0x50)
#define TREENVME_IOCTL_SUBMIT_IO 		_IOWR('$', 0x51, struct treenvme_user_io)
#define TREENVME_IOCTL_IO_CMD 			_IOWR('$', 0x52, struct treenvme_passthru_cmd)
#define TREENVME_IOCTL_SETUP 			_IOWR('$', 0x53, struct treenvme_params)
#define TREENVME_IOCTL_REGISTER_BLOCKTABLE	_IOWR('$', 0x54, struct treenvme_block_table)
#endif
