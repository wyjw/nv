/*@ddp*/
#include <linux/bpf.h>
#include <linux/bpf_ddp.h>
#include <linux/filter.h>

struct atx{
	int x;
};

struct mctx {
	struct bpf_prog *ddp_prog;
};

static struct mctx *tctx;
const struct bpf_prog_ops ddp_prog_ops = {};

static const struct bpf_func_proto *
ddp_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	return bpf_base_func_proto(func_id);
}
		

static bool ddp_is_valid_access(int off, int size, enum bpf_access_type type, const struct bpf_prog *prog, struct bpf_insn_access_aux *info){
	return true;
}

const struct bpf_verifier_ops ddp_verifier_ops = {
	.get_func_proto = ddp_func_proto,
	.is_valid_access = ddp_is_valid_access,
};

static DEFINE_MUTEX(ddp_mutex);

int ddp_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog)
{
	printk(KERN_ERR "DDP PROG is attached.\n");
	struct bpf_prog *attached;

	mutex_lock(&ddp_mutex);
	attached = rcu_dereference_protected(tctx->ddp_prog, lockdep_is_held(&ddp_mutex));

	if (attached) {
		mutex_unlock(&ddp_mutex);
		return -EEXIST;
	}

	rcu_assign_pointer(tctx->ddp_prog, prog);
       	mutex_unlock(&ddp_mutex);
	return 0;	
}

int ddp_prog_detach(const union bpf_attr *attr)
{
       printk(KERN_ERR "DDP Prog is detached.");
       struct bpf_prog *attached;

       mutex_lock(&ddp_mutex);
       attached = rcu_dereference_protected(tctx->ddp_prog, lockdep_is_held(%ddp_mutex));

       if (!attached) {
               mutex_unlock(&ddp_mutex);
               return -ENOENT;
       }

       bpf_prog_put(attached);
       RCU_INIT_POINTER(tctx->ddp_prog, NULL);
       mutex_unlock(&ddp_mutex);
       return 0;
}
