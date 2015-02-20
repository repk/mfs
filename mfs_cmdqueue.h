#ifndef _MFS_CMDQUEUE_H_
#define _MFS_CMDQUEUE_H_

struct mfs_cmdq {
	struct list_head cmd;
	wait_queue_head_t rwait;
	spinlock_t wlock;
	atomic_t nr;
	atomic_t wr;
};

struct mfs_cmdqueue {
	struct mfs_cmdq q[2];
	atomic_t active;
};

int mfs_cmdqueue_init(struct mfs_cmdqueue *cmd);
int mfs_cmdqueue_wait(struct mfs_cmdqueue *cmd, struct list_head **cmds);
int mfs_cmdqueue_add(struct mfs_cmdqueue *q, struct list_head *cmd);


#endif
