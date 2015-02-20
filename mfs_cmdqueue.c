#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/sched.h>

#include "mfs_cmdqueue.h"

#define MFS_CMDNRQUEUE(c) (sizeof((c)->q) / sizeof(*(c)->q))

static inline void _mfs_init_cmdq(struct mfs_cmdq *cq)
{
	INIT_LIST_HEAD(&cq->cmd);
	init_waitqueue_head(&cq->rwait);
	spin_lock_init(&cq->wlock);
	atomic_set(&cq->nr, 0);
	atomic_set(&cq->wr, 0);
}

int mfs_cmdqueue_init(struct mfs_cmdqueue *cmd)
{
	size_t i;

	for(i = 0; i < MFS_CMDNRQUEUE(cmd); ++i)
		_mfs_init_cmdq(&cmd->q[i]);

	atomic_set(&cmd->active, 0);

	return 0;
}

int mfs_cmdqueue_wait(struct mfs_cmdqueue *cmd, struct list_head **cmds)
{
	int ret;
	size_t active;

	active = atomic_read(&cmd->active);
	*cmds = NULL;

	/**
	 * Wait for at least one command is waiting
	 */
	ret = wait_event_interruptible(cmd->q[active].rwait,
			atomic_read(&cmd->q[active].nr) != 0);
	if(ret < 0)
		goto out;

	_mfs_init_cmdq(&cmd->q[(active + 1) % MFS_CMDNRQUEUE(cmd)]);
	*cmds = &cmd->q[active].cmd;

	/**
	 * Use xchg here, we need a memory barrier
	 */
	atomic_xchg(&cmd->active, (active + 1) % MFS_CMDNRQUEUE(cmd));

	/**
	 * Wait for all pending command enqueue to finish
	 */
	ret = wait_event_interruptible(cmd->q[active].rwait,
			atomic_read(&cmd->q[active].wr) == 0);
	if(ret < 0)
		goto out;

out:
	if(ret < 0)
		pr_err("Cannot add command, Some command can be lost :S\n");

	return ret;
}

int mfs_cmdqueue_add(struct mfs_cmdqueue *q, struct list_head *cmd)
{
	size_t active, wr;

	/**
	 * Get active command queue
	 */
	while(1) {
		active = atomic_read(&q->active);
		atomic_inc(&q->q[active].wr);

		if(active == atomic_read(&q->active))
			break;

		if(atomic_dec_return(&q->q[active].wr) == 0)
			wake_up_interruptible(&q->q[active].rwait);
	}

	spin_lock(&q->q[active].wlock);
	list_add_tail(&q->q[active].cmd, cmd);
	spin_unlock(&q->q[active].wlock);

	atomic_inc(&q->q[active].nr);

	wr = atomic_dec_return(&q->q[active].wr);

	/**
	 * Wake up waiter if we have enqueued first command or if we are the
	 * last command writer
	 */
	if(active == atomic_read(&q->active) || (wr == 0))
		wake_up_interruptible(&q->q[active].rwait);

	return 0;
}
