#ifndef _MFS_IMAP_H_
#define _MFS_IMAP_H_

#include "mfs_cmdqueue.h"

#define MAXTAG 63
#define IDLETAG 63
#define NRTAG 64

#define IMAP_TIMEOUT (msecs_to_jiffies(30000))

enum imap_cmd_id {
	IMAPCMD_LOGIN,
	IMAPCMD_LOGOUT,
	IMAPCMD_LIST,
	IMAPCMD_SELECT,
	IMAPCMD_FETCHALL,
	IMAPCMD_FETCHFROM,
	IMAPCMD_FETCHMAIL,
	IMAPCMD_IDLE,
	IMAPCMD_DONE,
	IMAPCMD_NR
};

struct imap_cmd {
	struct list_head next;
	struct kref refcnt;
	char *str;
	ssize_t len;
	enum imap_cmd_id id;
	uint8_t cont;
};

struct imap_rcv_handle {
	struct imap_msg **rcv;
	wait_queue_head_t qwait;
	atomic_t reserved;
	atomic_t ready;
};

struct box;
struct message;

struct imap {
	struct task_struct *rcv_thread;
	struct task_struct *con_thread;
	struct task_struct *snd_thread;
	struct task_struct *idl_thread;
	struct mfs_cmdqueue send;
	struct imap_rcv_handle rcv_handle[NRTAG];
	struct list_head boxes;
	struct list_head fetching;
	struct box *selbox;
	wait_queue_head_t rcvwait;
	wait_queue_head_t idlwait;
	wait_queue_head_t conwait;
	size_t mcachesz;
	atomic_t next_tag;
	atomic_t ctag;
	atomic_t idling;
	unsigned int flags;
	struct msgcache *mcache[];
};

#define IMAP_CONN (1 << 0)
#define IMAP_AUTH (1 << 1)
#define IMAP_INIT (1 << 2)
#define IMAP_EXIT (1 << 3)


extern struct mfs_client_operations imapops;

/**
 * TODO: remove put these into mfs_imap_cmd
 */
void imap_cleanup_cmd(struct imap_cmd *c);

#endif
