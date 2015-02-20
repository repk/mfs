#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/uaccess.h>
#include <linux/kref.h>

#include "mfs_client.h"
#include "mfs_inode.h"
#include "mfs_imap.h"
#include "mfs_imap_parse.h"
#include "mfs_cmdqueue.h"

#define DEBUG

#ifndef DEBUG
#define IMAP_DBG(...)
#else
#define IMAP_DBG(...) pr_err("[MFS/IMAP]: " __VA_ARGS__)
#endif

#define XSTR(a) #a
#define STR(a) XSTR(a)

#define MAXTAG 63
#define IDLETAG 63
#define NRTAG 64

/**
 * Keep enough space for 3 digits tag
 */
#define ITAG "## "

#define MSGCACHESZ 128
#define BODYMAXLEN (1 << 16)

#define IMAP_TIMEOUT (msecs_to_jiffies(30000))
#define IMAP_IDLE_TIMEOUT (msecs_to_jiffies(28000 * 60)) /* 28 minutes */

#define NAME "test"
#define PASS "test"

enum mfs_imap_f_type {
	MFS_IMAP_F_UNKNOWN,
	MFS_IMAP_F_MAIL,
};

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

#define IMAPCMD_TAG(id, s) [id] = {					\
	.fmt = (ITAG s "\r\n")						\
}

#define IMAPCONTCMD_TAG(id, s) [id] = {					\
	.fmt = (ITAG s "\r\n"),						\
	.cont = 1							\
}


struct imap_cmdfmt {
	char *fmt;
	uint8_t cont;
};

static struct imap_cmdfmt const cmdfmt[] = {
	IMAPCMD_TAG(IMAPCMD_LOGIN, "LOGIN %s %s"),
	IMAPCMD_TAG(IMAPCMD_LOGOUT, "LOGOUT"),
	IMAPCMD_TAG(IMAPCMD_LIST, "LIST \"\" \"*\""),
	IMAPCMD_TAG(IMAPCMD_SELECT, "SELECT %s"),
	IMAPCMD_TAG(IMAPCMD_FETCHALL, "UID FETCH 1:* FLAGS"),
	IMAPCMD_TAG(IMAPCMD_FETCHFROM, "UID FETCH %lu:* FLAGS"),
	IMAPCMD_TAG(IMAPCMD_FETCHMAIL, "UID FETCH %lu BODY[]"),
	IMAPCONTCMD_TAG(IMAPCMD_IDLE, "IDLE"),
	IMAPCMD_TAG(IMAPCMD_DONE, "DONE"),
};

struct msgcache {
	struct message *m;
	size_t len;
	char body[];
};

struct msgdesc {
	enum mfs_imap_f_type ftype;
};

struct message {
	struct msgdesc msgd;
	struct list_head box_next;
	struct list_head cache_next;
	struct list_head fetch_next;
	struct msgcache *mfetch;
	unsigned int flags;
	unsigned int uid;
	unsigned int seqid;
	char name[];
};

struct box {
	struct list_head next;
	struct list_head msg;
	struct dentry *dir;
	off_t uidlast;
	off_t sidlast;
	char name[];
};

struct imap_rcv_handle {
	struct imap_msg **rcv;
	wait_queue_head_t qwait;
	atomic_t reserved;
	atomic_t ready;
};

struct imap {
	struct task_struct *rcv_thread;
	struct task_struct *snd_thread;
	struct task_struct *idl_thread;
	struct mfs_cmdqueue send;
	struct imap_rcv_handle rcv_handle[NRTAG];
	struct list_head boxes;
	struct list_head fetching;
	struct box *selbox;
	wait_queue_head_t rcvwait;
	wait_queue_head_t idlwait;
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

static inline struct msgcache *imap_new_msgcache(char const *data)
{
	struct msgcache *mc;

	mc = kmalloc(sizeof(*mc) + strlen(data) + 1, GFP_KERNEL);
	if(mc == NULL)
		return NULL;

	strcpy(mc->body, data);
	mc->len = strlen(data);

	return mc;
}

static inline void imap_del_msgcache(struct msgcache *mc)
{
	kfree(mc);
}

static inline struct message *imap_new_msg(char const *name, unsigned int uid,
		unsigned int seqid)
{
	struct message *m;

	m = kmalloc(sizeof(*m) + strlen(name) + 1, GFP_KERNEL);

	if(m == NULL)
		return m;

	m->msgd.ftype = MFS_IMAP_F_MAIL;
	m->seqid = seqid;
	m->uid = uid;
	INIT_LIST_HEAD(&m->box_next);
	INIT_LIST_HEAD(&m->fetch_next);
	INIT_LIST_HEAD(&m->cache_next);
	strcpy(m->name, name);

	return m;
}

static inline void imap_del_msg(struct message *m)
{
	list_del(&m->box_next);
	list_del(&m->fetch_next);
	list_del(&m->cache_next);

	kfree(m);
}

static struct imap_cmd *imap_create_cmd(struct imap *i,
		enum imap_cmd_id id, ...)
{
	struct imap_cmd *c;
	va_list args;
	unsigned int len;

	if(id >= IMAPCMD_NR) {
		c = ERR_PTR(-EINVAL);
		goto out;
	}

	va_start(args, id);

	/**
	 * Get string final size
	 */
	len = vsnprintf(NULL, 0, cmdfmt[id].fmt, args);
	va_end(args);

	c = kmalloc(sizeof(*c) + len + 1, GFP_KERNEL);
	if(c == NULL) {
		c = ERR_PTR(-ENOMEM);
		goto out;
	}

	c->str = (char *)(c + 1);
	c->len = len;
	c->id = id;
	c->cont = cmdfmt[id].cont;
	kref_init(&c->refcnt);
	INIT_LIST_HEAD(&c->next);

	va_start(args, id);
	len = vsnprintf(c->str, len + 1, cmdfmt[id].fmt, args);
	va_end(args);

out:
	return c;

}

static void imap_del_cmd(struct kref *kref)
{
	struct imap_cmd *c = container_of(kref, struct imap_cmd, refcnt);
	kfree(c);
}

static void imap_cleanup_cmd(struct imap_cmd *c)
{
	kref_put(&c->refcnt, imap_del_cmd);
}

static struct box * imap_create_box(char const *name)
{
	struct box *b = kmalloc(sizeof(*b) + strlen(name) + 1, GFP_KERNEL);
	if(b == NULL)
		return NULL;

	INIT_LIST_HEAD(&b->msg);
	b->uidlast = 0;
	b->sidlast = 0;

	strcpy(b->name, name);

	return b;
}

static void imap_del_box(struct box *b)
{
	/**
	 * remove dentry b->dir
	 */
	kfree(b);
}

static inline struct imap *mfs_imap_alloc(ssize_t mcachesz)
{
	struct imap *i;
	i = kzalloc(sizeof(struct imap) +
			mcachesz * sizeof(struct msgcache *), GFP_KERNEL);

	if(i != NULL) {
		i->mcachesz = mcachesz;
		init_waitqueue_head(&i->rcvwait);
		init_waitqueue_head(&i->idlwait);
		mfs_cmdqueue_init(&i->send);
		INIT_LIST_HEAD(&i->boxes);
		INIT_LIST_HEAD(&i->fetching);
		atomic_set(&i->ctag, NRTAG);
		i->flags |= IMAP_INIT;
	}

	return i;
}

static inline void mfs_imap_free(struct imap *imap)
{
	struct box *p, *n;

	list_for_each_entry_safe(p, n, &imap->boxes, next)
		imap_del_box(p);

	kfree(imap);
}

static void mfs_imap_wait_conn(struct imap *i, int intr)
{
	wait_event(i->rcvwait, i->flags & IMAP_CONN);
}

#define MFS_IMAP_ALLOC() mfs_imap_alloc(MSGCACHESZ)
#define MFS_IMAP_FREE(i) mfs_imap_free(i)

static int imap_add_box(struct mfs_client *clt, char const *name)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct box *b = imap_create_box(name);
	struct dentry *dir;

	if(b == NULL)
		return -1;

	dir = mfs_inode_create_dir(clt->sb, clt->sb->s_root, b->name, b);

	if(dir == NULL) {
		imap_del_box(b);
		return -1;
	}

	b->dir = dir;

	list_add_tail(&b->next, &i->boxes);

	return 0;
}

static int imap_add_mail(struct mfs_client *clt, unsigned int uid,
		unsigned int seqid, char const *name)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct dentry *d;
	struct message *m;

	if(i->selbox == NULL)
		return -1;

	m = imap_new_msg(name, uid, seqid);
	if(m == NULL)
		return -1;

	/**
	 * TODO lock selbox ?
	 */
	list_add(&m->box_next, &i->selbox->msg);

	d = mfs_inode_create_file(clt->sb, i->selbox->dir, name, &m->msgd);
	if(d == NULL) {
		imap_del_msg(m);
		return -1;
	}

	return 0;
}

static int imap_rm_mail(struct mfs_client *clt, char const *name)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct message *m;
	struct dentry *d;

	if(i->selbox == NULL)
		return -1;

	d = mfs_inode_get(clt->sb, i->selbox->dir, name);
	if(d == NULL)
		return -1;


	m = container_of(d->d_inode->i_private, struct message, msgd);

	mfs_inode_delete_file(clt->sb, i->selbox->dir, d);

	mfs_inode_put(d);

	imap_del_msg(m);

	return 0;
}

static inline int __mfs_imap_send_cmd(struct mfs_client *clt,
		struct imap_cmd *c)
{
	size_t ret;

	ret = mfs_client_kernel_net_send(clt, c->str, c->len);
	if(ret < 0)
		return ret;

	return 0;
}

static inline int mfs_imap_send_cmd(struct mfs_client *clt,
		struct imap_cmd *c)
{
	struct imap *i = (struct imap*)clt->private_data;
	int ret;

	ret = kref_get_unless_zero(&c->refcnt);
	if(ret == 0) {
		ret = -ENOMEM;
		goto out;
	}
	ret = mfs_cmdqueue_add(&i->send, &c->next);

out:
	return ret;
}

/**
 * Send command to server, if rcv is not NULL the send is done synchronously and
 * the thread goes to sleep until the response arrives
 */
static int _imap_send_cmd(struct mfs_client *clt, struct imap_cmd *send,
		struct imap_msg **rcv)
{
	struct imap *i = (struct imap*)clt->private_data;
	struct imap_rcv_handle *h;
	unsigned int tagid;
	ssize_t ret;

	/**
	 * Do async send
	 */
	if(rcv == NULL)
		return mfs_imap_send_cmd(clt, send);
	/**
	 * Here we prepare everything to get a synchronous send
	 */

	/**
	 * Set appropriate tag and reserved receive slot
	 */
	if(send->id == IMAPCMD_IDLE || send->id == IMAPCMD_DONE)
		tagid = IDLETAG;
	else
		tagid = atomic_inc_return(&i->next_tag) % MAXTAG;

	h = &i->rcv_handle[tagid];
	if(atomic_cmpxchg(&h->reserved, 0, 1) != 0)
		return -EAGAIN;

	if(send->id != IMAPCMD_DONE) {
		send->str[0] = tagid / 10 + '0';
		send->str[1] = tagid % 10 + '0';
	}

	/**
	 * Fill appropriate receive handler fields
	 */
	init_waitqueue_head(&h->qwait);
	h->rcv = rcv;

	if((send->cont) &&
			(atomic_cmpxchg(&i->ctag, NRTAG, tagid) != NRTAG)) {
		ret = -EAGAIN;
		goto release;
	}

	/**
	 * Use atomic_xchg() because it uses memory barrier in contrary of
	 * atomic_set()
	 */
	if(atomic_xchg(&h->ready, 1) == 1)
		pr_err("[MFS/IMAP]: Receiver handler list was corrupt");

	ret = mfs_imap_send_cmd(clt, send);
	if(ret < 0)
		goto release;

	/**
	 * Sleep here waiting for response
	 */
	ret = wait_event_interruptible_timeout(h->qwait,
			!atomic_read(&h->ready), IMAP_TIMEOUT);
	if(ret < 0) {
		goto release;
	} else if(ret == 0) {
		/**
		 * Better error code for timeout
		 */
		ret = -EINVAL;
		goto release;
	}

	ret = 0;

release:
	if(send->cont)
		atomic_cmpxchg(&i->ctag, tagid, NRTAG);
	/**
	 * Release receive handler slot
	 */
	atomic_xchg(&h->ready, 0);
	atomic_xchg(&h->reserved, 0);
	return ret;
}

static inline int imap_send_idle(struct mfs_client *clt, struct imap_msg **r)
{
	struct imap *i = (struct imap*)clt->private_data;
	struct imap_rcv_handle *h;
	ssize_t ret;
	static struct imap_cmd imap_idlecmd = {
		.str = STR(IDLETAG) " IDLE" "\r\n",
		.len = sizeof(STR(IDLETAG) " IDLE" "\r\n") - 1,
		.id = IMAPCMD_IDLE,
		.cont = 1
	};

	/**
	 * Set appropriate tag and reserved receive slot
	 */
	h = &i->rcv_handle[IDLETAG];
	if(atomic_cmpxchg(&h->reserved, 0, 1) != 0)
		return -EAGAIN;

	/**
	 * Fill appropriate receive handler fields
	 */
	init_waitqueue_head(&h->qwait);
	h->rcv = r;

	if((atomic_cmpxchg(&i->ctag, NRTAG, IDLETAG) != NRTAG)) {
		ret = -EAGAIN;
		goto release;
	}

	/**
	 * Use atomic_xchg() because it uses memory barrier in contrary of
	 * atomic_set()
	 */
	if(atomic_xchg(&h->ready, 1) == 1)
		pr_err("[MFS/IMAP]: Receiver handler list was corrupt");

	ret = __mfs_imap_send_cmd(clt, &imap_idlecmd);
	if(ret < 0)
		goto release;

	/**
	 * Sleep here waiting for response
	 */
	ret = wait_event_interruptible_timeout(h->qwait,
			!atomic_read(&h->ready), IMAP_TIMEOUT);
	if(ret < 0) {
		goto release;
	} else if(ret == 0) {
		/**
		 * Better error code for timeout
		 */
		ret = -EINVAL;
		goto release;
	}

	ret = 0;

release:
	atomic_cmpxchg(&i->ctag, IDLETAG, NRTAG);

	/**
	 * Release receive handler slot
	 */
	atomic_xchg(&h->ready, 0);
	atomic_xchg(&h->reserved, 0);
	return ret;
}

static inline int imap_send_unidle(struct mfs_client *clt, struct imap_msg **r)
{
	struct imap *i = (struct imap*)clt->private_data;
	struct imap_rcv_handle *h;
	ssize_t ret;
	static struct imap_cmd imap_donecmd = {
		.str = "DONE" "\r\n",
		.len = sizeof("DONE" "\r\n") - 1,
		.id = IMAPCMD_DONE,
	};


	/**
	 * Set appropriate tag and reserved receive slot
	 */
	h = &i->rcv_handle[IDLETAG];
	if(atomic_cmpxchg(&h->reserved, 0, 1) != 0)
		return -EAGAIN;

	/**
	 * Fill appropriate receive handler fields
	 */
	init_waitqueue_head(&h->qwait);
	h->rcv = r;

	/**
	 * Use atomic_xchg() because it uses memory barrier in contrary of
	 * atomic_set()
	 */
	if(atomic_xchg(&h->ready, 1) == 1)
		pr_err("[MFS/IMAP]: Receiver handler list was corrupt");

	ret = __mfs_imap_send_cmd(clt, &imap_donecmd);
	if(ret < 0)
		goto release;

	/**
	 * Sleep here waiting for response
	 */
	ret = wait_event_interruptible_timeout(h->qwait,
			!atomic_read(&h->ready), IMAP_TIMEOUT);
	if(ret < 0) {
		goto release;
	} else if(ret == 0) {
		/**
		 * Better error code for timeout
		 */
		ret = -EINVAL;
		goto release;
	}

	ret = 0;

release:
	/**
	 * Release receive handler slot
	 */
	atomic_xchg(&h->ready, 0);
	atomic_xchg(&h->reserved, 0);
	return ret;
}

static int imap_unidle(struct mfs_client *clt)
{
	struct imap *i = (struct imap*)clt->private_data;
	struct imap_msg *r;
	struct imap_elt *e;
	int ret;

	/**
	 * Here imap should be locked by imap_send_cmd
	 */
	ret = imap_send_unidle(clt, &r);
	if(ret < 0)
		goto out;

	list_for_each_entry(e, &r->elt, next) {
		if(!IMAP_ELT_ATOM(e))
			continue;
		ret = strcmp(IMAP_ELT_ATOM(e), "OK");
		if(ret == 0)
			break;
	}

	mfs_imap_msg_put(r);

	if(ret > 0 || ret < 0) {
		IMAP_DBG("Failed to unidle\n");
		return -EINVAL;
	}

	atomic_xchg(&i->idling, 0);

out:
	return ret;
}

static int imap_send_cmd(struct mfs_client *clt, struct imap_cmd *send,
		struct imap_msg **rcv)
{
	INIT_LIST_HEAD(&send->next);
	return _imap_send_cmd(clt, send, rcv);
}

/**
 * This is the thread function that keep imap idling
 */
static int imap_idle(void *data)
{
	struct mfs_client *clt = (struct mfs_client *)data;
	struct imap *i = (struct imap*)clt->private_data;
	struct imap_msg *r;
	int ret;

	while(!kthread_should_stop()) {
		ret = wait_event_interruptible_timeout(i->idlwait,
				!atomic_read(&i->idling), IMAP_IDLE_TIMEOUT);

		if(kthread_should_stop())
			break;

		if(ret == -ERESTARTSYS)
			continue;

		/**
		 * At idle timeout, we should first unidle
		 */
		if(atomic_read(&i->idling)) {
			ret = imap_unidle(clt);
			if(ret < 0) {
				IMAP_DBG("Fail to unidle\n");
				continue;
			}
		}

		ret = imap_send_idle(clt, &r);
		if(ret < 0) {
			IMAP_DBG("Fail to idle\n");
			continue;
		}

		mfs_imap_msg_put(r);

	}

	return 0;
}

#define list_last_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)

static int imap_rcv_box(struct mfs_client *clt, struct imap_msg *m)
{
	struct imap_elt *e;
	int ret;

	e = list_last_entry(&m->elt, struct imap_elt, next);
	if(e->type != IET_ATOM)
		IMAP_DBG("Wrong box list message\n");

	ret = imap_add_box(clt, IMAP_ELT_ATOM(e));
	if(ret != 0) {
		IMAP_DBG("Failed to create box %s\n", IMAP_ELT_ATOM(e));
		return 0;
	}
	IMAP_DBG("Box %s created\n", IMAP_ELT_ATOM(e));

	return 0;
}

static inline int imap_fetch_body(struct mfs_client *clt, char const *name,
		char const *data)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct message *m;

	list_for_each_entry(m, &i->fetching, fetch_next) {
		if(strcmp(m->name, name) == 0)
			break;
	}

	if(strcmp(m->name, name) != 0)
		return -1;

	m->mfetch = imap_new_msgcache(data);
	if(m->mfetch == NULL)
		return -1;

	return 0;
}

static int imap_rcv_mail(struct mfs_client *clt, struct imap_msg *m)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct imap_elt *r = NULL, *p, *e;
	char name[32];
	int ret, uid_elt = 0, body = 0;
	off_t uid;

	e = list_last_entry(&m->elt, struct imap_elt, next);
	if(e->type != IET_LIST) {
		IMAP_DBG("Malformed fetch message %s\n", e->data);
		return 0;
	}

	list_for_each_entry(p, &IMAP_ELT_MSG(e)->elt, next) {
		if(uid_elt) {
			r = p;
			break;
		} else if((p->type == IET_ATOM) &&
				(strcmp(IMAP_ELT_ATOM(p), "UID") == 0)) {
			uid_elt = 1;
		}
	}

	if(r == NULL || r->type != IET_NUMBER) {
		IMAP_DBG("Malformed fetch message 2\n");
		return 0;
	}

	uid = *IMAP_ELT_NUM(r);
	snprintf(name, 31, "%lu", uid);
	name[31] = '\0';

	list_for_each_entry(p, &r->next, next) {
		if(body) {
			r = p;
			break;
		} else if((p->type == IET_ATOM) &&
				(strcmp(IMAP_ELT_ATOM(p), "BODY[]") == 0)) {
			body = 1;
		}
	}

	/**
	 * If fetching body do fetch else add mail in filesystem
	 */
	/**
	 * TODO lock box here ????
	 */
	if(uid > i->selbox->uidlast) {
		i->selbox->uidlast = uid;
		i->selbox->sidlast++;
		ret = imap_add_mail(clt, uid, i->selbox->sidlast, name);
		if(ret != 0) {
			IMAP_DBG("Failed to fetch message %s\n", name);
			return 0;
		}
	}

	if(body) {
		if(r == NULL || r->type != IET_STRING) {
			IMAP_DBG("Malformed fetch message 2\n");
			return 0;
		}
		ret = imap_fetch_body(clt, name, IMAP_ELT_STR(r));
		if(ret != 0) {
			IMAP_DBG("Cannot fetch body for message %s\n", name);
			return 0;
		}
		IMAP_DBG("Fetched msg body");
	}

	IMAP_DBG("Message fetched %s\n", name);
	return 0;
}

static int imap_new_mail(struct mfs_client *clt, struct imap_msg *m)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct imap_cmd *c;
	int ret;

	if(i->selbox == NULL)
		return 0;

	/**
	 * Todo do not fetch if seqid > EXISTS
	 */
	c = imap_create_cmd(i, IMAPCMD_FETCHFROM, i->selbox->uidlast + 1);
	if(IS_ERR(c))
		return 0;

	ret = imap_send_cmd(clt, c, NULL);

	imap_cleanup_cmd(c);

	return 0;
}

static int imap_del_mail(struct mfs_client *clt, struct imap_msg *m)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct imap_elt *p;
	struct message *msg;
	off_t n = 0;

	list_for_each_entry(p, &m->elt, next) {
		if(n == 1)
			break;
		++n;
	}

	if(p == NULL || p->type != IET_NUMBER) {
		IMAP_DBG("Malformed EXPUNGE\n");
		return 0;
	}

	list_for_each_entry(msg, &i->selbox->msg, box_next)
		if(msg->seqid == *IMAP_ELT_NUM(p))
			break;

	if(msg->seqid != *IMAP_ELT_NUM(p)) {
		IMAP_DBG("Failed to find message to remove\n");
		return 0;
	}

	if(imap_rm_mail(clt, msg->name) != 0) {
		IMAP_DBG("Failed to remove message %s\n", msg->name);
		return 0;
	}

	--i->selbox->sidlast;

	list_for_each_entry(msg, &i->selbox->msg, box_next)
		if(msg->seqid > *IMAP_ELT_NUM(p))
			msg->seqid--;

	IMAP_DBG("Message removed\n");

	return 0;
}

#define IACTION_DEFINE(s, o, a) {					\
	.token = s,							\
	.off = o,							\
	.action = a,							\
}

struct {
	int (*action)(struct mfs_client *clt, struct imap_msg *im);
	char *token;
	size_t off;
} iaction[] = {
	IACTION_DEFINE("LIST", 1, imap_rcv_box),
	IACTION_DEFINE("FETCH", 2, imap_rcv_mail),
	IACTION_DEFINE("EXISTS", 2, imap_new_mail),
	IACTION_DEFINE("EXPUNGE", 2, imap_del_mail),
};

#define IACTIONSZ (sizeof(iaction) / sizeof(*iaction))

/**
 * Process an imap message
 */
static inline int imap_process_msg(struct mfs_client *clt, struct imap_msg *msg)
{
	struct imap_elt *e;
	struct imap *i = (struct imap *)clt->private_data;
	struct imap_rcv_handle *r;
	size_t o;
	unsigned int tagid, n;

	/**
	 * Send response to the waiting thread
	 */
	e = list_first_entry(&msg->elt, struct imap_elt, next);
	if((e->type == IET_ATOM) && (strcmp(IMAP_ELT_ATOM(e), "+") == 0)) {
		tagid = atomic_read(&i->ctag);
		if(tagid == NRTAG) {
			IMAP_DBG("Continuation command bug\n");
			return 0;
		}

		if(tagid == IDLETAG) {
			atomic_xchg(&i->idling, 1);
			wake_up_interruptible(&i->idlwait);
		}

		r = &i->rcv_handle[tagid];

		if(atomic_xchg(&r->ready, 0) == 1) {
			if(mfs_imap_msg_get(msg) != 0)
				*(r->rcv) = msg;
			IMAP_DBG("Rcv continuation command response\n");
			/**
			 * Wake up process that is waiting for a response
			 */
			wake_up_interruptible(&r->qwait);
		}
	} else if((e->type == IET_NUMBER) && (*IMAP_ELT_NUM(e) < NRTAG)) {
		tagid = *IMAP_ELT_NUM(e);
		r = &i->rcv_handle[tagid];
		if(atomic_xchg(&r->ready, 0) == 1) {
			if(mfs_imap_msg_get(msg) != 0)
				*(r->rcv) = msg;
			IMAP_DBG("Rcv tagid %u for msg %p\n", tagid, msg);
			/**
			 * Wake up process that is waiting for a response
			 */
			wake_up_interruptible(&r->qwait);
		}
	}

	/**
	 * Do some action for this message
	 */
	for(n = 0; n < IACTIONSZ; ++n) {
		o = 0;
		/**
		 * Find matching element from message
		 */
		list_for_each_entry(e, &msg->elt, next) {
			if(o == iaction[n].off)
				break;
			++o;
		}

		if(o != iaction[n].off)
			continue;

		/**
		 * If matching action, execute action
		 */
		if((e->type == IET_ATOM) && (strcmp(IMAP_ELT_ATOM(e),
						iaction[n].token) == 0)) {
			iaction[n].action(clt, msg);
			break;
		}
	}

	if(!(i->flags & IMAP_CONN)) {
		i->flags |= IMAP_CONN;
		/**
		 * Wake up all connection waiting process
		 */
		wake_up_all(&i->rcvwait);
	}

	return 0;
}

#define MFS_IMAP_BUFLEN 2048

static int imap_receive(void *data)
{
	struct imap_msg *im;
	struct mfs_client *clt = (struct mfs_client *)data;
	struct imap_parse_ctx *c;
	char *b;
	char const *p;
	size_t l = 0;

	b = kmalloc(MFS_IMAP_BUFLEN * sizeof(*b), GFP_KERNEL);
	if(b == NULL) {
		IMAP_DBG("[MFS/IMAP] Out of memory\n");
		return -ENOMEM;
	}

	c = mfs_imap_parse_new_ctx();
	if(c == NULL) {
		kfree(b);
		IMAP_DBG("[MFS/IMAP] Out of memory\n");
		return -ENOMEM;
	}

	while(!kthread_should_stop()) {
		l = mfs_client_kernel_net_recv(clt, b, MFS_IMAP_BUFLEN - 1);

		if(kthread_should_stop())
			break;

		if(l <= 0)
			continue;

		p = b;
		/**
		 * Iterate over all received messages
		 */
		while(!IS_ERR_OR_NULL((im = mfs_imap_parse_msg(c, &p, &l)))) {
			imap_process_msg(clt, im);
			mfs_imap_msg_put(im);
		}
	}

	mfs_imap_parse_del_ctx(c);
	kfree(b);

	return 0;
}

static int imap_send(void *data)
{
	struct mfs_client *clt = (struct mfs_client *)data;
	struct imap *i = (struct imap*)clt->private_data;
	struct list_head *msg;
	struct imap_cmd *c, *n;
	int ret;

	while(!kthread_should_stop()) {
		ret = mfs_cmdqueue_wait(&i->send, &msg);
		if(ret < 0) {
			list_for_each_entry_safe(c, n, msg, next) {
				list_del(&c->next);
				imap_cleanup_cmd(c);
			}
			continue;
		}

		list_for_each_entry_safe(c, n, msg, next) {
			if(atomic_read(&i->idling)) {
				do {
					schedule();
					ret = imap_unidle(clt);
				} while(ret == -EAGAIN);
				if(ret < 0) {
					imap_cleanup_cmd(c);
					continue;
				}
			}

			__mfs_imap_send_cmd(clt, c);
			list_del(&c->next);
			imap_cleanup_cmd(c);

			if(!atomic_read(&i->idling) &&
					!(i->flags & IMAP_EXIT) &&
					!(i->flags & IMAP_INIT)) {
				wake_up_interruptible(&i->idlwait);
				ret = wait_event_interruptible_timeout(i->idlwait, atomic_read(&i->idling), IMAP_IDLE_TIMEOUT);
			}
		}
	}

	return 0;
}

static int imap_get_msg_body(struct mfs_client *clt, struct message *msg)
{
	struct imap_cmd *c;
	struct imap_msg *r;
	struct imap_elt *e;
	struct imap *i = (struct imap *)clt->private_data;
	int ret;

	c = imap_create_cmd(i, IMAPCMD_FETCHMAIL, msg->uid);
	if(IS_ERR(c))
		return PTR_ERR(c);

	list_add_tail(&msg->fetch_next, &i->fetching);

	ret = imap_send_cmd(clt, c, &r);

	imap_cleanup_cmd(c);
	list_del(&msg->fetch_next);
	INIT_LIST_HEAD(&msg->fetch_next);

	if(ret < 0)
		goto out;

	list_for_each_entry(e, &r->elt, next) {
		if(!IMAP_ELT_ATOM(e))
			continue;
		ret = strcmp(IMAP_ELT_ATOM(e), "OK");
		if(ret == 0)
			break;
	}

	mfs_imap_msg_put(r);

	if(ret > 0 || ret < 0) {
		IMAP_DBG("Failed to fetch mail\n");
		return -EINVAL;
	}

out:
	return ret;
}

static int imap_put_msg_body(struct message *msg)
{
	imap_del_msgcache(msg->mfetch);
	return 0;
}

static inline int mfs_imap_login(struct mfs_client *clt)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct imap_cmd *c;
	struct imap_elt *e;
	struct imap_msg *r;
	int ret;

	c = imap_create_cmd(i, IMAPCMD_LOGIN, NAME, PASS);
	if(IS_ERR(c))
		return PTR_ERR(c);

	ret = imap_send_cmd(clt, c, &r);

	imap_cleanup_cmd(c);

	if(ret < 0)
		goto out;

	list_for_each_entry(e, &r->elt, next) {
		if(!IMAP_ELT_ATOM(e))
			continue;
		ret = strcmp(IMAP_ELT_ATOM(e), "OK");
		if(ret == 0)
			break;
	}

	mfs_imap_msg_put(r);

	if(ret > 0 || ret < 0) {
		IMAP_DBG("Failed to login\n");
		return -EINVAL;
	}

out:
	return ret;
}

static inline int mfs_imap_get_boxes(struct mfs_client *clt)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct imap_cmd *c;
	struct imap_elt *e;
	struct imap_msg *r;
	int ret;

	c = imap_create_cmd(i, IMAPCMD_LIST);
	if(IS_ERR(c))
		return PTR_ERR(c);

	ret = imap_send_cmd(clt, c, &r);

	imap_cleanup_cmd(c);

	if(ret < 0)
		goto out;

	list_for_each_entry(e, &r->elt, next) {
		if(!IMAP_ELT_ATOM(e))
			continue;
		ret = strcmp(IMAP_ELT_ATOM(e), "OK");
		if(ret == 0)
			break;
	}

	mfs_imap_msg_put(r);

	if(ret > 0 || ret < 0) {
		IMAP_DBG("Failed to receive boxes list\n");
		return -EINVAL;
	}

	IMAP_DBG("Received boxes list\n");

out:
	return ret;
}

static inline int mfs_imap_select_inbox(struct mfs_client *clt)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct imap_cmd *c;
	struct imap_elt *e;
	struct imap_msg *r;
	struct box *b;
	int ret;

	list_for_each_entry(b, &i->boxes, next) {
		if(strcmp("INBOX", b->name) == 0)
			break;
	}

	if(strcmp("INBOX", b->name) != 0)
		return -EINVAL;

	c = imap_create_cmd(i, IMAPCMD_SELECT, "INBOX");
	if(IS_ERR(c))
		return PTR_ERR(c);

	ret = imap_send_cmd(clt, c, &r);

	imap_cleanup_cmd(c);

	if(ret < 0)
		goto out;

	list_for_each_entry(e, &r->elt, next) {
		if(!IMAP_ELT_ATOM(e))
			continue;
		ret = strcmp(IMAP_ELT_ATOM(e), "OK");
		if(ret == 0)
			break;
	}

	mfs_imap_msg_put(r);

	if(ret > 0 || ret < 0) {
		IMAP_DBG("Failed to select inbox\n");
		return -EINVAL;
	}

	i->selbox = b;
	IMAP_DBG("inbox selected\n");

out:
	return ret;
}

static inline int mfs_imap_list_mail(struct mfs_client *clt)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct imap_cmd *c;
	struct imap_elt *e;
	struct imap_msg *r;
	int ret;

	c = imap_create_cmd(i, IMAPCMD_FETCHALL);
	if(IS_ERR(c))
		return PTR_ERR(c);

	ret = imap_send_cmd(clt, c, &r);

	imap_cleanup_cmd(c);

	if(ret < 0)
		goto out;

	list_for_each_entry(e, &r->elt, next) {
		if(!IMAP_ELT_ATOM(e))
			continue;
		ret = strcmp(IMAP_ELT_ATOM(e), "OK");
		if(ret == 0)
			break;
	}

	mfs_imap_msg_put(r);

	if(ret > 0 || ret < 0) {
		IMAP_DBG("Failed to get mail list\n");
		return -EINVAL;
	}

	IMAP_DBG("Mail list fetched\n");

out:
	return ret;
}

static int mfs_imap_connect(struct mfs_client *clt)
{
	struct imap *i;
	int ret = 0;

	i = MFS_IMAP_ALLOC();
	if(i == NULL)
		return -ENOMEM;

	clt->private_data = i;

	i->rcv_thread = kthread_run(imap_receive, clt, "kmfs_imap_rcv");
	i->snd_thread = kthread_run(imap_send, clt, "kmfs_imap_send");

	mfs_imap_wait_conn(i, 0);

	ret = mfs_imap_login(clt);
	if(ret < 0)
		return ret;

	ret = mfs_imap_get_boxes(clt);
	if(ret < 0)
		return ret;

	ret = mfs_imap_select_inbox(clt);
	if(ret < 0)
		return ret;

	ret = mfs_imap_list_mail(clt);
	if(ret < 0)
		return ret;

	i->idl_thread = kthread_run(imap_idle, clt, "kmfs_imap_idle");
	i->flags &= ~IMAP_INIT;

	return ret;
}

static void mfs_imap_kill_thread(struct imap *i)
{
	/**
	 * XXX The following is not race condition safe
	 * TODO set thread state to stop, use smb_mb() init_completion
	 * and wait_for_completion
	 */
	force_sig(SIGHUP, i->rcv_thread);
	kthread_stop(i->rcv_thread);
	force_sig(SIGHUP, i->snd_thread);
	kthread_stop(i->snd_thread);
	force_sig(SIGHUP, i->idl_thread);
	kthread_stop(i->idl_thread);
}

static void mfs_imap_close(struct mfs_client *clt)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct imap_cmd *c;

	c = imap_create_cmd(i, IMAPCMD_LOGOUT);
	if(IS_ERR(c))
		goto ifree;

	i->flags |= IMAP_EXIT;
	imap_send_cmd(clt, c, NULL);
	imap_cleanup_cmd(c);


	mfs_imap_kill_thread(i);
ifree:
	MFS_IMAP_FREE(clt->private_data);
}

static ssize_t mfs_imap_read(struct mfs_client *clt, struct file *f,
		void *pdata, char __user *buf, size_t size, loff_t off)
{
	struct msgdesc *md = (struct msgdesc *)pdata;
	struct message *msg;
	ssize_t ret = -EINVAL;
	size_t len;

	/**
	 * XXX Need to lock imap
	 */
	switch(md->ftype) {
	case MFS_IMAP_F_MAIL:
		msg = container_of(md, struct message, msgd);

		ret = imap_get_msg_body(clt, msg);
		if(ret != 0)
			break;

		if(off >= msg->mfetch->len) {
			ret = 0;
			break;
		}

		len = min(size, (size_t)(msg->mfetch->len - off));
		ret = copy_to_user(buf, msg->mfetch->body + off, len);
		if(ret == 0)
			ret = len;
		imap_put_msg_body(msg);
		break;
	default:
		IMAP_DBG("Invalid imap file type");
		break;
	}

	return ret;
}

static ssize_t mfs_imap_write(struct mfs_client *clt, struct file *f,
		void *pdata, const char __user *buf, size_t size)
{
	return -EINVAL;
}

struct mfs_client_operations imapops = {
	.connect = mfs_imap_connect,
	.close = mfs_imap_close,
	.read = mfs_imap_read,
	.write = mfs_imap_write,
};
