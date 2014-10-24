#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include <linux/fs.h>
#include <linux/err.h>

#include "mfs_client.h"
#include "mfs_inode.h"
#include "mfs_imap.h"
#include "mfs_imap_parse.h"

#define DEBUG

#ifndef DEBUG
#define IMAP_DBG(...)
#else
#define IMAP_DBG(...) pr_err("[MFS/IMAP]: " __VA_ARGS__)
#endif

#define MAXTAG 64
/**
 * Keep enough space for 3 digits tag
 */
#define ITAG "## "

#define MSGCACHESZ 128
#define BODYMAXLEN (1 << 16)

#define IMAP_TIMEOUT (msecs_to_jiffies(30000))

#define NAME "test"
#define PASS "test"

struct imap_cmd {
	char *str;
	ssize_t len;
};

enum imap_cmd_id {
	IMAPCMD_LOGIN,
	IMAPCMD_LOGOUT,
	IMAPCMD_LIST,
	IMAPCMD_SELECT,
	IMAPCMD_FETCHALL,
	IMAPCMD_NR
};

#define IMAPCMD_TAG(id, s) [id] = (ITAG s "\r\n")

static char const * cmdfmt[] = {
	IMAPCMD_TAG(IMAPCMD_LOGIN, "LOGIN %s %s"),
	IMAPCMD_TAG(IMAPCMD_LOGOUT, "LOGOUT"),
	IMAPCMD_TAG(IMAPCMD_LIST, "LIST \"\" \"*\""),
	IMAPCMD_TAG(IMAPCMD_SELECT, "SELECT %s"),
	IMAPCMD_TAG(IMAPCMD_FETCHALL, "UID FETCH 1:* FLAGS"),
};

struct msgcache {
	struct message *m;
	size_t len;
	char body[];
};

struct message {
	struct list_head next;
	struct msgcache *mfetch;
	unsigned int uid;
	unsigned int flags;
};

struct box {
	struct list_head next;
	struct message *msg;
	struct dentry *dir;
	char name[];
};

struct imap_rcv_handle {
	struct imap_msg **rcv;
	wait_queue_head_t qwait;
	atomic_t reserved;
	atomic_t ready;
};

struct imap {
	struct task_struct *thread;
	struct imap_rcv_handle rcv_handle[MAXTAG];
	struct list_head boxes;
	wait_queue_head_t rcvwait;
	size_t mcachesz;
	atomic_t next_tag;
	unsigned int flags;
	struct msgcache *mcache[];
};

#define IMAP_CONN (1 << 0)
#define IMAP_AUTH (1 << 1)

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
	len = vsnprintf(NULL, 0, cmdfmt[id], args);
	va_end(args);

	c = kmalloc(sizeof(*c) + len + 1, GFP_KERNEL);
	if(c == NULL) {
		c = ERR_PTR(-ENOMEM);
		goto out;
	}

	c->str = (char *)(c + 1);
	c->len = len;

	va_start(args, id);
	len = vsnprintf(c->str, len + 1, cmdfmt[id], args);
	va_end(args);

out:
	return c;

}

static void imap_cleanup_cmd(struct imap_cmd *c)
{
	kfree(c);
}

static struct box * imap_create_box(char const *name)
{
	struct box *b = kmalloc(sizeof(*b) + strlen(name) + 1, GFP_KERNEL);
	if(b == NULL)
		return NULL;

	b->msg = NULL;

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
		INIT_LIST_HEAD(&i->boxes);
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

static int imap_add_mail(struct mfs_client *clt, char const *name)
{
	/**
	 * Next STEP do this TODO
	 */
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

static int imap_rcv_mail(struct mfs_client *clt, struct imap_msg *m)
{
	struct imap_elt *r = NULL, *p, *e;
	char name[32];
	int ret, uid = 0;

	e = list_last_entry(&m->elt, struct imap_elt, next);
	if(e->type != IET_LIST) {
		IMAP_DBG("Malformed fetch message %s\n", e->data);
		return 0;
	}

	list_for_each_entry(p, &IMAP_ELT_MSG(e)->elt, next) {
		if(uid) {
			r = p;
			break;
		} else if((p->type == IET_ATOM) &&
				(strcmp(IMAP_ELT_ATOM(p), "UID") == 0)) {
			uid = 1;
		}
	}

	if(r == NULL || r->type != IET_NUMBER) {
		IMAP_DBG("Malformed fetch message 2\n");
		return 0;
	}

	snprintf(name, 31, "%u", *IMAP_ELT_NUM(r));
	name[31] = '\0';

	ret = imap_add_mail(clt, name);
	if(ret != 0) {
		IMAP_DBG("Failed to fetch message %s\n", name);
		return 0;
	}

	IMAP_DBG("Message fetched %s\n", name);
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
	if((e->type == IET_NUMBER) && (*IMAP_ELT_NUM(e) < MAXTAG)) {
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

static int imap_receive(void *data)
{
	struct imap_msg *im;
	struct mfs_client *clt = (struct mfs_client *)data;
	char *buf, *p, *nxt;
	size_t len, msglen;

	buf = kmalloc(2048 * sizeof(*buf), GFP_KERNEL);
	if(buf == NULL) {
		IMAP_DBG("[MFS/IMAP] Out of memory\n");
		return -ENOMEM;
	}

	while(!kthread_should_stop()) {
		len = mfs_client_kernel_read(clt, buf, 2047);
		/**
		 * XXX should lock imap
		 */
		if(len <= 2 || buf[len - 1] != '\n' || buf[len - 2] != '\r')
			continue;

		buf[len] = '\0';

		/**
		 * Iterate over all received messages
		 */
		p = buf;
		while((nxt = strstr(p, "\r\n")) != NULL) {
			msglen = nxt - p + 2;
			if(len < msglen) {
				pr_err("[MFS/IMAP] Bugged command parsing\n");
				continue;
			}

			im = mfs_imap_parse_msg(p, msglen);
			len -= msglen;
			p = nxt + 2;
			if(IS_ERR_OR_NULL(im)) {
				IMAP_DBG("Invalid imap msg");
				continue;
			}

			imap_process_msg(clt, im);
			mfs_imap_msg_put(im);
		}
	}

	kfree(buf);

	return 0;
}

static inline int __mfs_imap_send_cmd(struct mfs_client *clt,
		struct imap_cmd *c)
{
	size_t ret;

	ret = mfs_client_kernel_write(clt, c->str, c->len);
	if(ret < 0)
		return ret;

	return 0;
}

/**
 * Send command to server, if rcv is not NULL the send is done synchronously and
 * the thread goes to sleep until the response arrives
 */
static int imap_send_cmd(struct mfs_client *clt, struct imap_cmd *send,
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
		return __mfs_imap_send_cmd(clt, send);
	/**
	 * Here we prepare everything to get a synchronous send
	 */

	/**
	 * Set appropriate tag and reserved receive slot
	 */
	tagid = atomic_inc_return(&i->next_tag) % MAXTAG;
	h = &i->rcv_handle[tagid];
	if(atomic_xchg(&h->reserved, 1) == 1) {
		return -ENOMEM;
	}
	send->str[0] = tagid / 10 + '0';
	send->str[1] = tagid % 10 + '0';

	/**
	 * Fill appropriate receive handler fields
	 */
	init_waitqueue_head(&h->qwait);
	h->rcv = rcv;

	/**
	 * Use atomic_xchg() because it uses memory barrier in contrary of
	 * atomic_set()
	 */
	if(atomic_xchg(&h->ready, 1) == 1)
		pr_err("[MFS/IMAP]: Receiver handler list was corrupt");

	ret = __mfs_imap_send_cmd(clt, send);
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
	int ret;

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
	int ret;

	i = MFS_IMAP_ALLOC();
	if(i == NULL)
		return -ENOMEM;

	clt->private_data = i;

	i->thread = kthread_run(imap_receive, clt, "kmfs_imap");

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

	return ret;
}

static void mfs_imap_kill_thread(struct imap *i)
{
	/**
	 * XXX The following is not race condition safe
	 * TODO set thread state to stop, use smb_mb() init_completion
	 * and wait_for_completion
	 */
	force_sig(SIGHUP, i->thread);
	kthread_stop(i->thread);
}

static void mfs_imap_close(struct mfs_client *clt)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct imap_cmd *c;

	c = imap_create_cmd(i, IMAPCMD_LOGOUT);
	if(IS_ERR(c))
		goto ifree;

	mfs_client_kernel_write(clt, c->str, c->len);
	imap_cleanup_cmd(c);

	mfs_imap_kill_thread(i);
ifree:
	MFS_IMAP_FREE(clt->private_data);
}

struct mfs_client_operations imapops = {
	.connect = mfs_imap_connect,
	.close = mfs_imap_close,
};
