#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/uaccess.h>

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

enum mfs_imap_f_type {
	MFS_IMAP_F_UNKNOWN,
	MFS_IMAP_F_MAIL,
};

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
	IMAPCMD_FETCHMAIL,
	IMAPCMD_NR
};

#define IMAPCMD_TAG(id, s) [id] = (ITAG s "\r\n")

static char const * cmdfmt[] = {
	IMAPCMD_TAG(IMAPCMD_LOGIN, "LOGIN %s %s"),
	IMAPCMD_TAG(IMAPCMD_LOGOUT, "LOGOUT"),
	IMAPCMD_TAG(IMAPCMD_LIST, "LIST \"\" \"*\""),
	IMAPCMD_TAG(IMAPCMD_SELECT, "SELECT %s"),
	IMAPCMD_TAG(IMAPCMD_FETCHALL, "UID FETCH 1:* FLAGS"),
	IMAPCMD_TAG(IMAPCMD_FETCHMAIL, "UID FETCH %s BODY[]"),
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
	struct list_head cache_next;
	struct list_head fetch_next;
	struct msgcache *mfetch;
	unsigned int flags;
	char uid[];
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
	struct list_head fetching;
	struct box *selbox;
	wait_queue_head_t rcvwait;
	size_t mcachesz;
	atomic_t next_tag;
	unsigned int flags;
	struct msgcache *mcache[];
};

#define IMAP_CONN (1 << 0)
#define IMAP_AUTH (1 << 1)

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

static inline struct message *imap_new_msg(char const *uid)
{
	struct message *m;

	m = kmalloc(sizeof(*m) + strlen(uid) + 1, GFP_KERNEL);

	if(m == NULL)
		return m;

	m->msgd.ftype = MFS_IMAP_F_MAIL;
	strcpy(m->uid, uid);

	return m;
}

static inline void imap_del_msg(struct message *m)
{
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
		INIT_LIST_HEAD(&i->fetching);
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
	struct imap *i = (struct imap *)clt->private_data;
	struct message *m;

	if(i->selbox == NULL)
		return -1;

	m = imap_new_msg(name);
	if(m == NULL)
		return -1;

	mfs_inode_create_file(clt->sb, i->selbox->dir, name, &m->msgd);
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
		if(strcmp(m->uid, name) == 0)
			break;
	}

	if(strcmp(m->uid, name) != 0)
		return -1;

	m->mfetch = imap_new_msgcache(data);
	if(m->mfetch == NULL)
		return -1;

	return 0;
}

static int imap_rcv_mail(struct mfs_client *clt, struct imap_msg *m)
{
	struct imap_elt *r = NULL, *p, *e;
	char name[32];
	int ret, uid = 0, fetch = 0;

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

	list_for_each_entry(p, &r->next, next) {
		if(fetch) {
			r = p;
			break;
		} else if((p->type == IET_ATOM) &&
				(strcmp(IMAP_ELT_ATOM(p), "BODY[]") == 0)) {
			fetch = 1;
		}
	}

	/**
	 * If fetching body do fetch else add mail in filesystem
	 */

	if(!fetch) {
		ret = imap_add_mail(clt, name);
		if(ret != 0) {
			IMAP_DBG("Failed to fetch message %s\n", name);
			return 0;
		}
	} else {
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
	char *buf;
	char const *p;
	size_t len;

	buf = kmalloc(2048 * sizeof(*buf), GFP_KERNEL);
	if(buf == NULL) {
		IMAP_DBG("[MFS/IMAP] Out of memory\n");
		return -ENOMEM;
	}

	while(!kthread_should_stop()) {
		len = mfs_client_kernel_net_recv(clt, buf, 2047);
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
		while(!IS_ERR_OR_NULL((im = mfs_imap_parse_msg(&p, &len)))) {
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

	ret = mfs_client_kernel_net_send(clt, c->str, c->len);
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

	mfs_client_kernel_net_send(clt, c->str, c->len);
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
