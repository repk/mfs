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
#include "mfs_cmdqueue.h"
#include "mfs_imap.h"
#include "mfs_imap_send.h"
#include "mfs_imap_parse.h"

#ifndef DEBUG
#define IMAP_DBG(...)
#else
#define IMAP_DBG(...) pr_err("[MFS/IMAP]: " __VA_ARGS__)
#endif

/**
 * Keep enough space for 3 digits tag
 */
#define ITAG "## "

#define MSGCACHESZ 128
#define BODYMAXLEN (1 << 16)

enum mfs_imap_f_type {
	MFS_IMAP_F_UNKNOWN,
	MFS_IMAP_F_MAIL,
	MFS_IMAP_F_BOX,
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
	IMAPCMD_TAG(IMAPCMD_SELECT, "SELECT \"%s\""),
	IMAPCMD_TAG(IMAPCMD_FETCHALL, "UID FETCH 1:* FLAGS"),
	IMAPCMD_TAG(IMAPCMD_FETCHFROM, "UID FETCH %lu:* FLAGS"),
	IMAPCMD_TAG(IMAPCMD_FETCHFULLMAIL, "UID FETCH %lu BODY[]"),
	IMAPCMD_TAG(IMAPCMD_FETCHMAIL, "UID FETCH %lu BODY[]<%lld.%zu>"),
	IMAPCONTCMD_TAG(IMAPCMD_IDLE, "IDLE"),
	IMAPCMD_TAG(IMAPCMD_DONE, "DONE"),
};

struct msgcache {
	struct message *m;
	loff_t off;
	size_t len;
	char body[];
};

struct filedesc {
	enum mfs_imap_f_type ftype;
};

struct message {
	struct filedesc msgd;
	struct list_head box_next;
	struct list_head cache_next;
	struct list_head fetch_next;
	struct msgcache *mfetch;
	unsigned int flags;
	unsigned int uid;
	unsigned int seqid;
	char name[];
};

#define	MFS_IMAP_B_NOSELECT	1
#define	MFS_IMAP_B_HASCHILDREN	2

struct box {
	struct filedesc boxd;
	struct list_head next;
	struct list_head msg;
	struct list_head shrink;
	struct box *parent;
	struct dentry *dir;
	unsigned int type;
	off_t uidlast;
	off_t sidlast;
	char *name;
	char path[];
};

static inline struct msgcache *imap_new_msgcache(char const *data, loff_t off)
{
	struct msgcache *mc;

	mc = kmalloc(sizeof(*mc) + strlen(data) + 1, GFP_KERNEL);
	if(mc == NULL)
		return NULL;

	strcpy(mc->body, data);
	mc->len = strlen(data);
	mc->off = off;

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

void imap_cleanup_cmd(struct imap_cmd *c)
{
	kref_put(&c->refcnt, imap_del_cmd);
}

static struct box * imap_create_box(struct imap *i, char const *path,
		struct imap_msg *attr)
{
	struct box *b, *p;
	struct imap_elt *e;
	unsigned int type = 0;
	char const *end;

	list_for_each_entry(e, &attr->elt, next) {
		if(e->type != IET_ATOM)
			continue;
		if(strcmp(IMAP_ELT_ATOM(e), "\\Noselect") == 0)
			type |= MFS_IMAP_B_NOSELECT;
		else if(strcmp(IMAP_ELT_ATOM(e), "\\HasChildren") == 0)
			type |= MFS_IMAP_B_HASCHILDREN;
	}

	b = kmalloc(sizeof(*b) + strlen(path) + 1, GFP_KERNEL);
	if(b == NULL)
		return NULL;

	INIT_LIST_HEAD(&b->msg);
	INIT_LIST_HEAD(&b->shrink);
	b->boxd.ftype = MFS_IMAP_F_BOX;
	b->type = type;
	b->uidlast = 0;
	b->sidlast = 0;
	b->parent = NULL;
	b->name = b->path;

	/**
	 * Add mailbox parent
	 */
	end = strrchr(path, '/');
	if(end != NULL) {
		list_for_each_entry(p, &i->boxes, next) {
			if((p->type & MFS_IMAP_B_HASCHILDREN) &&
					(!strncmp(p->name, path, end - path)) &&
					(p->name[end - path] == '\0')) {
				b->parent = p;
				break;
			}
		}
		b->name = &b->path[end - path + 1];
	}

	strcpy(b->path, path);

	return b;
}

static void imap_del_box(struct box *b)
{
	/**
	 * remove dentry b->dir
	 */
	kfree(b);
}

static inline void mfs_imap_opt_init(struct imap_opt *opt)
{
	/**
	 * Put not NULL initialization HERE
	 */
}

static inline void mfs_imap_opt_clean(struct imap_opt *opt)
{
	if(opt->login)
		kfree(opt->login);
	if(opt->pass)
		kfree(opt->pass);
}

static inline int mfs_imap_opt_login(struct imap_opt *opt, char *sopt)
{
	char *p, *e;
	char *login;

	p = strstr(sopt, "login=");
	if(p == NULL) {
		IMAP_DBG("Missing login\n");
		return -EINVAL;
	}
	p += strlen("login=");

	e = strchr(p, ',');
	if(e == NULL)
		e = p + strlen(sopt);

	login = kmalloc(e - p + 1, GFP_KERNEL);
	if(login == NULL)
		return -EINVAL;

	memcpy(login, p, e - p);
	login[e - p] = '\0';

	opt->login = login;

	return 0;
}

static inline int mfs_imap_opt_pass(struct imap_opt *opt, char *sopt)
{
	char *p, *e;
	char *pass;

	p = strstr(sopt, "pass=");
	if(p == NULL) {
		IMAP_DBG("Missing pass\n");
		return -EINVAL;
	}
	p += strlen("pass=");

	e = strchr(p, ',');
	if(e == NULL)
		e = p + strlen(sopt);

	pass = kmalloc(e - p + 1, GFP_KERNEL);
	if(pass == NULL)
		return -EINVAL;

	memcpy(pass, p, e - p);
	pass[e - p] = '\0';

	opt->pass = pass;

	return 0;
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
		init_waitqueue_head(&i->conwait);
		mfs_cmdqueue_init(&i->send);
		INIT_LIST_HEAD(&i->boxes);
		INIT_LIST_HEAD(&i->fetching);
		atomic_set(&i->ctag, NRTAG);
		i->flags |= IMAP_INIT;
		mfs_imap_opt_init(&i->opt);
	}

	return i;
}

static inline void mfs_imap_free(struct imap *imap)
{
	struct box *p, *n;

	list_for_each_entry_safe(p, n, &imap->boxes, next)
		imap_del_box(p);

	mfs_imap_opt_clean(&imap->opt);

	kfree(imap);
}

static int mfs_imap_wait_conn(struct imap *i)
{
	int ret;

	ret = wait_event_interruptible_timeout(i->rcvwait,
			i->flags & IMAP_CONN, IMAP_TIMEOUT);
	if(ret == 0)
		ret = -EAGAIN;

	return ret;
}

#define MFS_IMAP_ALLOC() mfs_imap_alloc(MSGCACHESZ)
#define MFS_IMAP_FREE(i) mfs_imap_free(i)

static int imap_add_box(struct mfs_client *clt, char const *path,
		struct imap_msg *attr)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct box *b;
	struct dentry *dir, *parent = clt->sb->s_root;

	b = imap_create_box(i, path, attr);
	if(b == NULL)
		return -1;

	if(b->parent)
		parent = b->parent->dir;

	dir = mfs_inode_create_dir(clt->sb, parent, b->name, &b->boxd);
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

#define list_last_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)

static int imap_rcv_box(struct mfs_client *clt, struct imap_msg *m)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct imap_msg *attr = NULL;
	struct imap_elt *e;
	struct box *b;
	char *path = NULL;
	int ret;

	list_for_each_entry(e, &m->elt, next) {
		if(e->type == IET_LIST) {
			attr = IMAP_ELT_MSG(e);
			break;
		}
	}

	if(attr == NULL) {
		IMAP_DBG("Wrong box list message\n");
		return -1;
	}

	e = list_last_entry(&m->elt, struct imap_elt, next);
	if(e->type == IET_STRING) {
		path = IMAP_ELT_STR(e);
	} else if(e->type == IET_ATOM) {
		path = IMAP_ELT_ATOM(e);
	} else {
		IMAP_DBG("Wrong box list message\n");
		return -1;
	}

	/**
	 * If box already here, exit
	 */
	list_for_each_entry(b, &i->boxes, next) {
		if(strcmp(b->path, path) == 0) {
			IMAP_DBG("Box already created\n");
			return 0;
		}
	}

	ret = imap_add_box(clt, path, attr);
	if(ret != 0) {
		IMAP_DBG("Failed to create box %s\n", path);
		return -1;
	}
	IMAP_DBG("Box %s created\n", path);

	return 0;
}

static inline int imap_fetch_body(struct mfs_client *clt, char const *name,
		char const *data, loff_t off)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct message *m;

	list_for_each_entry(m, &i->fetching, fetch_next) {
		if(strcmp(m->name, name) == 0)
			break;
	}

	if(strcmp(m->name, name) != 0)
		return -1;

	m->mfetch = imap_new_msgcache(data, off);
	if(m->mfetch == NULL)
		return -1;

	return 0;
}

static inline void imap_keep_mail(struct mfs_client *clt, off_t uid)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct box *b = i->selbox;
	struct message *m;

	if(b == NULL)
		return;

	list_for_each_entry(m, &b->shrink, box_next) {
		if(m->uid == uid) {
			list_move(&m->box_next, &b->msg);
			break;
		}
	}
}

static inline void imap_prepare_shrink(struct mfs_client *clt)
{
	struct imap *i = (struct imap *)clt->private_data;

	list_splice_init(&i->selbox->msg, &i->selbox->shrink);
}

static inline void imap_shrink(struct mfs_client *clt)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct message *m, *tmp;

	list_for_each_entry_safe(m, tmp, &i->selbox->shrink, box_next) {
		imap_rm_mail(clt, m->name);
	}

	INIT_LIST_HEAD(&i->selbox->shrink);
}

static int imap_rcv_mail(struct mfs_client *clt, struct imap_msg *m)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct imap_elt *r = NULL, *p, *e;
	char name[32];
	int ret, uid_elt = 0, body = 0;
	loff_t off;
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
				(sscanf(IMAP_ELT_ATOM(p),
					"BODY[]<%lld>", &off) == 1)) {
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
	} else if(!list_empty(&i->selbox->shrink)) {
		/**
		 * We are doing a box shrink here to resynchronize mail
		 */
		imap_keep_mail(clt, uid);
	}

	if(body) {
		if(r == NULL || r->type != IET_STRING) {
			IMAP_DBG("Empty fetched message\n");
			return 0;
		}
		ret = imap_fetch_body(clt, name, IMAP_ELT_STR(r), off);
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

	/**
	 * Asynchronous mail fetching only if imap is idling
	 */
	if((i->selbox == NULL) || (atomic_read(&i->idling) == 0))
		return 0;

	/**
	 * Todo do not fetch if seqid > EXISTS
	 */
	c = imap_create_cmd(i, IMAPCMD_FETCHFROM, i->selbox->uidlast + 1);
	if(IS_ERR(c))
		return 0;

	ret = mfs_imap_send_cmd(clt, c, NULL);

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

static int imap_wait_hello(struct mfs_client *clt)
{
	struct imap *i = (struct imap *)clt->private_data;
	ssize_t l;

	l = mfs_client_kernel_wait_recv(clt, 7 * HZ);


	if(l > 0) {
		i->flags |= IMAP_CONN;
		/**
		 * Wake up all connection waiting process
		 */
		wake_up_all(&i->rcvwait);
	} else if(l == 0) {
		l = -EIO;
	}

	return l;
}

static int imap_receive(void *data)
{
	struct imap_msg *im;
	struct mfs_client *clt = (struct mfs_client *)data;
	struct imap_parse_ctx *c;
	struct imap *i = (struct imap *)clt->private_data;
	char *b;
	char const *p;
	size_t l = 0;
	int ret;

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

		if(l < 0) {
			schedule();
			continue;
		}

		/**
		 * This is a disconnection, try to reconnect
		 */
		if(l == 0) {
			i->flags &= ~IMAP_CONN;
			wake_up_interruptible(&i->conwait);
			do {
				ret = mfs_imap_wait_conn(i);
			} while(!kthread_should_stop() && ret <= 0);
			continue;
		}

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

static inline void imap_prepare_msg_fetch(struct mfs_client *clt,
		struct message *msg)
{
	struct imap *i = (struct imap *)clt->private_data;

	/** TODO BUG if msg->mfetch != NULL; */
	list_add_tail(&msg->fetch_next, &i->fetching);
}

static int imap_get_msg_body(struct mfs_client *clt, struct message *msg,
		loff_t offset, size_t len)
{
	struct imap_cmd *c;
	struct imap_msg *r;
	struct imap_elt *e;
	struct imap *i = (struct imap *)clt->private_data;
	int ret;

	c = imap_create_cmd(i, IMAPCMD_FETCHMAIL, msg->uid, offset, len);
	if(IS_ERR(c))
		return PTR_ERR(c);

	imap_prepare_msg_fetch(clt, msg);

	ret = mfs_imap_send_cmd(clt, c, &r);

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
	msg->mfetch = NULL;
	return 0;
}

static inline int mfs_imap_login(struct mfs_client *clt)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct imap_cmd *c;
	struct imap_elt *e;
	struct imap_msg *r;
	int ret;

	c = imap_create_cmd(i, IMAPCMD_LOGIN, i->opt.login, i->opt.pass);
	if(IS_ERR(c))
		return PTR_ERR(c);

	ret = mfs_imap_send_cmd(clt, c, &r);

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
		return -EACCES;
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

	ret = mfs_imap_send_cmd(clt, c, &r);

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

static inline int mfs_imap_select_box(struct mfs_client *clt, struct box *b)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct imap_cmd *c;
	struct imap_elt *e;
	struct imap_msg *r;
	struct box *box = i->selbox;
	int ret;

	i->selbox = NULL;

	c = imap_create_cmd(i, IMAPCMD_SELECT, b->path);
	if(IS_ERR(c))
		return PTR_ERR(c);

	ret = mfs_imap_send_cmd(clt, c, &r);

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
		IMAP_DBG("Failed to select box %s\n", b->path);
		return -EINVAL;
	}

	box = b;
	IMAP_DBG("Box %s selected\n", b->path);

out:
	i->selbox = box;
	return ret;
}

static inline int mfs_imap_select_inbox(struct mfs_client *clt)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct box *b;

	list_for_each_entry(b, &i->boxes, next) {
		if(strcmp("INBOX", b->name) == 0)
			break;
	}

	if(strcmp("INBOX", b->name) != 0)
		return -EINVAL;


	return mfs_imap_select_box(clt, b);
}

static inline int mfs_imap_sync_mail(struct mfs_client *clt)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct imap_cmd *c;
	struct imap_elt *e;
	struct imap_msg *r;
	int ret;

	if(i->selbox == NULL)
		return -EINVAL;

	imap_prepare_shrink(clt);

	c = imap_create_cmd(i, IMAPCMD_FETCHALL);
	if(IS_ERR(c))
		return PTR_ERR(c);

	ret = mfs_imap_send_cmd(clt, c, &r);

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
	imap_shrink(clt);
	return ret;
}

static inline int imap_parse_opt(struct mfs_client *clt, char *data)
{
	struct imap *i = (struct imap *)clt->private_data;
	int ret = -EINVAL;

	if(data == NULL) {
		IMAP_DBG("Missing imap options\n");
		goto err;
	}

	ret = mfs_imap_opt_login(&i->opt, data);
	if(ret < 0)
		goto err;

	ret = mfs_imap_opt_pass(&i->opt, data);
	if(ret < 0)
		goto err;

	return 0;

err:
	mfs_imap_opt_clean(&i->opt);
	return ret;
}

static int mfs_imap_connect(struct mfs_client *clt, char *data)
{
	struct imap *i;
	int ret = 0;

	i = MFS_IMAP_ALLOC();
	if(i == NULL)
		return -ENOMEM;

	clt->private_data = i;

	ret = imap_parse_opt(clt, data);
	if(ret < 0)
		goto out;

	ret = imap_wait_hello(clt);
	if(ret < 0)
		goto out;

	i->rcv_thread = kthread_run(imap_receive, clt, "kmfs_imap_rcv");
	i->snd_thread = kthread_run(mfs_imap_send_process, clt,
			"kmfs_imap_send");

	ret = mfs_imap_login(clt);
	if(ret < 0)
		goto out;

	ret = mfs_imap_get_boxes(clt);
	if(ret < 0)
		goto out;

	ret = mfs_imap_select_inbox(clt);
	if(ret < 0)
		goto out;

	ret = mfs_imap_sync_mail(clt);
	if(ret < 0)
		goto out;

	i->idl_thread = kthread_run(mfs_imap_keep_idling, clt,
			"kmfs_imap_idle");
	i->con_thread = kthread_run(mfs_imap_keep_connected, clt,
			"kmfs_imap_con");
	i->flags &= ~IMAP_INIT;

out:
	return ret;
}

static int mfs_imap_reconnect(struct mfs_client *clt)
{
	struct imap *i = (struct imap *)clt->private_data;
	int ret = 0;

	i->flags |= IMAP_INIT;

	wake_up_all(&i->rcvwait);

	ret = imap_wait_hello(clt);
	if(ret < 0)
		return ret;

	ret = mfs_imap_login(clt);
	if(ret < 0)
		return ret;

	ret = mfs_imap_get_boxes(clt);
	if(ret < 0)
		return ret;

	ret = mfs_imap_select_inbox(clt);
	if(ret < 0)
		return ret;

	ret = mfs_imap_sync_mail(clt);
	if(ret < 0)
		return ret;

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
	if(i->rcv_thread) {
		force_sig(SIGHUP, i->rcv_thread);
		kthread_stop(i->rcv_thread);
		i->rcv_thread = NULL;
	}
	if(i->snd_thread) {
		force_sig(SIGHUP, i->snd_thread);
		kthread_stop(i->snd_thread);
		i->snd_thread = NULL;
	}
	if(i->con_thread) {
		force_sig(SIGHUP, i->con_thread);
		kthread_stop(i->con_thread);
		i->con_thread = NULL;
	}
	if(i->idl_thread) {
		force_sig(SIGHUP, i->idl_thread);
		kthread_stop(i->idl_thread);
		i->idl_thread = NULL;
	}
}

static void mfs_imap_close(struct mfs_client *clt)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct imap_cmd *c;

	if(i == NULL)
		return;

	c = imap_create_cmd(i, IMAPCMD_LOGOUT);
	if(IS_ERR(c))
		goto killthread;

	i->flags |= IMAP_EXIT;
	mfs_imap_send_cmd(clt, c, NULL);
	imap_cleanup_cmd(c);


killthread:
	mfs_imap_kill_thread(i);
	MFS_IMAP_FREE(clt->private_data);
}

static ssize_t mfs_imap_read(struct mfs_client *clt, struct file *f,
		void *pdata, char __user *buf, size_t size, loff_t off)
{
	struct filedesc *fd = (struct filedesc *)pdata;
	struct message *msg;
	ssize_t ret = -EINVAL;
	size_t len;

	/**
	 * XXX Need to lock imap
	 */
	switch(fd->ftype) {
	case MFS_IMAP_F_MAIL:
		msg = container_of(fd, struct message, msgd);

		ret = imap_get_msg_body(clt, msg, off, size);
		if((ret != 0) || (msg->mfetch == NULL))
			break;

		if(off != msg->mfetch->off) {
			ret = 0;
			imap_put_msg_body(msg);
			break;
		}

		len = min(size, msg->mfetch->len);
		ret = copy_to_user(buf, msg->mfetch->body, len);
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

static int mfs_imap_readdir(struct mfs_client *clt, struct file *f,
		void *pdata, void *dirent, filldir_t filldir)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct filedesc *fd = (struct filedesc *)pdata;
	struct box *box;
	ssize_t ret = -EINVAL;

	/**
	 * XXX Need to lock imap
	 */
	switch(fd->ftype) {
	case MFS_IMAP_F_BOX:
		box = container_of(fd, struct box, boxd);
		if((box == i->selbox) || (box->type & MFS_IMAP_B_NOSELECT)) {
			ret = 0;
			break;
		}

		IMAP_DBG("Change to Box %s\n", box->name);
		ret = mfs_imap_select_box(clt, box);
		if(ret < 0)
			break;
		ret = mfs_imap_sync_mail(clt);
		break;
	default:
		IMAP_DBG("Invalid imap file type");
		break;
	}

	return ret;
}

struct mfs_client_operations imapops = {
	.connect = mfs_imap_connect,
	.close = mfs_imap_close,
	.reconnect = mfs_imap_reconnect,
	.read = mfs_imap_read,
	.write = mfs_imap_write,
	.readdir = mfs_imap_readdir,
};
