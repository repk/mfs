#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/err.h>
#include <linux/kref.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include <linux/jiffies.h>
#include <linux/delay.h>

#include "mfs_client.h"
#include "mfs_imap.h"
#include "mfs_cmdqueue.h"
#include "mfs_imap_send.h"

#ifndef DEBUG
#define IMAP_DBG(...)
#else
#define IMAP_DBG(...) pr_err("[MFS/IMAP]: " __VA_ARGS__)
#endif

#define XSTR(a) #a
#define STR(a) XSTR(a)

#define IMAP_IDLE_TIMEOUT (msecs_to_jiffies(28000 * 60)) /* 28 minutes */

/**
 * Find msg tag id considering a receive handler
 */
static inline int imap_handle_get_tag_id(struct imap *i,
		struct imap_rcv_handle *c)
{
	return (c - i->rcv_handle);
}

/**
 * Set appropriate tag and reserved receive slot
 */
static inline int imap_cmd_rsv_tag_id(struct imap *i, struct imap_cmd *c)
{
	int tagid;

	if(c->id == IMAPCMD_IDLE || c->id == IMAPCMD_DONE)
		tagid = IDLETAG;
	else
		tagid = atomic_inc_return(&i->next_tag) % MAXTAG;

	return tagid;
}

/**
 * Prepare a command to be sent
 */
static struct imap_rcv_handle *imap_prepare_cmd(struct mfs_client *clt,
		struct imap_cmd *send, struct imap_msg **rcv)
{
	struct imap *i = (struct imap*)clt->private_data;
	struct imap_rcv_handle *h;
	unsigned int tagid;
	struct imap_rcv_handle *ret = ERR_PTR(-EAGAIN);

	/**
	 * For asynchronous sending, no preparation is needed
	 */
	if(rcv == NULL)
		return NULL;

	/**
	 * Here we prepare everything to get a synchronous send
	 */

	tagid = imap_cmd_rsv_tag_id(i, send);

	h = &i->rcv_handle[tagid];
	if(atomic_cmpxchg(&h->reserved, 0, 1) != 0)
		goto out;

	if(send->id != IMAPCMD_DONE) {
		send->str[0] = tagid / 10 + '0';
		send->str[1] = tagid % 10 + '0';
	}

	/**
	 * Fill appropriate receive handler fields
	 */
	init_waitqueue_head(&h->qwait);
	h->rcv = rcv;

	/**
	 * If command expect continuous response
	 */
	if((send->cont) &&
			(atomic_cmpxchg(&i->ctag, NRTAG, tagid) != NRTAG))
		goto out;

	/**
	 * Use atomic_xchg() because it uses memory barrier in contrary of
	 * atomic_set()
	 */
	if(atomic_xchg(&h->ready, 1) == 1)
		pr_err("[MFS/IMAP]: Receiver handler list was corrupt");

	ret = h;

out:
	return ret;
}

/**
 * Wait for sent command response
 */
static inline int imap_wait_cmd(struct mfs_client *clt, struct imap_cmd *send,
		struct imap_rcv_handle *h)
{
	/**
	 * Sleep here waiting for response
	 */
	return wait_event_interruptible_timeout(h->qwait,
			!atomic_read(&h->ready), IMAP_TIMEOUT);
}

/**
 * Realease a sent command
 */
static int imap_release_cmd(struct mfs_client *clt, struct imap_cmd *send,
	struct imap_rcv_handle *h)
{
	struct imap *i = (struct imap*)clt->private_data;
	int tagid = imap_handle_get_tag_id(i, h);

	if(send->cont)
		atomic_cmpxchg(&i->ctag, tagid, NRTAG);
	/**
	 * Release receive handler slot
	 */
	atomic_xchg(&h->ready, 0);
	atomic_xchg(&h->reserved, 0);

	return 0;
}

/**
 * Actualy send command through network
 */
static inline int _imap_send_cmd(struct mfs_client *clt, struct imap_cmd *c)
{
	return mfs_client_kernel_net_send(clt, c->str, c->len);
}

/**
 * Enqueue command to be processed by sending thread
 */
static inline int _imap_enqueue_cmd(struct mfs_client *clt,
		struct imap_cmd *c){
	struct imap *i = (struct imap *)clt->private_data;
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
 *
 * If sendthread equals 1 then command is send through network, else command is
 * enqueue waiting to be processed by sending thread.
 */
static int imap_send_cmd(struct mfs_client *clt, struct imap_cmd *send,
		struct imap_msg **rcv, int sendthread)
{
	struct imap_rcv_handle *h;
	int ret;

	h = imap_prepare_cmd(clt, send, rcv);
	if(IS_ERR(h)) {
		ret = PTR_ERR(h);
		goto out;
	}

	if(sendthread)
		ret = _imap_send_cmd(clt, send);
	else
		ret = _imap_enqueue_cmd(clt, send);

	if(ret < 0)
		goto release;

	/**
	 * This is async command no need to wait for response
	 */
	if(h == NULL)
		goto out;

	/**
	 * Sleep here waiting for response
	 */
	ret = imap_wait_cmd(clt, send, h);
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
	imap_release_cmd(clt, send, h);
out:
	return ret;
}

static int imap_send_unidle_cmd(struct mfs_client *clt)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct imap_msg *r;
	struct imap_elt *e;
	int ret;
	static struct imap_cmd imap_donecmd = {
		.str = "DONE" "\r\n",
		.len = sizeof("DONE" "\r\n") - 1,
		.id = IMAPCMD_DONE,
	};

	/**
	 * Here imap should be locked, I guess
	 */
	ret = imap_send_cmd(clt, &imap_donecmd, &r, 1);
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

static int imap_send_idle_cmd(struct mfs_client *clt)
{
	struct imap *i = (struct imap *)clt->private_data;
	struct imap_msg *r = NULL;
	int ret;
	static struct imap_cmd imap_idlecmd = {
		.str = STR(IDLETAG) " IDLE" "\r\n",
		.len = sizeof(STR(IDLETAG) " IDLE" "\r\n") - 1,
		.id = IMAPCMD_IDLE,
		.cont = 1
	};

	/**
	 * Here imap should be locked, I guess
	 */
	ret = imap_send_cmd(clt, &imap_idlecmd, &r, 1);
	if(ret < 0) {
		IMAP_DBG("Failed to idle\n");
		return -EINVAL;
	}

	mfs_imap_msg_put(r);

	atomic_xchg(&i->idling, 1);

	return ret;
}

static inline int imap_idle(struct mfs_client *clt)
{
	struct imap *i = (struct imap *)clt->private_data;
	int ret = 0;

	if(atomic_read(&i->idling) || (i->flags & IMAP_EXIT) ||
			(i->flags & IMAP_INIT))
		goto out;

	/**
	 * Wait for idling to be back
	 */
	wake_up_interruptible(&i->idlwait);
	ret = wait_event_interruptible_timeout(i->idlwait,
			atomic_read(&i->idling), IMAP_IDLE_TIMEOUT);

out:
	return ret;
}

static inline int imap_unidle(struct mfs_client *clt)
{
	struct imap *i = (struct imap *)clt->private_data;
	int ret = 0;

	if(!atomic_read(&i->idling))
		goto out;

	while((ret = imap_send_unidle_cmd(clt)) == -EAGAIN)
		schedule();
out:
	return ret;
}

#define IMAP_RECO_WAIT 2000 /* 2 sec */

/**
 * This is the thread function that keep imap connected
 */
int mfs_imap_keep_connected(void *data)
{
	struct mfs_client *clt = (struct mfs_client *)data;
	struct imap *i = (struct imap*)clt->private_data;
	int ret;

	while(!kthread_should_stop()) {
		ret = wait_event_interruptible(i->conwait,
				!(i->flags & IMAP_CONN));

		if(kthread_should_stop())
			break;

		if(ret == -ERESTARTSYS)
			continue;

		IMAP_DBG("Reconnect\n");
		atomic_xchg(&i->idling, 0);
		ret = mfs_client_restart_session(clt);
		if(ret != 0) {
			IMAP_DBG("Fail to reconnect retrying\n");
			msleep(IMAP_RECO_WAIT);
		}
	}

	return 0;
}

/**
 * This is the thread function that keep imap idling
 */
int mfs_imap_keep_idling(void *data)
{
	struct mfs_client *clt = (struct mfs_client *)data;
	struct imap *i = (struct imap*)clt->private_data;
	int ret;

	while(!kthread_should_stop()) {
		ret = wait_event_interruptible_timeout(i->idlwait,
				!atomic_read(&i->idling) ||
				!(i->flags & IMAP_CONN), IMAP_IDLE_TIMEOUT);

		if(kthread_should_stop())
			break;

		if(ret == -ERESTARTSYS)
			continue;

		if(!(i->flags & IMAP_CONN)) {
			/**
			 * TODO: wait for reco here
			 */
		}

		/**
		 * At idle timeout, we should first unidle
		 */
		ret = imap_unidle(clt);
		if(ret < 0) {
			IMAP_DBG("Fail to unidle\n");
			continue;
		}

		ret = imap_send_idle_cmd(clt);
		if(ret < 0) {
			IMAP_DBG("Fail to idle\n");
			continue;
		}
	}

	return 0;
}

/**
 * Function that send a command. If rcv is not null, send is synchronous and rcv
 * get server response
 */
int mfs_imap_send_cmd(struct mfs_client *clt, struct imap_cmd *send,
		struct imap_msg **rcv)
{
	INIT_LIST_HEAD(&send->next);
	return imap_send_cmd(clt, send, rcv, 0);
}

/**
 * This is the thread function that get IMAP message from fs and send them to
 * the server
 */
int mfs_imap_send_process(void *data)
{
	struct mfs_client *clt = (struct mfs_client *)data;
	struct imap *i = (struct imap*)clt->private_data;
	struct list_head *msg;
	struct imap_cmd *c, *n;
	int ret;

	while(!kthread_should_stop()) {
		ret = mfs_cmdqueue_wait(&i->send, &msg);
		if(ret < 0) {
			if(msg == NULL)
				continue;
			list_for_each_entry_safe(c, n, msg, next) {
				list_del(&c->next);
				imap_cleanup_cmd(c);
			}
			continue;
		}

		list_for_each_entry_safe(c, n, msg, next) {
			imap_unidle(clt);

			_imap_send_cmd(clt, c);
			list_del(&c->next);
			imap_cleanup_cmd(c);

			imap_idle(clt);
		}
	}

	return 0;
}
