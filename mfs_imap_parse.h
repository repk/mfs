#ifndef _MFS_IMAP_PARSE_H_
#define _MFS_IMAP_PARSE_H_

#include <linux/list.h>
#include <linux/kref.h>

/**
 * Imap message element type
 */
enum imap_elt_type {
	IET_NIL,
	IET_ATOM,
	IET_NUMBER,
	IET_STRING,
	IET_LIST
};

/**
 * XXX Are we unalgined safe ?
 */
#define IMAP_ELT_NUM(e)		((unsigned int *)(e)->data)
#define IMAP_ELT_MSG(e)		((struct imap_msg *)(e)->data)
#define IMAP_ELT_ATOM(e)	((e)->data)
#define IMAP_ELT_STR(e)		((e)->data)

/**
 * Imap message element
 */
struct imap_elt {
	struct list_head next;
	enum imap_elt_type type;
	char data[];
};

/**
 * Imap message
 */
struct imap_msg {
	struct kref refcnt;
	struct list_head elt;
};

/**
 * Transform received message into structured imap message
 */
struct imap_msg *mfs_imap_parse_msg(char const **msg, size_t *len);
/**
 * Get a reference on imap msg
 *
 * Returns non zero if get suceed 0 otherwise
 */
int __must_check mfs_imap_msg_get(struct imap_msg *im);
/**
 * Release a reference on imap msg
 */
int mfs_imap_msg_put(struct imap_msg *im);

#endif
