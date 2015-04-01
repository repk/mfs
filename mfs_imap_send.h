#ifndef _MFS_IMAP_SEND_H_
#define _MFS_IMAP_SEND_H_

#include "mfs_client.h"
#include "mfs_imap.h"
#include "mfs_imap_parse.h"

/**
 * This is the thread function that keep imap connected
 */
int mfs_imap_keep_connected(void *data);

/**
 * This is the thread function that keep imap idling
 */
int mfs_imap_keep_idling(void *data);

/**
 * Function that send a command. If rcv is not null, send is synchronous and rcv
 * get server response
 */
int mfs_imap_send_cmd(struct mfs_client *clt, struct imap_cmd *send,
		struct imap_msg **rcv);

/**
 * This is the thread function that get IMAP message from fs and send them to
 * the server
 */
int mfs_imap_send_process(void *data);

/**
 * This relaunch imap idle
 */
int mfs_imap_send_rsp(struct mfs_client *clt);

#endif
