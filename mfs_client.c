#include <linux/net.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/netdevice.h>

#include "mfs_client.h"
#include "mfs_imap.h"

#define MFS_PORT 143

/**
 * -------------------------------------
 * File handling network operations
 * -------------------------------------
 */


/**
 * Init a network session with server
 */
int mfs_client_init_session(struct mfs_client *clt, char const *addr,
		char *data)
{
	struct sockaddr_in sin;
	struct socket *cs;
	int err;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = in_aton(addr);
	sin.sin_port = htons(MFS_PORT);

	/**
	 * XXX should I use sock_create() instead ?
	 */
	err = __sock_create(read_pnet(&current->nsproxy->net_ns), PF_INET,
			SOCK_STREAM, IPPROTO_TCP, &cs, 1);
	if(err != 0)
		goto err;

	err = cs->ops->connect(cs, (struct sockaddr *)&sin, sizeof(sin), 0);
	if(err < 0)
		goto sockrelease;

	clt->cs = cs;
	clt->ops = &imapops;

	err = clt->ops->connect(clt);
	if(err < 0)
		goto sockrelease;

	return 0;

sockrelease:
	sock_release(cs);
err:
	return err;
}

/**
 * Close network session
 */
void mfs_client_close_session(struct mfs_client *clt)
{
	clt->ops->close(clt);
	sock_release(clt->cs);
}

/**
 * Associate a superblock with client
 */
void mfs_client_set_sb(struct mfs_client *clt, struct super_block *sb)
{
	clt->sb = sb;
}

/**
 * Receive a network message through session
 * XXX For userspace buffer
 */
ssize_t mfs_client_read(struct mfs_client *clt, char __user *buf, size_t size)
{
	/**
	 * Struct iovec is for userspace buffers. If it were for kernel space
	 * buffer, struct kvec would have been used as well as kernel_recvmsg()
	 * instread of socket_recvmsg().
	 */
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = size,
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	return sock_recvmsg(clt->cs, &msg, size, 0);
}

/**
 * Receive a network message through session
 * XXX For kernel space buffer
 */
ssize_t mfs_client_kernel_read(struct mfs_client *clt, char *buf, size_t size)
{
	struct msghdr msg = {};
	struct kvec iov = {
		.iov_base = buf,
		.iov_len = size,
	};

	return kernel_recvmsg(clt->cs, &msg, &iov, 1, size, 0);
}

/**
 * Send a message through client session
 * XXX For userspace buffer
 */
ssize_t mfs_client_write(struct mfs_client *clt, const char __user *buf,
		size_t size)
{
	/**
	 * Struct iovec is for userspace buffers. If it were for kernel space
	 * buffer, struct kvec would have been used as well as kernel_sendmsg()
	 * instread of socket_sendmsg().
	 */
	struct iovec iov = {
		.iov_base = (void __user *)buf,
		.iov_len = size,
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	return sock_sendmsg(clt->cs, &msg, size);
}

/**
 * Send a message through client session
 * XXX For kernelspace buffer
 */
ssize_t mfs_client_kernel_write(struct mfs_client *clt, const char *buf,
		size_t size)
{
	struct msghdr msg = {};
	struct kvec iov = {
		.iov_base = (void *)buf,
		.iov_len = size,
	};

	return kernel_sendmsg(clt->cs, &msg, &iov, 1, size);
}
