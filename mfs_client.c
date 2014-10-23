#include <linux/net.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/netdevice.h>

#include "mfs_client.h"

#define MFS_PORT 12112

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
		return err;

	err = cs->ops->connect(cs, (struct sockaddr *)&sin, sizeof(sin), 0);	
	if(err < 0) {
		sock_release(cs);
		return err;
	}

	clt->cs = cs;

	return 0;
}

/**
 * Close network session
 */
void mfs_client_close_session(struct mfs_client *clt)
{
	sock_release(clt->cs);
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
