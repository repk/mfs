#include <linux/net.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <net/sock.h>

#include "mfs_client.h"
#include "mfs_imap.h"

#define MFS_DFT_PORT 143

/**
 * -------------------------------------
 * File handling network operations
 * -------------------------------------
 */


/**
 * Close a connected socket
 */
static inline void client_close_socket(struct mfs_client *clt)
{
	if(clt->cs != NULL)
		sock_release(clt->cs);

	clt->cs = NULL;
}

/**
 * Create a new socket and connect it
 */
static inline struct socket *client_open_socket(struct mfs_client *clt)
{
	struct socket *cs;
	int e = 0;

	/**
	 * XXX should I use sock_create() instead ?
	 */
	e = __sock_create(read_pnet(&current->nsproxy->net_ns), PF_INET,
			SOCK_STREAM, IPPROTO_TCP, &cs, 1);
	if(e != 0)
		goto err;

	e = cs->ops->connect(cs, (struct sockaddr *)&clt->sin,
			sizeof(clt->sin), 0);
	if(e < 0)
		goto sockrelease;

	return cs;

sockrelease:
	sock_release(cs);
err:
	return ERR_PTR(e);
}

static int mfs_client_parse_opt(struct mfs_client *clt, char *opt)
{
	char *p;
	unsigned short port;
	int ret;

	clt->opt.port = MFS_DFT_PORT;

	if(opt == NULL)
		return 0;

	p = strstr(opt, "port=");
	if(p != NULL) {
		ret = sscanf(p, "port=%hu", &port);
		if(ret == 1)
			clt->opt.port = port;
	}

	return 0;
}

/**
 * Init a network session with server
 */
int mfs_client_init_session(struct mfs_client *clt, char const *addr,
		char *data)
{
	struct sockaddr_in *sin = &clt->sin;
	struct socket *cs;
	int e;

	e = mfs_client_parse_opt(clt, data);
	if(e != 0)
		goto err;

	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = in_aton(addr);
	sin->sin_port = htons(clt->opt.port);

	cs = client_open_socket(clt);
	if(IS_ERR_OR_NULL(cs)) {
		e = PTR_ERR(cs);
		goto err;
	}

	clt->cs = cs;
	clt->ops = &imapops;

	e = clt->ops->connect(clt, data);
	if(e < 0)
		goto err;

	return 0;

err:
	return e;
}

/**
 * Close network session
 */
void mfs_client_close_session(struct mfs_client *clt)
{
	if(clt->ops)
		clt->ops->close(clt);
	client_close_socket(clt);
}

/**
 * Restart network session
 */
int mfs_client_restart_session(struct mfs_client *clt)
{
	struct socket *cs = NULL;
	int e;

	client_close_socket(clt);

	cs = client_open_socket(clt);
	if(IS_ERR_OR_NULL(cs)) {
		e = PTR_ERR(cs);
		goto err;
	}

	clt->cs = cs;
	clt->ops = &imapops;

	e = clt->ops->reconnect(clt);
	if(e < 0)
		goto closesock;

	return 0;

closesock:
	client_close_socket(clt);
err:
	return e;
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
ssize_t mfs_client_net_recv(struct mfs_client *clt, char __user *buf,
		size_t size)
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
ssize_t mfs_client_kernel_net_recv(struct mfs_client *clt, char *buf,
		size_t size)
{
	struct msghdr msg = {
		.msg_flags = MSG_NOSIGNAL
	};
	struct kvec iov = {
		.iov_base = buf,
		.iov_len = size,
	};

	return kernel_recvmsg(clt->cs, &msg, &iov, 1, size, msg.msg_flags);
}

/**
 * Generic function called to read from a file
 */
ssize_t mfs_client_read(struct mfs_client *clt, struct file *f,
		char __user *buf, size_t size, loff_t off)
{
	struct inode *i = file_inode(f);
	if(i->i_private == NULL)
		return mfs_client_net_recv(clt, buf, size);

	return clt->ops->read(clt, f, i->i_private, buf, size, off);
}


/**
 * Send a message through client session
 * XXX For userspace buffer
 */
ssize_t mfs_client_net_send(struct mfs_client *clt, const char __user *buf,
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
ssize_t mfs_client_kernel_net_send(struct mfs_client *clt, const char *buf,
		size_t size)
{
	struct msghdr msg = {
		.msg_flags = MSG_NOSIGNAL
	};
	struct kvec iov = {
		.iov_base = (void *)buf,
		.iov_len = size,
	};

	return kernel_sendmsg(clt->cs, &msg, &iov, 1, size);
}

/**
 * Generic function called to write into a file
 */
ssize_t mfs_client_write(struct mfs_client *clt, struct file *f,
		const char __user *buf, size_t size)
{
	struct inode *i = file_inode(f);

	if(i->i_private == NULL)
		return mfs_client_net_send(clt, buf, size);

	return clt->ops->write(clt, f, i->i_private, buf, size);
}

/**
 * Wait for socket to have message to be read
 */
int mfs_client_kernel_wait_recv(struct mfs_client *clt, long timeout)
{
	char b;
	ssize_t ret;
	long timeo_old;
	struct msghdr msg = {
		.msg_flags = MSG_NOSIGNAL | MSG_PEEK
	};
	struct kvec iov = {
		.iov_base = &b,
		.iov_len = 1,
	};


	timeo_old = clt->cs->sk->sk_rcvtimeo;
	clt->cs->sk->sk_rcvtimeo = timeout;

	ret = kernel_recvmsg(clt->cs, &msg, &iov, 1, 1, msg.msg_flags);

	clt->cs->sk->sk_rcvtimeo = timeo_old;

	return ret;
}

int mfs_client_readdir(struct mfs_client *clt, struct file *f,
		void *dirent, filldir_t filldir)
{
	struct inode *i = file_inode(f);

	if(i->i_private == NULL)
		return -EINVAL;

	return clt->ops->readdir(clt, f, i->i_private, dirent, filldir);
}
