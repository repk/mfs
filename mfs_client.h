#ifndef _MFS_CLIENT_H_
#define _MFS_CLIENT_H_

#include <linux/netdevice.h>

struct mfs_client_opt {
	unsigned short port;
};

struct mfs_client {
	struct socket *cs;
	struct mfs_client_operations *ops;
	struct super_block *sb;
	void *private_data;
	struct sockaddr_in sin;
	struct mfs_client_opt opt;
};

struct mfs_client_operations {
	int (*connect)(struct mfs_client *clt, char *data);
	void (*close)(struct mfs_client *clt);
	int (*reconnect)(struct mfs_client *clt);
	ssize_t (*read)(struct mfs_client *clt, struct file *f, void *pdata,
			char __user *buf, size_t size, loff_t off);
	ssize_t (*write)(struct mfs_client *clt, struct file *f, void *pdata,
			const char __user *buf, size_t size);
};

struct mfs_client *mfs_client_create(struct super_block *sb);
void mfs_client_destroy(struct mfs_client *clt);
int mfs_client_init_session(struct mfs_client *clt, char const *addr,
		char *data);
void mfs_client_close_session(struct mfs_client *clt);
int mfs_client_restart_session(struct mfs_client *clt);
void mfs_client_set_sb(struct mfs_client *clt, struct super_block *sb);
ssize_t mfs_client_net_recv(struct mfs_client *clt, char __user *buf,
		size_t size);
ssize_t mfs_client_kernel_net_recv(struct mfs_client *clt, char *buf,
		size_t size);
ssize_t mfs_client_read(struct mfs_client *clt, struct file *f,
		char __user *buf, size_t size, loff_t off);
ssize_t mfs_client_net_send(struct mfs_client *clt, const char __user *buf,
		size_t size);
ssize_t mfs_client_kernel_net_send(struct mfs_client *clt, const char *buf,
		size_t size);
ssize_t mfs_client_write(struct mfs_client *clt, struct file *f,
		const char __user *buf, size_t size);
int mfs_client_kernel_wait_recv(struct mfs_client *clt, long timeout);

#endif
