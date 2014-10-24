#ifndef _MFS_CLIENT_H_
#define _MFS_CLIENT_H_

struct mfs_client {
	struct socket *cs;
	struct mfs_client_operations *ops;
	struct super_block *sb;
	void *private_data;
};

struct mfs_client_operations {
	int (*connect)(struct mfs_client *clt);
	void (*close)(struct mfs_client *clt);
};

struct mfs_client *mfs_client_create(struct super_block *sb);
void mfs_client_destroy(struct mfs_client *clt);
int mfs_client_init_session(struct mfs_client *clt, char const *addr,
		char *data);
void mfs_client_close_session(struct mfs_client *clt);
void mfs_client_set_sb(struct mfs_client *clt, struct super_block *sb);
ssize_t mfs_client_read(struct mfs_client *clt, char __user *buf, size_t size);
ssize_t mfs_client_kernel_read(struct mfs_client *clt, char *buf, size_t size);
ssize_t mfs_client_write(struct mfs_client *clt, const char __user *buf,
		size_t size);
ssize_t mfs_client_kernel_write(struct mfs_client *clt, const char *buf,
		size_t size);

#endif
