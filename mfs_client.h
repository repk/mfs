#ifndef _MFS_CLIENT_H_
#define _MFS_CLIENT_H_

struct mfs_client {
	struct socket *cs;
};

int mfs_client_init_session(struct mfs_client *clt, char const *addr,
		char *data);
void mfs_client_close_session(struct mfs_client *clt);
ssize_t mfs_client_read(struct mfs_client *clt, char __user *buf, size_t size);
ssize_t mfs_client_write(struct mfs_client *clt, const char __user *buf,
		size_t size);

#endif
