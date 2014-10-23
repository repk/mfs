#include <linux/fs.h>

#include "mfs_file.h"
#include "mfs_client.h"

/**
 * -------------------------------------
 * File operations handling
 * -------------------------------------
 */


static int mfs_file_open(struct inode *inode, struct file *f)
{
	f->private_data = inode->i_sb->s_fs_info;
	return 0;
}

static ssize_t mfs_file_read(struct file *f, char __user *buf, size_t size,
		loff_t *off)
{
	struct mfs_client *clt = (struct mfs_client *)f->private_data;
	return mfs_client_read(clt, buf, size);
}

static ssize_t mfs_file_write(struct file *f, const char __user *buf,
		size_t size, loff_t *off)
{
	struct mfs_client *clt = (struct mfs_client *)f->private_data;
	return mfs_client_write(clt, buf, size);
}

struct file_operations mfs_file_ops = {
	.open = mfs_file_open,
	.read = mfs_file_read,
	.write = mfs_file_write,
};
