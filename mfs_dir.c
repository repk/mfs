#include <linux/fs.h>

#include "mfs_dir.h"
#include "mfs_client.h"

/**
 * -------------------------------------
 * Directory operations handling
 * -------------------------------------
 */

static int mfs_dir_readdir(struct file *filp, void *dirent, filldir_t filldir)
{
	struct inode *i = file_inode(filp);
	struct mfs_client *clt = i->i_sb->s_fs_info;
	int res;

	res = mfs_client_readdir(clt, filp, dirent, filldir);
	if(res < 0)
		goto out;

	res = dcache_readdir(filp, dirent, filldir);
out:
	return res;
}

struct file_operations const mfs_dir_ops = {
	.open		= dcache_dir_open,
	.release	= dcache_dir_close,
	.llseek		= dcache_dir_lseek,
	.read		= generic_read_dir,
	.readdir	= mfs_dir_readdir,
	.fsync		= noop_fsync,
};
