#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>

#include "mfs_super.h"
#include "mfs_client.h"

/**
 * -------------------------------------
 * File system kernel module
 * -------------------------------------
 */


/**
 * This describes the filesystem (1 per filesystem shared amoung all mount)
 */

/**
 * Called by vfs when mount syscall has been raised
 */
static struct dentry *mfs_mod_mount(struct file_system_type *fst, int flags,
		const char *dev_name, void *data)
{
	struct mfs_client *clt;
	struct super_block *sb = NULL;
	int err;

	clt = kzalloc(sizeof(*clt), GFP_KERNEL);
	if(clt == NULL) {
		err = -ENOMEM;
		goto error;
	}

	sb = sget(fst, NULL, mfs_super_set, flags, clt);
	if(IS_ERR(sb)) {
		err = PTR_ERR(sb);
		goto free_client;
	}

	err = mfs_super_fill(sb, flags, data);
	if(err != 0)
		goto release_sb;

	mfs_client_set_sb(clt, sb);

	err = mfs_client_init_session(clt, dev_name, data);
	if(err != 0)
		goto release_sb;

	/**
	 * Get reference to superblock
	 */
	return dget(sb->s_root);

release_sb:
	deactivate_locked_super(sb);
free_client:
	kfree(clt);
error:
	return ERR_PTR(err);
}

/**
 * Called by vfs to kill super block (umount)
 */
static void mfs_mod_kill_super(struct super_block *s)
{
	struct mfs_client *clt = (struct mfs_client *)s->s_fs_info;

	kill_litter_super(s);
	mfs_client_close_session(clt);
	kfree(clt);
}


static struct file_system_type mfstype = {
	.owner = THIS_MODULE,
	.name = "mfs",
	.mount = mfs_mod_mount,
	.kill_sb = mfs_mod_kill_super,
};

/**
 * Typical kernel module functions
 */

/**
 * MODULE_ALIAS for module autoloading
 */
MODULE_ALIAS_FS("mfs");

/**
 * Module initialization
 */
static int __init mfs_mod_init(void)
{
	return register_filesystem(&mfstype);
}

/**
 * Module Exit
 */
static void __exit mfs_mod_exit(void)
{
	unregister_filesystem(&mfstype);
}

module_init(mfs_mod_init);
module_exit(mfs_mod_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Remi Pommarel");

