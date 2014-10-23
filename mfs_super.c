#include <linux/fs.h>
#include <linux/pagemap.h> /* (PAGE_CACHE_SIZE, ...) */

#include "mfs_super.h"
#include "mfs_inode.h"

#define MFS_MAGIC 0x20141012

/**
 * -------------------------------------
 * Super block operations handling
 * -------------------------------------
 */


/**
 * A superblock describes a mounted fs (1 superblock per mount)
 */
static struct super_operations mfs_ops = {
	/**
	 * For now do not cache inodes
	 * TODO: Set to NULL for inode caching
	 */
	.drop_inode = generic_delete_inode,
	/**
	 * Use simple template
	 */
	.statfs = simple_statfs,
};


/**
 * Fill a new superblock
 */
int mfs_super_fill(struct super_block *sb, int flags, void *data)
{
	struct inode *root;
	struct dentry *rdentry;

	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = MFS_MAGIC;
	sb->s_op = &mfs_ops;


	/**
	 * Create our file system tree (content)
	 * One inode per filesystem objects
	 */
	root = mfs_inode_make(sb, S_IFDIR | 0755);
	if(root == NULL)
		goto err;

	/**
	 * Set inode operations for root as well as default file_ops
	 * For now use libfs's templates
	 */
	root->i_op = &simple_dir_inode_operations;
	root->i_fop = &simple_dir_operations;

	/**
	 * Create the root dentry (name to inode translation)
	 */
	rdentry = d_make_root(root);
	if(rdentry == NULL)
		goto err;

	/**
	 * Here we got our Root ok
	 */
	sb->s_root = rdentry;

	mfs_inode_populate_fs(sb, rdentry);
	return 0;

err:
	return -ENOMEM;
}

/**
 * TODO: Doc understand what set_anon_super does
 */
int mfs_super_set(struct super_block *s, void *data)
{
	s->s_fs_info = data;
	return set_anon_super(s, data);
}

