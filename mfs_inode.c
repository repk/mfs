#include <linux/fs.h>

#include "mfs_inode.h"
#include "mfs_file.h"

/**
 * -------------------------------------
 * Inode operations handling
 * -------------------------------------
 */


/**
 * Create a new inode
 */
struct inode *mfs_inode_make(struct super_block *sb, int mode)
{
	struct inode *ret;

	ret = new_inode(sb);
	if(ret == NULL)
		goto out;

	ret->i_mode = mode;
	ret->i_blocks = 0;
	ret->i_atime = CURRENT_TIME;
	ret->i_mtime = CURRENT_TIME;
	ret->i_ctime = CURRENT_TIME;

out:
	return ret;
}

/**
 * Create a new file
 */
static void mfs_inode_create_file(struct super_block *sb,
		struct dentry *parent, char const *name, void *data)
{
	struct dentry *dentry;
	struct inode *inode;
	struct qstr qname;

	/**
	 * Make new file dentry name hash
	 */
	qname.name = name;
	qname.len = strlen(name);
	qname.hash = full_name_hash(name, qname.len);

	/**
	 * Now create a dentry and inode
	 */
	dentry = d_alloc(parent, &qname);
	if(dentry == NULL)
		goto out;

	inode = mfs_inode_make(sb, S_IFREG | 0644);
	if(inode == NULL)
		goto out;

	inode->i_fop = &mfs_file_ops;

	/**
	 * Associate the file and its dentry
	 */
	d_add(dentry, inode);

out:
	return;
}

/**
 * Create a simple sample net file
 */
static void mfs_inode_create_netfile(struct super_block *sb,
		struct dentry *parent)
{
	mfs_inode_create_file(sb, parent, "net", NULL);
}

/**
 * Populate a simple static file tree
 */
void mfs_inode_populate_fs(struct super_block *sb, struct dentry *root)
{
	/**
	 * For now create only one stub file
	 */
	mfs_inode_create_netfile(sb, root);
}