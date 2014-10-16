#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/pagemap.h> /* (PAGE_CACHE_SIZE, etc) */

/**
 * Used by to detect superblocks' filesytem
 */
#define MFS_MAGIC 0x20141012

/**
 * -----------------------------------------------
 *  File
 *  TODO: simplify
 * -----------------------------------------------
 */

static int mfs_open(struct inode *inode, struct file *f)
{
	f->private_data = inode->i_private;
	return 0;
}

static ssize_t mfs_read_file(struct file *f, char __user *buf, size_t size,
                loff_t *off)
{
	char const *str = (char const *)f->private_data;
	size_t filesz = strlen(f->private_data);
	size_t len = min(size, filesz);
	int ret;

	/**
	 * Nothing to read here
	 */
	if(*off >= filesz)
		return 0;

	/**
	 * Fill user buffer
	 */
	ret = copy_to_user(buf, str + *off, len);
	if(ret)
		return -EINVAL;

	/**
	 * Forward the file read offset
	 */
	*off += len;

	return len;
}

static struct file_operations mfs_file_ops = {
	.open	= mfs_open,
	.read	= mfs_read_file,
};

/**
 * -----------------------------------------------
 *  Inodes
 * -----------------------------------------------
 */

/**
 * Create a new inode
 */
static struct inode *mfs_make_inode(struct super_block *sb, int mode)
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
 * Create a single read only file
 */
static void mfs_create_file(struct super_block *sb, struct dentry *parent,
		char const * name, char * data)
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
	 * Now create dentry and inode
	 */
	dentry = d_alloc(parent, &qname);
	if(dentry == NULL)
		goto out;

	inode = mfs_make_inode(sb, S_IFREG | 0644);
	if(inode == NULL)
		goto out;

	inode->i_fop = &mfs_file_ops;
	inode->i_private = data;

	/**
	 * Put file in the tree
	 */
	d_add(dentry, inode);

out:
	return;
}

/**
 * Populate root with static file tree
 */
static void mfs_populate(struct super_block *sb, struct dentry *root)
{
	/**
	 * For now create only one file
	 */
	mfs_create_file(sb, root, "hey", "Hey dude where is my car\n");
}

/**
 * -----------------------------------------------
 *  Superblock
 * -----------------------------------------------
 */

/**
 * A superblock describes a mounted fs (1 superblock per mount)
 */
static struct super_operations mfs_ops = {
	/**
	 * For now do not cache inodes.
	 * Set to NULL for inode caching
	 */
	.drop_inode = generic_delete_inode,
	/**
	 * Use simple template
	 */
	.statfs = simple_statfs,
};

/**
 * Fill a superblock
 */
static int mfs_fill_super(struct super_block *sb, void *data, int silent)
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
	root = mfs_make_inode(sb, S_IFDIR | 0755);
	if(root == NULL)
		goto err;
	/**
	 * Set inode operations for root as well as default file_ops
	 * For now use libfs templates
	 */
	root->i_op = &simple_dir_inode_operations;
	root->i_fop = &simple_dir_operations;

	/**
	 * Create the root dentry name to inode translation
	 */
	rdentry = d_make_root(root);
	if(rdentry == NULL)
		goto err;
	/**
	 * Here we got our Root ok
	 */
	sb->s_root = rdentry;

	mfs_populate(sb, rdentry);
	return 0;

err:
	return -ENOMEM;
}

/**
 * -----------------------------------------------
 *  File system type
 * -----------------------------------------------
 */

/**
 * Called by vfs when mount syscall has been raised
 */
static struct dentry *mfs_mount(struct file_system_type *fst, int flags,
		const char *devname, void *data)
{
	return mount_nodev(fst, flags, data, mfs_fill_super);
}

/**
 * Describe the fs.
 * There is only one file_system_type for all the filesystem's instances
 */
static struct file_system_type mfstype = {
	.owner = THIS_MODULE,
	.name = "mfs",
	.mount = mfs_mount,
	.kill_sb = kill_litter_super,
};


/**
 * -----------------------------------------------
 *  Kernel module
 * -----------------------------------------------
 */

/**
 * MODULE_ALIAS for module autoloading
 */
MODULE_ALIAS_FS("mfs");


/**
 * Module initialization
 */
static int __init mfs_init(void)
{
	return register_filesystem(&mfstype);
}

/**
 * Module exit
 */
static void __exit mfs_exit(void)
{
	unregister_filesystem(&mfstype);
}

module_init(mfs_init);
module_exit(mfs_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Remi Pommarel");

