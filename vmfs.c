#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/pagemap.h> /* (PAGE_CACHE_SIZE, etc) */
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/netdevice.h>

/**
 * Used by to detect superblocks' filesytem
 */
#define MFS_MAGIC 0x20141012
#define MFS_PORT 12112


/**
 * -----------------------------------------------
 *  TCP session
 * -----------------------------------------------
 */
struct mfs_client {
	struct socket *cs;
};

/**
 * Init tcp session for mfs
 */
static int mfs_init_session(struct mfs_client *clt, char const *addr,
		char *data)
{
	struct sockaddr_in sin;
	struct socket *cs;
	int err;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = in_aton(addr);
	sin.sin_port = htons(MFS_PORT);

	/**
	 * XXX should I use sock_create() instead ?
	 */
	err = __sock_create(read_pnet(&current->nsproxy->net_ns), PF_INET,
			SOCK_STREAM, IPPROTO_TCP, &cs, 1);
	if(err != 0)
		return err;

	/**
	 * XXX use kernel_connect() ???
	 */
	err = cs->ops->connect(cs, (struct sockaddr *)&sin, sizeof(sin), 0);
	if (err < 0) {
		sock_release(cs);
		return err;
	}

	clt->cs = cs;

	return 0;
}

/**
 * Close tcp session
 */
static void mfs_close_session(struct mfs_client *clt)
{
	sock_release(clt->cs);
}


/**
 * -----------------------------------------------
 *  File
 *  TODO: simplify
 * -----------------------------------------------
 */

static int mfs_open(struct inode *inode, struct file *f)
{
	f->private_data = inode->i_sb->s_fs_info;
	return 0;
}

static ssize_t mfs_read_file(struct file *f, char __user *buf, size_t size,
                loff_t *off)
{
	struct mfs_client *clt = (struct mfs_client *)f->private_data;
	/**
	 * Struct iovec is for userspace buffers. If it were for kernel space
	 * buffer, struct kvec would have been used as well as kernel_recvmsg()
	 * instead of socket_recvmsg.
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

static ssize_t mfs_write_file(struct file *f, const char __user *buf,
		size_t size, loff_t *off)
{
	struct mfs_client *clt = (struct mfs_client *)f->private_data;
	/**
	 * Struct iovec is for userspace buffers. If it were for kernel space
	 * buffer, struct kvec would have been used as well as kernel_sendmsg()
	 * instead of socket_sendmsg.
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

static struct file_operations mfs_file_ops = {
	.open	= mfs_open,
	.read	= mfs_read_file,
	.write	= mfs_write_file,
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
		char const * name, void * data)
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

	/**
	 * Put file in the tree
	 */
	d_add(dentry, inode);

out:
	return;
}

static void mfs_create_netfile(struct super_block *sb, struct dentry *parent)
{
	mfs_create_file(sb, parent, "net", sb->s_fs_info);
}

/**
 * Populate root with static file tree
 */
static void mfs_populate(struct super_block *sb, struct dentry *root)
{
	/**
	 * For now create only one file
	 */
	mfs_create_netfile(sb, root);
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
static int mfs_fill_super(struct super_block *sb, int flags, void *data)
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
 * TODO: Doc understand what this does
 */
static int mfs_set_super(struct super_block *s, void *data)
{
	s->s_fs_info = data;
	return set_anon_super(s, data);
}

/**
 * Called by vfs when mount syscall has been raised
 */
static struct dentry *mfs_mount(struct file_system_type *fst, int flags,
		const char *dev_name, void *data)
{
	struct mfs_client *clt;
	struct super_block *sb = NULL;
	int err;

	clt = kzalloc(sizeof(*clt), GFP_KERNEL);
	if (clt == NULL) {
		err = -ENOMEM;
		goto error;
	}

	err = mfs_init_session(clt, dev_name, data);
	if (err != 0)
		goto free_client;

	sb = sget(fst, NULL, mfs_set_super, flags, clt);

	if (IS_ERR(sb)) {
		err = PTR_ERR(sb);
		goto close_sess;
	}

	err = mfs_fill_super(sb, flags, data);
	if(err != 0)
		goto release_sb;

	return dget(sb->s_root);

release_sb:
	deactivate_locked_super(sb);
close_sess:
	mfs_close_session(clt);
free_client:
	kfree(clt);
error:
	return ERR_PTR(err);
}

/**
 * Called by vfs to kill super block (umount)
 */
static void mfs_kill_super(struct super_block *s)
{
	struct mfs_client *clt = (struct mfs_client *)s->s_fs_info;

	kill_litter_super(s);
	mfs_close_session(clt);
	kfree(clt);
}

/**
 * Describe the fs.
 * There is only one file_system_type for all the filesystem's instances
 */
static struct file_system_type mfstype = {
	.owner = THIS_MODULE,
	.name = "mfs",
	.mount = mfs_mount,
	.kill_sb = mfs_kill_super,
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

