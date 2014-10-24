#ifndef _MFS_INODE_H_
#define _MFS_INODE_H_

struct inode *mfs_inode_make(struct super_block *sb, int mode);
struct dentry *mfs_inode_create_dir(struct super_block *sb,
		struct dentry *parent, char const *name, void *data);
struct dentry *mfs_inode_create_file(struct super_block *sb,
		struct dentry *parent, char const *name, void *data);
void mfs_inode_populate_fs(struct super_block *sb, struct dentry *root);

#endif
