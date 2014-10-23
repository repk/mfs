#ifndef _MFS_INODE_H_
#define _MFS_INODE_H_

struct inode *mfs_inode_make(struct super_block *sb, int mode);
void mfs_inode_populate_fs(struct super_block *sb, struct dentry *root);

#endif
