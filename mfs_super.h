#ifndef _MFS_SUPER_H_
#define _MFS_SUPER_H_

int mfs_super_fill(struct super_block *sb, int flags, void *data);
int mfs_super_set(struct super_block *s, void *data);

#endif
