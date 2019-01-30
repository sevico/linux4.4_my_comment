/*
  File: fs/ext2/acl.h

  (C) 2001 Andreas Gruenbacher, <a.gruenbacher@computer.org>
*/
//linux支持POSIX标准

#include <linux/posix_acl_xattr.h>

#define EXT2_ACL_VERSION	0x0001
/*ext2文件系统的acl结构体，遵循posix标准，和POSIX标准的一样*/

typedef struct {
	__le16		e_tag;
	__le16		e_perm;
	__le32		e_id;
} ext2_acl_entry;
/*ext2文件系统的简短的结构体，和posix标准的区别是没有了e_id字段*/

typedef struct {
	__le16		e_tag;
	__le16		e_perm;
} ext2_acl_entry_short;
/*ext2的头部，仅仅有一个版本号*/

typedef struct {
	__le32		a_version;
} ext2_acl_header;
/*内联函数，从acl项目的数目获得ext2的acl大小*/

static inline size_t ext2_acl_size(int count)
{
	/*由于e_id字段除了ACL_USER和ACL_GROUP都是空，所以如果count<=4的话，就是没有e_id的4个，就是acl头的大小加上count乘上ext2_acl_entry_short的大小*/

	if (count <= 4) {
		return sizeof(ext2_acl_header) +
		       count * sizeof(ext2_acl_entry_short);
	} else {
		/*如果大于4，说明有ACL_USER和ACL_GROUP这两个字段，e_id不为空，所以除了头的大小和四个没有e_id字段的大小，加上*/
		return sizeof(ext2_acl_header) +
		       4 * sizeof(ext2_acl_entry_short) +
		       (count - 4) * sizeof(ext2_acl_entry);
	}
}
/*从acl控制结构体的大小返回acl项的数目*/

static inline int ext2_acl_count(size_t size)
{
	ssize_t s;
	/*所有的acl都有acl头，所以先去除头结构体的大小*/
	size -= sizeof(ext2_acl_header);
	/*然后减去4个默认的 ACL_USER_OBJ, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER*/
	s = size - 4 * sizeof(ext2_acl_entry_short);
	if (s < 0) {
		if (size % sizeof(ext2_acl_entry_short))
			return -1;
		return size / sizeof(ext2_acl_entry_short);
	} else {
		/*如果大于0，说明有e_id不为0的项，所以余下的大小除以ext2_acl_entry就得到数目*/
		if (s % sizeof(ext2_acl_entry))
			return -1;
		return s / sizeof(ext2_acl_entry) + 4;
	}
}
/*如果配置了CONFIG_EXT2_FS_POSIX_ACL，就设置一些宏，否则设置宏和函数为空*/

#ifdef CONFIG_EXT2_FS_POSIX_ACL

/* acl.c */
extern struct posix_acl *ext2_get_acl(struct inode *inode, int type);
extern int ext2_set_acl(struct inode *inode, struct posix_acl *acl, int type);
extern int ext2_init_acl (struct inode *, struct inode *);

#else
/*如果没有配置这个宏*/
#include <linux/sched.h>
#define ext2_get_acl	NULL
#define ext2_set_acl	NULL

static inline int ext2_init_acl (struct inode *inode, struct inode *dir)
{
	return 0;
}
#endif

