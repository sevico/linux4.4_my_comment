/*
 * linux/fs/ext2/acl.c
 *
 * Copyright (C) 2001-2003 Andreas Gruenbacher, <agruen@suse.de>
 */

#include <linux/init.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include "ext2.h"
#include "xattr.h"
#include "acl.h"

/*
 * Convert from filesystem to in-memory representation.
 */
 /*把硬盘上的ext2的acl数据转成内存上的posix标准的acl数据
ext2文件系统的acl格式数据是开头是一个ext2_acl_header结构体的ext2头部，然后接下来是ext2_acl_entry_short或者是ext2_acl_entry结构体的acl实体
内存存储的posix标准的acl数据是开头是一个posix_acl结构体，然后随后就是count个posix_acl_entry结构体
*/
static struct posix_acl *
ext2_acl_from_disk(const void *value, size_t size)
{
	const char *end = (char *)value + size;
	int n, count;
	struct posix_acl *acl;
	/*如果参数是NULL，直接返回NULL*/
	if (!value)
		return NULL;
	/*如果大小小于ext2_acl_header大小，说明有错误*/
	if (size < sizeof(ext2_acl_header))
		 return ERR_PTR(-EINVAL);
	/*如果数据合法的话，开头肯定是ext2_acl_header，直接转化为ext2_acl_header指针，检验当前版本是否一致*/
	if (((ext2_acl_header *)value)->a_version !=
	    cpu_to_le32(EXT2_ACL_VERSION))
		return ERR_PTR(-EINVAL);
	/*value指向头部后边的数据部分*/
	value = (char *)value + sizeof(ext2_acl_header);
	/*这个函数之前讲过，根据acl数据大小返回数据项数目*/
	count = ext2_acl_count(size);
	/*返回参数检查*/
	if (count < 0)
		return ERR_PTR(-EINVAL);
	if (count == 0)
		return NULL;	
	/*根据返回的 项数，分配一定的posix标准结构体内存，这个函数是在fs/posix_acl.c实现，实现很简单*/
	acl = posix_acl_alloc(count, GFP_KERNEL);
	if (!acl)
		return ERR_PTR(-ENOMEM);	
	/*大循环来啦，对于每一项赋值*/
	for (n=0; n < count; n++) {
		/*entry指针指向第n项的ext2格式数据*/
		ext2_acl_entry *entry =
			(ext2_acl_entry *)value;
		if ((char *)value + sizeof(ext2_acl_entry_short) > end)
			goto fail;
		acl->a_entries[n].e_tag  = le16_to_cpu(entry->e_tag);
		acl->a_entries[n].e_perm = le16_to_cpu(entry->e_perm);
		switch(acl->a_entries[n].e_tag) {
			case ACL_USER_OBJ:
			case ACL_GROUP_OBJ:
			case ACL_MASK:
			case ACL_OTHER:
				value = (char *)value +
					sizeof(ext2_acl_entry_short);
				break;

			case ACL_USER:
				value = (char *)value + sizeof(ext2_acl_entry);
				if ((char *)value > end)
					goto fail;
				acl->a_entries[n].e_uid =
					make_kuid(&init_user_ns,
						  le32_to_cpu(entry->e_id));
				break;
			case ACL_GROUP:
				value = (char *)value + sizeof(ext2_acl_entry);
				if ((char *)value > end)
					goto fail;
				acl->a_entries[n].e_gid =
					make_kgid(&init_user_ns,
						  le32_to_cpu(entry->e_id));
				break;

			default:
				goto fail;
		}
	}
	if (value != end)
		goto fail;
	return acl;

fail:
	posix_acl_release(acl);
	return ERR_PTR(-EINVAL);
}

/*
 * Convert from in-memory to filesystem representation.
 */
static void *
ext2_acl_to_disk(const struct posix_acl *acl, size_t *size)
{
	ext2_acl_header *ext_acl;
	char *e;
	size_t n;

	*size = ext2_acl_size(acl->a_count);
	ext_acl = kmalloc(sizeof(ext2_acl_header) + acl->a_count *
			sizeof(ext2_acl_entry), GFP_KERNEL);
	if (!ext_acl)
		return ERR_PTR(-ENOMEM);
	ext_acl->a_version = cpu_to_le32(EXT2_ACL_VERSION);
	e = (char *)ext_acl + sizeof(ext2_acl_header);
	for (n=0; n < acl->a_count; n++) {
		const struct posix_acl_entry *acl_e = &acl->a_entries[n];
		ext2_acl_entry *entry = (ext2_acl_entry *)e;
		entry->e_tag  = cpu_to_le16(acl_e->e_tag);
		entry->e_perm = cpu_to_le16(acl_e->e_perm);
		switch(acl_e->e_tag) {
			case ACL_USER:
				entry->e_id = cpu_to_le32(
					from_kuid(&init_user_ns, acl_e->e_uid));
				e += sizeof(ext2_acl_entry);
				break;
			case ACL_GROUP:
				entry->e_id = cpu_to_le32(
					from_kgid(&init_user_ns, acl_e->e_gid));
				e += sizeof(ext2_acl_entry);
				break;

			case ACL_USER_OBJ:
			case ACL_GROUP_OBJ:
			case ACL_MASK:
			case ACL_OTHER:
				e += sizeof(ext2_acl_entry_short);
				break;

			default:
				goto fail;
		}
	}
	return (char *)ext_acl;

fail:
	kfree(ext_acl);
	return ERR_PTR(-EINVAL);
}

/*
 * inode->i_mutex: don't care
 */
struct posix_acl *
ext2_get_acl(struct inode *inode, int type)
{
	int name_index;
	char *value = NULL;
	struct posix_acl *acl;
	int retval;

	switch (type) {
	case ACL_TYPE_ACCESS:
		name_index = EXT2_XATTR_INDEX_POSIX_ACL_ACCESS;
		break;
	case ACL_TYPE_DEFAULT:
		name_index = EXT2_XATTR_INDEX_POSIX_ACL_DEFAULT;
		break;
	default:
		BUG();
	}
	retval = ext2_xattr_get(inode, name_index, "", NULL, 0);
	if (retval > 0) {
		value = kmalloc(retval, GFP_KERNEL);
		if (!value)
			return ERR_PTR(-ENOMEM);
		retval = ext2_xattr_get(inode, name_index, "", value, retval);
	}
	if (retval > 0)
		acl = ext2_acl_from_disk(value, retval);
	else if (retval == -ENODATA || retval == -ENOSYS)
		acl = NULL;
	else
		acl = ERR_PTR(retval);
	kfree(value);

	if (!IS_ERR(acl))
		set_cached_acl(inode, type, acl);

	return acl;
}

static int
__ext2_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	int name_index;
	void *value = NULL;
	size_t size = 0;
	int error;

	switch(type) {
		case ACL_TYPE_ACCESS:
			name_index = EXT2_XATTR_INDEX_POSIX_ACL_ACCESS;
			break;

		case ACL_TYPE_DEFAULT:
			name_index = EXT2_XATTR_INDEX_POSIX_ACL_DEFAULT;
			if (!S_ISDIR(inode->i_mode))
				return acl ? -EACCES : 0;
			break;

		default:
			return -EINVAL;
	}
 	if (acl) {
		value = ext2_acl_to_disk(acl, &size);
		if (IS_ERR(value))
			return (int)PTR_ERR(value);
	}

	error = ext2_xattr_set(inode, name_index, "", value, size, 0);

	kfree(value);
	if (!error)
		set_cached_acl(inode, type, acl);
	return error;
}

/*
 * inode->i_mutex: down
 */
int
ext2_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	int error;

	if (type == ACL_TYPE_ACCESS && acl) {
		error = posix_acl_update_mode(inode, &inode->i_mode, &acl);
		if (error)
			return error;
		inode->i_ctime = CURRENT_TIME_SEC;
		mark_inode_dirty(inode);
	}
	return __ext2_set_acl(inode, acl, type);
}

/*
 * Initialize the ACLs of a new inode. Called from ext2_new_inode.
 *
 * dir->i_mutex: down
 * inode->i_mutex: up (access to inode is still exclusive)
 */
int
ext2_init_acl(struct inode *inode, struct inode *dir)
{
	struct posix_acl *default_acl, *acl;
	int error;

	error = posix_acl_create(dir, &inode->i_mode, &default_acl, &acl);
	if (error)
		return error;

	if (default_acl) {
		error = __ext2_set_acl(inode, default_acl, ACL_TYPE_DEFAULT);
		posix_acl_release(default_acl);
	}
	if (acl) {
		if (!error)
			error = __ext2_set_acl(inode, acl, ACL_TYPE_ACCESS);
		posix_acl_release(acl);
	}
	return error;
}
