/*
 *  linux/fs/ext2/dir.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/dir.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext2 directory handling functions
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 *
 * All code that works with directory layout had been switched to pagecache
 * and moved here. AV
 */

#include "ext2.h"
#include <linux/buffer_head.h>
#include <linux/pagemap.h>
#include <linux/swap.h>

typedef struct ext2_dir_entry_2 ext2_dirent;

/*
 * Tests against MAX_REC_LEN etc were put in place for 64k block
 * sizes; if that is not possible on this arch, we can skip
 * those tests and speed things up.
 */
static inline unsigned ext2_rec_len_from_disk(__le16 dlen)
{
	unsigned len = le16_to_cpu(dlen);

#if (PAGE_CACHE_SIZE >= 65536)
	if (len == EXT2_MAX_REC_LEN)
		return 1 << 16;
#endif
	return len;
}

static inline __le16 ext2_rec_len_to_disk(unsigned len)
{
#if (PAGE_CACHE_SIZE >= 65536)
	if (len == (1 << 16))
		return cpu_to_le16(EXT2_MAX_REC_LEN);
	else
		BUG_ON(len > (1 << 16));
#endif
	return cpu_to_le16(len);
}

/*
 * ext2 uses block-sized chunks. Arguably, sector-sized ones would be
 * more robust, but we have what we have
 */ 
/*返回inode结构体所属的文件系统的块大小字节数*/
static inline unsigned ext2_chunk_size(struct inode *inode)
{
	return inode->i_sb->s_blocksize;
}
/*释放申请的页*/

static inline void ext2_put_page(struct page *page)
{
	kunmap(page);
	page_cache_release(page);
}

/*
 * Return the offset into page `page_nr' of the last valid
 * byte in that page, plus one.
 */
 
/*返回inode对应的文件的页号为page_nr的最后一个合法的字节的位置，再加一，
提示：页号从零开始*/
static unsigned
ext2_last_byte(struct inode *inode, unsigned long page_nr)
{
	/*先获得文件字节大小*/
	unsigned last_byte = inode->i_size;
	/*减去前边的页的字节数，page_nr << PAGE_CACHE_SHIFT就等于page_nr乘上页大小*/

	last_byte -= page_nr << PAGE_CACHE_SHIFT;
	/*如果page_nr不是最后一页，就返回当前页的最后一个字节位置加一*/
	if (last_byte > PAGE_CACHE_SIZE)
		last_byte = PAGE_CACHE_SIZE;
	return last_byte;
}
/*把page页缓存上的from到to的字节修改提交上去*/

static int ext2_commit_chunk(struct page *page, loff_t pos, unsigned len)
{
	/*找到这个缓冲区的拥有着*/
	struct address_space *mapping = page->mapping;
	struct inode *dir = mapping->host;
	int err = 0;

	dir->i_version++;
	block_write_end(NULL, mapping, pos, len, len, page, NULL);

	if (pos+len > dir->i_size) {
		i_size_write(dir, pos+len);
		mark_inode_dirty(dir);
	}
	/*如果标志上要求写入立刻同步，就同步，否则释放此页*/
	if (IS_DIRSYNC(dir)) {
		err = write_one_page(page, 1);
		if (!err)
			err = sync_inode_metadata(dir, 1);
	} else {
		unlock_page(page);
	}

	return err;
}
/*检验页有没有错误*/

static void ext2_check_page(struct page *page, int quiet)
{
	/*dir是页的主人*/
	struct inode *dir = page->mapping->host;
	/*sb是dir的文件系统vfs层的超级块*/
	struct super_block *sb = dir->i_sb;
	/*chunk_size是文件大小*/
	unsigned chunk_size = ext2_chunk_size(dir);
	/*返回页的虚拟地址*/
	char *kaddr = page_address(page);
	/*文件系统总的inode数目*/
	u32 max_inumber = le32_to_cpu(EXT2_SB(sb)->s_es->s_inodes_count);
	unsigned offs, rec_len;
	/*limit是页缓存的大小*/
	unsigned limit = PAGE_CACHE_SIZE;
	ext2_dirent *p;
	char *error;
	/*文件大小右移PAGE_CACHE_SHIFT位得到的是文件的最后一个缓存页的号码，如果等于page的index，就是说page就是文件的最后一部分对应的缓存页，并且文件都在缓冲区里*/

	if ((dir->i_size >> PAGE_CACHE_SHIFT) == page->index) {
		/*limit得到文件大小最后一个页的页内偏移*/
		limit = dir->i_size & ~PAGE_CACHE_MASK;
		/*如果不为零，说明这个文件目录不是一个完整的块大小的倍数，文件可能不是块大小的倍数，但是文件目录必定是块大小的倍数，这里就返回大小错误*/
		if (limit & (chunk_size - 1))
			goto Ebadsize;
		/*如果limit为0说明没问题*/
		if (!limit)
			goto out;
	}
	/*EXT2_DIR_REC_LEN宏我们前边讲过的，这里就是遍历目录的block块的内容，遍历块内的每一个ext2_dir_entry_2结构体*/
	for (offs = 0; offs <= limit - EXT2_DIR_REC_LEN(1); offs += rec_len) {		
		/*p指针指向当前应该指向的ext2_dir_entry_2结构体*/
		p = (ext2_dirent *)(kaddr + offs);
		/*rec_len当前项的长度*/
		rec_len = ext2_rec_len_from_disk(p->rec_len);
		/*当前项至少大于这个，如果小于，说明有问题，返回错误*/
		if (unlikely(rec_len < EXT2_DIR_REC_LEN(1)))
			goto Eshort;
		/*规定多余的目录项边界与4对齐，这说明没有对齐，返回没对齐的错误*/
		if (unlikely(rec_len & 3))
			goto Ealign;
		/*rec_len和文件名大小不一致*/
		if (unlikely(rec_len < EXT2_DIR_REC_LEN(p->name_len)))
			goto Enamelen;
		/*大小超出当前块了，说明rec_len有问题*/
		if (unlikely(((offs + rec_len - 1) ^ offs) & ~(chunk_size-1)))
			goto Espan;
		/*目录项的inode编号大于inode的最大编号，编号错误*/
		if (unlikely(le32_to_cpu(p->inode) > max_inumber))
			goto Einumber;
	}
	/*说明目录项没有和块边界对齐*/
	if (offs != limit)
		goto Eend;
out:
	/*page的flags有一个位标记这个page已经被检查过了，这里标记位为1*/
	SetPageChecked(page);
	return;

	/* Too bad, we had an error */

Ebadsize:
	/*目录的inode指向的文件大小不合法，打印这个块的大小不是块大小的倍数*/
	if (!quiet)
		ext2_error(sb, __func__,
			"size of directory #%lu is not a multiple "
			"of chunk size", dir->i_ino);
	goto fail;
Eshort:
	/*rec_len比最小的值还要小*/
	error = "rec_len is smaller than minimal";
	goto bad_entry;
Ealign:
	/*目录项未对齐*/
	error = "unaligned directory entry";
	goto bad_entry;
Enamelen:
	/*rec_len与名称长度不匹配*/
	error = "rec_len is too small for name_len";
	goto bad_entry;
Espan:
	/*目录项超出了块的边界*/
	error = "directory entry across blocks";
	goto bad_entry;
Einumber:
	/*inode号码错误*/
	error = "inode out of bounds";
bad_entry:
	/*目录项坏*/
	if (!quiet)
		ext2_error(sb, __func__, "bad entry in directory #%lu: : %s - "
			"offset=%lu, inode=%lu, rec_len=%d, name_len=%d",
			dir->i_ino, error, (page->index<<PAGE_CACHE_SHIFT)+offs,
			(unsigned long) le32_to_cpu(p->inode),
			rec_len, p->name_len);
	goto fail;
Eend:
	if (!quiet) {
		p = (ext2_dirent *)(kaddr + offs);
		ext2_error(sb, "ext2_check_page",
			"entry in directory #%lu spans the page boundary"
			"offset=%lu, inode=%lu",
			dir->i_ino, (page->index<<PAGE_CACHE_SHIFT)+offs,
			(unsigned long) le32_to_cpu(p->inode));
	}
fail:
	/*标记这个page标记过，但是有错误*/
	SetPageChecked(page);
	SetPageError(page);
}
/*从页缓存得到目录的inode的第n页数据*/

static struct page * ext2_get_page(struct inode *dir, unsigned long n,
				   int quiet)
{
	/*从目录的inode获得地址空间结构体*/
	struct address_space *mapping = dir->i_mapping;
	/*从地址空间读取第n页*/
	struct page *page = read_mapping_page(mapping, n, NULL);
	/*如果读取成功了*/
	if (!IS_ERR(page)) {
		/*映射后检查页*/
		kmap(page);
		if (!PageChecked(page))
			ext2_check_page(page, quiet);
		/*如果这个页有错误，就跳转到fail*/
		if (PageError(page))
			goto fail;
	}
	return page;

fail:
	/*有错误的页要释放掉，返回IO错误号码*/
	ext2_put_page(page);
	return ERR_PTR(-EIO);
}

/*
 * NOTE! unlike strncmp, ext2_match returns 1 for success, 0 for failure.
 *
 * len <= EXT2_NAME_LEN and de != NULL are guaranteed by caller.
 */
 /*ext2的字符串对比函数，和strncmp不一样，ext2_match成功返回1，失败返回0，在调用之前调用者需要保证len <= EXT2_NAME_LEN 并且de != NULL*/
static inline int ext2_match (int len, const char * const name,
					struct ext2_dir_entry_2 * de)
{
	/*如果长度都不一样，就不可能一样，直接返回错误*/
	if (len != de->name_len)
		return 0;
	/*如果目录项的inode为0，说明这个目录项被删除了，返回0*/
	if (!de->inode)
		return 0;
	/*对比name和de->name是否一致，返回和memcmp相反的返回值*/
	return !memcmp(name, de->name, len);
}

/*
 * p is at least 6 bytes before the end of page
 */
/*调用者需要保证p至少是页边界的前六个字节之前，这个函数返回p指向的目录项的下一个目录项*/
static inline ext2_dirent *ext2_next_entry(ext2_dirent *p)
{
	/*rec_len是当前的目录项的长度，当前指针加上rec_len个字节长度就得到了下一项的开头，但是rec_len是结构体的第5,6个字节，所以必须保证p至少是页边界的前六个字节之前*/
	return (ext2_dirent *)((char *)p +
			ext2_rec_len_from_disk(p->rec_len));
}
/*验证目录项，base是页的起始地址，offset是要检查的目录项偏移，mask是块大小减一得到的掩码*/

static inline unsigned 
ext2_validate_entry(char *base, unsigned offset, unsigned mask)
{
	/*指向要检查的目录项*/
	ext2_dirent *de = (ext2_dirent*)(base + offset);
	/*指向要检验的目录项所在页的第一个目录项位置*/
	ext2_dirent *p = (ext2_dirent*)(base + (offset&mask));
	/*遍历从第一个到我们要检验的这个*/
	while ((char*)p < (char*)de) {
		/*如果检验到rec_len=0，就是有错的，跳出循环*/
		if (p->rec_len == 0)
			break;
		p = ext2_next_entry(p);
	}	
	/*返回有错误的目录项的页内偏移*/
	return (char *)p - base;
}

static unsigned char ext2_filetype_table[EXT2_FT_MAX] = {
	[EXT2_FT_UNKNOWN]	= DT_UNKNOWN,
	[EXT2_FT_REG_FILE]	= DT_REG,
	[EXT2_FT_DIR]		= DT_DIR,
	[EXT2_FT_CHRDEV]	= DT_CHR,
	[EXT2_FT_BLKDEV]	= DT_BLK,
	[EXT2_FT_FIFO]		= DT_FIFO,
	[EXT2_FT_SOCK]		= DT_SOCK,
	[EXT2_FT_SYMLINK]	= DT_LNK,
};
/*S_SHIFT宏是位的偏移，S_IFREG等宏的位都在12位以后，这个结构体方便通过文件的模式，mode字段获得文件类型*/

#define S_SHIFT 12
static unsigned char ext2_type_by_mode[S_IFMT >> S_SHIFT] = {
	[S_IFREG >> S_SHIFT]	= EXT2_FT_REG_FILE,
	[S_IFDIR >> S_SHIFT]	= EXT2_FT_DIR,
	[S_IFCHR >> S_SHIFT]	= EXT2_FT_CHRDEV,
	[S_IFBLK >> S_SHIFT]	= EXT2_FT_BLKDEV,
	[S_IFIFO >> S_SHIFT]	= EXT2_FT_FIFO,
	[S_IFSOCK >> S_SHIFT]	= EXT2_FT_SOCK,
	[S_IFLNK >> S_SHIFT]	= EXT2_FT_SYMLINK,
};
/*设置目录项的类型*/

static inline void ext2_set_de_type(ext2_dirent *de, struct inode *inode)
{
	/*获得目录项的模式*/
	umode_t mode = inode->i_mode;
	/*检查EXT2_FEATURE_INCOMPAT_FILETYPE位，如果为1，就根据mode赋值文件类型，否则置为0，就是未知文件类型*/
	if (EXT2_HAS_INCOMPAT_FEATURE(inode->i_sb, EXT2_FEATURE_INCOMPAT_FILETYPE))
		de->file_type = ext2_type_by_mode[(mode & S_IFMT)>>S_SHIFT];
	else
		de->file_type = 0;
}
/*读取文件的目录内容，filp是要读取得文件指针，dirent是读取出来存放的缓冲区，filldir是把读取出来的数据按照不同的格式存放在dirent缓冲区里的方法*/

static int
ext2_readdir(struct file *file, struct dir_context *ctx)
{
	/*先得到文件的偏移*/

	loff_t pos = ctx->pos;
	/*获得目录的inode*/
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	/*pos与上缓存块的掩码得到了offset，得到的是在块内的偏移*/
	unsigned int offset = pos & ~PAGE_CACHE_MASK;
	/*n得到的是当前读取到的页编号*/
	unsigned long n = pos >> PAGE_CACHE_SHIFT;
	/*npages是文件占用的页数目*/
	unsigned long npages = dir_pages(inode);
	unsigned chunk_mask = ~(ext2_chunk_size(inode)-1);
	unsigned char *types = NULL;
	/*如果filp->f_version和inode->i_version不一致，就需要检验，这version记录文件的版本号，每次使用后都会加一，不一致就说明有可能内容不一样*/
	int need_revalidate = file->f_version != inode->i_version;
	/*检验pos值是不是超出限制了*/
	if (pos > inode->i_size - EXT2_DIR_REC_LEN(1))
		return 0;
	/*如果ext2文件系统有incompt_feature字段，先把types指针指向文件类型表*/
	if (EXT2_HAS_INCOMPAT_FEATURE(sb, EXT2_FEATURE_INCOMPAT_FILETYPE))
		types = ext2_filetype_table;
	/*遍历从当前读到的页到最后的页*/
	for ( ; n < npages; n++, offset = 0) {
		char *kaddr, *limit;
		ext2_dirent *de;
	/*前边讲过的函数，根据inode和页编号得到这个inode的第n页*/
		struct page *page = ext2_get_page(inode, n, 0);
		/*如果值有错，报错，并把f_pos指向下一页*/
		if (IS_ERR(page)) {
			ext2_error(sb, __func__,
				   "bad page in #%lu",
				   inode->i_ino);
			ctx->pos += PAGE_CACHE_SIZE - offset;
			return PTR_ERR(page);
		}
		/*获得page的虚拟地址*/
		kaddr = page_address(page);
		/*如果需要检验的话*/
		if (unlikely(need_revalidate)) {
			if (offset) {
				/*如果块内偏移不是0，就检验偏移的值，并且新的合法的偏移值赋给f_pos*/
				offset = ext2_validate_entry(kaddr, offset, chunk_mask);
				ctx->pos = (n<<PAGE_CACHE_SHIFT) + offset;
			}
			/*保持版本号一致，不需要检验*/
			file->f_version = inode->i_version;
			need_revalidate = 0;
		}
		/*根据得到的缓冲区，指向ext2的目录项结构体*/
		de = (ext2_dirent *)(kaddr+offset);
		/*ext2_last_byte函数我们上边讲过，就是页内最后一个合法的字节，得到的limit解释页内的合法的边界*/
		limit = kaddr + ext2_last_byte(inode, n) - EXT2_DIR_REC_LEN(1);		
		/*遍历页内的每一个目录项，ext2_next_entry函数我们之前也讲过，下一个目录项*/
		for ( ;(char*)de <= limit; de = ext2_next_entry(de)) {
			/*0长度的目录项是不合法的，返回IO错误，释放当前页*/
			if (de->rec_len == 0) {
				ext2_error(sb, __func__,
					"zero-length directory entry");
				ext2_put_page(page);
				return -EIO;
			}
			/*如果inode号不为0，(为0说明这个项已经被删除了，直接跳过)*/
			if (de->inode) {
				unsigned char d_type = DT_UNKNOWN;
				/*d_type从目录项里得到文件类型*/
				if (types && de->file_type < EXT2_FT_MAX)
					d_type = types[de->file_type];
				/*使用传进来的filldir(actor)函数来填充dirent缓冲区*/
				if (!dir_emit(ctx, de->name, de->name_len,
						le32_to_cpu(de->inode),
						d_type)) {
					ext2_put_page(page);
					return 0;
				}
			}
			ctx->pos += ext2_rec_len_from_disk(de->rec_len);
		}
		/*读完以后要释放*/
		ext2_put_page(page);
	}
	return 0;
}

/*
 *	ext2_find_entry()
 *
 * finds an entry in the specified directory with the wanted name. It
 * returns the page in which the entry was found (as a parameter - res_page),
 * and the entry itself. Page is returned mapped and unlocked.
 * Entry is guaranteed to be valid.
 */

/*ext2文件系统在一个给定的目录内寻找一个目录项，返回的目录项保证是合法的，
参数page得到的是目录项被找到的缓冲区，*/
struct ext2_dir_entry_2 *ext2_find_entry (struct inode * dir,
			struct qstr *child, struct page ** res_page)
{
	/*目录项名*/
	const char *name = child->name;
	int namelen = child->len;/*目录项名的长度*/
	/*EXT2_DIR_REC_LEN宏前边讲过，rec_len就是这个名字对应的目录项的大小，按字节算*/
	unsigned reclen = EXT2_DIR_REC_LEN(namelen);/*目录项的长度，这个宏前面解释过*/
	unsigned long start, n;
	unsigned long npages = dir_pages(dir);/*把以字节为单位的文件大小转换为物理页面数*/
	struct page *page = NULL;	
	/*从inode得到ext2_inode_info结构体，内存里的ext2_inode_info保存ext2的一些信息*/
	struct ext2_inode_info *ei = EXT2_I(dir);
	ext2_dirent * de;/*de为要返回的Ext2目录项结构*/
	int dir_has_error = 0;
	/*如果这个目录是空的，就直接返回*/
	if (npages == 0)
		goto out;

	/* OFFSET_CACHE */
	/* 先把它赋值为NULL */
	*res_page = NULL;
	/*开始查找的页数*/
	start = ei->i_dir_start_lookup;/*目录项在内存的起始位置*/
	if (start >= npages)
		start = 0;
	n = start;
	/*大循环，一个页一个页的查找*/
	do {
		char *kaddr;		
		/*从缓存中寻找，由inode结构体得到对应的页的数据，如果缓存上没有，就去硬盘上读取*/
		page = ext2_get_page(dir, n, dir_has_error);/*从页面高速缓存中获得目录项所在的页面*/
	/*查找成功，就在这个页上寻找*/
		if (!IS_ERR(page)) {
			/*获得page所对应的内核虚拟地址*/
			kaddr = page_address(page);
			/*获得该目录项结构的起始地址*/
			de = (ext2_dirent *) kaddr;
			kaddr += ext2_last_byte(dir, n) - reclen;
			/*只要没有到这个页的末尾，就继续循环*/
			while ((char *) de <= kaddr) {
				/*如果rec_len为0，就返回错误*/
				if (de->rec_len == 0) {
					ext2_error(dir->i_sb, __func__,
						"zero-length directory entry");
					ext2_put_page(page);
					goto out;
				}
				/*判断是否匹配*/
				if (ext2_match (namelen, name, de))
					goto found;
				/*取下一个 ext2_dir_entry_2*/
				de = ext2_next_entry(de);
			}
			/*释放目录项所在的页面*/
			ext2_put_page(page);
		} else
			dir_has_error = 1;
		/*n标记对应的开始页数*/
		if (++n >= npages)
			n = 0;
		/* next page is past the blocks we've got */
		if (unlikely(n > (dir->i_blocks >> (PAGE_CACHE_SHIFT - 9)))) {
			ext2_error(dir->i_sb, __func__,
				"dir %lu size %lld exceeds block count %llu",
				dir->i_ino, dir->i_size,
				(unsigned long long)dir->i_blocks);
			goto out;
		}
	} while (n != start);
out:
	return NULL;

found:
	/*找到了，就返回inode的页和ext信息结构体*/
	*res_page = page;
	ei->i_dir_start_lookup = n;
	return de;
}
/*获得dir目录所在的../目录项,p获得../目录项所在的页*/

struct ext2_dir_entry_2 * ext2_dotdot (struct inode *dir, struct page **p)
{
	/*之前讲过，这个函数获得dir目录的第0页*/

	struct page *page = ext2_get_page(dir, 0, 0);
	ext2_dirent *de = NULL;
	/*页正确的话*/
	if (!IS_ERR(page)) {
		/*目录项列表中，第一个是./，而下一个就是../*/
		de = ext2_next_entry((ext2_dirent *) page_address(page));
		*p = page;
	}
	return de;
}
/*通过目录的文件名获得这个文件的inode编号，dir是目录的inode，dentry是文件的dentry结构体*/

ino_t ext2_inode_by_name(struct inode *dir, struct qstr *child)
{
	ino_t res = 0;
	struct ext2_dir_entry_2 *de;
	struct page *page;
	/*上边刚讲过的函数，获得目录项结构体*/
	de = ext2_find_entry (dir, child, &page);
	if (de) {
		/*如果返回正确，得到inode号码，然后释放page*/
		res = le32_to_cpu(de->inode);
		ext2_put_page(page);
	}
	return res;
}

static int ext2_prepare_chunk(struct page *page, loff_t pos, unsigned len)
{
	return __block_write_begin(page, pos, len, ext2_get_block);
}

/* Releases the page */
/* ext2里把目录项列表的一个项变成inode文件指向的文件 */

void ext2_set_link(struct inode *dir, struct ext2_dir_entry_2 *de,
		   struct page *page, struct inode *inode, int update_times)
{
	loff_t pos = page_offset(page) +
			(char *) de - (char *) page_address(page);
	unsigned len = ext2_rec_len_from_disk(de->rec_len);
	int err;
	/*对页缓冲区写入要先锁住，然后调用prepare_write准备都下*/
	lock_page(page);
	err = ext2_prepare_chunk(page, pos, len);
	BUG_ON(err);
	/*赋值inode编号*/
	de->inode = cpu_to_le32(inode->i_ino);
	/*之前讲过的函数，写完编号写文件类型*/
	ext2_set_de_type(de, inode);
	/*把修改提交*/
	err = ext2_commit_chunk(page, pos, len);
	/*减少页引用计数*/
	ext2_put_page(page);
	/*目录的inode修改时间记录*/
	if (update_times)
		dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
	EXT2_I(dir)->i_flags &= ~EXT2_BTREE_FL;
	/*这个inode已经脏了*/
	mark_inode_dirty(dir);
}

/*
 *	Parent is locked.
 */ 
/*ext2增加目录对于文件的连接，就是把一个文件放到目录里，dentry是要放入的文件的dentry结构体，inode是要放的文件*/
int ext2_add_link (struct dentry *dentry, struct inode *inode)
{
	/*要放入的目录的inode*/
	struct inode *dir = d_inode(dentry->d_parent);
	/*文件名和名字长度*/
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	/*块大小*/
	unsigned chunk_size = ext2_chunk_size(dir);
	/*目录项结构体大小*/
	unsigned reclen = EXT2_DIR_REC_LEN(namelen);
	unsigned short rec_len, name_len;
	struct page *page = NULL;
	ext2_dirent * de;
	/*这个文件的页数目*/
	unsigned long npages = dir_pages(dir);
	unsigned long n;
	char *kaddr;
	loff_t pos;
	int err;

	/*
	 * We take care of directory expansion in the same loop.
	 * This code plays outside i_size, so it locks the page
	 * to protect that region.
	 */
	 /*遍历目录的目录项列表*/
	for (n = 0; n <= npages; n++) {
		char *dir_end;
		/*前边讲过这个函数，获得dir目录的第n页*/
		page = ext2_get_page(dir, n, 0);
		/*检查返回结果*/
		err = PTR_ERR(page);
		if (IS_ERR(page))
			goto out;		
		/*页转化成为虚拟地址*/
		lock_page(page);
		kaddr = page_address(page);
		/*dir_end得到的值是页内的最后一合法字节在的偏移位置*/
		dir_end = kaddr + ext2_last_byte(dir, n);
		/*de指向开始的地址*/
		de = (ext2_dirent *)kaddr;		
		/*使kaddr指向最后，并且预留下足够存放要加入的目录项的空间*/
		kaddr += PAGE_CACHE_SIZE - reclen;
		/*遍历每一个项*/
		while ((char *)de <= kaddr) {
			/*已经到本页内的最后一项了，说明还有空间存放目录项，跳转到找到了*/
			if ((char *)de == dir_end) {
				/* We hit i_size */
				name_len = 0;
				rec_len = chunk_size;
				de->rec_len = ext2_rec_len_to_disk(chunk_size);
				de->inode = 0;
				goto got_it;
			}
			/*发现了rec_len为0的目录项，说明在IO读写的时候出现错误，释放锁，跳出*/
			if (de->rec_len == 0) {
				ext2_error(dir->i_sb, __func__,
					"zero-length directory entry");
				err = -EIO;
				goto out_unlock;
			}
			err = -EEXIST;
			/*发现目录内已经有和要加入的目录项名字一样的，退出*/
			if (ext2_match (namelen, name, de))
				goto out_unlock;
			/*name_len是当前到的目录项应该的rec_len，rec_len是当前项的记录的rec_len，因为可能后边的目录项被删除了，使得这两个字段不一样*/
			name_len = EXT2_DIR_REC_LEN(de->name_len);
			rec_len = ext2_rec_len_from_disk(de->rec_len);
			/*如果当前的目录项inode号是0说明已经被删除了，并且rec_len大于reclen，说明空间也足够，跳转到找到了*/
			if (!de->inode && rec_len >= reclen)
				goto got_it;			
			/*如果rec_len比本目录项的空间加上要添加的空间还大，说明后边的空间足够插入一个我们想要插入的目录项，跳转到找到了*/
			if (rec_len >= name_len + reclen)
				goto got_it;
			/*加上rec_len就是找下一项*/
			de = (ext2_dirent *) ((char *) de + rec_len);
		}
		/*遍历完这一页，仍然没有找到*/
		unlock_page(page);
		ext2_put_page(page);
	}
	/*没找到就报BUG*/
	BUG();
	return -EINVAL;

got_it:	
	pos = page_offset(page) +
		(char*)de - (char*)page_address(page);
	//建立缓存映射
	err = ext2_prepare_chunk(page, pos, rec_len);
	if (err)
		goto out_unlock;
	/*如果inode不为0，说明当前目录项不是空的，但是这个目录项的后边有空间*/
	if (de->inode) {
		ext2_dirent *de1 = (ext2_dirent *) ((char *) de + name_len);
		de1->rec_len = ext2_rec_len_to_disk(rec_len - name_len);
		de->rec_len = ext2_rec_len_to_disk(name_len);
		de = de1;
	}
	de->name_len = namelen;
	memcpy(de->name, name, namelen);
	de->inode = cpu_to_le32(inode->i_ino);
	ext2_set_de_type (de, inode);
	/*写完以后把修改提交*/
	err = ext2_commit_chunk(page, pos, rec_len);
	/*目录的inode修改时间更正*/
	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
	EXT2_I(dir)->i_flags &= ~EXT2_BTREE_FL;
	/*写后都要标记脏*/
	mark_inode_dirty(dir);
	/* OFFSET_CACHE */
out_put:
	ext2_put_page(page);
out:
	return err;
out_unlock:
	unlock_page(page);
	goto out_put;
}

/*
 * ext2_delete_entry deletes a directory entry by merging it with the
 * previous entry. Page is up-to-date. Releases the page.
 */
int ext2_delete_entry (struct ext2_dir_entry_2 * dir, struct page * page )
{
	struct inode *inode = page->mapping->host;
	char *kaddr = page_address(page);
	unsigned from = ((char*)dir - kaddr) & ~(ext2_chunk_size(inode)-1);
	unsigned to = ((char *)dir - kaddr) +
				ext2_rec_len_from_disk(dir->rec_len);
	loff_t pos;
	ext2_dirent * pde = NULL;
	ext2_dirent * de = (ext2_dirent *) (kaddr + from);
	int err;

	while ((char*)de < (char*)dir) {
		if (de->rec_len == 0) {
			ext2_error(inode->i_sb, __func__,
				"zero-length directory entry");
			err = -EIO;
			goto out;
		}
		pde = de;
		de = ext2_next_entry(de);
	}
	if (pde)
		from = (char*)pde - (char*)page_address(page);
	pos = page_offset(page) + from;
	lock_page(page);
	err = ext2_prepare_chunk(page, pos, to - from);
	BUG_ON(err);
	if (pde)
		pde->rec_len = ext2_rec_len_to_disk(to - from);
	dir->inode = 0;
	err = ext2_commit_chunk(page, pos, to - from);
	inode->i_ctime = inode->i_mtime = CURRENT_TIME_SEC;
	EXT2_I(inode)->i_flags &= ~EXT2_BTREE_FL;
	mark_inode_dirty(inode);
out:
	ext2_put_page(page);
	return err;
}

/*
 * Set the first fragment of directory.
 */
int ext2_make_empty(struct inode *inode, struct inode *parent)
{
	struct page *page = grab_cache_page(inode->i_mapping, 0);
	unsigned chunk_size = ext2_chunk_size(inode);
	struct ext2_dir_entry_2 * de;
	int err;
	void *kaddr;

	if (!page)
		return -ENOMEM;

	err = ext2_prepare_chunk(page, 0, chunk_size);
	if (err) {
		unlock_page(page);
		goto fail;
	}
	kaddr = kmap_atomic(page);
	memset(kaddr, 0, chunk_size);
	de = (struct ext2_dir_entry_2 *)kaddr;
	de->name_len = 1;
	de->rec_len = ext2_rec_len_to_disk(EXT2_DIR_REC_LEN(1));
	memcpy (de->name, ".\0\0", 4);
	de->inode = cpu_to_le32(inode->i_ino);
	ext2_set_de_type (de, inode);

	de = (struct ext2_dir_entry_2 *)(kaddr + EXT2_DIR_REC_LEN(1));
	de->name_len = 2;
	de->rec_len = ext2_rec_len_to_disk(chunk_size - EXT2_DIR_REC_LEN(1));
	de->inode = cpu_to_le32(parent->i_ino);
	memcpy (de->name, "..\0", 4);
	ext2_set_de_type (de, inode);
	kunmap_atomic(kaddr);
	err = ext2_commit_chunk(page, 0, chunk_size);
fail:
	page_cache_release(page);
	return err;
}

/*
 * routine to check that the specified directory is empty (for rmdir)
 */
int ext2_empty_dir (struct inode * inode)
{
	struct page *page = NULL;
	unsigned long i, npages = dir_pages(inode);
	int dir_has_error = 0;

	for (i = 0; i < npages; i++) {
		char *kaddr;
		ext2_dirent * de;
		page = ext2_get_page(inode, i, dir_has_error);

		if (IS_ERR(page)) {
			dir_has_error = 1;
			continue;
		}

		kaddr = page_address(page);
		de = (ext2_dirent *)kaddr;
		kaddr += ext2_last_byte(inode, i) - EXT2_DIR_REC_LEN(1);

		while ((char *)de <= kaddr) {
			if (de->rec_len == 0) {
				ext2_error(inode->i_sb, __func__,
					"zero-length directory entry");
				printk("kaddr=%p, de=%p\n", kaddr, de);
				goto not_empty;
			}
			if (de->inode != 0) {
				/* check for . and .. */
				if (de->name[0] != '.')
					goto not_empty;
				if (de->name_len > 2)
					goto not_empty;
				if (de->name_len < 2) {
					if (de->inode !=
					    cpu_to_le32(inode->i_ino))
						goto not_empty;
				} else if (de->name[1] != '.')
					goto not_empty;
			}
			de = ext2_next_entry(de);
		}
		ext2_put_page(page);
	}
	return 1;

not_empty:
	ext2_put_page(page);
	return 0;
}

const struct file_operations ext2_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate	= ext2_readdir,
	.unlocked_ioctl = ext2_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ext2_compat_ioctl,
#endif
	.fsync		= ext2_fsync,
};
