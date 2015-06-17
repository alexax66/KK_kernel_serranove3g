/*
 * zcache.c - zcache driver file
 *
 * The goal of zcache is implement a generic memory compression layer.
 * It's a backend of both frontswap and cleancache.
 *
 * This file only implemented cleancache part currently.
 * Concepts based on original zcache by Dan Magenheimer.
 *
 * Copyright (C) 2013  Bob Liu <bob.liu <at> oracle.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
*/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/cpu.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/cleancache.h>
#include <linux/rbtree.h>
#include <linux/radix-tree.h>
#include <linux/swap.h>
#include <linux/crypto.h>
#include <linux/mempool.h>
#include <linux/zbud.h>

#include <linux/mm_types.h>
#include <linux/page-flags.h>
#include <linux/swapops.h>
#include <linux/writeback.h>
#include <linux/pagemap.h>

/* Enable/disable zcache (disabled by default) */
static bool zcache_enabled __read_mostly;
module_param_named(enabled, zcache_enabled, bool, 0);

/* Enable/disable cleancache part of zcache */
static bool zcache_nocleancache __read_mostly;
module_param_named(nocleancache, zcache_nocleancache, bool, 0);

/* Compressor to be used by zcache */
#define ZCACHE_COMPRESSOR_DEFAULT "lzo"
static char *zcache_compressor = ZCACHE_COMPRESSOR_DEFAULT;
module_param_named(compressor, zcache_compressor, charp, 0);

/* The maximum percentage of memory that the compressed pool can occupy */
static unsigned int zcache_max_pool_percent = 10;
module_param_named(max_pool_percent,
			zcache_max_pool_percent, uint, 0644);

/* zcache cleancache part statistics */
static u64 zcache_cleancache_pool_pages;
static u64 zcache_cleancache_pool_limit_hit;
static u64 zcache_cleancache_written_back_pages;
static u64 zcache_cleancache_dup_entry;
static u64 zcache_cleancache_reclaim_fail;
static u64 zcache_cleancache_zbud_alloc_fail;
static atomic_t zcache_cleancache_stored_pages = ATOMIC_INIT(0);

struct zcache_cleancache_meta {
	int ra_index;
	int length;	/* compressed page size */
};

#define MAX_ZCACHE_POOLS 32 /* arbitrary */

/* Red-Black tree node. Maps inode to its page-tree */
struct zcache_rb_entry {
	int rb_index;
	struct kref refcount;

	struct radix_tree_root ra_root; /* maps inode index to page */
	spinlock_t ra_lock;		/* protects radix tree */
	struct rb_node rb_node;
};

/* One zcache pool per (cleancache aware) filesystem mount instance */
struct zcache_pool {
	struct rb_root rb_root;		/* maps inode number to page tree */
	rwlock_t rb_lock;		/* protects inode_tree */
	struct zbud_pool *pool;         /* zbud pool used */
};

/* Manage all zcache pools */
struct _zcache {
	struct zcache_pool *pools[MAX_ZCACHE_POOLS];
	u32 num_pools;		/* current no. of zcache pools */
	spinlock_t pool_lock;	/* protects pools[] and num_pools */
};
struct _zcache zcache;

static struct kmem_cache *zcache_cleancache_entry_cache;

/*********************************
* compression functions
**********************************/
/* per-cpu compression transforms */
static struct crypto_comp * __percpu *zcache_comp_pcpu_tfms;

enum comp_op {
	ZCACHE_COMPOP_COMPRESS,
	ZCACHE_COMPOP_DECOMPRESS
};

static int zcache_comp_op(enum comp_op op, const u8 *src, unsigned int slen,
				u8 *dst, unsigned int *dlen)
{
	struct crypto_comp *tfm;
	int ret;

	tfm = *per_cpu_ptr(zcache_comp_pcpu_tfms, get_cpu());
	switch (op) {
	case ZCACHE_COMPOP_COMPRESS:
		ret = crypto_comp_compress(tfm, src, slen, dst, dlen);
		break;
	case ZCACHE_COMPOP_DECOMPRESS:
		ret = crypto_comp_decompress(tfm, src, slen, dst, dlen);
		break;
	default:
		ret = -EINVAL;
	}

	put_cpu();
	return ret;
}

static int __init zcache_comp_init(void)
{
	if (!crypto_has_comp(zcache_compressor, 0, 0)) {
		pr_info("%s compressor not available\n", zcache_compressor);
		/* fall back to default compressor */
		zcache_compressor = ZCACHE_COMPRESSOR_DEFAULT;
		if (!crypto_has_comp(zcache_compressor, 0, 0))
			/* can't even load the default compressor */
			return -ENODEV;
	}
	pr_info("using %s compressor\n", zcache_compressor);

	/* alloc percpu transforms */
	zcache_comp_pcpu_tfms = alloc_percpu(struct crypto_comp *);
	if (!zcache_comp_pcpu_tfms)
		return -ENOMEM;
	return 0;
}

static void zcache_comp_exit(void)
{
	/* free percpu transforms */
	if (zcache_comp_pcpu_tfms)
		free_percpu(zcache_comp_pcpu_tfms);
}

/*********************************
* per-cpu code
**********************************/
static DEFINE_PER_CPU(u8 *, zcache_dstmem);

static int __zcache_cpu_notifier(unsigned long action, unsigned long cpu)
{
	struct crypto_comp *tfm;
	u8 *dst;

	switch (action) {
	case CPU_UP_PREPARE:
		tfm = crypto_alloc_comp(zcache_compressor, 0, 0);
		if (IS_ERR(tfm)) {
			pr_err("can't allocate compressor transform\n");
			return NOTIFY_BAD;
		}
		*per_cpu_ptr(zcache_comp_pcpu_tfms, cpu) = tfm;
		dst = kmalloc(PAGE_SIZE * 2, GFP_KERNEL);
		if (!dst) {
			pr_err("can't allocate compressor buffer\n");
			crypto_free_comp(tfm);
			*per_cpu_ptr(zcache_comp_pcpu_tfms, cpu) = NULL;
			return NOTIFY_BAD;
		}
		per_cpu(zcache_dstmem, cpu) = dst;
		break;
	case CPU_DEAD:
	case CPU_UP_CANCELED:
		tfm = *per_cpu_ptr(zcache_comp_pcpu_tfms, cpu);
		if (tfm) {
			crypto_free_comp(tfm);
			*per_cpu_ptr(zcache_comp_pcpu_tfms, cpu) = NULL;
		}
		dst = per_cpu(zcache_dstmem, cpu);
		kfree(dst);
		per_cpu(zcache_dstmem, cpu) = NULL;
		break;
	default:
		break;
	}
	return NOTIFY_OK;
}

static int zcache_cpu_notifier(struct notifier_block *nb,
				unsigned long action, void *pcpu)
{
	unsigned long cpu = (unsigned long)pcpu;
	return __zcache_cpu_notifier(action, cpu);
}

static struct notifier_block zcache_cpu_notifier_block = {
	.notifier_call = zcache_cpu_notifier
};

static int zcache_cpu_init(void)
{
	unsigned long cpu;

	get_online_cpus();
	for_each_online_cpu(cpu)
		if (__zcache_cpu_notifier(CPU_UP_PREPARE, cpu) != NOTIFY_OK)
			goto cleanup;
	register_cpu_notifier(&zcache_cpu_notifier_block);
	put_online_cpus();
	return 0;

cleanup:
	for_each_online_cpu(cpu)
		__zcache_cpu_notifier(CPU_UP_CANCELED, cpu);
	put_online_cpus();
	return -ENOMEM;
}

/*********************************
* helpers
**********************************/
static bool zcache_is_full(void)
{
	return (totalram_pages * zcache_max_pool_percent / 100 <
		zcache_cleancache_pool_pages);
}

static int zcache_cleancache_entry_cache_create(void)
{
	zcache_cleancache_entry_cache = KMEM_CACHE(zcache_rb_entry, 0);
	return (zcache_cleancache_entry_cache == NULL);
}
static void zcache_cleancache_entry_cache_destory(void)
{
	kmem_cache_destroy(zcache_cleancache_entry_cache);
}

static struct zcache_rb_entry *zcache_find_rb_entry(struct rb_root *root,
		int index, struct rb_node **rb_parent, struct rb_node ***rb_link)
{
	struct zcache_rb_entry *entry;
	struct rb_node **__rb_link, *__rb_parent, *rb_prev;

	__rb_link = &root->rb_node;
	rb_prev = __rb_parent = NULL;

	while (*__rb_link) {
		__rb_parent = *__rb_link;
		entry = rb_entry(__rb_parent, struct zcache_rb_entry, rb_node);
		if (entry->rb_index > index)
			__rb_link = &__rb_parent->rb_left;
		else if (entry->rb_index < index) {
			rb_prev = __rb_parent;
			__rb_link = &__rb_parent->rb_right;
		} else
			return entry;
	}

	if (rb_parent)
		*rb_parent = __rb_parent;
	if (rb_link)
		*rb_link = __rb_link;
	return NULL;
}

static struct zcache_rb_entry *zcache_find_get_rb_entry(struct zcache_pool *zpool,
					int rb_index)
{
	unsigned long flags;
	struct zcache_rb_entry *rb_entry;

	read_lock_irqsave(&zpool->rb_lock, flags);
	rb_entry = zcache_find_rb_entry(&zpool->rb_root, rb_index, 0, 0);
	if (rb_entry)
		kref_get(&rb_entry->refcount);
	read_unlock_irqrestore(&zpool->rb_lock, flags);
	return rb_entry;
}

/*
 * kref_put callback for zcache rb_entry.
 *
 * The entry must have been isolated from rbtree already.
 */
static void zcache_rb_entry_release(struct kref *kref)
{
	struct zcache_rb_entry *rb_entry;

	rb_entry = container_of(kref, struct zcache_rb_entry, refcount);
	BUG_ON(rb_entry->ra_root.rnode);
	kmem_cache_free(zcache_cleancache_entry_cache, rb_entry);
}

/*
 * Called under zcache_rb_entry->ra_lock
 */
static int zcache_rb_entry_is_empty(struct zcache_rb_entry *rb_entry)
{
	return rb_entry->ra_root.rnode == NULL;
}

/* Remove rb_entry from rbtree */
static void zcache_rb_entry_isolate(struct zcache_pool *zpool,
		struct zcache_rb_entry *rb_entry, bool hold_rblock)
{
	unsigned long flags;

	if (!hold_rblock)
		write_lock_irqsave(&zpool->rb_lock, flags);
	/*
	 * Someone can get reference on this node before we could
	 * acquire write lock above. We want to remove it from its
	 * inode_tree when only the caller and corresponding inode_tree
	 * holds a reference to it. This ensures that a racing zcache
	 * put will not end up adding a page to an isolated node and
	 * thereby losing that memory.
	 *
	 */
	if (atomic_read(&rb_entry->refcount.refcount) == 2) {
		rb_erase(&rb_entry->rb_node, &zpool->rb_root);
		RB_CLEAR_NODE(&rb_entry->rb_node);
		kref_put(&rb_entry->refcount, zcache_rb_entry_release);
	}
	if (!hold_rblock)
		write_unlock_irqrestore(&zpool->rb_lock, flags);
}


static int zcache_store_handle(struct zcache_pool *zpool,
		unsigned long handle, int rb_index, int ra_index)
{
	unsigned long flags;
	struct zcache_rb_entry *rb_entry, *tmp;
	struct rb_node **link = NULL, *parent = NULL;
	int ret;
	void *dup_handlep;

	rb_entry = zcache_find_get_rb_entry(zpool, rb_index);
	if (!rb_entry) {
		/* alloc new rb_entry */
		rb_entry = kmem_cache_alloc(zcache_cleancache_entry_cache, GFP_KERNEL);
		if (!rb_entry)
			return -ENOMEM;

		INIT_RADIX_TREE(&rb_entry->ra_root, GFP_ATOMIC|__GFP_NOWARN);
		spin_lock_init(&rb_entry->ra_lock);
		rb_entry->rb_index = rb_index;
		kref_init(&rb_entry->refcount);
		RB_CLEAR_NODE(&rb_entry->rb_node);

		/* add new entry to rb tree */
		write_lock_irqsave(&zpool->rb_lock, flags);

		tmp = zcache_find_rb_entry(&zpool->rb_root, rb_index, &parent, &link);
		if (tmp) {
			/* somebody else allocated new entry */
			kmem_cache_free(zcache_cleancache_entry_cache, rb_entry);
			rb_entry = tmp;
		} else {
			rb_link_node(&rb_entry->rb_node, parent, link);
			rb_insert_color(&rb_entry->rb_node, &zpool->rb_root);
		}

		kref_get(&rb_entry->refcount);
		write_unlock_irqrestore(&zpool->rb_lock, flags);
	}

	/* Succ get rb_entry and refcount after arrived here */
	spin_lock_irqsave(&rb_entry->ra_lock, flags);
	dup_handlep = radix_tree_delete(&rb_entry->ra_root, ra_index);
	if (unlikely(dup_handlep)) {
		WARN_ON("duplicated entry, will be replaced!\n");
		zbud_free(zpool->pool, (unsigned long)dup_handlep);
		atomic_dec(&zcache_cleancache_stored_pages);
		zcache_cleancache_pool_pages = zbud_get_pool_size(zpool->pool);
		zcache_cleancache_dup_entry++;
	}
	ret = radix_tree_insert(&rb_entry->ra_root, ra_index, (void *)handle);

	if (unlikely(ret))
		if (zcache_rb_entry_is_empty(rb_entry))
			zcache_rb_entry_isolate(zpool, rb_entry, 0);
	spin_unlock_irqrestore(&rb_entry->ra_lock, flags);

	kref_put(&rb_entry->refcount, zcache_rb_entry_release);
	return ret;
}

/* Load the handle, and delete it */
static unsigned long *zcache_load_delete_handle(struct zcache_pool *zpool, int rb_index,
				int ra_index)
{
	struct zcache_rb_entry *rb_entry;
	void *handlep = NULL;
	unsigned long flags;

	rb_entry = zcache_find_get_rb_entry(zpool, rb_index);
	if (!rb_entry)
		goto out;

	BUG_ON(rb_entry->rb_index != rb_index);

	spin_lock_irqsave(&rb_entry->ra_lock, flags);
	handlep = radix_tree_delete(&rb_entry->ra_root, ra_index);
	if (zcache_rb_entry_is_empty(rb_entry))
		/* If no more nodes in the rb_entry->radix_tree,
		 * rm rb_entry from the rbtree and drop the refcount
		 */
		zcache_rb_entry_isolate(zpool, rb_entry, 0);
	spin_unlock_irqrestore(&rb_entry->ra_lock, flags);

	/* After arrive here, rb_entry have dropped from rbtree */
	kref_put(&rb_entry->refcount, zcache_rb_entry_release);
out:
	return handlep;
}

static void zcache_cleancache_store_page(int pool_id, struct cleancache_filekey key,
			pgoff_t index, struct page *page)
{
	unsigned int dlen = PAGE_SIZE, len;
	unsigned long handle;
	char *buf;
	u8 *src, *dst;
	struct zcache_cleancache_meta *zmeta;
	int ret;

	struct zcache_pool *zpool = zcache.pools[pool_id];

	/* reclaim space if needed */
	if (zcache_is_full()) {
		/* Reclaim will be implemented in following version */
		zcache_cleancache_pool_limit_hit++;
		return;
	}

	/* compress */
	dst = get_cpu_var(zcache_dstmem);
	src = kmap_atomic(page);
	ret = zcache_comp_op(ZCACHE_COMPOP_COMPRESS, src, PAGE_SIZE, dst, &dlen);
	kunmap_atomic(src);
	if (ret) {
		pr_err("zcache_cleancache compress error ret %d\n", ret);
		put_cpu_var(zcache_dstmem);
		return;
	}

	/* store handle with meta data */
	len = dlen + sizeof(struct zcache_cleancache_meta);
	ret = zbud_alloc(zpool->pool, len, __GFP_NORETRY | __GFP_NOWARN, &handle);
	if (ret) {
		zcache_cleancache_zbud_alloc_fail++;
		put_cpu_var(zcache_dstmem);
		return;
	}

	zmeta = zbud_map(zpool->pool, handle);
	zmeta->ra_index = index;
	zmeta->length = dlen;
	buf = (u8 *)(zmeta + 1);
	memcpy(buf, dst, dlen);
	zbud_unmap(zpool->pool, handle);
	put_cpu_var(zcache_dstmem);

	/* populate entry */
	ret = zcache_store_handle(zpool, handle, key.u.ino, index);
	if (ret) {
		pr_err("%s: store handle error %d\n", __func__, ret);
		zbud_free(zpool->pool, handle);
	}

	/* update stats */
	atomic_inc(&zcache_cleancache_stored_pages);
	zcache_cleancache_pool_pages = zbud_get_pool_size(zpool->pool);
	return;
}

static int zcache_cleancache_load_page(int pool_id, struct cleancache_filekey key,
			pgoff_t index, struct page *page)
{
	struct zcache_pool *zpool = zcache.pools[pool_id];
	u8 *src, *dst;
	unsigned int dlen;
	int ret;
	unsigned long *handlep;
	struct zcache_cleancache_meta *zmeta;

	handlep = zcache_load_delete_handle(zpool, key.u.ino, index);
	if (!handlep)
		return -1;

	zmeta = (struct zcache_cleancache_meta *)zbud_map(zpool->pool, (unsigned long)handlep);
	src = (u8 *)(zmeta + 1);

	/* decompress */
	dlen = PAGE_SIZE;
	dst = kmap_atomic(page);
	ret = zcache_comp_op(ZCACHE_COMPOP_DECOMPRESS, src, zmeta->length, dst, &dlen);
	kunmap_atomic(dst);
	zbud_unmap(zpool->pool, (unsigned long)handlep);
	zbud_free(zpool->pool, (unsigned long)handlep);

	WARN_ON(ret);	/* decompress err, will fetch from real disk */
	/* update stats */
	atomic_dec(&zcache_cleancache_stored_pages);
	zcache_cleancache_pool_pages = zbud_get_pool_size(zpool->pool);
	return ret;
}

static void zcache_cleancache_flush_page(int pool_id, struct cleancache_filekey key,
			pgoff_t index)
{
	struct zcache_pool *zpool = zcache.pools[pool_id];
	unsigned long *handlep = NULL;

	handlep = zcache_load_delete_handle(zpool, key.u.ino, index);
	if (handlep) {
		zbud_free(zpool->pool, (unsigned long)handlep);
		atomic_dec(&zcache_cleancache_stored_pages);
		zcache_cleancache_pool_pages = zbud_get_pool_size(zpool->pool);
	}
}

#define FREE_BATCH 16
static void zcache_cleancache_flush_ratree(struct zcache_pool *zpool,
				struct zcache_rb_entry *entry)
{
	int count, i;
	unsigned long index = 0;

	do {
		struct zcache_cleancache_meta *handles[FREE_BATCH];

		count = radix_tree_gang_lookup(&entry->ra_root,
				(void **)handles, index, FREE_BATCH);

		for (i = 0; i < count; i++) {
			index = handles[i]->ra_index;
			radix_tree_delete(&entry->ra_root, index);
			zbud_free(zpool->pool, (unsigned long)handles[i]);
			atomic_dec(&zcache_cleancache_stored_pages);
			zcache_cleancache_pool_pages = zbud_get_pool_size(zpool->pool);
		}

		index++;
	} while (count == FREE_BATCH);
}

static void zcache_cleancache_flush_inode(int pool_id,
					struct cleancache_filekey key)
{
	struct zcache_rb_entry *rb_entry;
	unsigned long flags1, flags2;
	struct zcache_pool *zpool = zcache.pools[pool_id];

	/* refuse new pages added in to the same inode */
	write_lock_irqsave(&zpool->rb_lock, flags1);
	rb_entry = zcache_find_rb_entry(&zpool->rb_root, key.u.ino, 0, 0);
	if (!rb_entry) {
		write_unlock_irqrestore(&zpool->rb_lock, flags1);
		return;
	}

	kref_get(&rb_entry->refcount);

	spin_lock_irqsave(&rb_entry->ra_lock, flags2);
	zcache_cleancache_flush_ratree(zpool, rb_entry);
	if (zcache_rb_entry_is_empty(rb_entry))
		zcache_rb_entry_isolate(zpool, rb_entry, 1);
	spin_unlock_irqrestore(&rb_entry->ra_lock, flags2);

	write_unlock_irqrestore(&zpool->rb_lock, flags1);
	kref_put(&rb_entry->refcount, zcache_rb_entry_release);
}

static void zcache_destroy_pool(struct zcache_pool *zpool);
static void zcache_cleancache_flush_fs(int pool_id)
{
	struct zcache_rb_entry *entry = NULL;
	struct rb_node *node;
	unsigned long flags1, flags2;
	struct zcache_pool *zpool = zcache.pools[pool_id];

	if (!zpool)
		return;

	/* refuse new pages added in to the same inode */
	write_lock_irqsave(&zpool->rb_lock, flags1);

	node = rb_first(&zpool->rb_root);
	while (node) {
		entry = rb_entry(node, struct zcache_rb_entry, rb_node);
		node = rb_next(node);
		if (entry) {
			kref_get(&entry->refcount);
			spin_lock_irqsave(&entry->ra_lock, flags2);
			zcache_cleancache_flush_ratree(zpool, entry);
			if (zcache_rb_entry_is_empty(entry))
				zcache_rb_entry_isolate(zpool, entry, 1);
			spin_unlock_irqrestore(&entry->ra_lock, flags2);
			kref_put(&entry->refcount, zcache_rb_entry_release);
		}
	}

	write_unlock_irqrestore(&zpool->rb_lock, flags1);

	zcache_destroy_pool(zpool);
}

static int zcache_cleancache_evict_entry(struct zbud_pool *pool,
		unsigned long handle)
{
	return -1;
}

static struct zbud_ops zcache_cleancache_zbud_ops = {
	.evict = zcache_cleancache_evict_entry
};

static void zcache_destroy_pool(struct zcache_pool *zpool)
{
	int i;

	if (!zpool)
		return;

	spin_lock(&zcache.pool_lock);
	zcache.num_pools--;
	for (i = 0; i < MAX_ZCACHE_POOLS; i++)
		if (zcache.pools[i] == zpool)
			break;
	zcache.pools[i] = NULL;
	spin_unlock(&zcache.pool_lock);

	if (!RB_EMPTY_ROOT(&zpool->rb_root)) {
		WARN_ON("Memory leak detected. Freeing non-empty pool!\n");
	}

	zbud_destroy_pool(zpool->pool);
	kfree(zpool);
}

/* return pool id */
static int zcache_create_pool(void)
{
	int ret;
	struct zcache_pool *zpool;

	zpool = kzalloc(sizeof(*zpool), GFP_KERNEL);
	if (!zpool) {
		ret = -ENOMEM;
		goto out;
	}

	zpool->pool = zbud_create_pool(GFP_KERNEL, &zcache_cleancache_zbud_ops);
	if (!zpool->pool) {
		kfree(zpool);
		ret = -ENOMEM;
		goto out;
	}

	spin_lock(&zcache.pool_lock);
	if (zcache.num_pools == MAX_ZCACHE_POOLS) {
		pr_info("Cannot create new pool (limit: %u)\n",
					MAX_ZCACHE_POOLS);
		zbud_destroy_pool(zpool->pool);
		kfree(zpool);
		ret = -EPERM;
		goto out_unlock;
	}

	rwlock_init(&zpool->rb_lock);
	zpool->rb_root = RB_ROOT;

	/* Add to pool list */
	for (ret = 0; ret < MAX_ZCACHE_POOLS; ret++)
		if (!zcache.pools[ret])
			break;
	zcache.pools[ret] = zpool;
	zcache.num_pools++;
	pr_info("New pool created id:%d\n", ret);

out_unlock:
	spin_unlock(&zcache.pool_lock);
out:
	return ret;
}

static int zcache_cleancache_init_fs(size_t pagesize)
{
	int ret;

	if (pagesize != PAGE_SIZE) {
		pr_info("Unsupported page size: %zu", pagesize);
		ret = -EINVAL;
		goto out;
	}

	ret = zcache_create_pool();
	if (ret < 0) {
		pr_info("Failed to create new pool\n");
		ret = -ENOMEM;
		goto out;
	}

out:
	return ret;
}

static int zcache_cleancache_init_shared_fs(char *uuid, size_t pagesize)
{
	/* shared pools are unsupported and map to private */
	return zcache_cleancache_init_fs(pagesize);
}

static struct cleancache_ops zcache_cleancache_ops = {
	.put_page = zcache_cleancache_store_page,
	.get_page = zcache_cleancache_load_page,
	.invalidate_page = zcache_cleancache_flush_page,
	.invalidate_inode = zcache_cleancache_flush_inode,
	.invalidate_fs = zcache_cleancache_flush_fs,
	.init_shared_fs = zcache_cleancache_init_shared_fs,
	.init_fs = zcache_cleancache_init_fs
};

/*********************************
* debugfs functions
**********************************/
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>

static struct dentry *zcache_cleancache_debugfs_root;

static int __init zcache_debugfs_init(void)
{
	if (!debugfs_initialized())
		return -ENODEV;

	if (!zcache_nocleancache) {
		zcache_cleancache_debugfs_root = debugfs_create_dir("zcache_cleancache", NULL);
		if (!zcache_cleancache_debugfs_root)
			return -ENOMEM;

		debugfs_create_u64("pool_limit_hit", S_IRUGO,
				zcache_cleancache_debugfs_root, &zcache_cleancache_pool_limit_hit);
		debugfs_create_u64("reclaim_fail", S_IRUGO,
				zcache_cleancache_debugfs_root, &zcache_cleancache_reclaim_fail);
		debugfs_create_u64("reject_alloc_fail", S_IRUGO,
				zcache_cleancache_debugfs_root, &zcache_cleancache_zbud_alloc_fail);
		debugfs_create_u64("written_back_pages", S_IRUGO,
				zcache_cleancache_debugfs_root, &zcache_cleancache_written_back_pages);
		debugfs_create_u64("duplicate_entry", S_IRUGO,
				zcache_cleancache_debugfs_root, &zcache_cleancache_dup_entry);
		debugfs_create_u64("pool_pages", S_IRUGO,
				zcache_cleancache_debugfs_root, &zcache_cleancache_pool_pages);
		debugfs_create_atomic_t("stored_pages", S_IRUGO,
				zcache_cleancache_debugfs_root, &zcache_cleancache_stored_pages);
	}
	return 0;
}

static void __exit zcache_debugfs_exit(void)
{
	debugfs_remove_recursive(zcache_cleancache_debugfs_root);
}
#else
static int __init zcache_debugfs_init(void)
{
	return 0;
}
static void __exit zcache_debugfs_exit(void)
{
}
#endif

/*********************************
* module init and exit
**********************************/
static int __init init_zcache(void)
{
	if (!zcache_enabled)
		return 0;

	pr_info("loading zcache..\n");
	if (!zcache_nocleancache)
		if (zcache_cleancache_entry_cache_create()) {
			pr_err("entry cache creation failed\n");
			goto error;
		}

	if (zcache_comp_init()) {
		pr_err("compressor initialization failed\n");
		goto compfail;
	}
	if (zcache_cpu_init()) {
		pr_err("per-cpu initialization failed\n");
		goto pcpufail;
	}

	spin_lock_init(&zcache.pool_lock);
	if (!zcache_nocleancache)
		cleancache_register_ops(&zcache_cleancache_ops);

	if (zcache_debugfs_init())
		pr_warn("debugfs initialization failed\n");
	return 0;
pcpufail:
	zcache_comp_exit();
compfail:
	zcache_cleancache_entry_cache_destory();
error:
	return -ENOMEM;
}
/* must be late so crypto has time to come up */
late_initcall(init_zcache);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bob Liu <bob.liu <at> oracle.com>");
MODULE_DESCRIPTION("Compressed cache for clean file pages");