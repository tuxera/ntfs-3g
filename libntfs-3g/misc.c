/**
 * misc.c : miscellaneous :
 *		- dealing with errors in memory allocation
 *		- data caching
 *
 * Copyright (c) 2008 Jean-Pierre Andre
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the NTFS-3G
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "types.h"
#include "security.h"
#include "misc.h"
#include "logging.h"

/**
 * ntfs_calloc
 * 
 * Return a pointer to the allocated memory or NULL if the request fails.
 */
void *ntfs_calloc(size_t size)
{
	void *p;
	
	p = calloc(1, size);
	if (!p)
		ntfs_log_perror("Failed to calloc %lld bytes", (long long)size);
	return p;
}

void *ntfs_malloc(size_t size)
{
	void *p;
	
	p = malloc(size);
	if (!p)
		ntfs_log_perror("Failed to malloc %lld bytes", (long long)size);
	return p;
}

/*
 *		General functions to deal with LRU caches
 *
 *	The cached data have to be organized in a structure in which
 *	the first fields must follow a mandatory pattern and further
 *	fields may contain any fixed size data. They are stored in an
 *	LRU list.
 *
 *	A compare function must be provided for finding a wanted entry
 *	in the cache. Another function may be provided for invalidating
 *	an entry to facilitate multiple invalidation.
 *
 *	These functions never return error codes. When there is a
 *	shortage of memory, data is simply not cached.
 */

/*
 *		Fetch an entry from cache
 *
 *	returns the cache entry, or NULL if not available
 */

struct CACHED_GENERIC *ntfs_fetch_cache(struct CACHE_HEADER *cache,
		const struct CACHED_GENERIC *wanted, cache_compare compare)
{
	struct CACHED_GENERIC *current;
	struct CACHED_GENERIC *previous;

	current = (struct CACHED_GENERIC*)NULL;
	if (cache) {
			/*
			 * Search sequentially in LRU list
			 */
		current = cache->most_recent_entry;
		previous = (struct CACHED_GENERIC*)NULL;
		while (current
			   && compare(current, wanted)) {
			previous = current;
			current = current->next;
			}
		if (current)
			cache->hits++;
		if (current && previous) {
			/*
			 * found and not at head of list, unlink from current
			 * position and relink as head of list
			 */
			previous->next = current->next;
			current->next = cache->most_recent_entry;
			cache->most_recent_entry = current;
		}
		cache->reads++;
	}
	return (current);
}

/*
 *		Enter an inode number into cache
 *	returns the cache entry or NULL if not possible
 */

struct CACHED_GENERIC *ntfs_enter_cache(struct CACHE_HEADER *cache,
			const struct CACHED_GENERIC *item, cache_compare compare)
{
	struct CACHED_GENERIC *current;
	struct CACHED_GENERIC *previous;
	struct CACHED_GENERIC *before;

	current = (struct CACHED_GENERIC*)NULL;
	if (cache) {

			/*
			 * Search sequentially in LRU list to locate the end,
			 * and find out whether the entry is already in list
			 * As we normally go to the end, no statistics is
			 * kept.
		 	 */
		current = cache->most_recent_entry;
		previous = (struct CACHED_GENERIC*)NULL;
		before = (struct CACHED_GENERIC*)NULL;
		while (current
		   && compare(current, item)) {
			before = previous;
			previous = current;
			current = current->next;
			}

		if (!current) {
			/*
			 * Not in list, get a free entry or reuse the
			 * last entry, and relink as head of list
			 * Note : we assume at least three entries, so
			 * before, previous and first are different when
			 * an entry is reused.
			 */

			if (cache->free_entry) {
				current = cache->free_entry;
				cache->free_entry = cache->free_entry->next;
				if (item->varsize) {
					current->variable = ntfs_malloc(
						item->varsize);
				} else
					current->variable = (void*)NULL;
				current->varsize = item->varsize;
			} else {
				before->next = (struct CACHED_GENERIC*)NULL;
				current = previous;
				if (item->varsize) {
					if (current->varsize)
						current->variable = realloc(
							current->variable,
							item->varsize);
					else
						current->variable = ntfs_malloc(
							item->varsize);
				} else {
					if (current->varsize)
						free(current->variable);
					current->variable = (void*)NULL;
				}
				current->varsize = item->varsize;
			}
			current->next = cache->most_recent_entry;
			cache->most_recent_entry = current;
			memcpy(current->fixed, item->fixed, cache->fixed_size);
			if (item->varsize) {
				if (current->variable) {
					memcpy(current->variable,
						item->variable, item->varsize);
				} else {
					/*
					 * no more memory for variable part
					 * recycle entry in free list
					 * not an error, just uncacheable
					 */
					cache->most_recent_entry = current->next;
					current->next = cache->free_entry;
					cache->free_entry = current;
					current = (struct CACHED_GENERIC*)NULL;
				}
			} else {
				current->variable = (void*)NULL;
				current->varsize = 0;
			}
		}
		cache->writes++;
	}
	return (current);
}

/*
 *		Invalidate entries in cache
 *
 *	Several entries may have to be invalidated (at least for inodes
 *	associated to directories which have been renamed), a different
 *	compare function may be provided to select entries to invalidate
 *
 *	Returns the number of deleted entries, this can be used by
 *	the caller to signal a cache corruption if the entry was
 *	supposed to be found.
 */

int ntfs_invalidate_cache(struct CACHE_HEADER *cache,
		const struct CACHED_GENERIC *item, cache_compare compare)
{
	struct CACHED_GENERIC *current;
	struct CACHED_GENERIC *previous;
	int count;

	current = (struct CACHED_GENERIC*)NULL;
	count = 0;
	if (cache) {
			/*
			 * Search sequentially in LRU list
			 */
		current = cache->most_recent_entry;
		previous = (struct CACHED_GENERIC*)NULL;
		while (current) {
			if (!compare(current, item)) {
				/*
				 * Relink into free list
				 */
				if (previous)
					previous->next = current->next;
				else
					cache->most_recent_entry = current->next;
				current->next = cache->free_entry;
				cache->free_entry = current;
				if (current->variable)
					free(current->variable);
				current->varsize = 0;
				if (previous)
					current = previous->next;
				else
					current = cache->most_recent_entry;
				count++;
			} else {
				previous = current;
				current = current->next;
			}
		}
	}
	return (count);
}

/*
 *		Free memory allocated to a cache
 */

static void ntfs_free_cache(struct CACHE_HEADER *cache)
{
	struct CACHED_GENERIC *entry;

	if (cache) {
		for (entry=cache->most_recent_entry; entry; entry=entry->next)
			if (entry->variable)
				free(entry->variable);
		free(cache);
	}
}

/*
 *		Create a cache
 *
 *	Returns the cache header, or NULL if the cache could not be created
 */

static struct CACHE_HEADER *ntfs_create_cache(const char *name,
			int full_item_size, int item_count)
{
	struct CACHE_HEADER *cache;
	struct CACHED_GENERIC *p;
	struct CACHED_GENERIC *q;
	int i;

	cache = (struct CACHE_HEADER*)
		ntfs_malloc(sizeof(struct CACHE_HEADER)
			 + item_count*full_item_size);
	if (cache) {
		cache->name = name;
		cache->fixed_size = full_item_size - sizeof(struct CACHED_GENERIC);
		cache->reads = 0;
		cache->writes = 0;
		cache->hits = 0;
		/* chain the entries, and mark an invalid entry */
		cache->most_recent_entry = (struct CACHED_GENERIC*)NULL;
		cache->free_entry = &cache->entry[0];
		p = &cache->entry[0];
		for (i=0; i<(item_count - 1); i++) {
			q = (struct CACHED_GENERIC*)((char*)p + full_item_size);
			p->next = q;
			p->variable = (void*)NULL;
			p->varsize = 0;
			p = q;
		}
			/* special for the last entry */
		p->next =  (struct CACHED_GENERIC*)NULL;
		p->variable = (void*)NULL;
		p->varsize = 0;
	}
	return (cache);
}

/*
 *		Create all LRU caches
 *
 *	No error return, if creation is not possible, cacheing will
 *	just be not available
 */

void ntfs_create_lru_caches(ntfs_volume *vol)
{
#if CACHE_INODE_SIZE
		 /* inode cache */
	vol->xinode_cache = ntfs_create_cache("inode",
		sizeof(struct CACHED_INODE), CACHE_INODE_SIZE);
#endif
	vol->securid_cache = ntfs_create_cache("securid",
		sizeof(struct CACHED_SECURID), CACHE_SECURID_SIZE);
#if CACHE_LEGACY_SIZE
	vol->legacy_cache = ntfs_create_cache("legacy",
		sizeof(struct CACHED_PERMISSIONS_LEGACY), CACHE_LEGACY_SIZE);
#endif
}

/*
 *		Free all LRU caches
 */

void ntfs_free_lru_caches(ntfs_volume *vol)
{
#if CACHE_INODE_SIZE
	ntfs_free_cache(vol->xinode_cache);
#endif
	ntfs_free_cache(vol->securid_cache);
#if CACHE_LEGACY_SIZE
	ntfs_free_cache(vol->legacy_cache);
#endif
}
