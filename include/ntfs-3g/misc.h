#ifndef _NTFS_MISC_H_
#define _NTFS_MISC_H_

#include "volume.h"

struct CACHED_GENERIC {
	struct CACHED_GENERIC *next;
	char *pathname;
	void *fixed[0];
} ;

struct CACHED_INODE {
	struct CACHED_INODE *next;
	char *pathname;
	u64 inum;
} ;

typedef int (*cache_compare)(const struct CACHED_GENERIC *cached,
				const struct CACHED_GENERIC *item);

struct CACHE_HEADER {
	const char *name;
	struct CACHED_GENERIC *most_recent_entry;
	struct CACHED_GENERIC *free_entry;
	unsigned long reads;
	unsigned long writes;
	unsigned long hits;
	int fixed_size;
	struct CACHED_GENERIC entry[0];
} ;

	/* cast to generic, avoiding gcc warnings */
#define GENERIC(pstr) ((const struct CACHED_GENERIC*)(const void*)(pstr))

struct CACHED_GENERIC *ntfs_fetch_cache(struct CACHE_HEADER *cache,
		const struct CACHED_GENERIC *wanted, cache_compare compare);
struct CACHED_GENERIC *ntfs_enter_cache(struct CACHE_HEADER *cache,
			const struct CACHED_GENERIC *item, cache_compare compare);
int ntfs_invalidate_cache(struct CACHE_HEADER *cache,
		const struct CACHED_GENERIC *item, cache_compare compare);
void ntfs_create_lru_caches(ntfs_volume *vol);
void ntfs_free_lru_caches(ntfs_volume *vol);

void *ntfs_calloc(size_t size);
void *ntfs_malloc(size_t size);

#endif /* _NTFS_MISC_H_ */

