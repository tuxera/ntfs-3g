#ifndef _NTFS_MISC_H_
#define _NTFS_MISC_H_

void *ntfs_calloc(size_t size);
void *ntfs_malloc(size_t size);
void ntfs_free(const void *ptr); /* JPA please do not remove the 'const' */

#endif /* _NTFS_MISC_H_ */

