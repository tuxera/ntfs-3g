/*
 * decrypt.h - interface for decryption rutines.
 * Part of the Linux-NTFS project.
 *
 * Copyright (c) 2005 Yuval Fledel
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
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _NTFS_DECRYPT_H
#define _NTFS_DECRYPT_H

typedef void *decrypt_session;
typedef void *decrypt_key;

extern decrypt_session *decrypt_open(void);
extern void decrypt_close(decrypt_session *session);
extern decrypt_key *decrypt_user_key_open(decrypt_session *session, 
			int thumb_size, void *thumb_print);
extern void decrypt_user_key_close(decrypt_key *key);
extern unsigned int decrypt_decrypt(decrypt_key *key, unsigned int data_size, 
					unsigned char *data);
extern unsigned int decrypt_decrypt_sector(decrypt_key *key, void *data,
			unsigned long long offset);
extern decrypt_key *decrypt_make_key(decrypt_session *session,
			unsigned int data_size, unsigned char *data);
extern int decrypt_get_block_size(decrypt_key *key);

#endif /* defined _NTFS_DECRYPT_H */
