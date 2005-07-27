/*
 * decrypt.h - Interface for decryption rutines.  Part of the Linux-NTFS
 *	       project.
 *
 * Copyright (c) 2005 Yuval Fledel
 * Copyright (c) 2005 Anton Altaparmakov
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

typedef void *ntfs_decrypt_user_key_session;
typedef void *ntfs_decrypt_user_key;
typedef void *ntfs_decrypt_data_key;

extern ntfs_decrypt_user_key_session *ntfs_decrypt_user_key_session_open(void);
extern void ntfs_decrypt_user_key_session_close(
		ntfs_decrypt_user_key_session *session);

extern ntfs_decrypt_user_key *ntfs_decrypt_user_key_open(
		ntfs_decrypt_user_key_session *session,
		unsigned char *thumb_print, unsigned thumb_size);
extern void ntfs_decrypt_user_key_close(ntfs_decrypt_user_key *key);

extern unsigned ntfs_decrypt_user_key_decrypt(ntfs_decrypt_user_key *key,
		unsigned char *data, unsigned data_size);

extern ntfs_decrypt_data_key *ntfs_decrypt_data_key_open(unsigned char *data,
		unsigned data_size);
extern void ntfs_decrypt_data_key_close(ntfs_decrypt_data_key *key);

extern unsigned ntfs_decrypt_data_key_decrypt_sector(ntfs_decrypt_data_key *key,
		unsigned char *data, unsigned long long offset);

#endif /* defined _NTFS_DECRYPT_H */
