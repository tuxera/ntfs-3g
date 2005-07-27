/**
 * ntfsdecrypt - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2005 Yuval Fledel
 * Copyright (c) 2005 Anton Altaparmakov
 *
 * This utility will decrypt files and print on the standard output.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "config.h"

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "attrib.h"
#include "utils.h"
#include "volume.h"
#include "debug.h"
#include "dir.h"
#include "layout.h"
#include "decrypt.h"

struct options {
	char *device;		/* Device/File to work with */
	char *file;		/* File to display */
	s64 inode;		/* Inode to work with */
	ATTR_TYPES attr;	/* Attribute type to display */
	int force;		/* Override common sense */
	int quiet;		/* Less output */
	int verbose;		/* Extra output */
};

static const char *EXEC_NAME = "ntfsdecrypt";
static struct options opts;

GEN_PRINTF(Eprintf, stderr, NULL, FALSE)
GEN_PRINTF(Vprintf, stderr, &opts.verbose, TRUE)
GEN_PRINTF(Qprintf, stderr, &opts.quiet, FALSE)
static GEN_PRINTF(Printf, stderr, NULL, FALSE)

static ntfschar EFS[5] = {
	const_cpu_to_le16('$'), const_cpu_to_le16('E'), const_cpu_to_le16('F'),
	const_cpu_to_le16('S'), const_cpu_to_le16('\0')
};
static const int EFS_name_length = 4;

/**
 * version - Print version information about the program
 *
 * Print a copyright statement and a brief description of the program.
 *
 * Return:  none
 */
static void version(void)
{
	Printf("\n%s v%s - Decrypt files and print on the standard output.\n\n",
			EXEC_NAME, VERSION);
	Printf("Copyright (c) 2005 Yuval Fledel\n");
	Printf("Copyright (c) 2005 Anton Altaparmakov\n");
	Printf("\n%s\n%s%s\n", ntfs_gpl, ntfs_bugs, ntfs_home);
}

/**
 * usage - Print a list of the parameters to the program
 *
 * Print a list of the parameters and options for the program.
 *
 * Return:  none
 */
static void usage(void)
{
	Printf("\nUsage: %s [options] device [file]\n\n"
	       "    -i, --inode num       Display this inode\n\n"
	       "    -f  --force           Use less caution\n"
	       "    -h  --help            Print this help\n"
	       "    -q  --quiet           Less output\n"
	       "    -V  --version         Version information\n"
	       "    -v  --verbose         More output\n\n",
	       //"    -r  --raw             Display the compressed or encrypted file",
	       EXEC_NAME);
	Printf("%s%s\n", ntfs_bugs, ntfs_home);
}

/**
 * parse_options - Read and validate the programs command line
 *
 * Read the command line, verify the syntax and parse the options.
 * This function is very long, but quite simple.
 *
 * Return:  1 Success
 *	    0 Error, one or more problems
 */
static int parse_options(int argc, char **argv)
{
	static const char *sopt = "-fh?i:qVv";	// F:N:
	static const struct option lopt[] = {
		{"force", no_argument, NULL, 'f'},
		{"help", no_argument, NULL, 'h'},
		{"inode", required_argument, NULL, 'i'},
		{"quiet", no_argument, NULL, 'q'},
		{"version", no_argument, NULL, 'V'},
		{"verbose", no_argument, NULL, 'v'},
		{NULL, 0, NULL, 0}
	};

	char c = -1;
	int err = 0;
	int ver = 0;
	int help = 0;

	opterr = 0;		/* We'll handle the errors, thank you. */

	opts.inode = -1;

	while ((c = getopt_long(argc, argv, sopt, lopt, NULL)) != (char)-1) {
		switch (c) {
		case 1:	/* A non-option argument */
			if (!opts.device)
				opts.device = argv[optind - 1];
			else if (!opts.file)
				opts.file = argv[optind - 1];
			else {
				Eprintf("You must specify exactly one file.\n");
				err++;
			}
			break;
		case 'f':
			opts.force++;
			break;
		case 'h':
		case '?':
			help++;
			break;
		case 'i':
			if (opts.inode != -1)
				Eprintf("You must specify exactly one "
						"inode.\n");
			else if (utils_parse_size(optarg, &opts.inode, FALSE))
				break;
			else
				Eprintf("Couldn't parse inode number.\n");
			err++;
			break;
		case 'q':
			opts.quiet++;
			break;
		case 'V':
			ver++;
			break;
		case 'v':
			opts.verbose++;
			break;
		default:
			Eprintf("Unknown option '%s'.\n", argv[optind - 1]);
			err++;
			break;
		}
	}

	if (help || ver) {
		opts.quiet = 0;
	} else {
		if (opts.device == NULL) {
			Eprintf("You must specify a device.\n");
			err++;

		} else if (opts.file == NULL && opts.inode == -1) {
			Eprintf("You must specify a file or inode with the -i "
					"option.\n");
			err++;

		} else if (opts.file != NULL && opts.inode != -1) {
			Eprintf("You can't specify both a file and inode.\n");
			err++;
		}

		if (opts.quiet && opts.verbose) {
			Eprintf("You may not use --quiet and --verbose at the "
					"same time.\n");
			err++;
		}
	}

	if (ver)
		version();
	if (help || err)
		usage();

	return (!err && !help && !ver);
}

/**
 * cat
 */
static int cat_decrypt(ntfs_inode *inode, ntfs_decrypt_data_key *fek)
{
	int bufsize = 512;
	char *buffer;
	ntfs_attr *attr;
	s64 bytes_read, written, offset, total;
	s64 old_data_size, old_initialized_size;
	unsigned i;

	buffer = malloc(bufsize);
	if (!buffer)
		return 1;
	attr = ntfs_attr_open(inode, AT_DATA, NULL, 0);
	if (!attr) {
		Eprintf("Cannot cat a directory.\n");
		free(buffer);
		return 1;
	}
	total = attr->data_size;

	// hack: make sure attr will not be commited to disk if you use this.
	// clear the encrypted bit, otherwise the library won't allow reading.
	NAttrClearEncrypted(attr);
	// extend the size, we may need to read past the end of the stream.
	old_data_size = attr->data_size;
	old_initialized_size = attr->initialized_size;
	attr->data_size = attr->initialized_size = attr->allocated_size;

	offset = 0;
	while (total > 0) {
		bytes_read = ntfs_attr_pread(attr, offset, 512, buffer);
		if (bytes_read == -1) {
			perror("ERROR: Couldn't read file");
			break;
		}
		if (!bytes_read)
			break;
		if ((i = ntfs_decrypt_data_key_decrypt_sector(fek, buffer,
				offset)) < bytes_read) {
			perror("ERROR: Couldn't decrypt all data!");
			Eprintf("%u/%lld/%lld/%lld\n", i, (long long)bytes_read,
					(long long)offset, (long long)total);
			break;
		}
		if (bytes_read > total)
			bytes_read = total;
		written = fwrite(buffer, 1, bytes_read, stdout);
		if (written != bytes_read) {
			perror("ERROR: Couldn't output all data!");
			break;
		}
		offset += bytes_read;
		total -= bytes_read;
	}
	attr->data_size = old_data_size;
	attr->initialized_size = old_initialized_size;
	NAttrSetEncrypted(attr);
	ntfs_attr_close(attr);
	free(buffer);
	return 0;
}

/**
 * get_fek
 */
static ntfs_decrypt_data_key *get_fek(ntfs_inode *inode)
{
	ntfs_attr *na;
	unsigned char *efs_buffer, *ddf, *certificate, *hash_data, *fek_buf;
	u32 ddf_count, hash_size, fek_size;
	unsigned i;
	ntfs_decrypt_user_key_session *session;
	ntfs_decrypt_user_key *key;

	/* Obtain the $EFS contents. */
	na = ntfs_attr_open(inode, AT_LOGGED_UTILITY_STREAM,
			EFS, EFS_name_length);
	if (!na) {
		perror("Failed to open $EFS attribute");
		return NULL;
	}
	efs_buffer = malloc(na->data_size);
	if (!efs_buffer) {
		perror("Failed to allocate internal buffer");
		ntfs_attr_close(na);
		return NULL;
	}
	if (ntfs_attr_pread(na, 0, na->data_size, efs_buffer) !=
			na->data_size) {
		perror("Failed to read $EFS attribute");
		free(efs_buffer);
		ntfs_attr_close(na);
		return NULL;
	}
	ntfs_attr_close(na);

	/* Init the CryptoAPI. */
	if (!(session = ntfs_decrypt_user_key_session_open())) {
		perror("Failed to initialize the cryptoAPI");
		free(efs_buffer);
		return NULL;
	}
	/* Iterate through the DDFs & DRFs until we obtain a key. */
	ddf = efs_buffer + le32_to_cpu(*(u32*)(efs_buffer + 0x40));
	ddf_count = le32_to_cpu(*(u32*)ddf);

	ddf = ddf + 0x04;
	for (i = 0; i < ddf_count; i++) {
		//Eprintf("ddf #%u.\n", i);
		if (*(u32*)(ddf + 0x18))
			certificate = (ddf + 0x30 +
					le32_to_cpu(*(u32*)(ddf + 0x18)));
		else
			certificate = (ddf + 0x30);
		hash_size = (unsigned)le32_to_cpu(*(u32*)certificate);
		hash_data = certificate + (unsigned)
				le32_to_cpu(*(u32*)(certificate + 0x04));
		fek_size = (unsigned)le32_to_cpu(*(u32*)(ddf + 0x08));
		fek_buf = ddf + (unsigned)le32_to_cpu(*(u32*)(ddf + 0x0c));
		if ((key = ntfs_decrypt_user_key_open(session, hash_data,
				hash_size))) {
			fek_size = ntfs_decrypt_user_key_decrypt(key, fek_buf,
					fek_size);
			ntfs_decrypt_user_key_close(key);
			if (fek_size) {
				ntfs_decrypt_data_key *fek;

				ntfs_decrypt_user_key_session_close(session);
				fek = ntfs_decrypt_data_key_open(fek_buf,
						fek_size);
				free(efs_buffer);
				return fek;
			}
			fprintf(stderr, "Failed to decrypt the FEK.\n");
		} else
			perror("Failed to open user key");
		ddf = ddf + le32_to_cpu(*(u32*)(ddf + 0x08)) +
				le32_to_cpu(*(u32*)(ddf + 0x0c));
	}
	ntfs_decrypt_user_key_session_close(session);
	return NULL;
}

/**
 * main - Begin here
 *
 * Start from here.
 *
 * Return:  0  Success, the program worked
 *	    1  Error, something went wrong
 */
int main(int argc, char *argv[])
{
	ntfs_volume *vol;
	ntfs_inode *inode;
	ntfs_decrypt_data_key *fek;
	int result = 1;

	if (!parse_options(argc, argv))
		return 1;
	utils_set_locale();

	//XXX quieten errors, temporarily

	vol = utils_mount_volume(opts.device, MS_RDONLY, opts.force);
	if (!vol) {
		perror("ERROR: couldn't mount volume");
		return 1;
	}
	if (opts.inode != -1)
		inode = ntfs_inode_open(vol, opts.inode);
	else
		inode = ntfs_pathname_to_inode(vol, NULL, opts.file);
	if (!inode) {
		perror("ERROR: Couldn't open inode");
		return 1;
	}
	fek = get_fek(inode);
	if (fek) {
		result = cat_decrypt(inode, fek);
		ntfs_decrypt_data_key_close(fek);
	} else {
		Eprintf("Could not obtain FEK.\n");
		result = 1;
	}
	ntfs_inode_close(inode);
	ntfs_umount(vol, FALSE);
	return result;
}
