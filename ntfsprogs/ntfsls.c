/**
 * ntfsls - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2003 Lode Leroy
 *
 * This utility will list a directory's files.
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
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <getopt.h>
#include <string.h>

#include "types.h"
#include "mft.h"
#include "attrib.h"
#include "layout.h"
#include "inode.h"
#include "utils.h"
#include "dir.h"

static const char *EXEC_NAME = "ntfsls";

static struct options {
	char	*device;	/* Device/File to work with */
	int	 quiet;		/* Less output */
	int	 verbose;	/* Extra output */
	int	 force;		/* Override common sense */
	int all;
	int sys;
	int dos;
	int lng;
	int	inode;
	int classify;
	int readonly;
	int hidden;
	int archive;
	int system;
	char    *path;
} opts;

GEN_PRINTF (Eprintf, stderr, NULL,          FALSE)
GEN_PRINTF (Vprintf, stdout, &opts.verbose, TRUE)
GEN_PRINTF (Qprintf, stdout, &opts.quiet,   FALSE)

/**
 * version - Print version information about the program
 *
 * Print a copyright statement and a brief description of the program.
 *
 * Return:  none
 */
void version (void)
{
	printf ("\n%s v%s - Display information about an NTFS Volume.\n\n",
		EXEC_NAME, VERSION);
	printf ("Copyright (c)\n");
	printf ("    2003      Lode Leroy\n");
	printf ("\n%s\n%s%s\n", ntfs_gpl, ntfs_bugs, ntfs_home);
}

/**
 * usage - Print a list of the parameters to the program
 *
 * Print a list of the parameters and options for the program.
 *
 * Return:  none
 */
void usage (void)
{
	printf ("\nUsage: %s [options] -d /dev/hda1 -p /WINDOWS\n"
		"\n"
		"    -d      --device     NTFS volume\n"
		"    -p      --path       Relative path to the directory\n"
		"    -l      --long       Display long info\n"
		"    -F      --classify   Display classification\n"
		"    -f      --force      Use less caution\n"
		"    -q      --quiet      Less output\n"
		"    -v      --verbose    More output\n"
		"    -V      --version    Display version information\n"
		"    -h      --help       Display this help\n"
		"    -a                   Display all files\n"
		"    -x                   Use short (DOS 8.3) names\n"
		"    -s                   Display system files\n"
		"\n",
		EXEC_NAME);
	printf ("%s%s\n", ntfs_bugs, ntfs_home);
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
int parse_options (int argc, char *argv[])
{
	static const char *sopt = "-fh?qvVd:p:asxliFRHSA";
	static const struct option lopt[] = {
		{ "device",      required_argument,	NULL, 'd' },
		{ "path",	 required_argument,     NULL, 'p' },
		{ "all",	 no_argument,		NULL, 'a' },
		{ "sys",	 no_argument,		NULL, 's' },
		{ "long",	 no_argument,		NULL, 'l' },
		{ "inode",	 no_argument,		NULL, 'i' },
		{ "classify",	 no_argument,		NULL, 'F' },
		{ "system",	 no_argument,		NULL, 'S' },
		{ "dos",	 no_argument,		NULL, 'x' },

		{ "force",	 no_argument,		NULL, 'f' },
		{ "help",	 no_argument,		NULL, 'h' },
		{ "quiet",	 no_argument,		NULL, 'q' },
		{ "verbose",	 no_argument,		NULL, 'v' },
		{ "version",	 no_argument,		NULL, 'V' },
		{ NULL, 0, NULL, 0 },
	};

	char c = -1;
	int err  = 0;
	int ver  = 0;
	int help = 0;

	opterr = 0; /* We'll handle the errors, thank you. */

	memset(&opts, 0, sizeof(opts));
	opts.device = "/dev/hda1";
	opts.path = "/";

	while ((c = getopt_long (argc, argv, sopt, lopt, NULL)) != -1) {
		switch (c) {
		case 'd':	/* A non-option argument */
			opts.device = argv[optind-1];
			break;
		case 'p':
			opts.path = optarg;
			break;
		case 'f':
			opts.force++;
			break;
		case 'h':
		case '?':
			help++;
			break;
		case 'q':
			opts.quiet++;
			break;
		case 'v':
			opts.verbose++;
			break;
		case 'V':
			ver++;
			break;
		case 'x':
			opts.dos++;
			break;
		case 'l':
			opts.lng++;
			break;
		case 'i':
			opts.inode++;
			break;
		case 'F':
			opts.classify++;
			break;
		case 'a':
			opts.all++;
			break;
		case 's':
			opts.sys++;
			break;
		case 'R':
			opts.readonly++;
			break;
		case 'H':
			opts.hidden++;
			break;
		case 'S':
			opts.system++;
			break;
		case 'A':
			opts.archive++;
			break;
		default:
			Eprintf ("Unknown option '%s'.\n", argv[optind-1]);
			err++;
			break;
		}
	}

	if (help || ver) {
		opts.quiet = 0;
	} else {
		if (opts.device == NULL) {
			if (argc > 1)
				Eprintf ("You must specify exactly one device.\n");
			err++;
		}

		if (opts.quiet && opts.verbose) {
			Eprintf ("You may not use --quiet and --verbose at the same time.\n");
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
 * ucstos - convert unicode-character string to ASCII
 * @dest:	points to buffer to receive the converted string
 * @src:	points to string to convert
 * @maxlen:	size of @dest buffer in bytes
 *
 * Return the number of characters written to @dest, not including the
 * terminating null byte. If a unicode character was encountered which could
 * not be converted -1 is returned.
 */
int ucstos(char *dest, const uchar_t *src, int maxlen)
{
	uchar_t u;
	int i;

	/* Need one byte for null terminator. */
	maxlen--;
	for (i = 0; i < maxlen; i++) {
		u = le16_to_cpu(src[i]);
		if (!u)
			break;
		if (u & 0xff00)
			return -1;
		dest[i] = u & 0xff;
	}
	dest[i] = 0;
	return i;
}

/**
 * stoucs - convert ASCII string to unicode-character string
 * @dest:	points to buffer to receive the converted string
 * @src:	points to string to convert
 * @maxlen:	size of @dest buffer in bytes
 *
 * Return the number of characters written to @dest, not including the
 * terminating null unicode character.
 */
int stoucs(uchar_t *dest, const char *src, int maxlen)
{
	char c;
	int i;

	/* Need two bytes for null terminator. */
	maxlen -= 2;
	for (i = 0; i < maxlen; i++) {
		c = src[i];
		if (!c)
			break;
		dest[i] = cpu_to_le16(c);
	}
	dest[i] = cpu_to_le16('\0');
	return i;
}

/* Dump a block of memory starting at buf. Display length bytes. The displayed
   index of the first byte is start */
void dump_mem(unsigned char *buf, int start, int length)
{
        int offs,i;
        for(offs=0;offs<length;offs+=16)
        {
                printf("%8.8X ",start+offs);
                for(i=0;i<16;i++)printf(offs+i<length?"%2X ":"   ",buf[offs+i]);
                for(i=0;i<16;i++)
		    if (offs+i>=length) { putchar(' '); } else
                        if(buf[offs+i]>31 && buf[offs+i]<128)putchar(buf[offs+i]
);
                        else putchar('.');
                putchar('\n');
        }
}

typedef struct {
  ntfs_volume* vol;
} ntfsls_dirent;

int
list_entry(ntfsls_dirent* dirent, const uchar_t* name, 
	   const int name_len, const int name_type, const s64 pos,
	   const MFT_REF mref, const unsigned dt_type) {

	char filename[200];
	ucstos(filename, name, min(name_len+1,sizeof(filename)));
	//printf("[%s\t,%d,%d]\n", filename, name_type, dt_type);
	if ((filename[0] == '$') && (!opts.sys)) {
		return 0;
	} else
	if (name_type == 0 && !opts.all) {
		return 0;
	}
	if (((name_type & 3) == 1) && (opts.dos!=0)) {
		return 0;
	}
	if (((name_type & 3) == 2) && (opts.dos!=1)) {
		return 0;
	}
	if (dt_type == NTFS_DT_DIR && opts.classify) {
	    sprintf(filename+strlen(filename),"/");
	}

	if (!opts.lng) {
		printf(filename);
		printf("\n");
	} else {
	    ntfs_inode *ni = NULL;
	    ntfs_attr_search_ctx *ctx = NULL;
	    FILE_NAME_ATTR *file_name_attr = NULL;
	    ATTR_RECORD *attr = NULL;
	    time_t ntfs_time;

	    ni = ntfs_inode_open(dirent->vol, mref);
	    if (!ni) { 
		return -1; 
	    }
	    //dump_mem(ni, 0, sizeof(ntfs_inode));

	    ctx = ntfs_attr_get_search_ctx(ni, ni->mrec);
	    if (!ctx) { 
		return -1; 
	    }
	    if(ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0, 0, 0, NULL, 0, ctx)) {
		return -1;
	    }
	    attr = ctx->attr;
	    //dump_mem(attr, 0, sizeof(*attr));

	    file_name_attr = (FILE_NAME_ATTR*)((char *)attr + le16_to_cpu(attr->value_offset));
	    if (!file_name_attr) {
		return -1;
	    }
	    //dump_mem(file_name_attr, 0, sizeof(*file_name_attr));

	    ntfs_time = ntfs2utc (sle64_to_cpu (file_name_attr->last_data_change_time));
	    char t_buf[26];
	    strcpy(t_buf, ctime(&ntfs_time));
	    t_buf[16] = '\0';

	    s64 filesize = 0;
	    if (dt_type != NTFS_DT_DIR) {
		if(!ntfs_attr_lookup(AT_DATA, AT_UNNAMED, 0, 0, 0, NULL, 0, ctx)) {
		    attr = ctx->attr;
		    filesize = ntfs_get_attribute_value_length(attr);
		}
	    }

	    if (opts.inode) {
		printf("%12lld  %18lld  %s\n", filesize, mref, filename);
	    } else {
		printf("%12lld  %s  %s\n", filesize, t_buf+4, filename);
	    }
	}
	
	return 0;
}

/**
 * main - Begin here
 *
 * Start from here.
 *
 * Return:  0  Success, the program worked
 *	    1  Error, something went wrong
 */
int main(int argc, char **argv)
{
	ntfs_volume *vol;

	if (!parse_options (argc, argv))
		return 1;

	utils_set_locale();

	vol = utils_mount_volume (opts.device, MS_RDONLY, opts.force);

	if (!vol)
		return 2;

	s64 pos = 0;
	u64 ino;
	ntfs_inode* ni = vol->mft_ni;
	uchar_t unicode[100];
	int len;
	ni = ntfs_inode_open(vol, FILE_root);
	char* p = opts.path;
	while (p && *p && *p == '/') p++;
	while (p && *p) {
		char* q = strchr(p, '/');
		if (q != NULL) {
			*q = '\0';
			q++;
		}
		len = stoucs(unicode, p, sizeof(unicode));
		ino = ntfs_inode_lookup_by_name(ni, unicode, len);
		ni = ntfs_inode_open(vol, ino);
		p = q;
		while (p && *p && *p == '/') p++;
	}
	ntfsls_dirent dirent;
	dirent.vol = vol;
	ntfs_readdir(ni, &pos, &dirent, list_entry);

	ntfs_umount (vol, FALSE);
	return 0;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * tab-width:8
 * End:
 */
