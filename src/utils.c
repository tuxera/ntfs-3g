/**
 * utils.c - Originated from the Linux-NTFS project.
 *
 * Copyright (c) 2002-2005 Richard Russon
 * Copyright (c) 2003-2006 Anton Altaparmakov
 * Copyright (c) 2003 Lode Leroy
 * Copyright (c) 2005-2008 Szabolcs Szakacsits
 *
 * A set of shared functions for ntfs utilities
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
 * along with this program (in the main directory of the NTFS-3G
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "utils.h"

const char *ntfs_home = 
	"Ntfs-3g news, support and information:  http://ntfs-3g.org\n";
const char *ntfs_gpl = "This program is free software, released under the GNU "
	"General Public License\nand you are welcome to redistribute it under "
	"certain conditions.  It comes with\nABSOLUTELY NO WARRANTY; for "
	"details read the GNU General Public License to be\nfound in the file "
	"\"COPYING\" distributed with this program, or online at:\n"
	"http://www.gnu.org/copyleft/gpl.html\n";

static const char *invalid_ntfs_msg =
"The device '%s' doesn't have a valid NTFS.\n"
"Maybe you selected the wrong device? Or the whole disk instead of a\n"
"partition (e.g. /dev/hda, not /dev/hda1)? Or the other way around?\n";

static const char *corrupt_volume_msg =
"NTFS is either inconsistent, or you have hardware faults, or you have a\n"
"SoftRAID/FakeRAID hardware. In the first case run chkdsk /f on Windows\n"
"then reboot into Windows TWICE. The usage of the /f parameter is very\n"
"important! If you have SoftRAID/FakeRAID then first you must activate\n"
"it and mount a different device under the /dev/mapper/ directory, (e.g.\n"
"/dev/mapper/nvidia_eahaabcc1). Please see the 'dmraid' documentation\n"
"for the details.\n";

static const char *hibernated_volume_msg =
"The NTFS partition is hibernated. Please resume and shutdown Windows\n"
"properly, or mount the volume read-only with the 'ro' mount option, or\n"
"mount the volume read-write with the 'remove_hiberfile' mount option.\n"
"For example type on the command line:\n"
"\n"
"            mount -t ntfs-3g %s %s -o remove_hiberfile\n"
"\n";

static const char *unclean_journal_msg =
"Mount is denied because NTFS is marked to be in use. Choose one action:\n"
"\n"
"Choice 1: If you have Windows then disconnect the external devices by\n"
"          clicking on the 'Safely Remove Hardware' icon in the Windows\n"
"          taskbar then shutdown Windows cleanly.\n"
"\n"
"Choice 2: If you don't have Windows then you can use the 'force' option for\n"
"          your own responsibility. For example type on the command line:\n";

static const char *opened_volume_msg =
"Mount is denied because the NTFS volume is already exclusively opened.\n"
"The volume may be already mounted, or another software may use it which\n"
"could be identified for example by the help of the 'fuser' command.\n";

static const char *fakeraid_msg =
"You seem to have a SoftRAID/FakeRAID hardware and must use an activated,\n"
"different device under /dev/mapper/, (e.g. /dev/mapper/nvidia_eahaabcc1)\n"
"to mount NTFS. Please see the 'dmraid' documentation for help.\n";

static const char *access_denied_msg =
"Please check the volume and the ntfs-3g binary permissions,\n"
"and the mounting user ID. More explanation is provided at\n"
"http://ntfs-3g.org/support.html#unprivileged\n";

static const char *forced_mount_msg =
"\n"
"            mount -t ntfs-3g %s %s -o force\n"
"\n"
"    Or add the option to the relevant row in the /etc/fstab file:\n"
"\n"
"            %s %s ntfs-3g force 0 0\n";

/**
 * utils_set_locale
 */
int utils_set_locale(void)
{
	const char *locale;

	locale = setlocale(LC_ALL, "");
	if (!locale) {
		locale = setlocale(LC_ALL, NULL);
		ntfs_log_error("Couldn't set local environment, using default "
			       "'%s'.\n", locale);
		return 1;
	}
	return 0;
}

void utils_mount_error(const char *volume, const char *mntpoint, int err)
{
	switch (err) {
		case NTFS_VOLUME_NOT_NTFS:
			ntfs_log_error(invalid_ntfs_msg, volume);
			break;
		case NTFS_VOLUME_CORRUPT:
			ntfs_log_error("%s", corrupt_volume_msg);
			break;
		case NTFS_VOLUME_HIBERNATED:
			ntfs_log_error(hibernated_volume_msg, volume, mntpoint);
			break;
		case NTFS_VOLUME_UNCLEAN_UNMOUNT:
			ntfs_log_error(unclean_journal_msg);
			ntfs_log_error(forced_mount_msg, volume, mntpoint, 
				       volume, mntpoint);
			break;
		case NTFS_VOLUME_LOCKED:
			ntfs_log_error("%s", opened_volume_msg);
			break;
		case NTFS_VOLUME_RAID:
			ntfs_log_error("%s", fakeraid_msg);
			break;
		case NTFS_VOLUME_NO_PRIVILEGE:
			ntfs_log_error(access_denied_msg, volume);
			break;
	}
}

