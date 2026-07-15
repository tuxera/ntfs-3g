/*
 *		NTFS bootsector, adapted from the vfat one.
 */

/* mkfs.fat.c - utility to create FAT/MS-DOS filesystems
 * Copyright (C) 1991 Linus Torvalds <torvalds@klaava.helsinki.fi>
 * Copyright (C) 1992-1993 Remy Card <card@masi.ibp.fr>
 * Copyright (C) 1993-1994 David Hudson <dave@humbug.demon.co.uk>
 * Copyright (C) 1998 H. Peter Anvin <hpa@zytor.com>
 * Copyright (C) 1998-2005 Roman Hodek <Roman.Hodek@informatik.uni-erlangen.de>
 * Copyright (C) 2008-2014 Daniel Baumann <mail@daniel-baumann.ch>
 * Copyright (C) 2015 Andreas Bombe <aeb@debian.org>
 *
 * The "boot code" is in the public domain.
 */

#include "boot.h"

#define BOOTCODE_SIZE 4136

/* The "boot code" we put into the filesystem... it writes a message and
   tells the user to try again. This "boot code" is in the public domain. */

#define MSG_OFFSET_OFFSET 3

const unsigned char boot_array[BOOTCODE_SIZE] =

	"\xeb\x52\x90"   /* jump to code at 0x54 (0x7c54) */
	"NTFS    \0"     /* NTFS signature */

	"\0\0\0\0\0\0\0\0\0\0\0\0"     /* 72 bytes for device parameters */
	"\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0"
	                               /* Boot code run at location 0x7c54 */
	"\x0e"		/* push cs */
	"\x1f"		/* pop ds */
	"\xbe\x71\x7c"	/* mov si, offset message_txt (at location 0x7c71) */
							/* write_msg: */
	"\xac"		/* lodsb */
	"\x22\xc0"	/* and al, al */
	"\x74\x0b"	/* jz key_press */
	"\x56"		/* push si */
	"\xb4\x0e"	/* mov ah, 0eh */
	"\xbb\x07\x00"	/* mov bx, 0007h */
	"\xcd\x10"	/* int 10h */
	"\x5e"		/* pop si */
	"\xeb\xf0"	/* jmp write_msg */
							/* key_press: */
	"\x32\xe4"	/* xor ah, ah */
	"\xcd\x16"	/* int 16h */
	"\xcd\x19"	/* int 19h */
	"\xeb\xfe"	/* foo: jmp foo */
	/* message_txt: */
	"This is not a bootable disk. Please insert a bootable floppy and\r\n"
	"press any key to try again ... \r\n"
				/* At location 0xd4, 298 bytes to reach 0x1fe */
				/* 298 = 4 blocks of 72 then 10 */
	"\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0"

	"\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0"

	"\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0"

	"\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0"

	"\0\0\0\0\0\0\0\0\0\0"
					/* Boot signature at 0x1fe */
	"\x55\xaa";
