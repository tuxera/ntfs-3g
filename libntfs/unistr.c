/*
 * unistr.c - Unicode string handling. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2000-2004 Anton Altaparmakov
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>
#include <errno.h>

#include "types.h"
#include "unistr.h"
#include "debug.h"

/*
 * IMPORTANT
 * =========
 *
 * All these routines assume that the Unicode characters are in little endian
 * encoding inside the strings!!!
 */

/*
 * This is used by the name collation functions to quickly determine what
 * characters are (in)valid.
 */
const u8 legal_ansi_char_array[0x40] = {
	0x00, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,

	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,

	0x17, 0x07, 0x18, 0x17, 0x17, 0x17, 0x17, 0x17,
	0x17, 0x17, 0x18, 0x16, 0x16, 0x17, 0x07, 0x00,

	0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,
	0x17, 0x17, 0x04, 0x16, 0x18, 0x16, 0x18, 0x18,
};

/**
 * ntfs_names_are_equal - compare two Unicode names for equality
 * @s1:			name to compare to @s2
 * @s1_len:		length in Unicode characters of @s1
 * @s2:			name to compare to @s1
 * @s2_len:		length in Unicode characters of @s2
 * @ic:			ignore case bool
 * @upcase:		upcase table (only if @ic == IGNORE_CASE)
 * @upcase_size:	length in Unicode characters of @upcase (if present)
 *
 * Compare the names @s1 and @s2 and return TRUE (1) if the names are
 * identical, or FALSE (0) if they are not identical. If @ic is IGNORE_CASE,
 * the @upcase table is used to performa a case insensitive comparison.
 */
BOOL ntfs_names_are_equal(const ntfschar *s1, size_t s1_len,
		const ntfschar *s2, size_t s2_len,
		const IGNORE_CASE_BOOL ic,
		const ntfschar *upcase, const u32 upcase_size)
{
	if (s1_len != s2_len)
		return FALSE;
	if (!s1_len)
		return TRUE;
	if (ic == CASE_SENSITIVE)
		return ntfs_ucsncmp(s1, s2, s1_len) ? FALSE: TRUE;
	return ntfs_ucsncasecmp(s1, s2, s1_len, upcase, upcase_size) ? FALSE:
								       TRUE;
}

/**
 * ntfs_names_collate - collate two Unicode names
 * @upcase:	upcase table (ignored if @ic is CASE_SENSITIVE)
 * @upcase_len:	upcase table size (ignored if @ic is CASE_SENSITIVE)
 * @name1:	first Unicode name to compare
 * @name2:	second Unicode name to compare
 * @ic:		either CASE_SENSITIVE or IGNORE_CASE
 * @err_val:	if @name1 contains an invalid character return this value
 *
 * ntfs_names_collate() collates two Unicode names and returns:
 *
 *  -1 if the first name collates before the second one,
 *   0 if the names match,
 *   1 if the second name collates before the first one, or
 * @err_val if an invalid character is found in @name1 during the comparison.
 *
 * The following characters are considered invalid: '"', '*', '<', '>' and '?'.
 */
int ntfs_names_collate(const ntfschar *name1, const u32 name1_len,
		const ntfschar *name2, const u32 name2_len,
		const int err_val, const IGNORE_CASE_BOOL ic,
		const ntfschar *upcase, const u32 upcase_len)
{
	u32 cnt;
	ntfschar c1, c2;

#ifdef DEBUG
	if (!name1 || !name2 || (ic && !upcase && upcase_len)) {
		Dputs("ntfs_names_collate received NULL pointer!");
		exit(1);
	}
#endif
	for (cnt = 0; cnt < min(name1_len, name2_len); ++cnt)
	{
		c1 = le16_to_cpu(*name1);
		name1++;
		c2 = le16_to_cpu(*name2);
		name2++;
		if (ic) {
			if (c1 < upcase_len)
				c1 = le16_to_cpu(upcase[c1]);
			if (c2 < upcase_len)
				c2 = le16_to_cpu(upcase[c2]);
		}
		if (c1 < 64 && legal_ansi_char_array[c1] & 8)
			return err_val;
		if (c1 < c2)
			return -1;
		if (c1 > c2)
			return 1;
	}
	if (name1_len < name2_len)
		return -1;
	if (name1_len == name2_len)
		return 0;
	/* name1_len > name2_len */
	c1 = le16_to_cpu(*name1);
	if (c1 < 64 && legal_ansi_char_array[c1] & 8)
		return err_val;
	return 1;
}

/**
 * ntfs_ucsncmp - compare two little endian Unicode strings
 * @s1:		first string
 * @s2:		second string
 * @n:		maximum unicode characters to compare
 *
 * Compare the first @n characters of the Unicode strings @s1 and @s2,
 * The strings in little endian format and appropriate le16_to_cpu()
 * conversion is performed on non-little endian machines.
 *
 * The function returns an integer less than, equal to, or greater than zero
 * if @s1 (or the first @n Unicode characters thereof) is found, respectively,
 * to be less than, to match, or be greater than @s2.
 */
int ntfs_ucsncmp(const ntfschar *s1, const ntfschar *s2, size_t n)
{
	ntfschar c1, c2;
	size_t i;

#ifdef DEBUG
	if (!s1 || !s2) {
		Dputs("ntfs_wcsncmp() received NULL pointer!");
		exit(1);
	}
#endif
	for (i = 0; i < n; ++i) {
		c1 = le16_to_cpu(s1[i]);
		c2 = le16_to_cpu(s2[i]);
		if (c1 < c2)
			return -1;
		if (c1 > c2)
			return 1;
		if (!c1)
			break;
	}
	return 0;
}

/**
 * ntfs_ucsncasecmp - compare two little endian Unicode strings, ignoring case
 * @s1:			first string
 * @s2:			second string
 * @n:			maximum unicode characters to compare
 * @upcase:		upcase table
 * @upcase_size:	upcase table size in Unicode characters
 *
 * Compare the first @n characters of the Unicode strings @s1 and @s2,
 * ignoring case. The strings in little endian format and appropriate
 * le16_to_cpu() conversion is performed on non-little endian machines.
 *
 * Each character is uppercased using the @upcase table before the comparison.
 *
 * The function returns an integer less than, equal to, or greater than zero
 * if @s1 (or the first @n Unicode characters thereof) is found, respectively,
 * to be less than, to match, or be greater than @s2.
 */
int ntfs_ucsncasecmp(const ntfschar *s1, const ntfschar *s2, size_t n,
		const ntfschar *upcase, const u32 upcase_size)
{
	ntfschar c1, c2;
	size_t i;

#ifdef DEBUG
	if (!s1 || !s2 || !upcase) {
		Dputs("ntfs_wcsncasecmp() received NULL pointer!");
		exit(1);
	}
#endif
	for (i = 0; i < n; ++i) {
		if ((c1 = le16_to_cpu(s1[i])) < upcase_size)
			c1 = le16_to_cpu(upcase[c1]);
		if ((c2 = le16_to_cpu(s2[i])) < upcase_size)
			c2 = le16_to_cpu(upcase[c2]);
		if (c1 < c2)
			return -1;
		if (c1 > c2)
			return 1;
		if (!c1)
			break;
	}
	return 0;
}

/**
 * ntfs_ucsnlen - determine the length of a little endian Unicode string
 * @s:		pointer to Unicode string
 * @maxlen:	maximum length of string @s
 *
 * Return the number of Unicode characters in the little endian Unicode
 * string @s up to a maximum of maxlen Unicode characters, not including
 * the terminating (ntfschar)'\0'. If there is no (ntfschar)'\0' between @s
 * and @s + @maxlen, @maxlen is returned.
 *
 * This function never looks beyond @s + @maxlen.
 */
u32 ntfs_ucsnlen(const ntfschar *s, u32 maxlen)
{
	u32 i;

	for (i = 0; i < maxlen; i++) {
		if (!le16_to_cpu(s[i]))
			break;
	}
	return i;
}

/**
 * ntfs_name_upcase
 */
void ntfs_name_upcase(ntfschar *name, u32 name_len, const ntfschar *upcase,
		const u32 upcase_len)
{
	u32 i;
	ntfschar u;

	for (i = 0; i < name_len; i++)
		if ((u = le16_to_cpu(name[i])) < upcase_len)
			name[i] = upcase[u];
}

/**
 * ntfs_file_value_upcase
 */
void ntfs_file_value_upcase(FILE_NAME_ATTR *file_name_attr,
		const ntfschar *upcase, const u32 upcase_len)
{
	ntfs_name_upcase((ntfschar*)&file_name_attr->file_name,
			file_name_attr->file_name_length, upcase, upcase_len);
}

/**
 * ntfs_file_values_compare
 */
int ntfs_file_values_compare(FILE_NAME_ATTR *file_name_attr1,
		FILE_NAME_ATTR *file_name_attr2,
		const int err_val, const IGNORE_CASE_BOOL ic,
		const ntfschar *upcase, const u32 upcase_len)
{
	return ntfs_names_collate((ntfschar*)&file_name_attr1->file_name,
			file_name_attr1->file_name_length,
			(ntfschar*)&file_name_attr2->file_name,
			file_name_attr2->file_name_length,
			err_val, ic, upcase, upcase_len);
}

/**
 * ntfs_ucstombs - convert a little endian Unicode string to a multibyte string
 * @ins:	input Unicode string buffer
 * @ins_len:	length of input string in Unicode characters
 * @outs:	on return contains the (allocated) output multibyte string
 * @outs_len:	length of output buffer in bytes
 *
 * Convert the input little endian, 2-byte Unicode string @ins, of length
 * @ins_len into the multibyte string format dictated by the current locale.
 *
 * If *@outs is NULL, the function allocates the string and the caller is
 * responsible for calling free(*@outs); when finished with it.
 *
 * On success the function returns the number of bytes written to the output
 * string *@outs (>= 0), not counting the terminating NULL byte. If the output
 * string buffer was allocated, *@outs is set to it.
 *
 * On error, -1 is returned, and errno is set to the error code. The following
 * error codes can be expected:
 *	EINVAL		Invalid arguments (e.g. @ins or @outs is NULL).
 *	EILSEQ		The input string cannot be represented as a multibyte
 *			sequence according to the current locale.
 *	ENAMETOOLONG	Destination buffer is too small for input string.
 *	ENOMEM		Not enough memory to allocate destination buffer.
 */
int ntfs_ucstombs(const ntfschar *ins, const int ins_len, char **outs,
		int outs_len)
{
	char *mbs;
	wchar_t wc;
	int i, o, mbs_len;
	int cnt = 0;
#ifdef HAVE_MBSINIT
	mbstate_t mbstate;
#endif

	if (!ins || !outs) {
		errno = EINVAL;
		return -1;
	}
	mbs = *outs;
	mbs_len = outs_len;
	if (mbs && !mbs_len) {
		errno = ENAMETOOLONG;
		return -1;
	}
	if (!mbs) {
		mbs_len = (ins_len + 1) * MB_CUR_MAX;
		mbs = (char*)malloc(mbs_len);
		if (!mbs)
			return -1;
	}
#ifdef HAVE_MBSINIT
	memset(&mbstate, 0, sizeof(mbstate));
#else
	wctomb(NULL, 0);
#endif
	for (i = o = 0; i < ins_len; i++) {
		/* Reallocate memory if necessary or abort. */
		if ((int)(o + MB_CUR_MAX) > mbs_len) {
			char *tc;
			if (mbs == *outs) {
				errno = ENAMETOOLONG;
				return -1;
			}
			tc = (char*)malloc((mbs_len + 64) & ~63);
			if (!tc)
				goto err_out;
			memcpy(tc, mbs, mbs_len);
			mbs_len = (mbs_len + 64) & ~63;
			free(mbs);
			mbs = tc;
		}
		/* Convert the LE Unicode character to a CPU wide character. */
		wc = (wchar_t)le16_to_cpu(ins[i]);
		if (!wc)
			break;
		/* Convert the CPU endian wide character to multibyte. */
#ifdef HAVE_MBSINIT
		cnt = wcrtomb(mbs + o, wc, &mbstate);
#else
		cnt = wctomb(mbs + o, wc);
#endif
		if (cnt == -1)
			goto err_out;
		if (cnt <= 0) {
			Dprintf("Eeek. cnt <= 0, cnt = %i\n", cnt);
			errno = EINVAL;
			goto err_out;
		}
		o += cnt;
	}
#ifdef HAVE_MBSINIT
	/* Make sure we are back in the initial state. */
	if (!mbsinit(&mbstate)) {
		Dputs("Eeek. mbstate not in initial state!");
		errno = EILSEQ;
		goto err_out;
	}
#endif
	/* Now write the NULL character. */
	mbs[o] = '\0';
	if (*outs != mbs)
		*outs = mbs;
	return o;
err_out:
	if (mbs != *outs) {
		int eo = errno;
		free(mbs);
		errno = eo;
	}
	return -1;
}

/**
 * ntfs_mbstoucs - convert a multibyte string to a little endian Unicode string
 * @ins:	input multibyte string buffer
 * @outs:	on return contains the (allocated) output Unicode string
 * @outs_len:	length of output buffer in Unicode characters
 *
 * Convert the input multibyte string @ins, from the current locale into the
 * corresponding little endian, 2-byte Unicode string.
 *
 * If *@outs is NULL, the function allocates the string and the caller is
 * responsible for calling free(*@outs); when finished with it.
 *
 * On success the function returns the number of Unicode characters written to
 * the output string *@outs (>= 0), not counting the terminating Unicode NULL
 * character. If the output string buffer was allocated, *@outs is set to it.
 *
 * On error, -1 is returned, and errno is set to the error code. The following
 * error codes can be expected:
 *	EINVAL		Invalid arguments (e.g. @ins or @outs is NULL).
 *	EILSEQ		The input string cannot be represented as a Unicode
 *			string according to the current locale.
 *	ENAMETOOLONG	Destination buffer is too small for input string.
 *	ENOMEM		Not enough memory to allocate destination buffer.
 */
int ntfs_mbstoucs(const char *ins, ntfschar **outs, int outs_len)
{
	ntfschar *ucs;
	const char *s;
	wchar_t wc;
	int i, o, cnt, ins_len, ucs_len;
#ifdef HAVE_MBSINIT
	mbstate_t mbstate;
#endif

	if (!ins || !outs) {
		errno = EINVAL;
		return -1;
	}
	ucs = *outs;
	ucs_len = outs_len;
	if (ucs && !ucs_len) {
		errno = ENAMETOOLONG;
		return -1;
	}
	/* Determine the length of the multi-byte string. */
	s = ins;
#if defined(HAVE_MBSINIT)
	memset(&mbstate, 0, sizeof(mbstate));
	ins_len = mbsrtowcs(NULL, (const char **)&s, 0, &mbstate);
#ifdef __CYGWIN32__
	if (!ins_len && *ins) {
		/* Older Cygwin had broken mbsrtowcs() implementation. */
		ins_len = strlen(ins);
	}
#endif
#elif !defined(DJGPP)
	ins_len = mbstowcs(NULL, s, 0);
#else
	/* Eeek!!! DJGPP has broken mbstowcs() implementation!!! */
	ins_len = strlen(ins);
#endif
	if (ins_len == -1)
		return ins_len;
#ifdef HAVE_MBSINIT
	if ((s != ins) || !mbsinit(&mbstate)) {
#else
	if (s != ins) {
#endif
		errno = EILSEQ;
		return -1;
	}
	/* Add the NULL terminator. */
	ins_len++;
	if (!ucs) {
		ucs_len = ins_len;
		ucs = (ntfschar*)malloc(ucs_len * sizeof(ntfschar));
		if (!ucs)
			return -1;
	}
#ifdef HAVE_MBSINIT
	memset(&mbstate, 0, sizeof(mbstate));
#else
	mbtowc(NULL, NULL, 0);
#endif
	for (i = o = cnt = 0; o < ins_len; i += cnt, o++) {
		/* Reallocate memory if necessary or abort. */
		if (o >= ucs_len) {
			ntfschar *tc;
			if (ucs == *outs) {
				errno = ENAMETOOLONG;
				return -1;
			}
			/*
			 * We will never get here but hey, it's only a bit of
			 * extra code...
			 */
			ucs_len = (ucs_len * sizeof(ntfschar) + 64) & ~63;
			tc = (ntfschar*)realloc(ucs, ucs_len);
			if (!tc)
				goto err_out;
			ucs = tc;
			ucs_len /= sizeof(ntfschar);
		}
		/* Convert the multibyte character to a wide character. */
#ifdef HAVE_MBSINIT
		cnt = mbrtowc(&wc, ins + i, ins_len - i, &mbstate);
#else
		cnt = mbtowc(&wc, ins + i, ins_len - i);
#endif
		if (!cnt)
			break;
		if (cnt == -1)
			goto err_out;
		if (cnt < -1) {
			Dprintf("%s(): Eeek. cnt = %i\n", __FUNCTION__, cnt);
			errno = EINVAL;
			goto err_out;
		}
		/* Make sure we are not overflowing the NTFS Unicode set. */
		if ((unsigned long)wc >= (unsigned long)(1 <<
				(8 * sizeof(ntfschar)))) {
			errno = EILSEQ;
			goto err_out;
		}
		/* Convert the CPU wide character to a LE Unicode character. */
		ucs[o] = cpu_to_le16(wc);
	}
#ifdef HAVE_MBSINIT
	/* Make sure we are back in the initial state. */
	if (!mbsinit(&mbstate)) {
		Dprintf("%s(): Eeek. mbstate not in initial state!\n",
				__FUNCTION__);
		errno = EILSEQ;
		goto err_out;
	}
#endif
	/* Now write the NULL character. */
	ucs[o] = cpu_to_le16(L'\0');
	if (*outs != ucs)
		*outs = ucs;
	return o;
err_out:
	if (ucs != *outs) {
		int eo = errno;
		free(ucs);
		errno = eo;
	}
	return -1;
}
