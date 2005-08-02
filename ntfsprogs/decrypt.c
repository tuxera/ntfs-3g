/*
 * decrypt.c - $EFS decryption routines.  Part of the Linux-NTFS project.
 *
 * Copyright (c) 2005 Yuval Fledel
 * Copyright (c) 2005 Anton Altaparmakov
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
 * You should have received a copy of the GNU General Public License along
 * with this program (in the main directory of the Linux-NTFS distribution
 * in the file COPYING); if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <gcrypt.h>

#include "decrypt.h"

#ifdef __CYGWIN__
#define _WIN32_WINNT 0x501
#define WINVER 0x501

#include <windows.h>
#include <wincrypt.h>

/* Missing cygwin macros */
#ifndef CERT_SYSTEM_STORE_CURRENT_USER
#define CERT_SYSTEM_STORE_CURRENT_USER 0x00010000
#endif

#ifndef CERT_CLOSE_STORE_CHECK_FLAG
#define CERT_CLOSE_STORE_CHECK_FLAG 2
#endif

#ifndef CRYPT_ACQUIRE_CACHE_FLAG
#define CRYPT_ACQUIRE_CACHE_FLAG 1
#endif

/* Windows 2k+ imports. */
typedef BOOL(WINAPI *LPFN_CryptAcquireCertificatePrivateKey)(PCCERT_CONTEXT,
		DWORD, void *, HCRYPTPROV *, DWORD *, BOOL *);
typedef BOOL(WINAPI *LPFN_CertCloseStore)(HCERTSTORE, DWORD);
typedef PCCERT_CONTEXT(WINAPI *LPFN_CertFindCertificateInStore)(HCERTSTORE,
		DWORD, DWORD, DWORD, const void *, PCCERT_CONTEXT);
typedef BOOL(WINAPI *LPFN_CertFreeCertificateContext)(PCCERT_CONTEXT);
typedef HCERTSTORE(WINAPI *LPFN_CertOpenStore)(LPCSTR, DWORD, HCRYPTPROV,
		DWORD, const void *);

// NT4SP3+ WINME or 95+ w/ IE5+
static LPFN_CryptAcquireCertificatePrivateKey
		fnCryptAcquireCertificatePrivateKey;
// osr2+ NT4SP3+ or NT4 w/ IE3.02:
static LPFN_CertCloseStore fnCertCloseStore;
static LPFN_CertFindCertificateInStore fnCertFindCertificateInStore;
static LPFN_CertFreeCertificateContext fnCertFreeCertificateContext;
static LPFN_CertOpenStore fnCertOpenStore;

/* Global variable: Handle to crypt32.dll */
static HMODULE hCrypt32 = INVALID_HANDLE_VALUE;

#else /* !defined(__CYGWIN__) */

#include <malloc.h>
#include <string.h>
#define CALG_DES (0x6601)
/* If not one of the below three, fall back to standard Des. */
#define CALG_3DES (0x6603)
#define CALG_DESX (0x6604)
#define CALG_AES_256 (0x6610)

#endif /* !defined(__CYGWIN__) */

/* This must be after windows.h include. */
#include "types.h"

typedef struct {
#ifdef __CYGWIN__
	HCERTSTORE hSystemStore;
#else /* !defined(__CYGWIN__) */
	int nothing;		/* unused */
#endif /* !defined(__CYGWIN__) */
} NTFS_DECRYPT_USER_KEY_SESSION;

typedef struct {
	gcry_sexp_t sexp_key;	// the user's RSA key.
} NTFS_DECRYPT_USER_KEY;

typedef struct {
	u8 *key_data;
	u32 alg_id;
	gcry_cipher_hd_t gcry_cipher_hd;
	gcry_cipher_hd_t *des_gcry_cipher_hd_ptr;
} NTFS_DECRYPT_DATA_KEY;

/* DESX-MS128 implementation for libgcrypt. */
static gcry_module_t ntfs_desx_module;
static int ntfs_desx_algorithm_id = -1;
static int ntfs_desx_module_count;

typedef struct {
	u64 in_whitening, out_whitening;
	gcry_cipher_hd_t gcry_cipher_hd;
} ntfs_desx_ctx;

#ifdef __CYGWIN__
static int cryptoAPI_init_imports(void)
{
	if (hCrypt32 == INVALID_HANDLE_VALUE)
		hCrypt32 = LoadLibrary("crypt32.dll");
	if (!fnCryptAcquireCertificatePrivateKey)
		fnCryptAcquireCertificatePrivateKey =
				(LPFN_CryptAcquireCertificatePrivateKey)
				GetProcAddress(hCrypt32,
				"CryptAcquireCertificatePrivateKey");
	if (!fnCertCloseStore)
		fnCertCloseStore = (LPFN_CertCloseStore)
				GetProcAddress(hCrypt32, "CertCloseStore");
	if (!fnCertFindCertificateInStore)
		fnCertFindCertificateInStore = (LPFN_CertFindCertificateInStore)
				GetProcAddress(hCrypt32,
				"CertFindCertificateInStore");
	if (!fnCertFreeCertificateContext)
		fnCertFreeCertificateContext = (LPFN_CertFreeCertificateContext)
				GetProcAddress(hCrypt32,
				"CertFreeCertificateContext");
	if (!fnCertOpenStore)
		fnCertOpenStore = (LPFN_CertOpenStore)GetProcAddress(hCrypt32,
				"CertOpenStore");
	return fnCryptAcquireCertificatePrivateKey && fnCertCloseStore &&
			fnCertFindCertificateInStore &&
			fnCertFreeCertificateContext && fnCertOpenStore;
}
#endif /* defined(__CYGWIN__) */

ntfs_decrypt_user_key_session *ntfs_decrypt_user_key_session_open(void)
{
	ntfs_decrypt_user_key_session *session;
#ifdef __CYGWIN__
	HCERTSTORE hSystemStore;

	/*
	 * FIXME: This really needs locking and reference counting so it is
	 * safe from races.
	 */
	if (!cryptoAPI_init_imports()) {
		fprintf(stderr, "Some imports do not exist.\n");
		errno = EINVAL;
		return NULL;
	}
	if (!(hSystemStore = fnCertOpenStore(((LPCSTR)CERT_STORE_PROV_SYSTEM),
			0, 0, CERT_SYSTEM_STORE_CURRENT_USER, L"MY"))) {
		fprintf(stderr, "Could not open system store.\n");
		errno = EINVAL;
		return NULL;
	}
#endif /* defined(__CYGWIN__) */
	session = malloc(sizeof(NTFS_DECRYPT_USER_KEY_SESSION));
#ifdef __CYGWIN__
	((NTFS_DECRYPT_USER_KEY_SESSION*)session)->hSystemStore = hSystemStore;
#endif /* defined(__CYGWIN__) */
	gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
	return session;
}

void ntfs_decrypt_user_key_session_close(ntfs_decrypt_user_key_session *session)
{
#ifdef __CYGWIN__
	HMODULE tmp;

	if (((NTFS_DECRYPT_USER_KEY_SESSION*)session)->hSystemStore)
		fnCertCloseStore(((NTFS_DECRYPT_USER_KEY_SESSION*)session)->
				hSystemStore, CERT_CLOSE_STORE_CHECK_FLAG);
	/*
	 * FIXME: This really needs locking and reference counting so it is
	 * safe from races.
	 */
	tmp = hCrypt32;
	hCrypt32 = INVALID_HANDLE_VALUE;
	FreeLibrary(tmp);
#endif /* defined(__CYGWIN__) */
	free(session);
}

/**
 * reverse_buffer -
 *
 * This is a utility function for reversing the order of a buffer in place.
 * Users of this function should be very careful not to sweep byte order
 * problems under the rug.
 */
static inline void reverse_buffer(unsigned char *buf, unsigned buf_size)
{
	unsigned char t;
	unsigned i;

	for (i = 0; i < buf_size / 2; i++) {
		t = buf[i];
		buf[i] = buf[buf_size - i - 1];
		buf[buf_size - i - 1] = t;
	}
}

ntfs_decrypt_user_key *ntfs_decrypt_user_key_open(
		ntfs_decrypt_user_key_session *session __attribute__((unused)),
		unsigned char *thumb_print __attribute__((unused)),
		unsigned thumb_size __attribute__((unused)))
{
#ifdef __CYGWIN__
	CRYPT_HASH_BLOB hash_blob;
	HCRYPTPROV hCryptProv;
	PCCERT_CONTEXT pCert;
	BOOL fCallerFreeProv;
	HCRYPTKEY hCryptKey;
	ntfs_decrypt_user_key *key;
	DWORD dwKeySpec;
	DWORD key_size;
	BYTE key_blob[1000];
	RSAPUBKEY *rsa_pub_key;
	gcry_ac_handle_t gcry_handle;
	unsigned char *mpi_data;
	gcry_mpi_t n, e, d, p, q, u;
	gcry_sexp_t sexp_key;
	gcry_error_t err;
	size_t size;
	int rc;

	hash_blob.cbData = thumb_size;
	hash_blob.pbData = thumb_print;

	if (!(pCert = fnCertFindCertificateInStore(
			((NTFS_DECRYPT_USER_KEY_SESSION*)session)->hSystemStore,
			(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING), 0,
			CERT_FIND_HASH, &hash_blob, NULL))) {
		fprintf(stderr, "Could not find cert in store.\n");
		goto decrypt_key_open_err;
	}
	dwKeySpec = AT_KEYEXCHANGE;
	if (!fnCryptAcquireCertificatePrivateKey(pCert,
			CRYPT_ACQUIRE_CACHE_FLAG, NULL, &hCryptProv,
			&dwKeySpec, &fCallerFreeProv)) {
		fprintf(stderr, "Could not aquire private key from cert.\n");
		goto decrypt_key_open_err;
	}
	if (!CryptGetUserKey(hCryptProv, AT_KEYEXCHANGE, &hCryptKey)) {
		fprintf(stderr, "Could not aquire user key.\n");
		goto decrypt_key_open_err;
	}
	key_size = sizeof(key_blob);
	if (!CryptExportKey(hCryptKey, 0, PRIVATEKEYBLOB, 0, key_blob,
			&key_size)) {
		fprintf(stderr, "Could not export key: Error 0x%x\n",
				(unsigned)GetLastError());
		errno = EINVAL;
		return NULL;
	}
	CryptDestroyKey(hCryptKey);
	rsa_pub_key = (RSAPUBKEY*)(key_blob + sizeof(PUBLICKEYSTRUC));
	if ((err = gcry_ac_open(&gcry_handle, GCRY_AC_RSA, 0))) {
		fprintf(stderr, "Could not init gcrypt handle\n");
		errno = EINVAL;
		return NULL;
	}
	gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
	e = gcry_mpi_set_ui(NULL, rsa_pub_key->pubexp);
	mpi_data = (key_blob + 0x14);
	size = rsa_pub_key->bitlen / 8;
	reverse_buffer(mpi_data, size);
	if ((rc = gcry_mpi_scan(&n, GCRYMPI_FMT_USG, mpi_data, size, &size)))
		fprintf(stderr, "error scanning n.\n");
	mpi_data += (rsa_pub_key->bitlen / 8);
	size = rsa_pub_key->bitlen / 16;
	reverse_buffer(mpi_data, size);
	if ((rc = gcry_mpi_scan(&q, GCRYMPI_FMT_USG, mpi_data, size, &size)))
		fprintf(stderr, "error scanning p.\n");
	mpi_data += (rsa_pub_key->bitlen / 16);
	size = rsa_pub_key->bitlen / 16;
	reverse_buffer(mpi_data, size);
	if ((rc = gcry_mpi_scan(&p, GCRYMPI_FMT_USG, mpi_data, size, &size)))
		fprintf(stderr, "error scanning q.\n");
	mpi_data += (rsa_pub_key->bitlen / 16) * 3;
	size = rsa_pub_key->bitlen / 16;
	reverse_buffer(mpi_data, size);
	if ((rc = gcry_mpi_scan(&u, GCRYMPI_FMT_USG, mpi_data, size, &size)))
		fprintf(stderr, "error scanning u.\n");
	mpi_data += (rsa_pub_key->bitlen / 16);
	size = rsa_pub_key->bitlen / 8;
	reverse_buffer(mpi_data, size);
	if ((rc = gcry_mpi_scan(&d, GCRYMPI_FMT_USG, mpi_data, size, &size)))
		fprintf(stderr, "error scanning d.\n");
	sexp_key = NULL;
	if ((rc = gcry_sexp_build(&sexp_key, NULL, "(private-key (rsa (n %m) "
			"(e %m) (d %m) (p %m) (q %m) (u %m)))", n, e, d, p, q,
			u))) {
		fprintf(stderr, "Could build sexp from data, (error = 0x%x)\n",
				rc);
		errno = EINVAL;
		return NULL;
	}
	if ((key = (ntfs_decrypt_user_key*)
			malloc(sizeof(NTFS_DECRYPT_USER_KEY))))
		((NTFS_DECRYPT_USER_KEY*)key)->sexp_key = sexp_key;
	// todo: release all
	return key;
decrypt_key_open_err: 
	if (hCryptKey)
		CryptDestroyKey(hCryptKey);
	if (pCert)
		fnCertFreeCertificateContext(pCert);
	errno = EINVAL;
#else /* !defined(__CYGWIN__) */
	errno = EOPNOTSUPP;
#endif /* !defined(__CYGWIN__) */
	return NULL;
}

void ntfs_decrypt_user_key_close(ntfs_decrypt_user_key *key)
{
	gcry_sexp_release(((NTFS_DECRYPT_USER_KEY*)key)->sexp_key);
	free(key);
}

/**
 * warning: decrypting into the input buffer!
 */
unsigned ntfs_decrypt_user_key_decrypt(ntfs_decrypt_user_key *key,
		unsigned char *data, unsigned data_size)
{
	gcry_sexp_t sexp_plain_data, sexp_enc_data;
	gcry_ac_handle_t gcry_handle;
	gcry_mpi_t mpi_buf;
	gcry_ac_data_t in;
	gcry_error_t err;
	unsigned size, padding_length, i;
	int rc;

	if ((err = gcry_ac_open(&gcry_handle, GCRY_AC_RSA, 0))) {
		fprintf(stderr, "Could not init gcrypt handle\n");
		errno = EINVAL;
		return 0;
	}
	if ((rc = gcry_ac_data_new(&in)))
		fprintf(stderr, "error allocating 'in'.\n");
	reverse_buffer(data, data_size);
	size = data_size;
	if ((rc = gcry_mpi_scan(&mpi_buf, GCRYMPI_FMT_USG, data,
			(size_t)data_size, &size)))
		fprintf(stderr, "error scanning 'in'.\n");
	if ((rc = gcry_sexp_build(&sexp_enc_data, &size, "(enc-val (flags) "
			"(rsa (a %m)))", mpi_buf))) {
		fprintf(stderr, "Could build sexp from data, (error = 0x%x)\n",
				rc);
		errno = EINVAL;
		return 0;
	}
	if ((rc = gcry_pk_decrypt(&sexp_plain_data, sexp_enc_data,
			((NTFS_DECRYPT_USER_KEY*)key)->sexp_key))) {
		fprintf(stderr, "Could not decrypt fek via s-exp, (error = "
				"0x%x)\n", rc);
		errno = EINVAL;
		return 0;
	}
	sexp_plain_data = gcry_sexp_find_token(sexp_plain_data, "value", 0);
	if (!mpi_buf) {
		fprintf(stderr, "Could find value in s-exp, (error = 0x%x)\n",
				rc);
		errno = EINVAL;
		return 0;
	}
	mpi_buf = gcry_sexp_nth_mpi(sexp_plain_data, 1, GCRYMPI_FMT_USG);
	if ((rc = gcry_mpi_print(GCRYMPI_FMT_USG, data, data_size, &size,
			mpi_buf))) {
		fprintf(stderr, "Could copy decrypted data back, (error = "
				"0x%x)\n", rc);
		errno = EINVAL;
		return 0;
	}
	// remove the pkcs1 padding
	for (padding_length = 1; (padding_length < size) &&
			data[padding_length]; padding_length++)
		;
	padding_length++;
	// todo: should memcpy fit? (overlapping)
	for (i = 0; i + padding_length < size; i++)
		data[i] = data[padding_length + i];
	// todo: mpi_buf->data
	// todo: release all
	gcry_ac_data_destroy(in);
	return size - padding_length;
}

#if 0
// This is the old code based on OpenSSL.  Please do not remove it.  AIA

#include <openssl/md5.h>

/**
 * ntfs_desx_key_expand - expand a 128-bit desx key to the needed 192-bit key
 * @src:	source buffer containing 128-bit key
 *
 * Expands the on-disk 128-bit desx key to the needed des key, the in-, and the
 * out-whitening keys required to perform desx {de,en}cryption.
 */
static void ntfs_desx_key_expand(const u8 *src, u32 *des_key,
		u64 *out_whitening, u64 *in_whitening)
{
	static const int salt_len = 12;
	static const u8 *salt1 = "Dan Simon  ";
	static const u8 *salt2 = "Scott Field";
	u32 md[4];
	MD5_CTX ctx1, ctx2;

	MD5_Init(&ctx1);

	/* Hash the on-disk key. */
	MD5_Update(&ctx1, src, 128 / 8);
	memcpy(&ctx2, &ctx1, sizeof(ctx1));

	/* Hash with the first salt and store the result. */
	MD5_Update(&ctx1, salt1, salt_len);
	MD5_Final((u8*)md, &ctx1);
	des_key[0] = md[0] ^ md[1];
	des_key[1] = md[2] ^ md[3];

	/* Hash with the second salt and store the result. */
	MD5_Update(&ctx2, salt2, salt_len);
	MD5_Final((u8*)md, &ctx2);
	*out_whitening = *(u64*)md;
	*in_whitening = *(u64*)(md + 2);
}
#endif

/**
 * ntfs_desx_key_expand - expand a 128-bit desx key to the needed 192-bit key
 * @src:	source buffer containing 128-bit key
 *
 * Expands the on-disk 128-bit desx key to the needed des key, the in-, and the
 * out-whitening keys required to perform desx {de,en}cryption.
 */
static gcry_error_t ntfs_desx_key_expand(const u8 *src, u32 *des_key,
		u64 *out_whitening, u64 *in_whitening)
{
	static const u8 *salt1 = "Dan Simon  ";
	static const u8 *salt2 = "Scott Field";
	static const int salt_len = 12;
	gcry_md_hd_t hd1, hd2;
	u32 *md;
	gcry_error_t err;

	err = gcry_md_open(&hd1, GCRY_MD_MD5, 0);
	if (err != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to open MD5 digest.\n");
		return err;
	}
	/* Hash the on-disk key. */
	gcry_md_write(hd1, src, 128 / 8);
	/* Copy the current hash for efficiency. */
	err = gcry_md_copy(&hd2, hd1);
	if (err != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to copy MD5 digest object.\n");
		goto out;
	}
	/* Hash with the first salt and store the result. */
	gcry_md_write(hd1, salt1, salt_len);
	md = (u32*)gcry_md_read(hd1, 0);
	des_key[0] = md[0] ^ md[1];
	des_key[1] = md[2] ^ md[3];
	/* Hash with the second salt and store the result. */
	gcry_md_write(hd2, salt2, salt_len);
	md = (u32*)gcry_md_read(hd2, 0);
	*out_whitening = *(u64*)md;
	*in_whitening = *(u64*)(md + 2);
	gcry_md_close(hd2);
out:
	gcry_md_close(hd1);
	return err;
}

/**
 * ntfs_desx_setkey - libgcrypt set_key implementation for DES-X-MS128
 * @context:	pointer to a variable of type ntfs_desx_ctx
 * @key:	the 128 bit DES-X-MS128 key, concated with the DES handle
 * @keylen:	must always be 16
 * 
 * This is the libgcrypt set_key implementation for DES-X-MS128.
 */
static gcry_err_code_t ntfs_desx_setkey(void *context, const u8 *key,
		unsigned keylen)
{
	ntfs_desx_ctx *ctx = context;
	gcry_error_t err;
	u8 des_key[8];

	if (keylen != 16) {
		fprintf(stderr, "Key length for desx must be 16.\n");
		return GPG_ERR_INV_KEYLEN;
	}
	err = gcry_cipher_open(&ctx->gcry_cipher_hd, GCRY_CIPHER_DES,
			GCRY_CIPHER_MODE_ECB, 0);
	if (err != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to open des cipher (error 0x%x).\n",
				err);
		return err;
	}
	err = ntfs_desx_key_expand(key, (u32*)des_key, &ctx->out_whitening,
			&ctx->in_whitening);
	if (err != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to expand desx key (error 0x%x).\n",
				err);
		gcry_cipher_close(ctx->gcry_cipher_hd);
		return err;
	}
	err = gcry_cipher_setkey(ctx->gcry_cipher_hd, des_key, sizeof(des_key));
	if (err != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to set des key (error 0x%x).\n", err);
		gcry_cipher_close(ctx->gcry_cipher_hd);
		return err;
	}
	/*
	 * Take a note of the ctx->gcry_cipher_hd since we need to close it at
	 * ntfs_decrypt_data_key_close() time.
	 */
	**(gcry_cipher_hd_t***)(key + ((keylen + 7) & ~7)) =
			&ctx->gcry_cipher_hd;
	return GPG_ERR_NO_ERROR;
}

static void ntfs_desx_decrypt(void *context, u8 *outbuf, const u8 *inbuf)
{
	ntfs_desx_ctx *ctx = context;
	gcry_error_t err;

	err = gcry_cipher_reset(ctx->gcry_cipher_hd);
	if (err != GPG_ERR_NO_ERROR)
		fprintf(stderr, "Failed to reset des cipher (error 0x%x).\n",
				err);
	*(u64*)outbuf = *(const u64*)inbuf ^ ctx->out_whitening;
	err = gcry_cipher_encrypt(ctx->gcry_cipher_hd, outbuf, 8, NULL, 0);
	if (err != GPG_ERR_NO_ERROR)
		fprintf(stderr, "Des decryption failed (error 0x%x).\n", err);
	*(u64*)outbuf ^= ctx->in_whitening;
}

static gcry_cipher_spec_t ntfs_desx_cipher = {
	.name = "DES-X-MS128",
	.blocksize = 8,
	.keylen = 128,
	.contextsize = sizeof(ntfs_desx_ctx),
	.setkey = ntfs_desx_setkey,
	.decrypt = ntfs_desx_decrypt,
};

//#define DO_CRYPTO_TESTS 1

#ifdef DO_CRYPTO_TESTS

/* Do not remove this test code from this file! AIA */
static BOOL ntfs_desx_key_expand_test(void)
{
	const u8 known_desx_on_disk_key[16] = {
		0xa1, 0xf9, 0xe0, 0xb2, 0x53, 0x23, 0x9e, 0x8f,
		0x0f, 0x91, 0x45, 0xd9, 0x8e, 0x20, 0xec, 0x30
	};
	const u8 known_des_key[8] = {
		0x27, 0xd1, 0x93, 0x09, 0xcb, 0x78, 0x93, 0x1f,
	};
	const u8 known_out_whitening[8] = {
		0xed, 0xda, 0x4c, 0x47, 0x60, 0x49, 0xdb, 0x8d,
	};
	const u8 known_in_whitening[8] = {
		0x75, 0xf6, 0xa0, 0x1a, 0xc0, 0xca, 0x28, 0x1e
	};
	u64 test_out_whitening, test_in_whitening;
	union {
		u64 u64;
		u32 u32[2];
	} test_des_key;
	gcry_error_t err;
	BOOL res;

	err = ntfs_desx_key_expand(known_desx_on_disk_key, test_des_key.u32,
			&test_out_whitening, &test_in_whitening);
	if (err != GPG_ERR_NO_ERROR)
		res = FALSE;
	else
		res = test_des_key.u64 == *(u64*)known_des_key &&
				test_out_whitening ==
				*(u64*)known_out_whitening &&
				test_in_whitening ==
				*(u64*)known_in_whitening;
	fprintf(stderr, "Testing whether ntfs_desx_key_expand() works: %s\n",
			res ? "SUCCESS" : "FAILED");
	return res;
}

static BOOL ntfs_des_test(void)
{
	const u8 known_des_key[8] = {
		0x27, 0xd1, 0x93, 0x09, 0xcb, 0x78, 0x93, 0x1f
	};
	const u8 known_des_encrypted_data[8] = {
		0xdc, 0xf7, 0x68, 0x2a, 0xaf, 0x48, 0x53, 0x0f
	};
	const u8 known_decrypted_data[8] = {
		0xd8, 0xd9, 0x15, 0x23, 0x5b, 0x88, 0x0e, 0x09
	};
	u8 test_decrypted_data[8];
	int res;
	gcry_error_t err;
	gcry_cipher_hd_t gcry_cipher_hd;

	err = gcry_cipher_open(&gcry_cipher_hd, GCRY_CIPHER_DES,
			GCRY_CIPHER_MODE_ECB, 0);
	if (err != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to open des cipher (error 0x%x).\n",
				err);
		return FALSE;
	}
	err = gcry_cipher_setkey(gcry_cipher_hd, known_des_key,
			sizeof(known_des_key));
	if (err != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to set des key (error 0x%x.\n", err);
		gcry_cipher_close(gcry_cipher_hd);
		return FALSE;
	}
	/*
	 * Apply DES decryption (ntfs actually uses encryption when decrypting).
	 */
	err = gcry_cipher_encrypt(gcry_cipher_hd, test_decrypted_data,
			sizeof(test_decrypted_data), known_des_encrypted_data,
			sizeof(known_des_encrypted_data));
	gcry_cipher_close(gcry_cipher_hd);
	if (err) {
		fprintf(stderr, "Failed to des decrypt test data (error "
				"0x%x).\n", err);
		return FALSE;
	}
	res = !memcmp(test_decrypted_data, known_decrypted_data,
			sizeof(known_decrypted_data));
	fprintf(stderr, "Testing whether des decryption works: %s\n",
			res ? "SUCCESS" : "FAILED");
	return res;
}

#else /* !defined(DO_CRYPTO_TESTS) */

static inline BOOL ntfs_desx_key_expand_test(void)
{
	return TRUE;
}

static inline BOOL ntfs_des_test(void)
{
	return TRUE;
}

#endif /* !defined(DO_CRYPTO_TESTS) */

ntfs_decrypt_data_key *ntfs_decrypt_data_key_open(unsigned char *data,
		unsigned data_size __attribute__((unused)))
{
	NTFS_DECRYPT_DATA_KEY *key;
	unsigned key_size, wanted_key_size, gcry_algo;
	gcry_error_t err;

	key_size = *(u32*)data;
	key = (NTFS_DECRYPT_DATA_KEY*)malloc(((((sizeof(*key) + 7) & ~7) +
			key_size + 7) & ~7) + sizeof(gcry_cipher_hd_t));
	if (!key) {
		errno = ENOMEM;
		return NULL;
	}
	key->alg_id = *(u32*)(data + 8);
	key->key_data = (u8*)key + ((sizeof(*key) + 7) & ~7);
	memcpy(key->key_data, data + 16, key_size);
	key->des_gcry_cipher_hd_ptr = NULL;
	*(gcry_cipher_hd_t***)(key->key_data + ((key_size + 7) & ~7)) =
			&key->des_gcry_cipher_hd_ptr;
	gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
	switch (key->alg_id) {
	case CALG_DESX:
		/* FIXME: This really needs locking so it is safe from races. */
		if (!ntfs_desx_module_count++) {
			if (!ntfs_desx_key_expand_test() || !ntfs_des_test()) {
				errno = EINVAL;
				return NULL;
			}
			err = gcry_cipher_register(&ntfs_desx_cipher,
					&ntfs_desx_algorithm_id,
					&ntfs_desx_module);
			if (err != GPG_ERR_NO_ERROR) {
				fprintf(stderr, "Failed to register desx "
						"cipher (error 0x%x).\n", err);
				errno = EINVAL;
				return NULL;
			}
		}
		wanted_key_size = 16;
		gcry_algo = ntfs_desx_algorithm_id;
		break;
	case CALG_3DES:
		wanted_key_size = 24;
		gcry_algo = GCRY_CIPHER_3DES;
		break;
	case CALG_AES_256:
		wanted_key_size = 32;
		gcry_algo = GCRY_CIPHER_AES256;
		break;
	default:
		wanted_key_size = 8;
		gcry_algo = GCRY_CIPHER_DES;
		fprintf(stderr, "DES is not supported at present.  Please "
				"email linux-ntfs-dev@lists.sourceforge.net "
				"and say that you saw this message.  We will "
				"then implement support for DES.\n");
		free(key);
		errno = EOPNOTSUPP;
		return NULL;
	}
	if (key_size != wanted_key_size) {
		fprintf(stderr, "%s key of %u bytes but needed size is %u "
				"bytes, assuming corrupt key.  Aborting.\n",
				gcry_cipher_algo_name(gcry_algo), key_size,
				wanted_key_size);
		free(key);
		errno = EIO;
		return NULL;
	}
	err = gcry_cipher_open(&key->gcry_cipher_hd, gcry_algo,
			GCRY_CIPHER_MODE_CBC, 0);
	if (err != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "gcry_cipher_open() failed with error 0x%x.\n",
				err);
		free(key);
		errno = EINVAL;
		return 0;
	}
	err = gcry_cipher_setkey(key->gcry_cipher_hd, key->key_data, key_size);
	if (err != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "gcry_cipher_setkey() failed with error "
				"0x%x.\n", err);
		gcry_cipher_close(key->gcry_cipher_hd);
		free(key);
		errno = EINVAL;
		return NULL;
	}
	return (ntfs_decrypt_data_key*)key;
}

void ntfs_decrypt_data_key_close(ntfs_decrypt_data_key *key)
{
	NTFS_DECRYPT_DATA_KEY *dkey = (NTFS_DECRYPT_DATA_KEY*)key;
	if (dkey->des_gcry_cipher_hd_ptr)
		gcry_cipher_close(*dkey->des_gcry_cipher_hd_ptr);
	gcry_cipher_close(dkey->gcry_cipher_hd);
	free(key);
	/* FIXME: This really needs locking so it is safe from races. */
	if (!--ntfs_desx_module_count) {
		gcry_cipher_unregister(ntfs_desx_module);
		ntfs_desx_module = NULL;
		ntfs_desx_algorithm_id = -1;
	}
}

unsigned ntfs_decrypt_data_key_decrypt_sector(ntfs_decrypt_data_key *key,
		unsigned char *data, unsigned long long offset)
{
	NTFS_DECRYPT_DATA_KEY *dkey = (NTFS_DECRYPT_DATA_KEY*)key;
	gcry_error_t err;

	err = gcry_cipher_reset(dkey->gcry_cipher_hd);
	if (err != GPG_ERR_NO_ERROR)
		fprintf(stderr, "Failed to reset cipher (error 0x%x).\n", err);
	/*
	 * Note: You may wonder why are we not calling gcry_cipher_setiv() here
	 * instead of doing it by hand after the decryption.  The answer is
	 * that gcry_cipher_setiv() wants an iv of length 8 bytes but we give
	 * it a length of 16 for AES256 so it does not like it.
	 */
	if ((err = gcry_cipher_decrypt(dkey->gcry_cipher_hd, data, 512, NULL,
			0)))
		fprintf(stderr, "Decryption failed (error 0x%x).\n", err);
	/* Apply the IV. */
	if (dkey->alg_id == CALG_AES_256) {
		((u64*)data)[0] ^= 0x5816657be9161312LL + offset;
		((u64*)data)[1] ^= 0x1989adbe44918961LL + offset;
	} else {
		/* All other algos (Des, 3Des, DesX) use the same IV. */
		((u64*)data)[0] ^= 0x169119629891ad13LL + offset;
	}
	return 512;
}
