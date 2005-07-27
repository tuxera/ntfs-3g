/*
 * decrypt.c - Part of the Linux-NTFS project.
 *
 * Copyright (c) 2005 Yuval Fledel
 * Copyright (c) 2005 Anton Altaparmakov
 *
 * $EFS decryption routines.
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
#include <openssl/md5.h>

#include "decrypt.h"

#ifdef __CYGWIN__
//#define USE_CRYPTOAPI_RSA 1
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

/* windows 2k+ imports */
typedef BOOL (WINAPI *LPFN_CryptAcquireCertificatePrivateKey) (PCCERT_CONTEXT,
		DWORD, void *, HCRYPTPROV *, DWORD *, BOOL*);
typedef BOOL (WINAPI *LPFN_CertCloseStore) (HCERTSTORE, DWORD);
typedef PCCERT_CONTEXT (WINAPI *LPFN_CertFindCertificateInStore) (HCERTSTORE, 
		DWORD, DWORD, DWORD, const void*, PCCERT_CONTEXT);
typedef BOOL (WINAPI *LPFN_CertFreeCertificateContext) (PCCERT_CONTEXT);
typedef HCERTSTORE (WINAPI *LPFN_CertOpenStore) (LPCSTR, DWORD, HCRYPTPROV, 
		DWORD, const void*);

// NT4SP3+ WINME or 95+ w/ IE5+
static LPFN_CryptAcquireCertificatePrivateKey 
	fnCryptAcquireCertificatePrivateKey; 
// osr2+ NT4SP3+ or NT4 w/ IE3.02:
static LPFN_CertCloseStore fnCertCloseStore;
static LPFN_CertFindCertificateInStore fnCertFindCertificateInStore;
static LPFN_CertFreeCertificateContext fnCertFreeCertificateContext;
static LPFN_CertOpenStore fnCertOpenStore;

/* global variable: handle to crypt32.dll */
static HMODULE hCrypt32 = INVALID_HANDLE_VALUE;

#else /* defined(__CYGWIN__) */

#include <malloc.h>
#include <string.h>
#define CALG_DES (0x6601)
/* If not one of the below three, fall back to standard Des. */
#define CALG_3DES (0x6603)
#define CALG_DESX (0x6604)
#define CALG_AES_256 (0x6610)

#endif /* defined(__CYGWIN__) */

/* This must be after windows.h include. */
#include "types.h"

typedef struct {
#ifdef __CYGWIN__
	HCERTSTORE hSystemStore;
#else
	int nothing; /* unused */
#endif /* defined(__CYGWIN__) */
} DECRYPT_SESSION;

typedef struct {
	u64 desx_key[3];
	u8 *key_data;
	u32 alg_id;
	gcry_cipher_hd_t gcry_cipher_hd; // handle to the decrypted FEK.
	gcry_sexp_t sexp_key;  // the user's RSA key.
#ifdef USE_CRYPTOAPI_RSA
	HCRYPTKEY hCryptKey;
#endif /* defined(__CYGWIN__) */
} DECRYPT_KEY;

/* DESX-MS128 implementation for libgcrypt. */
static gcry_module_t	desx_module;
static int		desx_algorithm_id = -1;

typedef struct desx_ctx {
	gcry_cipher_hd_t gcry_cipher_hd;
	u8 in_whitening[8], out_whitening[8];
} desx_ctx;

/**
 * desx_key_expand - expand a 128-bit desx key to the needed 192-bit key
 * @src:	source buffer containing 128-bit key
 * @dst:	destination buffer to write 192-bit key to
 *
 * Expands the on-disk 128-bit desx key to the needed full 192-bit desx key
 * required to perform desx {de,en}cryption.
 *
 * FIXME: Is this endianness safe?  I think so but I may be wrong...
 */
static void desx_key_expand(const u8 *src, u8 *in_whitening, u8 *out_whitening,
		u8 *des_key)
{
	static const int salt_len = 12;
	static const u8 *salt1 = "Dan Simon  ";
	static const u8 *salt2 = "Scott Field";
	u8 md[16];
	MD5_CTX ctx1, ctx2;

	MD5_Init(&ctx1);

	/* Hash the on-disk key. */
	MD5_Update(&ctx1, src, 128 / 8);
	memcpy(&ctx2, &ctx1, sizeof(ctx1));

	/* Hash with the first salt and store the result. */
	MD5_Update(&ctx1, salt1, salt_len);
	MD5_Final(md, &ctx1);
	((u32*)des_key)[0] = ((u32*)md)[0] ^ ((u32*)md)[1];
	((u32*)des_key)[1] = ((u32*)md)[2] ^ ((u32*)md)[3];

	/* Hash with the second salt and store the result. */
	MD5_Update(&ctx2, salt2, salt_len);
	MD5_Final(md, &ctx2);
	memcpy(out_whitening, md, 8);
	memcpy(in_whitening, md+8, 8);
}

static gcry_err_code_t do_desx_setkey(void *context, const u8 *key,
		unsigned keylen)
{
	struct desx_ctx *ctx = (desx_ctx *)context;
	gcry_error_t err;
	u8 des_key[8];

	if (keylen != 16) {
		fprintf(stderr, "not 16\n");
		return GPG_ERR_INV_KEYLEN;
	}

	if ((err = gcry_cipher_open(&ctx->gcry_cipher_hd, GCRY_CIPHER_DES,
				GCRY_CIPHER_MODE_ECB, 0)) != GPG_ERR_NO_ERROR)
		return err;

	if ((err = gcry_cipher_reset(ctx->gcry_cipher_hd))) {
		fprintf(stderr, "err is %u.\n", err);
	}

	desx_key_expand(key, ctx->in_whitening, ctx->out_whitening, des_key);

/*
	fprintf(stderr, "expanded keys (hex) =\n\t0x%llx (des)\n\t"
			"0x%llx (in-whitening)\n\t"
			"0x%llx (out-whitening)\n", *(u64*)des_key,
			*(u64*)ctx->in_whitening, *(u64*)ctx->out_whitening);
*/

	if ((err = gcry_cipher_setkey(ctx->gcry_cipher_hd, des_key, 8))) {
		fprintf(stderr, "do_desx_setkey: error %u.\n", err);
		// TODO: destroy gcry_cipher_hd
	}

	return GPG_ERR_NO_ERROR;
}

static void do_desx_decrypt(void *context, u8 *outbuf, const u8 *inbuf)
{
	struct desx_ctx *ctx = (desx_ctx *)context;
	gcry_error_t err;
	u8 buf[8];

	*((unsigned long long *)buf) = *((const unsigned long long *)inbuf)
			^ *(const unsigned long long *)ctx->out_whitening;

	if ((err = gcry_cipher_encrypt(ctx->gcry_cipher_hd,
				outbuf, 8, buf, 8))) {
		fprintf(stderr, "desx decryption failed: %u.\n", err);
	}

	*((unsigned long long *)outbuf) ^= *(const unsigned long long *)
				ctx->in_whitening;
}

static gcry_cipher_spec_t cipher = {
	.name = "DES-X-MS128",
	.blocksize = 8,
	.keylen = 128,
	.contextsize = sizeof (struct desx_ctx),
	.setkey = do_desx_setkey,
	.decrypt = do_desx_decrypt,
};

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
		fnCertFindCertificateInStore = 
			(LPFN_CertFindCertificateInStore)
			GetProcAddress(hCrypt32, "CertFindCertificateInStore");
	if (!fnCertFreeCertificateContext)
		fnCertFreeCertificateContext = 
			(LPFN_CertFreeCertificateContext)
			GetProcAddress(hCrypt32, "CertFreeCertificateContext");
	if (!fnCertOpenStore)
		fnCertOpenStore = (LPFN_CertOpenStore)
			GetProcAddress(hCrypt32, "CertOpenStore");

	return fnCryptAcquireCertificatePrivateKey && fnCertCloseStore &&
		fnCertFindCertificateInStore &&
		fnCertFreeCertificateContext && fnCertOpenStore;
}
#endif /* defined(__CYGWIN__) */

//#define DO_CRYPTO_TESTS 1

#ifdef DO_CRYPTO_TESTS
/* Do not remove this test code from this file! AIA */
static BOOL desx_key_expand_test(void) {
	const u8 known_desx_on_disk_key[16] = {
			0xa1, 0xf9, 0xe0, 0xb2, 0x53, 0x23, 0x9e, 0x8f,
			0x0f, 0x91, 0x45, 0xd9, 0x8e, 0x20, 0xec, 0x30 };
	const u8 known_desx_expanded_key[24] = {
			0x27, 0xd1, 0x93, 0x09, 0xcb, 0x78, 0x93, 0x1f,
			0xed, 0xda, 0x4c, 0x47, 0x60, 0x49, 0xdb, 0x8d,
			0x75, 0xf6, 0xa0, 0x1a, 0xc0, 0xca, 0x28, 0x1e };
	u8 test_desx_expanded_key[24];
	int res;

	desx_key_expand(known_desx_on_disk_key, test_desx_expanded_key);
	res = !memcmp(test_desx_expanded_key, known_desx_expanded_key,
			sizeof(known_desx_expanded_key));
	fprintf(stderr, "Testing whether desx_key_expand() works: %s\n",
		res ? "SUCCESS" : "FAILED");
	return res;
}

static BOOL des_test(void) {
	const u8 known_des_key[8] = {
			0x27, 0xd1, 0x93, 0x09, 0xcb, 0x78, 0x93, 0x1f };
	const u8 known_des_encrypted_data[8] = {
			0xdc, 0xf7, 0x68, 0x2a, 0xaf, 0x48, 0x53, 0x0f };
	const u8 known_decrypted_data[8] = {
			0xd8, 0xd9, 0x15, 0x23, 0x5b, 0x88, 0x0e, 0x09 };
	u8 test_decrypted_data[8];
	int res;
	gcry_error_t gcry_error2;
	gcry_cipher_hd_t gcry_cipher_hd;

	if ((gcry_error2 = gcry_cipher_open(&gcry_cipher_hd, GCRY_CIPHER_DES,
			GCRY_CIPHER_MODE_ECB, 0)) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "Failed to open des cipher (gcry_error2 is "
				"%u).\n", gcry_error2);
		return FALSE;
	}
	if ((gcry_error2 = gcry_cipher_setkey(gcry_cipher_hd,
			known_des_key, sizeof(known_des_key)))) {
		fprintf(stderr, "Failed to set des key (gcry_error2 is %u).\n",
				gcry_error2);
		gcry_cipher_close(gcry_cipher_hd);
		return FALSE;
	}
	memcpy(test_decrypted_data, known_des_encrypted_data,
			sizeof(known_des_encrypted_data));
	/* Apply DES decyption. */
	gcry_error2 = gcry_cipher_decrypt(gcry_cipher_hd,
			test_decrypted_data, sizeof(test_decrypted_data),
			NULL, 0);
	gcry_cipher_close(gcry_cipher_hd);
	if (gcry_error2) {
		fprintf(stderr, "Failed to des decrypt test data (gcry_error2 "
				"is %u).\n", gcry_error2);
		return FALSE;
	}
	res = !memcmp(test_decrypted_data, known_decrypted_data,
			sizeof(known_decrypted_data));
	fprintf(stderr, "Testing whether des decryption works: %s\n",
		res ? "SUCCESS" : "FAILED");
	return res;
}

#else

static inline BOOL desx_key_expand_test(void) {
	return TRUE;
}

static inline BOOL des_test(void) {
	return TRUE;
}

#endif

decrypt_session *decrypt_open(void) {
	decrypt_session *session;

	/* TODO: refcount 'module' */
	if (desx_algorithm_id==-1) {
		if (!desx_key_expand_test())
			return NULL;
		if (!des_test())
			return NULL;
		if (gcry_cipher_register(&cipher, &desx_algorithm_id,
				&desx_module))
			return NULL;
	}

	//fprintf(stderr, "desx_algorithm_id: %d\n", desx_algorithm_id);

	gcry_control(GCRYCTL_DISABLE_SECMEM, 0);

#ifdef __CYGWIN__
	HCERTSTORE hSystemStore;

	if (!cryptoAPI_init_imports()) {
		fprintf(stderr, "Some imports do not exist.\n");
		errno = -1;
		return NULL;
	}

	if (!(hSystemStore = fnCertOpenStore(((LPCSTR)CERT_STORE_PROV_SYSTEM),
			0, (HCRYPTPROV)NULL, CERT_SYSTEM_STORE_CURRENT_USER,
			L"MY"))) {
		fprintf(stderr, "Could not open system store.\n");
		errno = -1;
		return NULL;
	}
#endif /* defined(__CYGWIN__) */

	session = (decrypt_session *)malloc(sizeof(DECRYPT_SESSION));
#ifdef __CYGWIN__
	((DECRYPT_SESSION *)session)->hSystemStore = hSystemStore;
#endif /* defined(__CYGWIN__) */
	return session;
}

void decrypt_close(decrypt_session *session) {
#ifdef __CYGWIN__
	if (((DECRYPT_SESSION *)session)->hSystemStore)
		fnCertCloseStore(((DECRYPT_SESSION *)session)->hSystemStore,
					CERT_CLOSE_STORE_CHECK_FLAG);
	/* fixme: racy */
	FreeLibrary(hCrypt32);
	hCrypt32 = INVALID_HANDLE_VALUE;
#endif /* defined(__CYGWIN__) */

	free(session);
}

static inline void reverse_buffer(unsigned char *buf, unsigned int buf_size) {
    unsigned char t;
    unsigned int i;

    for (i=0; i<buf_size/2; i++) {
        t = buf[i];
        buf[i] = buf[buf_size-i-1];
        buf[buf_size-i-1] = t;
    }
}

decrypt_key *decrypt_user_key_open(decrypt_session *session
			__attribute__((unused)),
			int thumb_size, void *thumb_print) {
#ifdef __CYGWIN__
	CRYPT_HASH_BLOB hash_blob;
	HCRYPTPROV hCryptProv;
	PCCERT_CONTEXT pCert;
	BOOL fCallerFreeProv;
	HCRYPTKEY hCryptKey;
	decrypt_key *key;
	DWORD dwKeySpec;
	DWORD key_size;
	BYTE key_blob[1000];

	hash_blob.cbData = thumb_size;
	hash_blob.pbData = thumb_print;

	if (!(pCert = fnCertFindCertificateInStore(
				((DECRYPT_SESSION *)session)->hSystemStore,
				(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING),
				0, CERT_FIND_HASH, &hash_blob, NULL))) {
		fprintf(stderr, "Could not find cert in store.\n");
		goto decrypt_key_open_err;
	}

	dwKeySpec = AT_KEYEXCHANGE;
	if (!fnCryptAcquireCertificatePrivateKey(pCert,
				CRYPT_ACQUIRE_CACHE_FLAG, NULL,
				&hCryptProv, &dwKeySpec,
				&fCallerFreeProv)) {
		fprintf(stderr, "Could not aquire private key from cert.\n");
		goto decrypt_key_open_err;
	}

	if (!CryptGetUserKey(hCryptProv, AT_KEYEXCHANGE, &hCryptKey)) {
		fprintf(stderr, "Could not aquire user key.\n");
		goto decrypt_key_open_err;
	}

	key_size = sizeof(key_blob);
	if (!CryptExportKey(hCryptKey, 0, PRIVATEKEYBLOB, 0, key_blob, &key_size)) {
		fprintf(stderr, "Could not export key: Error 0x%x\n",
					(unsigned int)GetLastError());
		errno = -1;
		return NULL;
	}

	if (!(key = (decrypt_key *)malloc(sizeof(DECRYPT_KEY))))
		goto decrypt_key_open_err;

#ifdef USE_CRYPTOAPI_RSA
	((DECRYPT_KEY *)key)->hCryptKey = hCryptKey;
#else
	RSAPUBKEY *rsa_pub_key = (RSAPUBKEY *)(key_blob + sizeof(PUBLICKEYSTRUC));
	gcry_ac_handle_t gcry_handle;
	unsigned char *mpi_data;
	gcry_mpi_t n,e,d,p,q,u;
	gcry_sexp_t sexp_key;
	gcry_error_t err;
	size_t size;
	int rc;

	CryptDestroyKey(hCryptKey);

	if ((err = gcry_ac_open(&gcry_handle, GCRY_AC_RSA, 0))) {
		fprintf(stderr, "Could not init gcrypt handle\n");
		errno = -1;
		return NULL;
	}

	e = gcry_mpi_set_ui(NULL, rsa_pub_key->pubexp);

	mpi_data = (key_blob + 0x14);
	size = rsa_pub_key->bitlen / 8;
	reverse_buffer(mpi_data, size);
	if ((rc = gcry_mpi_scan(&n, GCRYMPI_FMT_USG, mpi_data, size, &size))) {
		fprintf(stderr, "error scanning n.\n");
	}

	mpi_data += (rsa_pub_key->bitlen / 8);
	size = rsa_pub_key->bitlen / 16;
	reverse_buffer(mpi_data, size);
	if ((rc = gcry_mpi_scan(&q, GCRYMPI_FMT_USG, mpi_data, size, &size))) {
		fprintf(stderr, "error scanning p.\n");
	}

	mpi_data += (rsa_pub_key->bitlen / 16);
	size = rsa_pub_key->bitlen / 16;
	reverse_buffer(mpi_data, size);
	if ((rc = gcry_mpi_scan(&p, GCRYMPI_FMT_USG, mpi_data, size, &size))) {
		fprintf(stderr, "error scanning q.\n");
	}

	mpi_data += (rsa_pub_key->bitlen / 16)*3;
	size = rsa_pub_key->bitlen / 16;
	reverse_buffer(mpi_data, size);
	if ((rc = gcry_mpi_scan(&u, GCRYMPI_FMT_USG, mpi_data, size, &size))) {
		fprintf(stderr, "error scanning u.\n");
	}

	mpi_data += (rsa_pub_key->bitlen / 16);
	size = rsa_pub_key->bitlen / 8;
	reverse_buffer(mpi_data, size);
	if ((rc = gcry_mpi_scan(&d, GCRYMPI_FMT_USG, mpi_data, size, &size))) {
		fprintf(stderr, "error scanning d.\n");
	}

	if ((rc = gcry_sexp_build(&sexp_key, NULL,
			"(private-key (rsa (n %m) (e %m) (d %m) (p %m) (q %m) (u %m)))",
			n, e, d, p, q, u))) {
		fprintf(stderr, "Could build sexp from data, (error = 0x%x)\n", rc);
		errno = -1;
		return FALSE;
	}

	((DECRYPT_KEY *)key)->sexp_key = sexp_key;

	// todo: release all
#endif
	return key;

decrypt_key_open_err:

	if (hCryptKey)
		CryptDestroyKey(hCryptKey);
	if (pCert)
		fnCertFreeCertificateContext(pCert);
#endif // defined(__CYGWIN__)
	errno = ENOTSUP;
	return NULL;
}

void decrypt_user_key_close(decrypt_key *key) {
	DECRYPT_KEY *dkey = (DECRYPT_KEY *)key;
	if (dkey->gcry_cipher_hd)
		gcry_cipher_close(dkey->gcry_cipher_hd);

	free(key);
}

/**
 * decrypt_decrypt
 *
 * warning: decrypting into the input buffer!
 */
unsigned int decrypt_decrypt(decrypt_key *key, unsigned int data_size, 
					unsigned char *data)
{
#ifdef USE_CRYPTOAPI_RSA
	DWORD size = data_size;

	if (!CryptDecrypt(((DECRYPT_KEY *)key)->hCryptKey, 0, 
				TRUE, 0, data, &size)) {
		errno = -1;
		return 0;
	}

	return size;
#else
	gcry_sexp_t sexp_plain_data, sexp_enc_data;
	gcry_ac_handle_t gcry_handle;
	gcry_mpi_t mpi_buf;
	gcry_ac_data_t in;
	gcry_error_t err;
	unsigned int size, padding_length, i;
	int rc;

	if ((err = gcry_ac_open(&gcry_handle, GCRY_AC_RSA, 0))) {
		fprintf(stderr, "Could not init gcrypt handle\n");
		errno = -1;
		return FALSE;
	}

	if ((rc = gcry_ac_data_new(&in))) {
		fprintf(stderr, "error allocating 'in'.\n");
	}

	reverse_buffer(data, data_size);

	size = data_size;
	if ((rc = gcry_mpi_scan(&mpi_buf, GCRYMPI_FMT_USG, data, (size_t)data_size, &size))) {
		fprintf(stderr, "error scanning 'in'.\n");
	}

	if ((rc = gcry_sexp_build(&sexp_enc_data, &size, "(enc-val (flags) (rsa (a %m)))", mpi_buf))) {
		fprintf(stderr, "Could build sexp from data, (error = 0x%x)\n", rc);
		errno = -1;
		return FALSE;
	}

	if ((rc = gcry_pk_decrypt(&sexp_plain_data, sexp_enc_data, ((DECRYPT_KEY *)key)->sexp_key))) {
		fprintf(stderr, "Could not decrypt fek via s-exp, (error = 0x%x)\n", rc);
		errno = -1;
		return FALSE;
	}

	sexp_plain_data = gcry_sexp_find_token(sexp_plain_data, "value", 0);
	if (!mpi_buf) {
		fprintf(stderr, "Could find value in s-exp, (error = 0x%x)\n", rc);
		errno = -1;
		return FALSE;
	}

	mpi_buf = gcry_sexp_nth_mpi(sexp_plain_data, 1, GCRYMPI_FMT_USG);

	if ((rc = gcry_mpi_print(GCRYMPI_FMT_USG, data, data_size, &size, mpi_buf))) {
		fprintf(stderr, "Could copy decrypted data back, (error = 0x%x)\n", rc);
		errno = -1;
		return FALSE;
	}

	// remove the pkcs1 padding
	for (padding_length = 1;(padding_length<size) && data[padding_length];
		padding_length++);
	padding_length++;
	for (i = 0;i+padding_length<size;i++) // todo: should memcpy fit? (overlapping)
		data[i]=data[padding_length+i];

	// todo: mpi_buf->data
	// todo: release all
	gcry_ac_data_destroy(in);

	return size - padding_length;
#endif // USER_CRYPTOAPI_RSA (else)
}

unsigned int decrypt_decrypt_sector(decrypt_key *key, void *data,
			unsigned long long offset) {
	gcry_error_t err;
	DECRYPT_KEY *dkey = (DECRYPT_KEY *)key;

	if ((err = gcry_cipher_reset(dkey->gcry_cipher_hd))) {
		fprintf(stderr, "sector_decrypt: error is %u.\n", err);
	}

	// FIXME: Why are we not calling gcry_cipher_setiv() here instead of
	// doing it by hand after the decryption?
	// It wants iv length 8 but we give it 16 for AES256 so it does not
	// like it...

	if ((err = gcry_cipher_decrypt(dkey->gcry_cipher_hd,
				data, 512, NULL, 0))) {
		fprintf(stderr, "sector_decrypt: error is %u.\n", err);
	}

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

decrypt_key *decrypt_make_key(decrypt_session *session __attribute__((unused)), 
		unsigned int data_size __attribute__((unused)),
		unsigned char *data) {
	DECRYPT_KEY *key;
	unsigned int key_size, gcry_algo;
	gcry_error_t err;

	key_size = *(u32*)data;

	if (!(key = (DECRYPT_KEY *)malloc(sizeof(DECRYPT_KEY)))) {
		errno = -1;
		return NULL;
	}

	key_size = *(u32*)data;
	key->alg_id = *(u32*)(data + 8);
	key->key_data = data + 16;

	switch (key->alg_id) {
	case CALG_DESX:
		fprintf(stderr, "DESX key of %u bytes\n", key_size);
		gcry_algo = desx_algorithm_id;
		break;
	case CALG_3DES:
		fprintf(stderr, "3DES Key of %u bytes\n", key_size);
		gcry_algo = GCRY_CIPHER_3DES; 
		break;
	case CALG_AES_256:
		fprintf(stderr, "AES Key of %u bytes\n", key_size);
		gcry_algo = GCRY_CIPHER_AES256;
		break;
	default:
		fprintf(stderr, "DES key of %u bytes\n", key_size);
		gcry_algo = GCRY_CIPHER_DES;
		break;
	}
	if ((err = gcry_cipher_open(&key->gcry_cipher_hd, gcry_algo,
			GCRY_CIPHER_MODE_CBC, 0)) != GPG_ERR_NO_ERROR) {
		fprintf(stderr, "gcry_cipher_open failed with 0x%x.\n", err);
		errno = -1;
		return 0;
	}
	if ((err = gcry_cipher_setkey(key->gcry_cipher_hd, key->key_data,
							key_size))) {
		fprintf(stderr, "gcry_cipher_setkey failed with 0x%x.\n", err);
	}
	return (decrypt_key *)key;
}
