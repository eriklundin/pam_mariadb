/*****************************************************************
 * File: hash.c                              Part of pam_mariadb *
 *                                                               *
 * Copyright (C) 2017 Erik Lundin. All Rights Reserved.          *
 *                                                               *
 * This software may be modified and distributed under the terms *
 * of the MIT license.  See the LICENSE file for details.        *
 *                                                               *
 *****************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/sha.h>
#include <openssl/md5.h>

/* Base64 */
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#include "config.h"
#include "hash.h"

extern const char *pwd_algo[];

HASHFUNC(hash_sha512);
HASHFUNC(hash_sha256);
HASHFUNC(hash_sha1);
HASHFUNC(hash_md5);

char *hash_string(struct modconfig *cfg, const char *pwd) {

	hashstruct hs;
	char *ret = NULL;
	BIO *bio, *b64;
	BUF_MEM *b64buf;
	int i = 0, algo_len;

	hs.length = 0;
	hs.data = NULL;

	switch(cfg->pwdalgo) {
		case PWDALGO_SHA512:
			hs = hash_sha512(pwd);
		break;
		case PWDALGO_SHA256:
			hs = hash_sha256(pwd);
		break;
		case PWDALGO_SHA1:
			hs = hash_sha1(pwd);
		break;
		case PWDALGO_MD5:
			hs = hash_md5(pwd);
		break;
	}

	if(cfg->pwdstyle == PWDSTYLE_HEX) {

		// Hex
		ret = (char *)calloc((hs.length * 2) + 1, sizeof(char));
		for(i = 0; i < hs.length; i++) {
			sprintf(ret + (i * 2), "%02x", hs.data[i]);
		}
		ret[hs.length * 2] = '\0';

	} else if(cfg->pwdstyle == PWDSTYLE_CURLYB64) {

		// Base64-encoded with algorithm name
		b64 = BIO_new(BIO_f_base64());
		bio = BIO_new(BIO_s_mem());
		bio = BIO_push(b64, bio);
		BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
		BIO_write(bio, hs.data, hs.length);
		BIO_flush(bio);
		BIO_get_mem_ptr(bio, &b64buf);
		BIO_set_close(bio, BIO_NOCLOSE);
		BIO_free_all(bio);

		algo_len = strlen(pwd_algo[cfg->pwdalgo]) + 2;
		ret = (char *)calloc(algo_len + (*b64buf).length + 1, sizeof(char));
		sprintf(ret, "{%s}", pwd_algo[cfg->pwdalgo]);
		strncat(ret, (*b64buf).data, (*b64buf).length);
		ret[algo_len + (*b64buf).length] = '\0';
		BUF_MEM_free(b64buf);
	}

	free(hs.data);
	return ret;
}

HASHFUNC(hash_sha512) {

	hashstruct hs;
	hs.length = SHA512_DIGEST_LENGTH;

	unsigned char hash[hs.length];
	SHA512_CTX sha512;

	SHA512_Init(&sha512);
	SHA512_Update(&sha512, string, strlen(string));
	SHA512_Final(hash, &sha512);

	hs.data = (unsigned char *)calloc(hs.length, sizeof(char));
	memcpy(hs.data, hash, hs.length);

	return hs;
}

HASHFUNC(hash_sha256) {

	hashstruct hs;
	hs.length = SHA256_DIGEST_LENGTH;

	unsigned char hash[hs.length];
	SHA256_CTX sha256;

	SHA256_Init(&sha256);
	SHA256_Update(&sha256, string, strlen(string));
	SHA256_Final(hash, &sha256);

	hs.data = (unsigned char *)calloc(hs.length, sizeof(char));
	memcpy(hs.data, hash, hs.length);

	return hs;
}

HASHFUNC(hash_sha1) {

	hashstruct hs;
	hs.length = SHA_DIGEST_LENGTH;

	unsigned char hash[hs.length];
	SHA_CTX sha1;

	SHA1_Init(&sha1);
	SHA1_Update(&sha1, string, strlen(string));
	SHA1_Final(hash, &sha1);

	hs.data = (unsigned char *)calloc(hs.length, sizeof(char));
	memcpy(hs.data, hash, hs.length);

	return hs;
}

HASHFUNC(hash_md5) {

	hashstruct hs;
	hs.length = MD5_DIGEST_LENGTH;

	unsigned char hash[hs.length];
	MD5_CTX md5;

	MD5_Init(&md5);
	MD5_Update(&md5, string, strlen(string));
	MD5_Final(hash, &md5);

	hs.data = (unsigned char *)calloc(hs.length, sizeof(char));
	memcpy(hs.data, hash, hs.length);

	return hs;
}
