/*****************************************************************
 * File: hash.h                              Part of pam_mariadb *
 *                                                               *
 * Copyright (C) 2017 Erik Lundin. All Rights Reserved.          *
 *                                                               *
 * This software may be modified and distributed under the terms *
 * of the MIT license.  See the LICENSE file for details.        *
 *                                                               *
 *****************************************************************/

#define HASHFUNC(name) \
	hashstruct name(const char *string)

char *hash_string(struct modconfig *cfg, const char *pwd);

typedef struct hashstruct {
	unsigned char *data;
	int length;
}hashstruct;

