/*****************************************************************
 * File: utils.c                             Part of pam_mariadb *
 *                                                               *
 * Copyright (C) 2017 Erik Lundin. All Rights Reserved.          *
 *                                                               *
 * This software may be modified and distributed under the terms *
 * of the MIT license.  See the LICENSE file for details.        *
 *                                                               *
 *****************************************************************/

#include <string.h>

/** Search an array for a string */
int search_array(char *arg, const char **list) {
	int i;

	for (i = 0; **(list + i) != '\n'; i++) {
		if (!strcmp(arg, *(list + i)))
			return i;
	}
	return -1;
}
