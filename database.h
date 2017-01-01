/*****************************************************************
 * File: database.h                          Part of pam_mariadb *
 *                                                               *
 * Copyright (C) 2017 Erik Lundin. All Rights Reserved.          *
 *                                                               *
 * This software may be modified and distributed under the terms *
 * of the MIT license.  See the LICENSE file for details.        *
 *                                                               *
 *****************************************************************/

int connect_db(struct modconfig *cfg);
void close_db(struct modconfig *cfg);
char *fetch_userinfo(struct modconfig *cfg, const char *username);
