/*****************************************************************
 * File: config.h                            Part of pam_mariadb *
 *                                                               *
 * Copyright (C) 2017 Erik Lundin. All Rights Reserved.          *
 *                                                               *
 * This software may be modified and distributed under the terms *
 * of the MIT license.  See the LICENSE file for details.        *
 *                                                               *
 *****************************************************************/

#include <stdlib.h>
#include <syslog.h>

#include <mysql/mysql.h>

#define PAM_MODULE_NAME "pam_mariadb"
#define PAM_LOG_PREFIX	PAM_MODULE_NAME " - "

struct modconfig {
        int debug;
	MYSQL *dbo;
	char *config_file;
	char *dbserver;
	char *dbuser;
	char *dbpassword;
	char *dbname;
	int pwdalgo;
	int pwdstyle;
	char *useridcolumn;
	char *pwdcolumn;
	char *usertable;
	char *userwhere;
};

extern const char *pwd_algo[];

void log_msg(int prio, const char *format, ...);
struct modconfig *parse_settings(int argc, const char **argv);
void free_config(struct modconfig *cfg);

#define CREATE(result, type, number)  do {\
	if ((number) * sizeof(type) <= 0)	\
		log_msg(LOG_WARNING, "Zero bytes or less requested at %s:%d.", __FILE__, __LINE__);	\
	if (!((result) = (type *) calloc ((number), sizeof(type))))	\
		{ perror("malloc failure"); abort(); } } while(0)

#define PWDALGO_SHA512		0
#define PWDALGO_SHA256		1
#define PWDALGO_SHA1		2
#define PWDALGO_MD5		3

#define PWDSTYLE_HEX		0
#define PWDSTYLE_CURLYB64	1
