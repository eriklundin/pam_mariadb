/*****************************************************************
 * File: database.c                          Part of pam_mariadb *
 *                                                               *
 * Copyright (C) 2017 Erik Lundin. All Rights Reserved.          *
 *                                                               *
 * This software may be modified and distributed under the terms *
 * of the MIT license.  See the LICENSE file for details.        *
 *                                                               *
 *****************************************************************/

#include <stdio.h>
#include <string.h>
#include <mysql/mysql.h>
#include "config.h"

int connect_db(struct modconfig *cfg) {

	if(cfg->debug) {
		log_msg(LOG_INFO, "DEBUG: MySQL Version: %s", mysql_get_client_info());
		log_msg(LOG_INFO, "DEBUG: Connecting to server '%s' with user '%s' (Database: %s)",
			cfg->dbserver, cfg->dbuser, cfg->dbname);
	}

	cfg->dbo = mysql_init(NULL);
	if(mysql_real_connect(cfg->dbo, cfg->dbserver, cfg->dbuser, cfg->dbpassword, cfg->dbname, 0, NULL, 0) == NULL) {
		log_msg(LOG_WARNING, "ERROR: %s", mysql_error(cfg->dbo));
		return 1;
	}

	return 0;
}

void close_db(struct modconfig *cfg) {
	mysql_close(cfg->dbo);
}

char *fetch_userinfo(struct modconfig *cfg, const char *username) {

	MYSQL_STMT *stmt;
        MYSQL_BIND param[1], result[1];
	my_ulonglong num_rows;
	my_bool is_null, error;
	int max_len_sql = 1024, res;
	unsigned long dbpwdlen;
	char sql[max_len_sql];
	char usrpwd[512];
	char *retval = NULL;

	sprintf(sql, "SELECT %s FROM %s WHERE %s = ?%s%s",
		cfg->pwdcolumn, cfg->usertable, cfg->useridcolumn,
		cfg->userwhere == NULL ? "" : " AND ",
		cfg->userwhere == NULL ? "" : cfg->userwhere
	);

	if(cfg->debug) {
		log_msg(LOG_INFO, "DEBUG: Fetching user with sql-query: %s", sql);
	}

	if((stmt = mysql_stmt_init(cfg->dbo)) == NULL) {
		log_msg(LOG_WARNING, "mysql_stmt_init() - Out of memory");
		return 0;
	}

	if(mysql_stmt_prepare(stmt, sql, strlen(sql))) {
		log_msg(LOG_WARNING, "mysql_stmt_prepare() failed: %s", mysql_stmt_error(stmt));
		return 0;
	}

	memset(param, 0, sizeof (param));
	memset(result, 0, sizeof(result));

	param[0].buffer_type = MYSQL_TYPE_STRING;
	param[0].buffer = (char *) username;
	param[0].buffer_length = strlen(username);
	param[0].is_null = 0;
	param[0].length = 0;

	result[0].buffer_type = MYSQL_TYPE_STRING;
	result[0].buffer = (char *) usrpwd;
	result[0].buffer_length = sizeof(usrpwd);
	result[0].is_null = &is_null;
	result[0].error = &error;
	result[0].length = &dbpwdlen;

	// Bind the parameters
	if(mysql_stmt_bind_param(stmt, param) != 0) {
		log_msg(LOG_WARNING, "mysql_stmt_bind_param() failed: %s", mysql_stmt_error(stmt));
		return NULL;
	}

	// Bind the result
	if(mysql_stmt_bind_result(stmt, result) != 0) {
		log_msg(LOG_WARNING, "mysql_stmt_bind_result() failed: %s", mysql_stmt_error(stmt));
		return NULL;
	}

	if(mysql_stmt_execute(stmt)) {
		log_msg(LOG_WARNING, "mysql_stmt_execute() failed: %s", mysql_stmt_error(stmt));
		return NULL;
	}

	if(mysql_stmt_store_result(stmt) != 0) {
		log_msg(LOG_WARNING, "mysql_stmt_store_result() failed: %s", mysql_stmt_error(stmt));
		return NULL;
	}

	num_rows = mysql_stmt_num_rows(stmt);
	if(num_rows == 0) {
		log_msg(LOG_INFO, "Found no users matching userid '%s' in table '%s'", username, cfg->usertable);
		goto cleanup;
	} else if(num_rows > 1) {
		log_msg(LOG_WARNING, "ERROR: Found %d users matching userid '%s' (Expected only 1)",
			num_rows, username);
		goto cleanup;
	}

	res = mysql_stmt_fetch(stmt);
	if(res == 1) {
		log_msg(LOG_WARNING, "ERROR: mysql_stmt_fetch() failed: %s", mysql_stmt_error(stmt));
		goto cleanup;
	}

	cleanup:

	mysql_stmt_free_result(stmt);

	if(mysql_stmt_close(stmt)) {
		log_msg(LOG_WARNING, "mysql_stmt_close() failed: %s", mysql_stmt_error(stmt));
	}

	retval = strdup(usrpwd);
	return retval;
}
