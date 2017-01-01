/*****************************************************************
 * File: config.c                            Part of pam_mariadb *
 *                                                               *
 * Copyright (C) 2017 Erik Lundin. All Rights Reserved.          *
 *                                                               *
 * This software may be modified and distributed under the terms *
 * of the MIT license.  See the LICENSE file for details.        *
 *                                                               *
 *****************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "config.h"
#include "utils.h"

const char *pwd_algo[] = {
	"sha512",
	"sha256",
	"sha1",
	"md5",
	"\n"
};

const char *pwd_styles[] = {
	"hex",
	"curlyb64",
	"\n"
};

const char *no_yes[] = {
	"no",
	"yes",
	"\n"
};

void log_msg(int prio, const char *format, ...) {

	va_list args;
	va_start(args, format);

	char *errstr = (char *)calloc(1024, sizeof(char));
	vsnprintf(errstr, 1024, format, args);
	syslog(LOG_AUTHPRIV | prio, "%s%s", PAM_LOG_PREFIX, errstr);

	free(errstr);
	va_end(args);
}

void init_config(struct modconfig *cfg) {

	cfg->debug = 0;
	cfg->dbo = NULL;
	cfg->dbserver = NULL;
	cfg->dbuser = NULL;
	cfg->dbpassword = NULL;
	cfg->dbname = NULL;
	cfg->pwdalgo = 0;
	cfg->pwdstyle = 0;
	cfg->useridcolumn = NULL;
	cfg->pwdcolumn = NULL;
	cfg->usertable = NULL;
	cfg->userwhere = NULL;
}

void free_config(struct modconfig *cfg) {

	if(cfg->dbserver != NULL)
		free(cfg->dbserver);
	if(cfg->dbuser != NULL)
		free(cfg->dbuser);
	if(cfg->dbpassword != NULL)
		free(cfg->dbpassword);
	if(cfg->dbname != NULL)
		free(cfg->dbname);
	if(cfg->useridcolumn != NULL)
		free(cfg->useridcolumn);
	if(cfg->pwdcolumn != NULL)
		free(cfg->pwdcolumn);
	if(cfg->usertable != NULL)
		free(cfg->usertable);
	if(cfg->userwhere != NULL)
		free(cfg->userwhere);

	free(cfg);
}

/* Print the contents of the configuration to the log file */
void log_config(struct modconfig *cfg) {

	log_msg(LOG_INFO, "config_file: %s", cfg->config_file);
	log_msg(LOG_INFO, "dbserver: %s", cfg->dbserver);
	log_msg(LOG_INFO, "dbuser: %s", cfg->dbuser);
	log_msg(LOG_INFO, "dbpassword: %s", cfg->dbpassword);
	log_msg(LOG_INFO, "dbname: %s", cfg->dbname);
	log_msg(LOG_INFO, "pwdalgo: %s", pwd_algo[cfg->pwdalgo]);
	log_msg(LOG_INFO, "pwdstyle: %s", pwd_styles[cfg->pwdstyle]);
	log_msg(LOG_INFO, "useridcolumn: %s", cfg->useridcolumn);
	log_msg(LOG_INFO, "pwdcolumn: %s", cfg->pwdcolumn);
	log_msg(LOG_INFO, "usertable: %s", cfg->usertable);
	log_msg(LOG_INFO, "userwhere: %s", cfg->userwhere);
}

/* Parse a settings row. Either from the file or from arguments */
int parse_settings_row(char *data, struct modconfig *cfg) {

	int i, start, len, val_len;
	int max_len_name = 24, max_len_value = 512;
	char *pos;
	char optname[max_len_name], value[max_len_value];

	// Remove any newlines
	i = strlen(data) - 1;
	while (data[i] == '\n' || data[i] == '\r')
		data[i--] = '\0';

	// Skip empty lines
	if(strlen(data) == 0)
		return 0;

	if((pos = strchr(data, '=')) == NULL) {
		log_msg(LOG_WARNING, "Invalid option '%s' (Missing =)", data);
		return 1;
	}

	start = pos - data + 1;
	if(start == 1) {
		log_msg(LOG_WARNING, "Invalid option '%s' (Cannot start with a =)", data);
		return 1;
	}

	if(start > max_len_name) {
		log_msg(LOG_WARNING, "Invalid option '%s' (Name to long. Max %d chars)", data, max_len_name);
		return 1;
	}

	strncpy(optname, data, start - 1);
	optname[start - 1] = '\0';

	// Read the value
	len = strlen(data);
	val_len = len - start;

	if(val_len == 0) {
		log_msg(LOG_WARNING, "Invalid option '%s' (No value)", data);
		return 1;
	}

	if(val_len > max_len_value) {
		log_msg(LOG_WARNING, "Invalid option '%s' (Value to long. Max %d chars)", optname, max_len_value);
		return 1;
	}

	strncpy(value, data + start, val_len);
	value[val_len] = '\0';

	if(strncmp("config_file", optname, 11) == 0) {
		cfg->config_file = strdup(value);
	} else if(strncmp("dbserver", optname, 8) == 0) {
		cfg->dbserver = strdup(value);
	} else if(strncmp("dbuser", optname, 6) == 0) {
		cfg->dbuser = strdup(value);
	} else if(strncmp("dbpassword", optname, 10) == 0) {
		cfg->dbpassword = strdup(value);
	} else if(strncmp("dbname", optname, 6) == 0) {
		cfg->dbname = strdup(value);
	} else if(strncmp("userwhere", optname, 5) == 0) {
		cfg->userwhere = strdup(value);
	} else if(strncmp("pwdalgo", optname, 8) == 0) {
		if((cfg->pwdalgo = search_array(value, pwd_algo)) == -1) {
			log_msg(LOG_WARNING, "Invalid pwdalgo '%s'", value);
			return 1;
		}
	} else if(strncmp("pwdstyle", optname, 8) == 0) {
		if((cfg->pwdstyle = search_array(value, pwd_styles)) == -1) {
			log_msg(LOG_WARNING, "Invalid pwdstyle '%s'", value);
			return 1;
		}
	} else if(strncmp("debug", optname, 5) == 0) {
		if((cfg->debug = search_array(value, no_yes)) == -1) {
			log_msg(LOG_WARNING, "Invalid value for debug '%s'", value);
			return 1;
		}
	} else {
		log_msg(LOG_WARNING, "Invalid option name '%s'", optname);
		return 1;
	}

	return 0;
}

struct modconfig *parse_settings(int argc, const char **argv) {

	struct modconfig *ret = NULL;
	FILE *fp;
	char line[1024];
	int i;

	CREATE(ret, struct modconfig, 1);
	init_config(ret);

	for (i = 0; i < argc; i++) {
		if(parse_settings_row((char *)argv[i], ret))
			return NULL;
	}

	// If we have a config file. Try to read it
	if(ret->config_file != NULL) {

		if(ret->debug) {
			log_msg(LOG_INFO, "DEBUG: Reading config file: %s\n", ret->config_file);
		}

		if((fp = fopen(ret->config_file, "r")) == NULL) {
			log_msg(LOG_WARNING, "Unable to read config file: %s", ret->config_file);
			return NULL;
		}

		while(fgets(line, sizeof(line), fp)) {
			if(parse_settings_row(line, ret)) {
				fclose(fp);
				return NULL;
			}
		}

		fclose(fp);
	}

	// Set default values
	if(ret->dbserver == NULL)
		ret->dbserver = strdup("localhost");
	if(ret->dbname == NULL)
		ret->dbname = strdup("userdb");
	if(ret->useridcolumn == NULL)
		ret->useridcolumn = strdup("userid");
	if(ret->pwdcolumn == NULL)
		ret->pwdcolumn = strdup("passwd");
	if(ret->usertable == NULL)
		ret->usertable = strdup("users");

	if(ret->debug)
		log_config(ret);

	return ret;
}

