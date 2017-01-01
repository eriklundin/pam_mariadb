/*****************************************************************
 * File: pam_mariadb.c                       Part of pam_mariadb *
 *                                                               *
 * Copyright (C) 2017 Erik Lundin. All Rights Reserved.          *
 *                                                               *
 * This software may be modified and distributed under the terms *
 * of the MIT license.  See the LICENSE file for details.        *
 *                                                               *
 *****************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>

#include <security/pam_modules.h>

#include <mysql/mysql.h>

#include "config.h"
#include "database.h"
#include "hash.h"
#include "utils.h"

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

static char password_prompt[] = "Password: ";

/* PAM entry point for session creation */
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {

	struct modconfig *config;

	if((config = parse_settings(argc, argv)) == NULL)
		return PAM_AUTHINFO_UNAVAIL;

	if(config->debug) {
		log_msg(LOG_INFO, "DEBUG: pam_sm_open_session() called");
	}

	return PAM_SUCCESS;
}

/* PAM entry point for session cleanup */
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {

	struct modconfig *config;

	if((config = parse_settings(argc, argv)) == NULL)
		return PAM_AUTHINFO_UNAVAIL;

	if(config->debug) {
		log_msg(LOG_INFO, "DEBUG: pam_sm_close_session() called");
	}

	return PAM_SUCCESS;
}

/* PAM entry point for accounting */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {

	struct modconfig *config;

	if((config = parse_settings(argc, argv)) == NULL)
		return PAM_AUTHINFO_UNAVAIL;

	if(config->debug) {
		log_msg(LOG_INFO, "DEBUG: pam_sm_acct_mgmt() called");
	}

	return PAM_IGNORE;
}

/* PAM entry point for setting user credentials */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	log_msg(LOG_WARNING, "pam_sm_setcred() called but is not implemented yet");
	return PAM_IGNORE;
}

/* PAM entry point for authentication verification */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {

	struct modconfig *config;
	int retval = PAM_SUCCESS, ret, len_dbhash;
	const char *username = NULL, *password = NULL;
	char *pwdhash = NULL, *dbhash = NULL, *tmpalgo = NULL;
	regex_t regex;
	regmatch_t match[2];

	const void *ptr;
	const struct pam_conv *conv;
	struct pam_message msg;
	const struct pam_message *msgp;
	struct pam_response *resp = NULL;

	// Get the username
	if((ret = pam_get_user(pamh, &username, NULL)) != PAM_SUCCESS) {
		log_msg(LOG_WARNING, "pam_get_user() returned %s", ret);
		return PAM_SYSTEM_ERR;
	}

	// Get the password
	if((ret = pam_get_item(pamh, PAM_CONV, &ptr)) != PAM_SUCCESS) {
		log_msg(LOG_WARNING, "pam_get_item() returned %d", ret);
		return PAM_SYSTEM_ERR;
	}

	conv = ptr;
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = password_prompt;
	msgp = &msg;

	if((ret = (*conv->conv)(1, &msgp, &resp, conv->appdata_ptr)) != PAM_SUCCESS) {
		return PAM_SYSTEM_ERR;
	}

	if(resp != NULL) {
		password = resp->resp;
		free(resp);
	}

	if((config = parse_settings(argc, argv)) == NULL)
		return PAM_AUTHINFO_UNAVAIL;

	if(config->debug) {
		log_msg(LOG_INFO, "DEBUG: pam_sm_authenticate() called");
	}

	// Get the hash from the database
	if(connect_db(config)) {
		// Connection to the database failed
		return PAM_AUTHINFO_UNAVAIL;
	}

	if((dbhash = fetch_userinfo(config, username)) == NULL) {
		return PAM_SYSTEM_ERR;
	}

	len_dbhash = strlen(dbhash);
	close_db(config);

	if(config->pwdstyle == PWDSTYLE_CURLYB64) {

		if(regcomp(&regex, "^\\{([a-z0-9]+)\\}", REG_EXTENDED) != 0) {
			log_msg(LOG_WARNING, "Unable to compile regex");
			return PAM_SYSTEM_ERR;
		}

		if(regexec(&regex, dbhash, 2, match, 0) == REG_NOMATCH) {
			log_msg(LOG_WARNING, "ERROR: Configured to read curlyb64 but hash for user '%s' was malformed",
				username);
			return PAM_AUTH_ERR;
		}

		regfree(&regex);

		// Save the algorithm so we can check if it's valid
		tmpalgo = (char *)calloc(match[1].rm_eo - match[1].rm_so + 1, sizeof(char));
		strncpy(tmpalgo, dbhash + match[1].rm_so, match[1].rm_eo - match[1].rm_so);
		tmpalgo[match[1].rm_eo - match[1].rm_so] = '\0';

		if((config->pwdalgo = search_array(tmpalgo, pwd_algo)) == -1) {
			log_msg(LOG_WARNING, "Invalid hash algorithm '%s' in curlyb64 hash on user '%s'", tmpalgo, username);
			return PAM_AUTH_ERR;
		}

	}


	// Calculate our own hash to compare
	pwdhash = hash_string(config, password);

	// Compare the hashes
	if(strncmp(dbhash, pwdhash, len_dbhash) == 0) {
		log_msg(LOG_INFO, "User '%s' successfully authenticated", username);
		retval = PAM_SUCCESS;
	} else {
		log_msg(LOG_INFO, "Invalid password for user '%s'", username);
		retval = PAM_AUTH_ERR;
	}

	if(dbhash != NULL)
		free(dbhash);
	if(pwdhash != NULL)
		free(pwdhash);

	return retval;
}

/* PAM entry point for authentication token (password) changes */
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	log_msg(LOG_INFO, "pam_sm_chauthtok() not implemented yet");
	return PAM_IGNORE;
}
