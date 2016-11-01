/*
 * Copyright (C) 2013 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * -------
 * 2013-02-28: Created (Liviu)
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>

#include "../../mem/shm_mem.h"
#include "../../async.h"
#include "rest_methods.h"
#include "rest_cb.h"
#include "../siptrace/siptrace.h"
#include "../../ip_addr.h"
#include "../../resolve.h"

#define TRACE_BUF_MAX_SIZE 1024

static char req_buf[TRACE_BUF_MAX_SIZE];
static char repl_buf[TRACE_BUF_MAX_SIZE];
static rest_trace_param_t trace_param;

extern siptrace_api_t siptrace_api;
extern trace_type_id_t rest_type_id;
extern int rest_message_id;


static inline int extract_host(str* url, char** host, unsigned int* port);
static inline int trace_enabled(void);
static int trace_rest_message(str* host, str* dest, str* body, str* correlation_id);

static char print_buff[MAX_CONTENT_TYPE_LEN];

CURLM *multi_handle;

/* additional HTTP headers for the next request */
static struct curl_slist *header_list = NULL;

/* simultaneous ongoing transfers within this process */
static int transfers;
static int read_fds[FD_SETSIZE];

/* libcurl's reported running handles */
static int running_handles;

static long sleep_on_bad_timeout = 50; /* ms */

#define clean_header_list \
	do { \
		if (header_list) { \
			curl_slist_free_all(header_list); \
			header_list = NULL; \
		} \
	} while (0)

#define w_curl_easy_setopt(h, opt, value) \
	do { \
		rc = curl_easy_setopt(h, opt, value); \
		if (rc != CURLE_OK) { \
			LM_ERR("curl_easy_setopt(%d): (%s)\n", opt, curl_easy_strerror(rc)); \
			clean_header_list; \
			goto cleanup; \
		} \
	} while (0)


int trace_rest_request_cb(CURL *handle, curl_infotype type, char *data, size_t size, void *userptr)
{
	int body_len;
	str url_s, buf;

	char* url;
	rest_trace_param_t* rest_p = userptr;


	if ( type == CURLINFO_HEADER_IN || type == CURLINFO_DATA_IN) {
		if (rest_p->reply_str.len + size > TRACE_BUF_MAX_SIZE) {
			LM_WARN("static buffer too small! increase TRACE_BUF_MAX_SIZE!\n");
			/* it's ok; save what we've got */
			return CURLE_OK;
		}

		memcpy(rest_p->reply_str.s+rest_p->reply_str.len, data, size);
		rest_p->reply_str.len += size;
	}

	if ( type != CURLINFO_HEADER_OUT)
		return CURLE_OK;

	if (curl_easy_getinfo(handle, CURLINFO_EFFECTIVE_URL, &url) != CURLE_OK) {
		LM_ERR("failed to fetch URL!\n");
		/* continue normally */
		return CURLE_OK;
	}

	url_s.s = url;
	url_s.len = strlen(url);


	if (rest_p->body) {
		body_len = strlen(rest_p->body);
		buf.len = size + body_len;


		if (TRACE_BUF_MAX_SIZE < buf.len) {
			LM_WARN("static buffer too small! increase TRACE_BUF_MAX_SIZE!\n");
			buf.s = data;
			buf.len = size;
		} else {
			buf.s = req_buf;
			memcpy(buf.s, data, size);
			memcpy(buf.s+size, rest_p->body, body_len);
		}
	} else {
		buf.s = data;
		buf.len = size;
	}

	if (trace_rest_message(NULL, &url_s, &buf, &rest_p->callid) < 0) {
		/* no need to exit; curl worked ok, tracing failed */
		LM_ERR("failed to trage rest request!\n");
	}

	return CURLE_OK;
}



static inline char is_new_transfer(int fd)
{
	int it;

	for (it = 0; it < transfers; it++) {
		if (fd == read_fds[it])
			return 0;
	}

	return 1;
}

static inline void add_transfer(int fd)
{
	read_fds[transfers++] = fd;
}

static inline char del_transfer(int fd)
{
	int it;

	LM_DBG("del fd %d\n", fd);

	for (it = 0; it < transfers; it++) {
		if (fd == read_fds[it]) {
			transfers--;
			for (; it < transfers; it++)
				read_fds[it] = read_fds[it + 1];

			return 0;
		}
	}

	return -1;
}

/**
 * start_async_http_req - performs an HTTP request, stores results in pvars
 *		- TCP connect phase is synchronous, due to libcurl limitations
 *		- TCP read phase is asynchronous, thanks to the libcurl multi interface
 *
 * @msg:		sip message struct
 * @method:		HTTP verb
 * @url:		HTTP URL to be queried
 * @req_body:	Body of the request (NULL if not needed)
 * @req_ctype:	Value for the "Content-Type: " header of the request (same as ^)
 * @out_handle: CURL easy handle used to perform the transfer
 * @body:	    reply body; gradually reallocated as data arrives
 * @ctype:	    will eventually hold the last "Content-Type" header of the reply
 */
int start_async_http_req(struct sip_msg *msg, enum rest_client_method method,
					     char *url, char *req_body, char *req_ctype,
					     CURL **out_handle, str *body, str *ctype,
						 rest_trace_param_t** rest_tparam_p)
{
	CURL *handle;
	CURLcode rc;
	CURLMcode mrc;
	fd_set rset, wset, eset;
	int max_fd, fd;
	long busy_wait, timeout;
	long retry_time;
	int msgs_in_queue;
	CURLMsg *cmsg;

	rest_trace_param_t* rest_tparam;

	if (transfers == FD_SETSIZE) {
		LM_ERR("too many ongoing tranfers: %d\n", FD_SETSIZE);
		clean_header_list;
		return ASYNC_NO_IO;
	}

	handle = curl_easy_init();
	if (!handle) {
		LM_ERR("Init curl handle failed!\n");
		clean_header_list;
		return ASYNC_NO_IO;
	}

	w_curl_easy_setopt(handle, CURLOPT_URL, url);

	if (trace_enabled()) {
		if (method == REST_CLIENT_POST) {
			/* for post we need both request and reply buffers because we need
			 * to concatenate the body with the headers for the request */
			rest_tparam = pkg_malloc(sizeof(rest_trace_param_t)
													+ 2 * TRACE_BUF_MAX_SIZE);
			rest_tparam->body = (char *)(rest_tparam+1);
			rest_tparam->reply_str.s = rest_tparam->body + TRACE_BUF_MAX_SIZE;
		} else {
			rest_tparam = pkg_malloc(sizeof(rest_trace_param_t)
													+ TRACE_BUF_MAX_SIZE);
			rest_tparam->reply_str.s = rest_tparam->body + TRACE_BUF_MAX_SIZE;
		}

		if (method == REST_CLIENT_POST)
			rest_tparam->body = req_body;
		else
			rest_tparam->body = NULL;

		rest_tparam->callid = msg->callid->body;

		rest_tparam->reply_str.s = repl_buf;
		rest_tparam->reply_str.len = 0;

		w_curl_easy_setopt(handle, CURLOPT_DEBUGDATA, rest_tparam);
		w_curl_easy_setopt(handle, CURLOPT_DEBUGFUNCTION, trace_rest_request_cb);
	}

	switch (method) {
	case REST_CLIENT_POST:
		w_curl_easy_setopt(handle, CURLOPT_POST, 1);
		w_curl_easy_setopt(handle, CURLOPT_POSTFIELDS, req_body);

		if (req_ctype) {
			sprintf(print_buff, "Content-Type: %s", req_ctype);
			header_list = curl_slist_append(header_list, print_buff);
			w_curl_easy_setopt(handle, CURLOPT_HTTPHEADER, header_list);
		}
		break;
	case REST_CLIENT_GET:
		break;

	default:
		LM_ERR("Unsupported rest_client_method: %d, defaulting to GET\n", method);
	}

	if (header_list)
		w_curl_easy_setopt(handle, CURLOPT_HTTPHEADER, header_list);

	w_curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, connection_timeout);
	w_curl_easy_setopt(handle, CURLOPT_TIMEOUT, curl_timeout);

	w_curl_easy_setopt(handle, CURLOPT_VERBOSE, 1);
	w_curl_easy_setopt(handle, CURLOPT_FAILONERROR, 1);
	w_curl_easy_setopt(handle, CURLOPT_STDERR, stdout);

	w_curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_func);
	w_curl_easy_setopt(handle, CURLOPT_WRITEDATA, body);

	if (ctype) {
		w_curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, header_func);
		w_curl_easy_setopt(handle, CURLOPT_HEADERDATA, ctype);
	}

	if (ssl_capath)
		w_curl_easy_setopt(handle, CURLOPT_CAPATH, ssl_capath);

	if (!ssl_verifypeer)
		w_curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0L);

	if (!ssl_verifyhost)
		w_curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0L);

	curl_multi_add_handle(multi_handle, handle);

	timeout = connection_timeout_ms;
	/* obtain a read fd in "connection_timeout" seconds at worst */
	for (timeout = connection_timeout_ms; timeout > 0; timeout -= busy_wait) {
		mrc = curl_multi_perform(multi_handle, &running_handles);
		if (mrc != CURLM_OK) {
			LM_ERR("curl_multi_perform: %s\n", curl_multi_strerror(mrc));
			goto error;
		}

		mrc = curl_multi_timeout(multi_handle, &retry_time);
		if (mrc != CURLM_OK) {
			LM_ERR("curl_multi_timeout: %s\n", curl_multi_strerror(mrc));
			goto error;
		}

		LM_DBG("libcurl TCP connect: we should wait up to %ldms "
		       "(timeout=%ldms)!\n", retry_time, connection_timeout_ms);

		if (retry_time == -1) {
			LM_INFO("curl_multi_timeout() returned -1, pausing %ldms...\n",
					sleep_on_bad_timeout);
			busy_wait = sleep_on_bad_timeout;
			goto busy_wait;
		}

		/* transfer may have already been completed!! */
		while ((cmsg = curl_multi_info_read(multi_handle, &msgs_in_queue))) {
			if (cmsg->easy_handle == handle && cmsg->msg == CURLMSG_DONE) {
				LM_DBG("done, no need for async!\n");

				clean_header_list;
				*out_handle = handle;
				return ASYNC_SYNC;
			}
		}

		FD_ZERO(&rset);
		mrc = curl_multi_fdset(multi_handle, &rset, &wset, &eset, &max_fd);
		if (mrc != CURLM_OK) {
			LM_ERR("curl_multi_fdset: %s\n", curl_multi_strerror(mrc));
			goto error;
		}

		if (max_fd != -1) {
			for (fd = 0; fd <= max_fd; fd++) {
				if (FD_ISSET(fd, &rset)) {

					LM_DBG("ongoing transfer on fd %d\n", fd);
					if (is_new_transfer(fd)) {
						LM_DBG(">>> add fd %d to ongoing transfers\n", fd);
						add_transfer(fd);
						goto success;
					}
				}
			}
		}

		/*
		 * from curl_multi_timeout() docs: "retry_time" milliseconds "at most!"
		 *         -> we'll wait only 1/10 of this time before retrying
		 */
		retry_time = retry_time / 10 + 1;
		busy_wait = retry_time < timeout ? retry_time : timeout;

busy_wait:
		/* libcurl seems to be stuck in internal operations (TCP connect?) */
		LM_DBG("busy waiting %ldms ...\n", busy_wait);
		usleep(1000UL * busy_wait);
	}

	LM_ERR("timeout while connecting to '%s' (%ld sec)\n", url, connection_timeout);
	goto error;

success:
	clean_header_list;
	*out_handle = handle;
	*rest_tparam_p = rest_tparam;
	return fd;

error:
	mrc = curl_multi_remove_handle(multi_handle, handle);
	if (mrc != CURLM_OK)
		LM_ERR("curl_multi_remove_handle: %s\n", curl_multi_strerror(mrc));


cleanup:
	pkg_free(rest_tparam);
	clean_header_list;
	curl_easy_cleanup(handle);
	return ASYNC_NO_IO;
}

enum async_ret_code resume_async_http_req(int fd, struct sip_msg *msg, void *_param)
{
	CURLcode rc;
	CURLMcode mrc;
	rest_async_param *param = (rest_async_param *)_param;
	int running, max_fd;
	long http_rc;
	fd_set rset, wset, eset;
	pv_value_t val;

	char* url;
	str url_s;

	mrc = curl_multi_perform(multi_handle, &running);
	if (mrc != CURLM_OK) {
		LM_ERR("curl_multi_perform: %s\n", curl_multi_strerror(mrc));
		return -1;
	}
	LM_DBG("running handles: %d\n", running);

	if (running == running_handles) {
		async_status = ASYNC_CONTINUE;
		return 1;
	}

	if (running > running_handles) {
		LM_BUG("incremented handles!!");
		/* default async status is DONE */
		return -1;
	}

	running_handles = running;

	FD_ZERO(&rset);
	mrc = curl_multi_fdset(multi_handle, &rset, &wset, &eset, &max_fd);
	if (mrc != CURLM_OK) {
		LM_ERR("curl_multi_fdset: %s\n", curl_multi_strerror(mrc));
		/* default async status is DONE */
		return -1;
	}

	if (max_fd == -1) {
		if (running_handles != 0) {
			LM_BUG("running_handles == %d", running_handles);
			abort();
			/* default async status is DONE */
			return -1;
		}

		if (FD_ISSET(fd, &rset)) {
			LM_BUG("fd %d is still in rset!", fd);
			abort();
			/* default async status is DONE */
			return -1;
		}

	} else if (FD_ISSET(fd, &rset)) {
		LM_DBG("fd %d still transferring...\n", fd);
		async_status = ASYNC_CONTINUE;
		return 1;
	}

	if (del_transfer(fd) != 0) {
		LM_BUG("failed to delete fd %d", fd);
		abort();
		/* default async status is DONE */
		return -1;
	}

	if (curl_easy_getinfo(param->handle, CURLINFO_EFFECTIVE_URL, &url) != CURLE_OK) {
		LM_ERR("failed to fetch URL!\n");
		/* continue normally */
		return -1;
	}


	mrc = curl_multi_remove_handle(multi_handle, param->handle);
	if (mrc != CURLM_OK) {
		LM_ERR("curl_multi_remove_handle: %s\n", curl_multi_strerror(mrc));
		/* default async status is DONE */
		return -1;
	}

	val.flags = PV_VAL_STR;
	val.rs = param->body;
	if (pv_set_value(msg, param->body_pv, 0, &val) != 0)
		LM_ERR("failed to set output body pv\n");

	if (param->ctype_pv) {
		val.rs = param->ctype;
		if (pv_set_value(msg, param->ctype_pv, 0, &val) != 0)
			LM_ERR("failed to set output ctype pv\n");
	}

	if (param->code_pv) {
		rc = curl_easy_getinfo(param->handle, CURLINFO_RESPONSE_CODE, &http_rc);
		if (rc != CURLE_OK) {
			LM_ERR("curl_easy_getinfo: %s\n", curl_easy_strerror(rc));
			http_rc = 0;
		}

		LM_DBG("Last response code: %ld\n", http_rc);

		val.flags = PV_VAL_INT|PV_TYPE_INT;
		val.ri = (int)http_rc;
		if (pv_set_value(msg, param->code_pv, 0, &val) != 0)
			LM_ERR("failed to set output code pv\n");
	}

	url_s.s = url;
	url_s.len = strlen(url);

	/* trace the reply */
	if (trace_rest_message( &url_s, NULL,
				&param->rest_tparam->reply_str, &msg->callid->body) < 0)
		LM_ERR("Failed to trace rest get reply!\n");

	pkg_free(param->rest_tparam);
	pkg_free(param->body.s);
	if (param->ctype_pv && param->ctype.s)
		pkg_free(param->ctype.s);
	curl_easy_cleanup(param->handle);
	pkg_free(param);

	/* default async status is DONE */
	return 1;
}

/**
 * rest_get_method - performs an HTTP GET request, stores results in pvars
 * @msg:		sip message struct
 * @url:		HTTP URL to be queried
 * @body_pv:	pseudo var which will hold the result body
 * @ctype_pv:	pvar which will hold the body encoding method
 * @code_pv:	pvar to hold the HTTP return code
 */
int rest_get_method(struct sip_msg *msg, char *url,
                    pv_spec_p body_pv, pv_spec_p ctype_pv, pv_spec_p code_pv)
{
	CURLcode rc;
	CURL *handle = NULL;
	long http_rc;
	pv_value_t pv_val;
	str st = { 0, 0 };
	str body = { NULL, 0 }, tbody;

	str url_s =  {url, strlen(url)};

	handle = curl_easy_init();
	if (!handle) {
		LM_ERR("Init curl handle failed!\n");
		clean_header_list;
		return -1;
	}

	/* Trace the request */
	if (trace_enabled()) {
		trace_param.body = NULL;
		trace_param.callid = msg->callid->body;

		trace_param.reply_str.s = repl_buf;
		trace_param.reply_str.len = 0;

		w_curl_easy_setopt(handle, CURLOPT_DEBUGDATA, &trace_param);
		w_curl_easy_setopt(handle, CURLOPT_DEBUGFUNCTION, trace_rest_request_cb);
	}

	if (header_list)
		w_curl_easy_setopt(handle, CURLOPT_HTTPHEADER, header_list);

	w_curl_easy_setopt(handle, CURLOPT_URL, url);

	w_curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, connection_timeout);
	w_curl_easy_setopt(handle, CURLOPT_TIMEOUT, curl_timeout);

	w_curl_easy_setopt(handle, CURLOPT_VERBOSE, 1);
	w_curl_easy_setopt(handle, CURLOPT_FAILONERROR, 1);
	w_curl_easy_setopt(handle, CURLOPT_STDERR, stdout);

	w_curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_func);
	w_curl_easy_setopt(handle, CURLOPT_WRITEDATA, &body);

	w_curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, header_func);
	w_curl_easy_setopt(handle, CURLOPT_HEADERDATA, &st);

	if (ssl_capath)
		w_curl_easy_setopt(handle, CURLOPT_CAPATH, ssl_capath);

	if (!ssl_verifypeer)
		w_curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0L);

	if (!ssl_verifyhost)
		w_curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0L);

	rc = curl_easy_perform(handle);
	clean_header_list;

	if (code_pv) {
		curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &http_rc);
		LM_DBG("Last response code: %ld\n", http_rc);

		pv_val.flags = PV_VAL_INT|PV_TYPE_INT;
		pv_val.ri = (int)http_rc;

		if (pv_set_value(msg, code_pv, 0, &pv_val) != 0) {
			LM_ERR("Set code pv value failed!\n");
			goto cleanup;
		}
	}

	if (rc != CURLE_OK) {
		LM_ERR("curl_easy_perform: %s\n", curl_easy_strerror(rc));
		goto cleanup;
	}

	tbody = body;
	trim(&tbody);

	pv_val.flags = PV_VAL_STR;
	pv_val.rs = tbody;

	if (pv_set_value(msg, body_pv, 0, &pv_val) != 0) {
		LM_ERR("Set body pv value failed!\n");
		goto cleanup;
	}

	/* trace the reply */
	if (trace_rest_message( &url_s, NULL, &trace_param.reply_str, &msg->callid->body) < 0)
		LM_ERR("Failed to trace rest get reply!\n");

	if (body.s) {
		pkg_free(body.s);
	}

	if (ctype_pv) {
		pv_val.rs = st;

		if (pv_set_value(msg, ctype_pv, 0, &pv_val) != 0) {
			LM_ERR("Set content type pv value failed!\n");
			goto cleanup;
		}

		if (st.s)
			pkg_free(st.s);
	}

	curl_easy_cleanup(handle);
	return 1;

cleanup:
	curl_easy_cleanup(handle);
	return -1;
}

/**
 * rest_post_method - performs an HTTP POST request, stores results in pvars
 * @msg:		sip message struct
 * @url:		HTTP URL to be queried
 * @ctype:		Value for the "Content-Type: " header of the request
 * @body:		Body of the request
 * @body_pv:	pseudo var which will hold the result body
 * @ctype_pv:	pvar which will hold the result content type
 * @code_pv:	pvar to hold the HTTP return code
 */
int rest_post_method(struct sip_msg *msg, char *url, char *body, char *ctype,
                     pv_spec_p body_pv, pv_spec_p ctype_pv, pv_spec_p code_pv)
{
	CURLcode rc;
	CURL *handle = NULL;
	long http_rc;
	str st = { 0, 0 };
	str res_body = { NULL, 0 }, tbody;
	pv_value_t pv_val;
	str url_s =  {url, strlen(url)};

	handle = curl_easy_init();
	if (!handle) {
		LM_ERR("Init curl handle failed!\n");
		clean_header_list;
		return -1;
	}

	if (ctype) {
		sprintf(print_buff, "Content-Type: %s", ctype);
		header_list = curl_slist_append(header_list, print_buff);
	}

	if (header_list)
		w_curl_easy_setopt(handle, CURLOPT_HTTPHEADER, header_list);

	if (trace_enabled()) {
		trace_param.body = body;
		trace_param.callid = msg->callid->body;

		trace_param.reply_str.s = repl_buf;
		trace_param.reply_str.len = 0;

		w_curl_easy_setopt(handle, CURLOPT_DEBUGDATA, &trace_param);
		w_curl_easy_setopt(handle, CURLOPT_DEBUGFUNCTION, trace_rest_request_cb);
	}

	w_curl_easy_setopt(handle, CURLOPT_URL, url);

	w_curl_easy_setopt(handle, CURLOPT_POST, 1);
	w_curl_easy_setopt(handle, CURLOPT_POSTFIELDS, body);

	w_curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, connection_timeout);
	w_curl_easy_setopt(handle, CURLOPT_TIMEOUT, curl_timeout);

	w_curl_easy_setopt(handle, CURLOPT_VERBOSE, 1);
	w_curl_easy_setopt(handle, CURLOPT_STDERR, stdout);
	w_curl_easy_setopt(handle, CURLOPT_FAILONERROR, 1);

	w_curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_func);
	w_curl_easy_setopt(handle, CURLOPT_WRITEDATA, &res_body);

	w_curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, header_func);
	w_curl_easy_setopt(handle, CURLOPT_HEADERDATA, &st);

	if (ssl_capath)
		w_curl_easy_setopt(handle, CURLOPT_CAPATH, ssl_capath);

	if (!ssl_verifypeer)
		w_curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0L);

	if (!ssl_verifyhost)
		w_curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0L);

	rc = curl_easy_perform(handle);
	clean_header_list;

	if (code_pv) {
		curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &http_rc);
		LM_DBG("Last response code: %ld\n", http_rc);

		pv_val.flags = PV_VAL_INT|PV_TYPE_INT;
		pv_val.ri = (int)http_rc;

		if (pv_set_value(msg, code_pv, 0, &pv_val) != 0) {
			LM_ERR("Set code pv value failed!\n");
			goto cleanup;
		}
	}

	if (rc != CURLE_OK) {
		LM_ERR("curl_easy_perform: %s\n", curl_easy_strerror(rc));
		goto cleanup;
	}

	tbody = res_body;
	trim(&tbody);

	pv_val.flags = PV_VAL_STR;
	pv_val.rs = tbody;

	if (pv_set_value(msg, body_pv, 0, &pv_val) != 0) {
		LM_ERR("Set body pv value failed!\n");
		goto cleanup;
	}

	/* trace the reply */
	if (trace_rest_message( &url_s, NULL, &trace_param.reply_str, &msg->callid->body) < 0)
		LM_ERR("Failed to trace rest get reply!\n");

	if (res_body.s) {
		pkg_free(res_body.s);
	}

	if (ctype_pv) {
		pv_val.rs = st;

		if (pv_set_value(msg, ctype_pv, 0, &pv_val) != 0) {
			LM_ERR("Set content type pv value failed!\n");
			goto cleanup;
		}

		if (st.s)
			pkg_free(st.s);
	}

	curl_easy_cleanup(handle);
	return 1;

cleanup:
	curl_easy_cleanup(handle);
	return -1;
}

/**
 * rest_append_hf - add a custom HTTP header before a rest call
 * @msg:		sip message struct
 * @hfv:		HTTP header field and value
 */
int rest_append_hf_method(struct sip_msg *msg, str *hfv)
{
	char buf[MAX_HEADER_FIELD_LEN];

	if (hfv->len > MAX_HEADER_FIELD_LEN) {
		LM_ERR("header field buffer too small\n");
		return -1;
	}

	/* TODO: header validation */

	/* append the header to the global list */
	strncpy(buf, hfv->s, hfv->len);
	header_list = curl_slist_append(header_list, buf);

	return 1;
}

static inline int extract_host(str* url, char** host, unsigned int* port)
{
	unsigned int default_port;;

	static const int http_port = 80;
	static const int https_port = 443;

	static char host_buf[MAX_HOST_LENGTH];
	static const char port_delim = ':';
	static const char host_delim = '/';

	static const str http_id_s = str_init("http://");
	static const str https_id_s = str_init("https://");

	str* url_cpy = url;
	str port_s;

	char* host_end = NULL;
	char* port_start = NULL;


	if (url == NULL || host == NULL || port == NULL) {
		LM_ERR("null parameters!\n");
		return -1;
	}

	if (url->len > http_id_s.len) {
		if(!strncmp(url->s, http_id_s.s, http_id_s.len)) {
			url_cpy->s = url->s + http_id_s.len;
			url_cpy->len = url->len - http_id_s.len;
			default_port = http_port;
		} else if (!strncmp(url->s, https_id_s.s, https_id_s.len)) {
			url_cpy->s = url->s + https_id_s.len;
			url_cpy->len = url->len - https_id_s.len;
			default_port = https_port;
		}
	}

	/* now try extracting the host and the port(if exists) */
	host_end = q_memchr(url_cpy->s, host_delim, url_cpy->len);
	port_start = q_memchr(url_cpy->s, port_delim, url_cpy->len);

	if (port_start == NULL) { /* job done */
		/* format: [http[s]://]<host>[/] */
		if (host_end == NULL)
			memcpy(host_buf, url_cpy->s, url_cpy->len);
		else
			memcpy(host_buf, url_cpy->s, host_end - url_cpy->s);

		host_buf[url_cpy->len] = '\0';

		*port = default_port;
	} else {
		/* format: [http[s]://]<host>:<port>[/] */
		/* parse the port; get it's number */
		if (host_end && port_start > host_end) {
			/* this does not delimit port; it's after host delimiter */
			port_start = NULL;
		}

		if (port_start) {
			memcpy(host_buf, url_cpy->s, port_start - url_cpy->s);
			host_buf[port_start-url_cpy->s] = '\0';

			port_s.s = port_start+1;
			if (host_end)
				port_s.len = (int)(unsigned long)(host_end - (port_s.s - url_cpy->s));
			else
				port_s.len = url_cpy->len - (port_s.s - url_cpy->s);


			if (str2int( &port_s, port) < 0) {
				LM_ERR("invalid port <%.*s>!\n", port_s.len, port_s.s);
				return -1;
			}
		} else {
			memcpy(host_buf, url_cpy->s, host_end - url_cpy->s);
			host_buf[host_end-url_cpy->s] = '\0';

			*port = default_port;
		}
	}

	*host = host_buf;

	return 0;
}

/*
 * FIXME only IPv4
 */
static inline unsigned long fix_host(char* host)
{
	str host_s = str_init(host);

	struct ip_addr* addr;
	struct addrinfo *res;

	if ((addr=str2ip(&host_s))==NULL) {
		if (getaddrinfo(host, NULL, NULL, &res) < 0) {
			LM_ERR("Invalid host <%s>!\n", host);
			/* ip 0.0.0.0 will be considered an error */
			return 0;
		}

		return ((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;
	}

	return addr->u.addrl[0];
}

static inline int trace_enabled(void)
{
	/* no need to check trace_api functions since they are loaded at mod_init */
	if (siptrace_api.trace_api == NULL) {
		LM_DBG("siptrace api not loaded! aborting trace...\n");
		return 0;
	}

	if (siptrace_api.is_id_traced(rest_type_id) == 0) {
		LM_DBG("Rest module not traced! aborting trace...\n");
		return 0;
	}

	return 1;
}

static int trace_rest_message(str* host, str* dest, str* body, str* correlation_id)
{
	int siptrace_id_hash=0;
	const int proto = IPPROTO_TCP;

	trace_dest send_dest, old_dest=NULL;
	trace_message trace_msg;

	union sockaddr_union to_su, from_su;

	char* host_addr;
	unsigned int port;

	/* no need to check trace_api functions since they are loaded at mod_init */
	if (siptrace_api.trace_api == NULL) {
		LM_DBG("siptrace api not loaded! aborting trace...\n");
		return 0;
	}

	if ((siptrace_id_hash=siptrace_api.is_id_traced(rest_type_id)) == 0) {
		LM_DBG("Rest module not traced! aborting trace...\n");
		return 0;
	}

	/* FIXME no IPv6 */
	if (host) {
		if (extract_host(host, &host_addr,&port) < 0){
			LM_ERR("failed to extract host and port from <%.*s>!\n",
					host->len, host->s);
			return -1;
		}

		from_su.sin.sin_addr.s_addr = fix_host(host_addr);
		if (from_su.sin.sin_addr.s_addr == 0) {
			LM_ERR("invalid address <%s>!\n", host_addr);
			return -1;
		}

		from_su.sin.sin_port = port;
	} else {
		from_su.sin.sin_addr.s_addr = TRACE_INADDR_LOOPBACK;
		from_su.sin.sin_port = 0;
	}

	from_su.sin.sin_family = AF_INET;

	/* FIXME no IPv6 */
	if (dest) {
		if (extract_host(dest, &host_addr,&port) < 0){
			LM_ERR("failed to extract host and port from <%.*s>!\n",
					host->len, host->s);
			return -1;
		}

		to_su.sin.sin_addr.s_addr = fix_host(host_addr);
		if (to_su.sin.sin_addr.s_addr == 0) {
			LM_ERR("invalid address <%s>!\n", host_addr);
			return -1;
		}

		to_su.sin.sin_port = port;
	} else {
		to_su.sin.sin_addr.s_addr = TRACE_INADDR_LOOPBACK;
		to_su.sin.sin_port = 0;
	}

	to_su.sin.sin_family = AF_INET;

	while((send_dest=siptrace_api.get_next_destination(old_dest, siptrace_id_hash))) {
		trace_msg = siptrace_api.trace_api->create_trace_message(&from_su, &to_su,
				proto, body, rest_message_id, send_dest);
		if (trace_msg == NULL) {
			LM_ERR("failed to create trace message!\n");
			return -1;
		}

		if (correlation_id &&
			siptrace_api.trace_api->add_trace_data(trace_msg, correlation_id->s,
			correlation_id->len, TRACE_TYPE_STR, 0x0011/* correlation id*/, 0) < 0) {
			LM_ERR("failed to add correlation id to the packet!\n");
			return -1;
		}

		if (siptrace_api.trace_api->send_message(trace_msg, send_dest, NULL) < 0) {
			LM_ERR("failed to send trace message!\n");
			return -1;
		}

		siptrace_api.trace_api->free_message(trace_msg);

		old_dest=send_dest;
	}


	return 0;
}
