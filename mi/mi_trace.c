/*
 * Copyright (C) 2016 - OpenSIPS Foundation
 * Copyright (C) 2001-2003 FhG Fokus
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 * History:
 * -------
 *  2016-09-19  first version (Ionut Ionita)
 */
#include "../ut.h"

#include "mi_trace.h"

#define TRACE_API_MODULE "proto_hep"
#define MI_ID_S "mi"


trace_proto_t* mi_trace_api=NULL;
int mi_message_id;


void try_load_trace_api(void)
{
	mi_trace_api = pkg_malloc(sizeof(trace_proto_t));
	if (mi_trace_api == NULL)
		return;

	memset(mi_trace_api, 0, sizeof(trace_proto_t));
	if (trace_prot_bind(TRACE_API_MODULE, mi_trace_api) < 0) {
		LM_DBG("No tracing module used!\n");
		return;
	}

	mi_message_id = mi_trace_api->get_message_id(MI_ID_S);
}


int trace_mi_message(union sockaddr_union* src, union sockaddr_union* dst,
		str* body, trace_dest trace_dst)
{
	/* FIXME is this the case for all mi impelementations?? */
	const int proto = IPPROTO_TCP;
	union sockaddr_union tmp, *to_su, *from_su;

	trace_message message;

	if (mi_trace_api->create_trace_message == NULL ||
			mi_trace_api->send_message == NULL) {
		LM_DBG("trace api not loaded!\n");
		return 0;
	}


	if (src == NULL || dst == NULL) {
		tmp.sin.sin_addr.s_addr = TRACE_INADDR_LOOPBACK;
		tmp.sin.sin_port = 0;
		tmp.sin.sin_family = AF_INET;
	}

	/* FIXME src and/or dst port might be in htons form */
	if (src)
		from_su = src;
	else
		from_su = &tmp;

	if (dst)
		to_su = dst;
	else
		to_su = &tmp;

	message = mi_trace_api->create_trace_message(from_su, to_su,
			proto, body, mi_message_id, trace_dst);
	if (message == NULL) {
		LM_ERR("failed to create trace message!\n");
		return -1;
	}

	if (mi_trace_api->send_message(message, trace_dst, NULL) < 0) {
		LM_ERR("failed to send trace message!\n");
		return -1;
	}

	mi_trace_api->free_message(message);

	return 0;
}


