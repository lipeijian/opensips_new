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
//#include "../modules/proto_hep/hep.h"

#include "mi_trace.h"

#define TRACE_API_MODULE "proto_hep"
/* FIXME this index should be taken using a function or sth */
#define HEP_PROTO_TYPE_MI   0x057


trace_proto_t* trace_api=NULL;


void try_load_trace_api(void)
{
	trace_api = pkg_malloc(sizeof(trace_proto_t));
	if (trace_api == NULL)
		return;

	memset(trace_api, 0, sizeof(trace_proto_t));
	if (trace_prot_bind(TRACE_API_MODULE, trace_api) < 0) {
		LM_DBG("No tracing module used!\n");
	}
}


int trace_mi_message(union sockaddr_union* src, union sockaddr_union* dst,
		str* body, trace_dest trace_dst)
{
	/* FIXME is this the case for all mi impelementations?? */
	const int proto = IPPROTO_TCP;
	union sockaddr_union tmp, *to_su, *from_su;

	trace_message message;

	if (trace_api->create_trace_message == NULL ||
			trace_api->send_message == NULL) {
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

	message = trace_api->create_trace_message(from_su, to_su,
			proto, body, HEP_PROTO_TYPE_MI, trace_dst);
	if (message == NULL) {
		LM_ERR("failed to create trace message!\n");
		return -1;
	}

	if (trace_api->send_message(message, trace_dst, NULL) < 0) {
		LM_ERR("failed to send trace message!\n");
		return -1;
	}

	trace_api->free_message(message);

	return 0;
}


