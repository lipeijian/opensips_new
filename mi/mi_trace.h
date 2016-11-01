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
#ifndef _mi_trace_h
#define _mi_trace_h

#include "../trace_api.h"

extern trace_proto_t* trace_api;

void try_load_trace_api(void);
int trace_mi_message(union sockaddr_union* src, union sockaddr_union* dst,
		str* body, trace_dest trace_dst);

#endif
