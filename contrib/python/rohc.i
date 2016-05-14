/*
 * Copyright 2015,2016 Didier Barvaux
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/**
 * @file    rohc.i
 * @brief   The python binding of the ROHC library
 * @author  Didier Barvaux <didier@barvaux.org>
 */

%module rohc
%{
#include "rohc/rohc_packets.h"
#include "rohc/rohc_time.h"
#include "rohc/rohc_buf.h"
#include "rohc/rohc.h"
#include "rohc/rohc_traces.h"
#include "rohc/rohc_comp.h"
#include "rohc/rohc_decomp.h"

#include "rohc_helpers2.h"
#include "rohc_helpers.h"
%}

#define __attribute__(x)
#define ROHC_DEPRECATED(x)

%include "rohc/rohc_packets.h"

%include "rohc/rohc_time.h"
%extend rohc_ts
{
   rohc_ts(unsigned int sec, unsigned int nsec)
   {
      struct rohc_ts *ts;
      ts = (struct rohc_ts *) malloc(sizeof(struct rohc_ts));
      ts->sec = sec;
      ts->nsec = nsec;
      return ts;
   }
   ~rohc_ts()
   {
      free($self);
   }
};

%typemap(in) (uint8_t *data, size_t max_len) %{
   $1 = PyBytes_AsString($input);
   $2 = PyBytes_Size($input);
%}
%include "rohc/rohc_buf.h"
%extend rohc_buf
{
   rohc_buf(uint8_t *data, size_t max_len, size_t len, struct rohc_ts *ts)
   {
      struct rohc_buf *buf;
      buf = (struct rohc_buf *) malloc(sizeof(struct rohc_buf));
      buf->data = data;
      buf->max_len = max_len;
      buf->offset = 0;
      buf->len = len;
      buf->time.sec = ts->sec;
      buf->time.nsec = ts->nsec;
      return buf;
   }
   ~rohc_buf()
   {
      free($self);
   }
   unsigned int get(size_t pos)
   {
      /* offset != 0 is not handled yet */
      if(pos < $self->len)
      {
         return $self->data[pos];
      }
      else
      {
         return 0;
      }
   }
};

%include "rohc/rohc.h"
%include "rohc/rohc_traces.h"
%include "rohc/rohc_comp.h"
%include "rohc/rohc_decomp.h"

%include "rohc_helpers2.h"

%constant void print_rohc_traces(void *const, const rohc_trace_level_t, const rohc_trace_entity_t, const int, const char *const, ...);
%constant int gen_false_random_num(const struct rohc_comp *const, void *const);
%constant bool rohc_comp_rtp_cb(const unsigned char *const, const unsigned char *const, const unsigned char *const, const unsigned int, void *const rtp_private);

