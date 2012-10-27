/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
  * @file trace.c
  * @brief Trace funtions.
  * @author FWX <rohc_team@dialine.fr>
  */


#include <unistd.h>
#include <stdio.h>
#include <netinet/ip.h>

#include "protocols/tcp.h"
#include "protocols/ipproto.h"
#include "rohc_traces.h"
#include "trace.h"


unsigned char hexatab[16] = { '0','1','2','3','4','5','6','7',
	                           '8','9','A','B','C','D','E','F' };

static char HexaBuffer[82] = {' ',' ',' ',' ',0};

void TraceData
(
   unsigned char *Data,
   unsigned int NumBytes
)
{
	char *ptr_to;
	unsigned int i;
	unsigned int j;
	unsigned int Offset = 0;
	unsigned char c;


	for(i = 0; i < NumBytes; i += 16)
	{

		ptr_to = HexaBuffer + 4;
		j = Offset & 0xFFFF;
		*(ptr_to++) = hexatab[ j >> 12 ];
		*(ptr_to++) = hexatab[ ( j >> 8 ) & 0x0F ];
		*(ptr_to++) = hexatab[ ( j >> 4 ) & 0x0F ];
		*(ptr_to++) = hexatab[ j & 0x0F ];
		*(ptr_to++) = ':';
		*(ptr_to++) = ' ';

		// Output the hex bytes
		for(j = i; j < (i + 16); ++j)
		{
			if(j < NumBytes)
			{
				c = (unsigned char) *(Data + j);
				*(ptr_to++) = hexatab[ c >> 4 ];
				*(ptr_to++) = hexatab[ c & 0x0F ];
			}
			else
			{
				*(ptr_to++) = ' ';
				*(ptr_to++) = ' ';
			}
			*(ptr_to++) = ' ';
		}

		*(ptr_to++) = ' ';
		*(ptr_to++) = ' ';

		// Output the ASCII bytes
		for(j = i; j < (i + 16); ++j)
		{
			if(j < NumBytes)
			{
				c = *(Data + j);
				if(c < ' ' || c > 'z' || c == '%')
				{
					*(ptr_to++) = '.';
				}
				else
				{
					*(ptr_to++) = c;
				}
			}
			else
			{
				*(ptr_to++) = ' ';
			}
		}

		*(ptr_to++) = '\n';
		*ptr_to = 0;

		printf("%s", HexaBuffer);

		Offset += 16;

	}
}


#if ROHC_TCP_DEBUG

void TraceIp( base_header_ip_vx_t *ip )
{
	if(ip->version == 4)
	{
		TraceIpV4((base_header_ip_v4_t*)ip);
	}
	else
	{
		TraceIpV6((base_header_ip_v6_t*)ip);
	}
}


void TraceIpV4( base_header_ip_v4_t *ip )
{
	rohc_debugf(3, "Header at %p IP version 4 size %d header_length %d\n",ip,
	            (int)sizeof(base_header_ip_v4_t),ip->header_length);
	rohc_debugf(3, "dscp %Xh ip_ecn_flags %d\n",ip->dscp,ip->ip_ecn_flags);
	rohc_debugf(3, "length %d (%4.4Xh) IP-ID %4.4Xh\n",ntohs(ip->length),ntohs(ip->length),
	            ntohs(ip->ip_id));
	  #if __BYTE_ORDER == __LITTLE_ENDIAN
	rohc_debugf(3, "rf %d mf %d df %d frag_offset %Xh\n",ip->rf,ip->mf,ip->df,
	            (ip->frag_offset1 << 5) | ip->frag_offset2);
	{
		u_int8_t *ptr = (u_int8_t*) ip;
		rohc_debugf(3, "=>frag_offset %Xh%Xh %2.2Xh %2.2Xh\n",ip->frag_offset1,ip->frag_offset2,
		            ptr[6],
		            ptr[7]);
	}

	  #elif __BYTE_ORDER == __BIG_ENDIAN
	rohc_debugf(3, "rf %d mf %d df %d frag_offset %Xh\n",ip->rf,ip->mf,ip->df,ip->frag_offset);
	  #endif
	rohc_debugf(3, "ttl_hopl %Xh protocol %d checksum %4.4Xh\n",ip->ttl_hopl,ip->protocol,
	            ntohs(ip->checksum));
	rohc_debugf(3, "src addr %Xh dst addr %Xh\n",ntohl(ip->src_addr),ntohl(ip->dest_addr));
}


void TraceIpV6( base_header_ip_v6_t *ip )
{
	rohc_debugf(3, "Header at %p IP version 6 size %d\n",ip,(int)sizeof(base_header_ip_v6_t));
	rohc_debugf(3, "dscp %Xh ip_ecn_flags %d\n",DSCP_V6(ip),ip->ip_ecn_flags);
	rohc_debugf(3, "flow_label %Xh payload_length %d\n",FLOW_LABEL_V6(ip),ntohs(ip->payload_length));
	rohc_debugf(3, "ttl_hopl %Xh next_header %d\n",ip->ttl_hopl,ip->next_header);
	rohc_debugf(3, "src addr %X.%X.%X.%Xh dest addr %X.%X.%X.%Xh\n",
	            ntohl(ip->src_addr[0]),ntohl(ip->src_addr[1]),ntohl(ip->src_addr[2]),
	            ntohl(ip->src_addr[3]),
	            ntohl(ip->dest_addr[0]),ntohl(ip->dest_addr[1]),ntohl(ip->dest_addr[2]),
	            ntohl(ip->dest_addr[3]));
}


void TraceIpV6option( u_int8_t previous_header, base_header_ip_t base_header )
{
	char *name;
	u_int8_t *ptr = NULL;
	int size;

	switch(previous_header)
	{
		case IPPROTO_HOPOPTS:    // IPv6 Hop-by-Hop options
			name = "Hop-by-Hop";
			break;
		case IPPROTO_ROUTING:    // IPv6 routing header
			name = "Routing";
			break;
		case IPPROTO_GRE:
			name = "GRE";
			break;
		case IPPROTO_DSTOPTS:    // IPv6 destination options
			name = "Destination";
			break;
		case IPPROTO_MIME:
			name = "MIME";
			break;
		case IPPROTO_AH:
			name = "Authentification";
			break;
		// case IPPROTO_ESP : ???
		default:
			name = "Unknown";
			break;
	}

	rohc_debugf(3, "Header at %p IPv6 option %s %d\n",base_header.uint8,name,previous_header);

	switch(previous_header)
	{
		case IPPROTO_HOPOPTS:    // IPv6 Hop-by-Hop options
			rohc_debugf(3, "next_header %d length %d\n",base_header.ipv6_opt->next_header,
			            base_header.ipv6_opt->length);
			ptr = base_header.ipv6_opt->value;
			size = base_header.ipv6_opt->length << 3;
			break;
		case IPPROTO_ROUTING:    // IPv6 routing header
			rohc_debugf(3, "next_header %d length %d\n",base_header.ipv6_opt->next_header,
			            base_header.ipv6_opt->length);
			ptr = base_header.ipv6_opt->value;
			size = base_header.ipv6_opt->length << 3;
			break;
		case IPPROTO_GRE:
			rohc_debugf(
			   3,
			   "c_flag %d k_flag %d s_flag %d protocol %Xh checksum %Xh key %Xh sequence_number %Xh\n",
			   base_header.ip_gre_opt->c_flag,base_header.ip_gre_opt->k_flag,
			   base_header.ip_gre_opt->s_flag,
			   ntohs(base_header.ip_gre_opt->protocol),
			   base_header.ip_gre_opt->c_flag != 0 ? ntohl(
			      base_header.ip_gre_opt->datas[0]) : 0,
			   base_header.ip_gre_opt->k_flag !=
			   0 ? ntohl(base_header.ip_gre_opt->datas[base_header.ip_gre_opt->c_flag]) : 0,
			   base_header.ip_gre_opt->s_flag !=
			   0 ? ntohl(base_header.ip_gre_opt->datas[base_header.ip_gre_opt->c_flag +
			                                           base_header.ip_gre_opt->k_flag]) : 0);
			size = 0;
			break;
		case IPPROTO_DSTOPTS:    // IPv6 destination options
			rohc_debugf(3, "next_header %d length %d\n",base_header.ipv6_opt->next_header,
			            base_header.ipv6_opt->length);
			ptr = base_header.ipv6_opt->value;
			size = base_header.ipv6_opt->length << 3;
			break;
		case IPPROTO_MIME:
			rohc_debugf(3, "next_header %d s_bit %d checksum %Xh orig_dest %Xh orig_src %Xh\n",
			            base_header.ip_mime_opt->next_header,base_header.ip_mime_opt->s_bit,
			            ntohs(base_header.ip_mime_opt->checksum),
			            ntohl(base_header.ip_mime_opt->orig_dest),
			            base_header.ip_mime_opt->s_bit != 0 ? ntohl(
			               base_header.ip_mime_opt->orig_src) : 0);
			size = 0;
			break;
		case IPPROTO_AH:
			rohc_debugf(3, "next_header %d length %d spi %Xh sequence_number %Xh\n",
			            base_header.ip_ah_opt->next_header,base_header.ip_ah_opt->length,ntohl(
			               base_header.ip_ah_opt->spi),ntohl(base_header.ip_ah_opt->sequence_number));
			ptr = (u_int8_t*) base_header.ip_ah_opt->auth_data;
			size = base_header.ip_ah_opt->length << 2;
			break;
		// case IPPROTO_ESP : ???
		default:
			size = 0;
			break;
	}

	if(size != 0 && ptr != NULL)
	{
		TraceData(ptr,size);
	}
}


void TraceTcp( tcphdr_t *tcp )
{
	rohc_debugf(3, "Header at %p TCP size %d\n",tcp,(int)sizeof(tcphdr_t));
	rohc_debugf(3, "TCP source port %d (%Xh) dest port %d (%Xh)\n", ntohs(tcp->src_port),
	            ntohs(tcp->src_port), ntohs(tcp->dst_port), ntohs(tcp->dst_port));
	rohc_debugf(3, "TCP seq %4.4Xh ack_seq %4.4Xh\n", ntohl(tcp->seq_number), ntohl(tcp->ack_number));
	/*
	rohc_debugf(3, "TCP begin %4.4Xh data offset %d %s%s%s%s%s%s%s%s\n",
	               *(u_int16_t*)(((unsigned char*)tcp)+12), tcp->doff,
	               (tcp->cwr!=0)?"CWR ":"", (tcp->ece!=0)?"ECE ":"",
	          (tcp->urg!=0)?"URG ":"", (tcp->ack!=0)?"ACK ":"",
	          (tcp->psh!=0)?"PSH ":"", (tcp->rst!=0)?"RST ":"",
	               (tcp->syn!=0)?"SYN ":"", (tcp->fin!=0)?"FIN":"" );
	*/
	rohc_debugf(3, "TCP begin %4.4Xh res_flags %d data offset %d rsf_flags %d ecn_flags %d %s%s%s\n",
	            *(u_int16_t*)(((unsigned char*)tcp) + 12),
	            tcp->tcp_res_flags, tcp->data_offset,
	            tcp->rsf_flags, tcp->tcp_ecn_flags,
	            (tcp->urg_flag != 0) ? "URG " : "", (tcp->ack_flag != 0) ? "ACK " : "",
	            (tcp->psh_flag != 0) ? "PSH " : "" );

	rohc_debugf(3, "TCP window %4.4Xh check %Xh urg_ptr %d\n",
	            ntohs(tcp->window), ntohs(tcp->checksum), ntohs(tcp->urg_ptr));

	if(tcp->data_offset > ( sizeof(tcphdr_t) >> 2 ) )
	{
		rohc_debugf(3, "TCP options length %d\n",(int)((tcp->data_offset << 2) - sizeof(tcphdr_t)));
		TraceData((unsigned char*)(tcp + 1),(tcp->data_offset << 2) - sizeof(tcphdr_t));
	}
	fflush(stdout);
}


#endif

