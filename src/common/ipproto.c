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
 * @file   ipproto.c
 * @brief  Description of IP protocole number.
 * @author FWX <rohc_team@dialine.fr>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "protocols/ipproto.h"

/**
 * @brief Table of characteristiques of IP Protocole number
 * tunneling or IP v6 option.
 */

uint8_t ipproto_specifications[256] =
{
/*   0 */ IPV6_OPTION,                   // IPPROTO_IP or IPPROTO_HOPOPTS IPv6 Hop-by-Hop options.
/*   1 */ 0,                             // IPPROTO_ICMP Internet Control Message Protocol.
/*   2 */ 0,                             // IPPROTO_IGMP Internet Group Management Protocol.
/*   3 */ 0,
/*   4 */ IPV4_TUNNELING|IPV6_TUNNELING, // IPPROTO_IPIP IPIP tunnels (older KA9Q tunnels use 94).
/*   5 */ 0,
/*   6 */ 0,                             // IPPROTO_TCP Transmission Control Protocol.
/*   7 */ 0,
/*   8 */ 0,                             // IPPROTO_EGP Exterior Gateway Protocol.
/*   9 */ 0,
/*  10 */ 0,
/*  11 */ 0,
/*  12 */ 0,                             // IPPROTO_PUP PUP protocol.
/*  13 */ 0,
/*  14 */ 0,
/*  15 */ 0,
/*  16 */ 0,
/*  17 */ 0,                             // IPPROTO_UDP User Datagram Protocol.
/*  18 */ 0,
/*  19 */ 0,
/*  20 */ 0,
/*  21 */ 0,
/*  22 */ 0,                             // IPPROTO_IDP XNS IDP protocol.
/*  23 */ 0,
/*  24 */ 0,
/*  25 */ 0,
/*  26 */ 0,
/*  27 */ 0,
/*  28 */ 0,
/*  29 */ 0,                             // IPPROTO_TP SO Transport Protocol Class 4.
/*  30 */ 0,
/*  31 */ 0,
/*  32 */ 0,
/*  33 */ 0,                             // IPPROTO_DCCP Datagram Congestion Control Protocol.
/*  34 */ 0,
/*  35 */ 0,
/*  36 */ 0,
/*  37 */ 0,
/*  38 */ 0,
/*  39 */ 0,
/*  40 */ 0,
/*  41 */ IPV4_TUNNELING|IPV6_TUNNELING, // IPPROTO_IPV6 IPv6 header.
/*  42 */ 0,
/*  43 */ IPV6_OPTION,                   // IPPROTO_ROUTING IPv6 routing header.
/*  44 */ 0,                             // IPPROTO_FRAGMENT IPv6 fragmentation header.
/*  45 */ 0,
/*  46 */ 0,                             // IPPROTO_RSVP Reservation Protocol.
/*  47 */ IPV6_OPTION,                   // IPPROTO_GRE General Routing Encapsulation.
/*  48 */ 0,
/*  49 */ 0,
/*  50 */ 0,                             // IPPROTO_ESP encapsulating security payload.
/*  51 */ IPV6_OPTION,                   // IPPROTO_AH authentication header.
/*  52 */ 0,
/*  53 */ 0,
/*  54 */ 0,
/*  55 */ IPV6_OPTION,                   // MIME see RFC2004
/*  56 */ 0,
/*  57 */ 0,
/*  58 */ 0,                             // IPPROTO_ICMPV6 ICMPv6.
/*  59 */ 0,                             // IPPROTO_NONE IPv6 no next header.
/*  60 */ IPV6_OPTION,                   // IPPROTO_DSTOPTS IPv6 destination options.
/*  61 */ 0,
/*  62 */ 0,
/*  63 */ 0,
/*  64 */ 0,
/*  65 */ 0,
/*  66 */ 0,
/*  67 */ 0,
/*  68 */ 0,
/*  69 */ 0,
/*  70 */ 0,
/*  71 */ 0,
/*  72 */ 0,
/*  73 */ 0,
/*  74 */ 0,
/*  75 */ 0,
/*  76 */ 0,
/*  77 */ 0,
/*  78 */ 0,
/*  79 */ 0,
/*  80 */ 0,
/*  81 */ 0,
/*  82 */ 0,
/*  83 */ 0,
/*  84 */ 0,
/*  85 */ 0,
/*  86 */ 0,
/*  87 */ 0,
/*  88 */ 0,
/*  89 */ 0,
/*  90 */ 0,
/*  91 */ 0,
/*  92 */ 0,                             // IPPROTO_MTP Multicast Transport Protocol.
/*  93 */ 0,
/*  94 */ 0,
/*  95 */ 0,
/*  96 */ 0,
/*  97 */ 0,
/*  98 */ 0,                             // IPPROTO_ENCAP Encapsulation Header.
/*  99 */ 0,
/* 100 */ 0,
/* 101 */ 0,
/* 102 */ 0,
/* 103 */ 0,                             // IPPROTO_PIM Protocol Independent Multicast.
/* 104 */ 0,
/* 105 */ 0,
/* 106 */ 0,
/* 107 */ 0,
/* 108 */ 0,                             // IPPROTO_COMP Compression Header Protocol.
/* 109 */ 0,
/* 110 */ 0,
/* 111 */ 0,
/* 112 */ 0,
/* 113 */ 0,
/* 114 */ 0,
/* 115 */ 0,
/* 116 */ 0,
/* 117 */ 0,
/* 118 */ 0,
/* 119 */ 0,
/* 120 */ 0,
/* 121 */ 0,
/* 122 */ 0,
/* 123 */ 0,
/* 124 */ 0,
/* 125 */ 0,
/* 126 */ 0,
/* 127 */ 0,
/* 128 */ 0,
/* 129 */ 0,
/* 130 */ 0,
/* 131 */ 0,
/* 132 */ 0,                             // IPPROTO_SCTP Stream Control Transmission Protocol.
/* 133 */ 0,
/* 134 */ 0,
/* 135 */ 0,
/* 136 */ 0,                             // IPPROTO_UDPLITE UDP-Lite protocol.
/* 137 */ 0,
/* 138 */ 0,
/* 139 */ 0,
/* 140 */ 0,
/* 141 */ 0,
/* 142 */ 0,
/* 143 */ 0,
/* 144 */ 0,
/* 145 */ 0,
/* 146 */ 0,
/* 147 */ 0,
/* 148 */ 0,
/* 149 */ 0,
/* 150 */ 0,
/* 151 */ 0,
/* 152 */ 0,
/* 153 */ 0,
/* 154 */ 0,
/* 155 */ 0,
/* 156 */ 0,
/* 157 */ 0,
/* 158 */ 0,
/* 159 */ 0,
/* 160 */ 0,
/* 161 */ 0,
/* 162 */ 0,
/* 163 */ 0,
/* 164 */ 0,
/* 165 */ 0,
/* 166 */ 0,
/* 167 */ 0,
/* 168 */ 0,
/* 169 */ 0,
/* 170 */ 0,
/* 171 */ 0,
/* 172 */ 0,
/* 173 */ 0,
/* 174 */ 0,
/* 175 */ 0,
/* 176 */ 0,
/* 177 */ 0,
/* 178 */ 0,
/* 179 */ 0,
/* 180 */ 0,
/* 181 */ 0,
/* 182 */ 0,
/* 183 */ 0,
/* 184 */ 0,
/* 185 */ 0,
/* 186 */ 0,
/* 187 */ 0,
/* 188 */ 0,
/* 189 */ 0,
/* 190 */ 0,
/* 191 */ 0,
/* 192 */ 0,
/* 193 */ 0,
/* 194 */ 0,
/* 195 */ 0,
/* 196 */ 0,
/* 197 */ 0,
/* 198 */ 0,
/* 199 */ 0,
/* 200 */ 0,
/* 201 */ 0,
/* 202 */ 0,
/* 203 */ 0,                             // IPPROTO_PIM Protocol Independent Multicast.
/* 204 */ 0,
/* 205 */ 0,
/* 206 */ 0,
/* 207 */ 0,
/* 208 */ 0,                             // IPPROTO_COMP Compression Header Protocol.
/* 209 */ 0,
/* 210 */ 0,
/* 211 */ 0,
/* 212 */ 0,
/* 213 */ 0,
/* 214 */ 0,
/* 215 */ 0,
/* 216 */ 0,
/* 217 */ 0,
/* 218 */ 0,
/* 219 */ 0,
/* 220 */ 0,
/* 221 */ 0,
/* 222 */ 0,
/* 223 */ 0,
/* 224 */ 0,
/* 225 */ 0,
/* 226 */ 0,
/* 227 */ 0,
/* 228 */ 0,
/* 229 */ 0,
/* 230 */ 0,
/* 231 */ 0,
/* 232 */ 0,                             // IPPROTO_SCTP Stream Control Transmission Protocol.
/* 233 */ 0,
/* 234 */ 0,
/* 235 */ 0,
/* 236 */ 0,                             // IPPROTO_UDPLITE UDP-Lite protocol.
/* 237 */ 0,
/* 238 */ 0,
/* 239 */ 0,
/* 240 */ 0,
/* 241 */ 0,
/* 242 */ 0,
/* 243 */ 0,
/* 244 */ 0,
/* 245 */ 0,
/* 246 */ 0,
/* 247 */ 0,
/* 248 */ 0,
/* 249 */ 0,
/* 250 */ 0,
/* 251 */ 0,
/* 252 */ 0,
/* 253 */ 0,
/* 254 */ 0,
/* 255 */ 0                              // IPPROTO_RAW Raw IP packets.
};


