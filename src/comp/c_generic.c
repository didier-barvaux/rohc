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
 * @file c_generic.c
 * @brief ROHC generic compression context for IP-only, UDP, UDP-Lite, ESP, and
 *        RTP profiles.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 * @author David Moreau from TAS
 * @author Emmanuelle Pechereau <epechereau@toulouse.viveris.com>
 * @author The hackers from ROHC for Linux
 */

#include "c_generic.h"
#include "c_rtp.h"
#include "rohc_traces.h"
#include "rohc_traces_internal.h"
#include "rohc_debug.h"
#include "rohc_packets.h"
#include "rohc_utils.h"
#include "cid.h"
#include "sdvl.h"
#include "crc.h"

#include <string.h>
#include <assert.h>

#include "config.h" /* for RTP_BIT_TYPE and ROHC_EXTRA_DEBUG definitions */


/*
 * Definitions of private constants and macros
 */

/** A flag to indicate that IPv4 Type Of Service field changed in IP header */
#define MOD_TOS       0x0001
/** A flag to indicate that IPv4 Time To Live field changed in IP header */
#define MOD_TTL       0x0010
/** A flag to indicate that the IPv4 Protocol field changed in IP header */
#define MOD_PROTOCOL  0x0020


/*
 * Function prototypes.
 */

static rohc_packet_t decide_packet(const struct c_context *context,
                                   const struct ip_packet *ip,
                                   const struct ip_packet *ip2);

int code_packet(struct c_context *const context,
                const struct ip_packet *ip,
                const struct ip_packet *ip2,
                const unsigned char *next_header,
                unsigned char *const dest);

int code_IR_packet(struct c_context *const context,
                   const struct ip_packet *ip,
                   const struct ip_packet *ip2,
                   const unsigned char *next_header,
                   unsigned char *const dest);

int code_IR_DYN_packet(struct c_context *const context,
                       const struct ip_packet *ip,
                       const struct ip_packet *ip2,
                       const unsigned char *next_header,
                       unsigned char *const dest);

int code_generic_static_part(const struct c_context *context,
                             struct ip_header_info *const header_info,
                             const struct ip_packet *ip,
                             unsigned char *const dest,
                             int counter);

int code_ipv4_static_part(const struct c_context *context,
                          struct ip_header_info *const header_info,
                          const struct ip_packet *ip,
                          unsigned char *const dest,
                          int counter);

int code_ipv6_static_part(const struct c_context *context,
                          struct ip_header_info *const header_info,
                          const struct ip_packet *ip,
                          unsigned char *const dest,
                          int counter);

int code_generic_dynamic_part(const struct c_context *context,
                              struct ip_header_info *const header_info,
                              const struct ip_packet *ip,
                              unsigned char *const dest,
                              int counter);

int code_ipv4_dynamic_part(const struct c_context *context,
                           struct ip_header_info *const header_info,
                           const struct ip_packet *ip,
                           unsigned char *const dest,
                           int counter);

int code_ipv6_dynamic_part(const struct c_context *context,
                           struct ip_header_info *const header_info,
                           const struct ip_packet *ip,
                           unsigned char *const dest,
                           int counter);

int code_uo_remainder(struct c_context *const context,
                      const struct ip_packet *ip,
                      const struct ip_packet *ip2,
                      const unsigned char *next_header,
                      unsigned char *const dest,
                      int counter);

int code_UO0_packet(struct c_context *const context,
                    const struct ip_packet *ip,
                    const struct ip_packet *ip2,
                    const unsigned char *next_header,
                    unsigned char *const dest);

int code_UO1_packet(struct c_context *const context,
                    const struct ip_packet *ip,
                    const struct ip_packet *ip2,
                    const unsigned char *next_header,
                    unsigned char *const dest);

int code_UO2_packet(struct c_context *const context,
                    const struct ip_packet *ip,
                    const struct ip_packet *ip2,
                    const unsigned char *next_header,
                    unsigned char *const dest);

int code_UOR2_bytes(const struct c_context *context,
                    const rohc_ext_t extension,
                    unsigned char *const f_byte,
                    unsigned char *const s_byte,
                    unsigned char *const t_byte);

int code_UOR2_RTP_bytes(const struct c_context *context,
                        const rohc_ext_t extension,
                        unsigned char *const f_byte,
                        unsigned char *const s_byte,
                        unsigned char *const t_byte);

int code_UOR2_TS_bytes(const struct c_context *context,
                       const rohc_ext_t extension,
                       unsigned char *const f_byte,
                       unsigned char *const s_byte,
                       unsigned char *const t_byte);

int code_UOR2_ID_bytes(const struct c_context *context,
                       const rohc_ext_t extension,
                       unsigned char *const f_byte,
                       unsigned char *const s_byte,
                       unsigned char *const t_byte);

int code_EXT0_packet(const struct c_context *context,
                     unsigned char *const dest,
                     int counter);

int code_EXT1_packet(const struct c_context *context,
                     unsigned char *const dest,
                     int counter);

int code_EXT2_packet(const struct c_context *context,
                     unsigned char *const dest,
                     int counter);

int code_EXT3_packet(const struct c_context *context,
                     const struct ip_packet *ip,
                     const struct ip_packet *ip2,
                     unsigned char *const dest,
                     int counter);

int rtp_header_flags_and_fields(const struct c_context *context,
                                const unsigned short changed_f,
                                const struct ip_packet *ip,
                                unsigned char *const dest,
                                int counter);

int header_flags(const struct c_context *context,
                 struct ip_header_info *const header_info,
                 const unsigned short changed_f,
                 const struct ip_packet *ip,
                 const int ip2_or_I2,
                 const size_t nr_ip_id_bits,
                 unsigned char *const dest,
                 int counter);

int header_fields(const struct c_context *context,
                  struct ip_header_info *const header_info,
                  const unsigned short changed_f,
                  const struct ip_packet *ip,
                  const int I,
                  const ip_header_pos_t ip_hdr_pos,
                  unsigned char *const dest,
                  int counter);

int changed_static_both_hdr(const struct c_context *context,
                            const struct ip_packet *ip,
                            const struct ip_packet *ip2);

int changed_static_one_hdr(const struct c_context *const context,
                           const unsigned short changed_fields,
                           struct ip_header_info *const header_info,
                           const struct ip_packet *ip);

int changed_dynamic_both_hdr(const struct c_context *context,
                             const struct ip_packet *ip,
                             const struct ip_packet *ip2);

int changed_dynamic_one_hdr(const struct c_context *const context,
                            const unsigned short changed_fields,
                            struct ip_header_info *const header_info,
                            const struct ip_packet *ip);

unsigned short changed_fields(const struct c_context *const context,
                              const struct ip_header_info *header_info,
                              const struct ip_packet *ip);


/*
 * Prototypes of main private functions
 */

static void detect_ip_id_behaviours(struct c_context *const context,
                                    const struct ip_packet *const outer_ip,
                                    const struct ip_packet *const inner_ip)
	__attribute__((nonnull(1, 2)));
static void detect_ip_id_behaviour(const struct c_context *const context,
                                   struct ip_header_info *const header_info,
                                   const struct ip_packet *const ip)
	__attribute__((nonnull(1, 2, 3)));
static bool is_ip_id_nbo(const uint16_t old_id, const uint16_t new_id);

static int encode_uncomp_fields(struct c_context *const context,
                                const struct ip_packet *const ip,
                                const struct ip_packet *const ip2,
                                const unsigned char *const next_header);

static void rohc_get_innermost_ipv4_non_rnd(const struct c_context *context,
                                            ip_header_pos_t *const pos,
                                            size_t *const nr_bits,
                                            uint16_t *const offset);


/*
 * Prototypes of private functions related to IPv6 extension headers
 */

static void ip6_c_init_table(struct list_comp *const comp);
static void list_comp_ipv6_destroy_table(struct list_comp *const comp);
static void create_ipv6_item(struct list_comp *const comp,
                             const unsigned int index_table,
                             const unsigned char *ext_data,
                             const size_t ext_size);
static unsigned char * get_ipv6_extension(const struct ip_packet *ip,
                                          const int index);
static int ipv6_compare(const struct list_comp *const comp,
                        const unsigned char *const ext,
                        const int size,
                        const int index_table);
static int get_index_ipv6_table(const struct ip_packet *ip, const int index);

static bool rohc_list_decide_ipv6_compression(struct list_comp *const comp,
                                              const struct ip_packet *const ip);


/*
 * Prototypes of private functions related to list compression
 */

static bool rohc_list_create_current(const int index,
                                     struct list_comp *const comp,
                                     const unsigned char *ext,
                                     const int index_table);
static int rohc_list_decide_type(struct list_comp *const comp);
static int rohc_list_encode(struct list_comp *const comp,
                            unsigned char *const dest,
                            int counter,
                            const int ps,
                            const int size);
static int rohc_list_encode_type_0(struct list_comp *const comp,
                                   unsigned char *const dest,
                                   int counter,
                                   const int ps);
static int rohc_list_encode_type_1(struct list_comp *const comp,
                                   unsigned char *const dest,
                                   int counter,
                                   const int ps);
static int rohc_list_encode_type_2(struct list_comp *const comp,
                                   unsigned char *const dest,
                                   int counter,
                                   const int ps);
static int rohc_list_encode_type_3(struct list_comp *const comp,
                                   unsigned char *const dest,
                                   int counter,
                                   const int ps);



/*
 * Definitions of public functions
 */


/**
 * @brief Check if a specified IP field has changed.
 *
 * @param changed_fields The fields that changed, created by the function
 *                       changed_fields
 * @param check_field    The field for which to check a change
 * @return               1 if the field changed, 0 if not
 *
 * @see changed_fields
 */
int is_changed(const unsigned short changed_fields,
               const unsigned short check_field)
{
	return ((changed_fields & check_field) != 0);
}


/**
 * @brief Initialize the inner or outer IP header info stored in the context.
 *
 * @param header_info        The inner or outer IP header info to initialize
 * @param ip                 The inner or outer IP header
 * @param wlsb_window_width  The width of the W-LSB sliding window for IPv4
 *                           IP-ID (must be > 0)
 * @param trace_callback     The function to call for printing traces
 * @param profile_id         The ID of the associated compression profile
 * @return                   1 if successful, 0 otherwise
 */
int c_init_header_info(struct ip_header_info *header_info,
                       const struct ip_packet *ip,
                       const size_t wlsb_window_width,
                       rohc_trace_callback_t trace_callback,
                       const int profile_id)
{
	assert(header_info != NULL);
	assert(ip != NULL);
	assert(wlsb_window_width > 0);

	/* store the IP version in the header info */
	header_info->version = ip_get_version(ip);

	/* we haven't seen any header so far */
	header_info->is_first_header = true;

	/* version specific initialization */
	if(header_info->version == IPV4)
	{
		/* init the parameters to encode the IP-ID with W-LSB encoding */
		header_info->info.v4.ip_id_window =
			c_create_wlsb(16, wlsb_window_width, ROHC_LSB_SHIFT_IP_ID);
		if(header_info->info.v4.ip_id_window == NULL)
		{
			__rohc_print(trace_callback, ROHC_TRACE_ERROR, ROHC_TRACE_COMP,
			             profile_id, "no memory to allocate W-LSB encoding "
			             "for IP-ID\n");
			goto error;
		}

		/* init the thresholds the counters must reach before launching
		 * an action */
		header_info->tos_count = MAX_FO_COUNT;
		header_info->ttl_count = MAX_FO_COUNT;
		header_info->info.v4.df_count = MAX_FO_COUNT;
		header_info->protocol_count = MAX_FO_COUNT;
		header_info->info.v4.rnd_count = MAX_FO_COUNT;
		header_info->info.v4.nbo_count = MAX_FO_COUNT;
	}
	else
	{
		/* init the compression context for IPv6 extension header list */
		header_info->info.v6.ext_comp = malloc(sizeof(struct list_comp));
		if(header_info->info.v6.ext_comp == NULL)
		{
			__rohc_print(trace_callback, ROHC_TRACE_ERROR, ROHC_TRACE_COMP,
			             profile_id, "no memory to allocate IPv6 extension list "
			             "compressor\n");
			goto error;
		}
		header_info->info.v6.ext_comp->ref_list = malloc(sizeof(struct c_list));
		if(header_info->info.v6.ext_comp->ref_list == NULL)
		{
			__rohc_print(trace_callback, ROHC_TRACE_ERROR, ROHC_TRACE_COMP,
			             profile_id, "cannot allocate memory for the reference "
			             "compression list\n");
			goto error;
		}
		header_info->info.v6.ext_comp->ref_list->gen_id = 0;
		header_info->info.v6.ext_comp->ref_list->first_elt = NULL;
		header_info->info.v6.ext_comp->curr_list = malloc(sizeof(struct c_list));
		if(header_info->info.v6.ext_comp->curr_list == NULL)
		{
			__rohc_print(trace_callback, ROHC_TRACE_ERROR, ROHC_TRACE_COMP,
			             profile_id, "cannot allocate memory for the current "
			             "compression list\n");
			goto error;
		}
		header_info->info.v6.ext_comp->curr_list->gen_id = 0;
		header_info->info.v6.ext_comp->curr_list->first_elt = NULL;

		header_info->info.v6.ext_comp->counter = 0;
		header_info->info.v6.ext_comp->changed = false;
		ip6_c_init_table(header_info->info.v6.ext_comp);
		header_info->info.v6.ext_comp->get_extension = get_ipv6_extension;
		header_info->info.v6.ext_comp->create_item = create_ipv6_item;
		header_info->info.v6.ext_comp->get_size = ip_get_extension_size;
		header_info->info.v6.ext_comp->compare = ipv6_compare;
		header_info->info.v6.ext_comp->free_table = list_comp_ipv6_destroy_table;
		header_info->info.v6.ext_comp->get_index_table = get_index_ipv6_table;
		header_info->info.v6.ext_comp->trace_callback = trace_callback;
		header_info->info.v6.ext_comp->profile_id = profile_id;
	}

	return 1;

error:
	return 0;
}


/**
 * @brief Initialize all temporary variables stored in the context.
 *
 * @param tmp_vars  The temporary variables to initialize
 */
void c_init_tmp_variables(struct generic_tmp_vars *tmp_vars)
{
	tmp_vars->nr_of_ip_hdr = -1;
	tmp_vars->changed_fields = -1;
	tmp_vars->changed_fields2 = -1;
	tmp_vars->send_static = -1;
	tmp_vars->send_dynamic = -1;

	/* do not send any bits of SN, outer/inner IP-IDs by default */
	tmp_vars->nr_sn_bits = 0;
	tmp_vars->nr_ip_id_bits = 0;
	tmp_vars->nr_ip_id_bits2 = 0;

	tmp_vars->packet_type = PACKET_UNKNOWN;
	tmp_vars->max_size = -1;
}


/**
 * @brief Create a new context and initialize it thanks to the given IP packet.
 *
 * @param context   The compression context
 * @param sn_shift  The shift parameter (p) to use for encoding SN with W-LSB
 * @param ip        The IP packet given to initialize the new context
 * @return          1 if successful, 0 otherwise
 */
int c_generic_create(struct c_context *const context,
                     const rohc_lsb_shift_t sn_shift,
                     const struct ip_packet *ip)
{
	struct c_generic_context *g_context;
	unsigned int ip_proto;

	assert(context != NULL);
	assert(context->profile != NULL);

	rohc_comp_debug(context, "new generic context required for a new stream\n");

	/* check the IP header(s) */
	ip_proto = ip_get_protocol(ip);
	if(ip_proto == ROHC_IPPROTO_IPIP || ip_proto == ROHC_IPPROTO_IPV6)
	{
		struct ip_packet ip2;

		if(!ip_get_inner_packet(ip, &ip2))
		{
			rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			           "cannot create the inner IP header\n");
			goto quit;
		}
	}

	/* allocate memory for the generic part of the context */
	g_context =
		(struct c_generic_context *) malloc(sizeof(struct c_generic_context));
	if(g_context == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "no memory for generic part of the profile context\n");
		goto quit;
	}
	memset(g_context, 0, sizeof(struct c_generic_context));
	context->specific = g_context;

	/* initialize some context variables:
	 *  1. init the parameters to encode the SN with W-LSB encoding
	 *  2. init the counters of packet types
	 *  3. init the counters for the periodic transition to lower states
	 *  4. init the info related to the outer IP header, the info related to the
	 *     inner IP header will be initialized later if necessary
	 *  5. init the temporary variables
	 *  6. init the profile-specific variables to safe values
	 */

	/* step 1 */
	rohc_comp_debug(context, "use shift parameter %d for LSB-encoding of SN\n",
	                sn_shift);
	g_context->sn_window =
		c_create_wlsb(16, context->compressor->wlsb_window_width, sn_shift);
	if(g_context->sn_window == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "no memory to allocate W-LSB encoding for SN\n");
		goto clean;
	}

	/* step 2 */
	g_context->ir_count = 0;
	g_context->fo_count = 0;
	g_context->so_count = 0;

	/* step 3 */
	g_context->go_back_fo_count = 0;
	g_context->go_back_ir_count = 0;

	/* step 4 */
	if(!c_init_header_info(&g_context->ip_flags, ip,
	                       context->compressor->wlsb_window_width,
	                       context->compressor->trace_callback,
	                       context->profile->id))
	{
		goto clean;
	}
	g_context->is_ip2_initialized = 0;

	/* step 5 */
	c_init_tmp_variables(&g_context->tmp);

	/* step 6 */
	g_context->specific = NULL;
	g_context->next_header_proto = 0;
	g_context->next_header_len = 0;
	g_context->decide_state = decide_state;
	g_context->decide_FO_packet = NULL;
	g_context->decide_SO_packet = NULL;
	g_context->decide_extension = NULL;
	g_context->init_at_IR = NULL;
	g_context->get_next_sn = NULL;
	g_context->code_static_part = NULL;
	g_context->code_dynamic_part = NULL;
	g_context->code_UO_packet_head = NULL;
	g_context->code_uo_remainder = NULL;
	g_context->compute_crc_static = compute_crc_static;
	g_context->compute_crc_dynamic = compute_crc_dynamic;

	return 1;

clean:
	c_generic_destroy(context);
quit:
	return 0;
}


/**
 * @brief Destroy the context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 */
void c_generic_destroy(struct c_context *const context)
{
	struct c_generic_context *g_context =
		(struct c_generic_context *) context->specific;

	if(g_context != NULL)
	{
		if(g_context->ip_flags.version == IPV4 &&
		   g_context->ip_flags.info.v4.ip_id_window != NULL)
		{
			c_destroy_wlsb(g_context->ip_flags.info.v4.ip_id_window);
		}
		if(g_context->is_ip2_initialized &&
		   g_context->ip2_flags.version == IPV4 &&
		   g_context->ip2_flags.info.v4.ip_id_window != NULL)
		{
			c_destroy_wlsb(g_context->ip2_flags.info.v4.ip_id_window);
		}
		if(g_context->ip_flags.version == IPV6 &&
		   g_context->ip_flags.info.v6.ext_comp != NULL)
		{
			if(g_context->ip_flags.info.v6.ext_comp->curr_list != NULL)
			{
				list_destroy(g_context->ip_flags.info.v6.ext_comp->curr_list);
			}
			if(g_context->ip_flags.info.v6.ext_comp->ref_list != NULL)
			{
				list_destroy(g_context->ip_flags.info.v6.ext_comp->ref_list);
			}
			list_comp_ipv6_destroy_table(g_context->ip_flags.info.v6.ext_comp);
			zfree(g_context->ip_flags.info.v6.ext_comp);
		}
		if(g_context->is_ip2_initialized &&
		   g_context->ip2_flags.version == IPV6 &&
		   g_context->ip2_flags.info.v6.ext_comp != NULL)
		{
			if(g_context->ip2_flags.info.v6.ext_comp->curr_list != NULL)
			{
				list_destroy(g_context->ip2_flags.info.v6.ext_comp->curr_list);
			}
			if(g_context->ip2_flags.info.v6.ext_comp->ref_list != NULL)
			{
				list_destroy(g_context->ip2_flags.info.v6.ext_comp->ref_list);
			}
			list_comp_ipv6_destroy_table(g_context->ip2_flags.info.v6.ext_comp);
			zfree(g_context->ip2_flags.info.v6.ext_comp);
		}
		if(g_context->sn_window != NULL)
		{
			c_destroy_wlsb(g_context->sn_window);
		}

		if(g_context->specific != NULL)
		{
			zfree(g_context->specific);
		}

		zfree(g_context);
	}
}


/**
 * @brief Change the mode of the context.
 *
 * @param context  The compression context
 * @param new_mode The new mode the context must enter in
 */
void change_mode(struct c_context *const context, const rohc_mode new_mode)
{
	if(context->mode != new_mode)
	{
		/* change mode and go back to IR state */
		rohc_comp_debug(context, "change from mode %d to mode %d\n",
		                context->mode, new_mode);
		context->mode = new_mode;
		change_state(context, IR);
	}
}


/**
 * @brief Change the state of the context.
 *
 * @param context   The compression context
 * @param new_state The new state the context must enter in
 */
void change_state(struct c_context *const context, const rohc_c_state new_state)
{
	struct c_generic_context *g_context;

	g_context = (struct c_generic_context *) context->specific;

	if(context->state != new_state)
	{
		rohc_comp_debug(context, "change from state %d to state %d\n",
		                context->state, new_state);

		/* reset counters */
		g_context->ir_count = 0;
		g_context->fo_count = 0;
		g_context->so_count = 0;

		/* change state */
		context->state = new_state;
	}
}


/**
 * @brief Encode an IP packet according to a pattern decided by several
 *        different factors.
 *
 * 1. Check if we have double IP headers.\n
 * 2. Check if the IP-ID fields are random and if they are in NBO.\n
 * 3. Decide in which state to go (IR, FO or SO).\n
 * 4. Decide how many bits are needed to send the IP-ID and SN fields and more
 *    important update the sliding windows.\n
 * 5. Decide which packet type to send.\n
 * 6. Code the packet.\n
 * \n
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context        The compression context
 * @param ip             The IP packet to encode
 * @param packet_size    The length of the IP packet to encode
 * @param dest           The rohc-packet-under-build buffer
 * @param dest_size      The length of the rohc-packet-under-build buffer
 * @param packet_type    OUT: The type of ROHC packet that is created
 * @param payload_offset The offset for the payload in the IP packet
 * @return               The length of the created ROHC packet
 *                       or -1 in case of failure
 */
int c_generic_encode(struct c_context *const context,
                     const struct ip_packet *ip,
                     const int packet_size,
                     unsigned char *const dest,
                     const int dest_size,
                     rohc_packet_t *const packet_type,
                     int *const payload_offset)
{
	struct c_generic_context *g_context;
	struct ip_packet ip2;
	struct ip_packet *inner_ip;
	const struct ip_packet *last_ip_header;
	unsigned char *next_header;
	unsigned int ip_proto;
	int size;
	int ret;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;
	g_context->tmp.changed_fields2 = 0;
	g_context->tmp.nr_ip_id_bits2 = 0;
	g_context->tmp.packet_type = PACKET_UNKNOWN;
	g_context->tmp.max_size = dest_size;

	/* STEP 1:
	 *  - check double IP headers
	 *  - find the next header
	 *  - compute the payload offset
	 *  - discard IP fragments
	 */
	ip_proto = ip_get_protocol(ip);
	if(ip_proto == ROHC_IPPROTO_IPIP || ip_proto == ROHC_IPPROTO_IPV6)
	{
		/* there are 2 IP headers */
		if(!ip_get_inner_packet(ip, &ip2))
		{
			goto error;
		}

		g_context->tmp.nr_of_ip_hdr = 2;
		inner_ip = &ip2;
		last_ip_header = &ip2;

		/* initialize IPv4 header info if the inner header is IPv4 */
		if(!g_context->is_ip2_initialized)
		{
			if(!c_init_header_info(&g_context->ip2_flags, inner_ip,
			                       context->compressor->wlsb_window_width,
			                       context->compressor->trace_callback,
			                       context->profile->id))
			{
				goto error;
			}
			g_context->is_ip2_initialized = 1;
		}
	}
	else
	{
		/* there is only one IP header */
		g_context->tmp.nr_of_ip_hdr = 1;
		inner_ip = NULL;
		last_ip_header = ip;
	}

	/* find the next header */
	next_header = ip_get_next_layer(last_ip_header);

	/* find the offset of the payload and its size */
	*payload_offset = ip_get_hdrlen(ip) + ip_get_total_extension_size(ip);
	if(g_context->tmp.nr_of_ip_hdr > 1)
	{
		*payload_offset += ip_get_hdrlen(inner_ip) +
		                   ip_get_total_extension_size(inner_ip);
	}
	*payload_offset += g_context->next_header_len;

	/* STEP 2:
	 *  - check NBO and RND of the IP-ID of the outer and inner IP headers
	 *    (IPv4 only, if the current packet is not the first one)
	 *  - get the next the Sequence Number (SN)
	 *  - find how many static and dynamic IP fields changed
	 */
	detect_ip_id_behaviours(context, ip, inner_ip);

	g_context->sn = g_context->get_next_sn(context, ip, inner_ip);
	rohc_comp_debug(context, "SN = %u\n", g_context->sn);

	/* find IP fields that changed */
	if(g_context->tmp.nr_of_ip_hdr == 1)
	{
		g_context->tmp.changed_fields = changed_fields(context,
		                                               &g_context->ip_flags, ip);
	}
	else
	{
		g_context->tmp.changed_fields = changed_fields(context,
		                                               &g_context->ip_flags, ip);
		g_context->tmp.changed_fields2 = changed_fields(context,
		                                                &g_context->ip2_flags,
		                                                inner_ip);
	}

	/* how many changed fields are static ones? */
	g_context->tmp.send_static = changed_static_both_hdr(context, ip, inner_ip);

	/* how many changed fields are dynamic ones? */
	g_context->tmp.send_dynamic = changed_dynamic_both_hdr(context, ip, inner_ip);

	rohc_comp_debug(context, "send_static = %d, send_dynamic = %d\n",
	                g_context->tmp.send_static, g_context->tmp.send_dynamic);

	/* STEP 3: decide in which state to go */
	if(g_context->decide_state != NULL)
	{
		g_context->decide_state(context);
	}

	if(ip_get_version(ip) == IPV4)
	{
		rohc_comp_debug(context, "ip_id = 0x%04x, context_sn = %u\n",
		                ntohs(ipv4_get_id(ip)), g_context->sn);
	}
	else /* IPV6 */
	{
		rohc_comp_debug(context, "context_sn = %d\n", g_context->sn);
	}

	/* STEP 4: compute how many bits are needed to send header fields */
	ret = encode_uncomp_fields(context, ip, inner_ip, next_header);
	if(ret != ROHC_OK)
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "failed to update the compression context\n");
		goto error;
	}

	/* STEP 5: decide which packet to send */
	g_context->tmp.packet_type = decide_packet(context, ip, inner_ip);

	/* STEP 6: code the packet (and the extension if needed) */
	size = code_packet(context, ip, inner_ip, next_header, dest);
	if(size < 0)
	{
		goto error;
	}

	/* update the context with the new headers */
	g_context->ip_flags.is_first_header = false;
	if(ip_get_version(ip) == IPV4)
	{
		g_context->ip_flags.info.v4.old_ip = *(ipv4_get_header(ip));
		g_context->ip_flags.info.v4.old_rnd = g_context->ip_flags.info.v4.rnd;
		g_context->ip_flags.info.v4.old_nbo = g_context->ip_flags.info.v4.nbo;
	}
	else /* IPV6 */
	{
		g_context->ip_flags.info.v6.old_ip = *(ipv6_get_header(ip));
		/* replace Next Header by the one of the last extension header */
		g_context->ip_flags.info.v6.old_ip.ip6_nxt = ip_get_protocol(ip);
	}

	if(g_context->tmp.nr_of_ip_hdr > 1)
	{
		g_context->ip2_flags.is_first_header = false;
		if(ip_get_version(inner_ip) == IPV4)
		{
			g_context->ip2_flags.info.v4.old_ip = *(ipv4_get_header(inner_ip));
			g_context->ip2_flags.info.v4.old_rnd = g_context->ip2_flags.info.v4.rnd;
			g_context->ip2_flags.info.v4.old_nbo = g_context->ip2_flags.info.v4.nbo;
		}
		else /* IPV6 */
		{
			g_context->ip2_flags.info.v6.old_ip = *(ipv6_get_header(inner_ip));
			/* replace Next Header by the one of the last extension header */
			g_context->ip2_flags.info.v6.old_ip.ip6_nxt = ip_get_protocol(inner_ip);
		}
	}

	/* update packet counters */
	if(g_context->tmp.packet_type == PACKET_IR)
	{
		context->num_sent_ir++;
	}
	else if(g_context->tmp.packet_type == PACKET_IR_DYN)
	{
		context->num_sent_ir_dyn++;
	}

	/* return the packet type */
	*packet_type = g_context->tmp.packet_type;

	/* return the length of the ROHC packet */
	return size;

error:
	return -1;
}


/**
 * @brief Update the profile when feedback arrives.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context  The compression context
 * @param feedback The feedback information including the whole feedback packet
 */
void c_generic_feedback(struct c_context *const context,
                        const struct c_feedback *feedback)
{
	struct c_generic_context *g_context;
	unsigned char *p; /* pointer to the profile-specific data
	                     in the feedback packet */
	uint32_t sn;

	g_context = (struct c_generic_context *) context->specific;
	p = feedback->data + feedback->specific_offset;

	switch(feedback->type)
	{
		case 1: /* FEEDBACK-1 */
			rohc_comp_debug(context, "feedback 1\n");
			sn = p[0] & 0xff;

			/* ack IP-ID only if IPv4, but always ack SN */
			if(g_context->ip_flags.version == IPV4)
			{
				c_ack_sn_wlsb(g_context->ip_flags.info.v4.ip_id_window, sn);
			}
			c_ack_sn_wlsb(g_context->sn_window, sn);
			break;

		case 2: /* FEEDBACK-2 */
		{
			unsigned int crc_in_packet = 0; /* initialized to avoid a GCC warning */
			bool is_crc_used = false;
			int sn_not_valid = 0;
			unsigned char mode = (p[0] >> 4) & 3;
			int remaining = feedback->specific_size - 2;
			int opt, optlen;

			rohc_comp_debug(context, "feedback 2\n");

			sn = ((p[0] & 0x0f) << 8) + (p[1] & 0xff);
			assert((sn & 0x0fff) == sn);
			p += 2;

			while(remaining > 0)
			{
				opt = p[0] >> 4;
				optlen = p[0] & 0x0f;

				switch(opt)
				{
					case 1: /* CRC */
						crc_in_packet = p[1];
						is_crc_used = true;
						p[1] = 0; /* set to zero for crc computation */
						break;
					case 3: /* SN-Not-Valid */
						sn_not_valid = 1;
						break;
					case 4: /* SN */
						if((sn & 0xff000000) != 0)
						{
							rohc_warning(context->compressor, ROHC_TRACE_COMP,
							             context->profile->id, "more than 32 bits "
							             "used for feedback SN, this is not "
							             "expected, truncate value\n");
							sn &= 0x00ffffff;
						}
						sn = (sn << 8) + (p[1] & 0xff);
						break;
					case 2: /* Reject */
					case 7: /* Loss */
					default:
						rohc_comp_debug(context, "unknown feedback type: %d\n", opt);
						break;
				}

				remaining -= 1 + optlen;
				p += 1 + optlen;
			}

			/* check CRC if present in feedback */
			if(is_crc_used == true)
			{
				unsigned int crc_computed;

				/* compute the CRC of the feedback packet */
				crc_computed = crc_calculate(ROHC_CRC_TYPE_8,
				                             feedback->data, feedback->size,
				                             CRC_INIT_8, context->compressor->crc_table_8);

				/* ignore feedback in case of bad CRC */
				if(crc_in_packet != crc_computed)
				{
					rohc_comp_debug(context, "CRC check failed (size = %d)\n",
					                feedback->size);
					return;
				}
			}

			/* change mode if present in feedback */
			if(mode != 0)
			{
				/* mode can be changed only if feedback is protected by a CRC */
				if(is_crc_used == true)
				{
					change_mode(context, mode);
				}
				else
				{
					rohc_warning(context->compressor, ROHC_TRACE_COMP,
					             context->profile->id,
					             "mode change requested but no CRC was given\n");
				}
			}

			switch(feedback->acktype)
			{
				case ACK:
					rohc_comp_debug(context, "ACK (SN = 0x%08x, SN-not-valid = %u)\n",
					                sn, sn_not_valid);
					if(sn_not_valid == 0)
					{
						/* ack outer/inner IP-ID only if IPv4, but always ack SN */
						if(g_context->ip_flags.version == IPV4)
						{
							c_ack_sn_wlsb(g_context->ip_flags.info.v4.ip_id_window, sn);
						}
						if(g_context->is_ip2_initialized &&
						   g_context->ip2_flags.version == IPV4)
						{
							c_ack_sn_wlsb(g_context->ip2_flags.info.v4.ip_id_window, sn);
						}
						c_ack_sn_wlsb(g_context->sn_window, sn);
					}
					break;

				case NACK:
					rohc_comp_debug(context, "NACK\n");
					if(context->state == SO)
					{
						change_state(context, FO);
					}
					break;

				case STATIC_NACK:
					rohc_comp_debug(context, "STATIC-NACK\n");
					change_state(context, IR);
					break;

				case RESERVED:
					rohc_warning(context->compressor, ROHC_TRACE_COMP,
					             context->profile->id, "reserved field used\n");
					break;

				default:
					/* impossible value */
					rohc_warning(context->compressor, ROHC_TRACE_COMP,
					             context->profile->id, "unknown ack type\n");
			}
		}
		break;

		default: /* not FEEDBACK-1 nor FEEDBACK-2 */
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "feedback type not implemented (%d)\n", feedback->type);
	}
}


/**
 * @brief Periodically change the context state after a certain number
 *        of packets.
 *
 * @param context The compression context
 */
void periodic_down_transition(struct c_context *context)
{
	struct c_generic_context *g_context;

	g_context = (struct c_generic_context *) context->specific;

	if(g_context->go_back_fo_count >=
	   context->compressor->periodic_refreshes_fo_timeout)
	{
		rohc_comp_debug(context, "periodic change to FO state\n");
		g_context->go_back_fo_count = 0;
		change_state(context, FO);
	}
	else if(g_context->go_back_ir_count >=
	        context->compressor->periodic_refreshes_ir_timeout)
	{
		rohc_comp_debug(context, "periodic change to IR state\n");
		g_context->go_back_ir_count = 0;
		change_state(context, IR);
	}

	if(context->state == SO)
	{
		g_context->go_back_fo_count++;
	}
	if(context->state == SO || context->state == FO)
	{
		g_context->go_back_ir_count++;
	}
}


/**
 * @brief Decide the state that should be used for the next packet.
 *
 * The three states are:\n
 *  - Initialization and Refresh (IR),\n
 *  - First Order (FO),\n
 *  - Second Order (SO).
 *
 * @param context The compression context
 */
void decide_state(struct c_context *const context)
{
	struct c_generic_context *g_context;
	rohc_c_state curr_state;
	rohc_c_state next_state;

	curr_state = context->state;
	g_context = (struct c_generic_context *) context->specific;

	if(curr_state == IR && g_context->ir_count >= MAX_IR_COUNT)
	{
		if(g_context->tmp.send_static)
		{
			rohc_comp_debug(context, "%d STATIC fields changed now or in the "
			                "last few packets, so stay in IR state\n",
			                g_context->tmp.send_static);
			next_state = IR;
		}
		else if(g_context->tmp.send_dynamic)
		{
			rohc_comp_debug(context, "no STATIC field, but %d DYNAMIC fields "
			                "changed now or in the last few packets, so go in "
			                "FO state\n", g_context->tmp.send_dynamic);
			next_state = FO;
		}
		else
		{
			rohc_comp_debug(context, "no STATIC nor DYNAMIC field changed in "
			                "the last few packets, so go in SO state\n");
			next_state = SO;
		}
	}
	else if(curr_state == FO && g_context->fo_count >= MAX_FO_COUNT)
	{
		if(g_context->tmp.send_static || g_context->tmp.send_dynamic)
		{
			rohc_comp_debug(context, "%d STATIC and %d DYNAMIC fields changed "
			                "now or in the last few packets, so stay in FO "
			                "state\n", g_context->tmp.send_static,
			                g_context->tmp.send_dynamic);
			next_state = FO;
		}
		else
		{
			rohc_comp_debug(context, "no STATIC nor DYNAMIC field changed in "
			                "the last few packets, so go in SO state\n");
			next_state = SO;
		}
	}
	else if(curr_state == SO)
	{
		if(g_context->tmp.send_static || g_context->tmp.send_dynamic)
		{
			rohc_comp_debug(context, "%d STATIC and %d DYNAMIC fields changed "
			                "now or in the last few packets, so go in FO "
			                "state\n", g_context->tmp.send_static,
			                g_context->tmp.send_dynamic);
			next_state = FO;
		}
		else
		{
			rohc_comp_debug(context, "no STATIC nor DYNAMIC field changed in "
			                "the last few packets, so stay in SO state\n");
			next_state = SO;
		}
	}
	else
	{
		next_state = curr_state;
	}

	change_state(context, next_state);

	if(context->mode == U_MODE)
	{
		periodic_down_transition(context);
	}
}


/**
 * @brief Decide which packet to send when in the different states.
 *
 * In IR state, IR packets are used. In FO and SO, the profile-specific
 * functions are called if they are defined, otherwise IR packets are used.
 *
 * @param context   The compression context
 * @param ip        The ip packet to compress
 * @param ip2       The inner ip packet
 * @return          \li The packet type among PACKET_IR, PACKET_IR_DYN,
 *                      PACKET_UO_0, PACKET_UO_1* and PACKET_UOR_2* in case
 *                      of success
 *                  \li PACKET_UNKNOWN in case of failure
 */
static rohc_packet_t decide_packet(const struct c_context *context,
                                   const struct ip_packet *ip,
                                   const struct ip_packet *ip2)
{
	struct c_generic_context *g_context;
	rohc_packet_t packet;
	bool is_fine;

	g_context = (struct c_generic_context *) context->specific;

	switch(context->state)
	{
		case IR:
		{
			rohc_comp_debug(context, "IR state\n");
			g_context->ir_count++;
			packet = PACKET_IR;
			break;
		}

		case FO:
		{
			rohc_comp_debug(context, "FO state\n");
			g_context->fo_count++;
			if(g_context->decide_FO_packet != NULL)
			{
				packet = g_context->decide_FO_packet(context);
			}
			else
			{
				packet = PACKET_IR;
			}
			break;
		}

		case SO:
		{
			rohc_comp_debug(context, "SO state\n");
			g_context->so_count++;
			if(g_context->decide_SO_packet != NULL)
			{
				packet = g_context->decide_SO_packet(context);
			}
			else
			{
				packet = PACKET_IR;
			}
			break;
		}

		default:
		{
			/* impossible value */
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            false, error,
			            "unknown state (%d), cannot determine packet type\n",
			            context->state);
		}
	}
	rohc_comp_debug(context, "packet '%s' chosen\n",
	                rohc_get_packet_descr(packet));

	/* IPv6 extension headers */
	if(g_context->ip_flags.version == IPV6)
	{
		/* update context with changes on the outer IPv6 extension headers */
		is_fine = rohc_list_decide_ipv6_compression(g_context->ip_flags.info.v6.ext_comp, ip);
		if(!is_fine)
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "failed to update context with changes on the outer "
			             "IPv6 extension headers\n");
			goto error;
		}
		/* does the current packet fit the changes on outer IPv6 extension
		 * headers? */
		if(packet != PACKET_IR && g_context->ip_flags.info.v6.ext_comp->changed)
		{
			rohc_comp_debug(context, "change packet type to IR-DYN because "
			                "outer IPv6 extension headers changed\n");
			packet = PACKET_IR_DYN;
		}
	}
	if(g_context->tmp.nr_of_ip_hdr > 1 && g_context->ip2_flags.version == IPV6)
	{
		/* update context with changes on the inner IPv6 extension headers */
		is_fine = rohc_list_decide_ipv6_compression(g_context->ip2_flags.info.v6.ext_comp, ip2);
		if(!is_fine)
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "failed to update context with changes on the inner "
			             "IPv6 extension headers\n");
			goto error;
		}
		/* does the current packet fit the changes on inner IPv6 extension
		 * headers? */
		if(packet != PACKET_IR && g_context->ip2_flags.info.v6.ext_comp->changed)
		{
			rohc_comp_debug(context, "change packet type to IR-DYN because "
			                "inner IPv6 extension headers changed\n");
			packet = PACKET_IR_DYN;
		}
	}

	return packet;

error:
	return PACKET_UNKNOWN;
}


/**
 * @brief Build the ROHC packet to send.
 *
 * @param context     The compression context
 * @param ip          The outer IP header
 * @param ip2         The inner IP header
 * @param next_header The next header such as UDP or UDP-Lite
 * @param dest        The rohc-packet-under-build buffer
 * @return            The position in the rohc-packet-under-build buffer
 *                    if successful, -1 otherwise
 */
int code_packet(struct c_context *const context,
                const struct ip_packet *ip,
                const struct ip_packet *ip2,
                const unsigned char *next_header,
                unsigned char *const dest)
{
	struct c_generic_context *g_context;
	int (*code_packet_type)(struct c_context *context,
	                        const struct ip_packet *ip,
	                        const struct ip_packet *ip2,
	                        const unsigned char *next_header,
	                        unsigned char *dest);

	g_context = (struct c_generic_context *) context->specific;

	switch(g_context->tmp.packet_type)
	{
		case PACKET_IR:
			code_packet_type = code_IR_packet;
			break;

		case PACKET_IR_DYN:
			code_packet_type = code_IR_DYN_packet;
			break;

		case PACKET_UO_0:
			code_packet_type = code_UO0_packet;
			break;

		case PACKET_UO_1:
		case PACKET_UO_1_RTP:
		case PACKET_UO_1_TS:
		case PACKET_UO_1_ID:
			code_packet_type = code_UO1_packet;
			break;

		case PACKET_UOR_2:
		case PACKET_UOR_2_RTP:
		case PACKET_UOR_2_TS:
		case PACKET_UOR_2_ID:
			code_packet_type = code_UO2_packet;
			break;

		default:
			rohc_comp_debug(context, "unknown packet, failure\n");
			goto error;
	}

	return code_packet_type(context, ip, ip2, next_header, dest);

error:
	return -1;
}


/**
 * @brief Build the IR packet.
 *
 * \verbatim

 IR packet (5.7.7.1):

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  |         Add-CID octet         |  if for small CIDs and CID != 0
    +---+---+---+---+---+---+---+---+
 2  | 1   1   1   1   1   1   0 | D |
    +---+---+---+---+---+---+---+---+
    |                               |
 3  /    0-2 octets of CID info     /  1-2 octets if for large CIDs
    |                               |
    +---+---+---+---+---+---+---+---+
 4  |            Profile            |  1 octet
    +---+---+---+---+---+---+---+---+
 5  |              CRC              |  1 octet
    +---+---+---+---+---+---+---+---+
    |                               |
 6  |         Static chain          |  variable length
    |                               |
    +---+---+---+---+---+---+---+---+
    |                               |
 7  |         Dynamic chain         |  present if D = 1, variable length
    |                               |
    +---+---+---+---+---+---+---+---+
 8  |             SN                |  2 octets if not RTP nor ESP
    +---+---+---+---+---+---+---+---+
    |                               |
    |           Payload             |  variable length
    |                               |
     - - - - - - - - - - - - - - - -

\endverbatim
 *
 * @param context      The compression context
 * @param ip           The outer IP header
 * @param ip2          The inner IP header
 * @param next_header  The next header data used to code the static and
 *                     dynamic parts of the next header for some profiles such
 *                     as UDP, UDP-Lite, and so on.
 * @param dest         The rohc-packet-under-build buffer
 * @return             The position in the rohc-packet-under-build buffer
 */
int code_IR_packet(struct c_context *const context,
                   const struct ip_packet *ip,
                   const struct ip_packet *ip2,
                   const unsigned char *next_header,
                   unsigned char *const dest)
{
	struct c_generic_context *g_context;
	int nr_of_ip_hdr;
	unsigned char type;
	int counter;
	int first_position;
	int crc_position;

	assert(context != NULL);
	assert(context->specific != NULL);

	g_context = (struct c_generic_context *) context->specific;
	nr_of_ip_hdr = g_context->tmp.nr_of_ip_hdr;

	assert(ip != NULL);
	assert((nr_of_ip_hdr == 1 && ip2 == NULL) ||
	       (nr_of_ip_hdr == 2 && ip2 != NULL));
	assert(g_context->tmp.nr_sn_bits == 16);
	assert((ip_get_version(ip) == IPV4 && g_context->tmp.nr_ip_id_bits <= 16) ||
	       (ip_get_version(ip) != IPV4 && g_context->tmp.nr_ip_id_bits == 0));
	assert((nr_of_ip_hdr == 1 && g_context->tmp.nr_ip_id_bits2 == 0) ||
	       (nr_of_ip_hdr == 2 && ip_get_version(ip2) == IPV4 &&
	        g_context->tmp.nr_ip_id_bits2 == 16) ||
	       (nr_of_ip_hdr == 2 && ip_get_version(ip2) != IPV4 &&
	        g_context->tmp.nr_ip_id_bits2 == 0));

	rohc_comp_debug(context, "code IR packet (CID = %d)\n", context->cid);

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - part 4 will start at 'counter'
	 */
	counter = code_cid_values(context->compressor->medium.cid_type, context->cid,
	                          dest, g_context->tmp.max_size, &first_position);

	/* initialize some profile-specific things when building an IR
	 * or IR-DYN packet */
	if(g_context->init_at_IR != NULL)
	{
		g_context->init_at_IR(context, next_header);
	}

	/* part 2: type of packet and D flag if dynamic part is included */
	type = 0xfc;
	type |= 1; /* D flag */
	rohc_comp_debug(context, "type of packet + D flag = 0x%02x\n", type);
	dest[first_position] = type;

	/* part 4 */
	rohc_comp_debug(context, "profile ID = 0x%02x\n", context->profile->id);
	dest[counter] = context->profile->id;
	counter++;

	/* part 5: the CRC is computed later since it must be computed
	 * over the whole packet with an empty CRC field */
	rohc_comp_debug(context, "CRC = 0x00 for CRC calculation\n");
	crc_position = counter;
	dest[counter] = 0;
	counter++;

	/* part 6: static part */
	counter = code_generic_static_part(context, &g_context->ip_flags,
	                                   ip, dest, counter);
	if(counter < 0)
	{
		goto error;
	}

	if(nr_of_ip_hdr > 1)
	{
		counter = code_generic_static_part(context, &g_context->ip2_flags,
		                                   ip2, dest, counter);
		if(counter < 0)
		{
			goto error;
		}
	}

	if(g_context->code_static_part != NULL && next_header != NULL)
	{
		/* static part of next header */
		counter = g_context->code_static_part(context, next_header,
		                                      dest, counter);
		if(counter < 0)
		{
			goto error;
		}
	}

	/* part 7: if we do not want dynamic part in IR packet, we should not
	 * send the following */
	counter = code_generic_dynamic_part(context, &g_context->ip_flags,
	                                    ip, dest, counter);
	if(counter < 0)
	{
		goto error;
	}

	if(nr_of_ip_hdr > 1)
	{
		counter = code_generic_dynamic_part(context, &g_context->ip2_flags,
		                                    ip2, dest, counter);
		if(counter < 0)
		{
			goto error;
		}
	}

	if(g_context->code_dynamic_part != NULL && next_header != NULL)
	{
		/* dynamic part of next header */
		counter = g_context->code_dynamic_part(context, next_header,
		                                       dest, counter);
		if(counter < 0)
		{
			goto error;
		}
	}

	/* part 8: IR remainder header */
	if(g_context->code_ir_remainder != NULL)
	{
		counter = g_context->code_ir_remainder(context, dest, counter);
		if(counter < 0)
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "failed to code IR remainder header\n");
			goto error;
		}
	}

	/* part 5 */
	dest[crc_position] = crc_calculate(ROHC_CRC_TYPE_8, dest, counter,
	                                   CRC_INIT_8,
	                                   context->compressor->crc_table_8);
	rohc_comp_debug(context, "CRC (header length = %d, crc = 0x%x)\n",
	                counter, dest[crc_position]);

error:
	return counter;
}


/**
 * @brief Build the IR-DYN packet.
 *
 * \verbatim

 IR-DYN packet (5.7.7.2):

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         : if for small CIDs and CID != 0
    +---+---+---+---+---+---+---+---+
 2  | 1   1   1   1   1   0   0   0 | IR-DYN packet type
    +---+---+---+---+---+---+---+---+
    :                               :
 3  /     0-2 octets of CID info    / 1-2 octets if for large CIDs
    :                               :
    +---+---+---+---+---+---+---+---+
 4  |            Profile            | 1 octet
    +---+---+---+---+---+---+---+---+
 5  |              CRC              | 1 octet
    +---+---+---+---+---+---+---+---+
    |                               |
 6  /         Dynamic chain         / variable length
    |                               |
    +---+---+---+---+---+---+---+---+
 7  |             SN                | 2 octets if not RTP nor ESP
    +---+---+---+---+---+---+---+---+
    :                               :
    /           Payload             / variable length
    :                               :
     - - - - - - - - - - - - - - - -

\endverbatim
 *
 * @param context      The compression context
 * @param ip           The outer IP header
 * @param ip2          The inner IP header
 * @param next_header  The next header data used to code the dynamic part
 *                     of the next header for some profiles such as UDP,
 *                     UDP-Lite, etc.
 * @param dest         The rohc-packet-under-build buffer
 * @return             The position in the rohc-packet-under-build buffer
 */
int code_IR_DYN_packet(struct c_context *const context,
                       const struct ip_packet *ip,
                       const struct ip_packet *ip2,
                       const unsigned char *next_header,
                       unsigned char *const dest)
{
	struct c_generic_context *g_context;
	int counter;
	int first_position;
	int crc_position;

	assert(context != NULL);
	assert(context->specific != NULL);

	g_context = (struct c_generic_context *) context->specific;

	rohc_comp_debug(context, "code IR-DYN packet (CID = %d)\n", context->cid);

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - part 4 will start at 'counter'
	 */
	counter = code_cid_values(context->compressor->medium.cid_type, context->cid,
	                          dest, g_context->tmp.max_size, &first_position);

	/* initialize some profile-specific things when building an IR
	 * or IR-DYN packet */
	if(g_context->init_at_IR != NULL)
	{
		g_context->init_at_IR(context, next_header);
	}

	/* part 2 */
	dest[first_position] = 0xf8;

	/* part 4 */
	dest[counter] = context->profile->id;
	counter++;

	/* part 5: the CRC is computed later since it must be computed
	 * over the whole packet with an empty CRC field */
	crc_position = counter;
	dest[counter] = 0;
	counter++;

	/* part 6: dynamic part of outer and inner IP header and dynamic part
	 * of next header */
	counter = code_generic_dynamic_part(context, &g_context->ip_flags,
	                                    ip, dest, counter);
	if(counter < 0)
	{
		goto error;
	}

	if(g_context->tmp.nr_of_ip_hdr > 1)
	{
		counter = code_generic_dynamic_part(context, &g_context->ip2_flags,
		                                    ip2, dest, counter);
		if(counter < 0)
		{
			goto error;
		}
	}

	if(g_context->code_dynamic_part != NULL && next_header != NULL)
	{
		/* dynamic part of next header */
		counter = g_context->code_dynamic_part(context, next_header, dest, counter);
		if(counter < 0)
		{
			goto error;
		}
	}

	/* part 7: IR-DYN remainder header */
	if(g_context->code_ir_remainder != NULL)
	{
		counter = g_context->code_ir_remainder(context, dest, counter);
		if(counter < 0)
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "failed to code IR-DYN remainder header\n");
			goto error;
		}
	}

	/* part 5 */
	dest[crc_position] = crc_calculate(ROHC_CRC_TYPE_8, dest, counter,
	                                   CRC_INIT_8,
	                                   context->compressor->crc_table_8);
	rohc_comp_debug(context, "CRC (header length = %d, crc = 0x%x)\n",
	                counter, dest[crc_position]);

error:
	return counter;
}


/**
 * @brief Build the static part of the IR and IR-DYN packets.
 *
 * @param context     The compression context
 * @param header_info The IP header info stored in the profile
 * @param ip          The IP header the static part is built for
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
int code_generic_static_part(const struct c_context *context,
                             struct ip_header_info *const header_info,
                             const struct ip_packet *ip,
                             unsigned char *const dest,
                             int counter)
{
	if(ip_get_version(ip) == IPV4)
	{
		counter = code_ipv4_static_part(context, header_info,
		                                ip, dest, counter);
	}
	else /* IPV6 */
	{
		counter = code_ipv6_static_part(context, header_info,
		                                ip, dest, counter);
	}

	return counter;
}


/**
 * @brief Build the IPv4 static part of the IR and IR-DYN packets.
 *
 * \verbatim

 Static part IPv4 (5.7.7.4):

    +---+---+---+---+---+---+---+---+
 1  |  Version = 4  |       0       |
    +---+---+---+---+---+---+---+---+
 2  |           Protocol            |
    +---+---+---+---+---+---+---+---+
 3  /        Source Address         /   4 octets
    +---+---+---+---+---+---+---+---+
 4  /      Destination Address      /   4 octets
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context     The compression context
 * @param header_info The IP header info stored in the profile
 * @param ip          The IPv4 header the static part is built for
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
int code_ipv4_static_part(const struct c_context *context,
                          struct ip_header_info *const header_info,
                          const struct ip_packet *ip,
                          unsigned char *const dest,
                          int counter)
{
	unsigned int protocol;
	uint32_t saddr;
	uint32_t daddr;

	/* part 1 */
	dest[counter] = 0x40;
	rohc_comp_debug(context, "version = 0x40\n");
	counter++;

	/* part 2 */
	protocol = ip_get_protocol(ip);
	rohc_comp_debug(context, "protocol = 0x%02x\n", protocol);
	dest[counter] = protocol;
	counter++;
	header_info->protocol_count++;

	/* part 3 */
	saddr = ipv4_get_saddr(ip);
	memcpy(&dest[counter], &saddr, 4);
	rohc_comp_debug(context, "src addr = " IPV4_ADDR_FORMAT "\n",
	                IPV4_ADDR_RAW(dest + counter));
	counter += 4;

	/* part 4 */
	daddr = ipv4_get_daddr(ip);
	memcpy(&dest[counter], &daddr, 4);
	rohc_comp_debug(context, "dst addr = " IPV4_ADDR_FORMAT "\n",
	                IPV4_ADDR_RAW(dest + counter));
	counter += 4;

	return counter;
}


/**
 * @brief Build the IPv6 static part of the IR and IR-DYN packets.
 *
 * \verbatim

 Static part IPv6 (5.7.7.3):

    +---+---+---+---+---+---+---+---+
 1  |  Version = 6  |Flow Label(msb)|   1 octet
    +---+---+---+---+---+---+---+---+
 2  /        Flow Label (lsb)       /   2 octets
    +---+---+---+---+---+---+---+---+
 3  |          Next Header          |   1 octet
    +---+---+---+---+---+---+---+---+
 4  /        Source Address         /   16 octets
    +---+---+---+---+---+---+---+---+
 5  /      Destination Address      /   16 octets
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context     The compression context
 * @param header_info The IP header info stored in the profile
 * @param ip          The IPv6 header the static part is built for
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
int code_ipv6_static_part(const struct c_context *context,
                          struct ip_header_info *const header_info,
                          const struct ip_packet *ip,
                          unsigned char *const dest,
                          int counter)
{
	unsigned int flow_label;
	unsigned int protocol;
	const struct ipv6_addr *saddr;
	const struct ipv6_addr *daddr;

	/* part 1 */
	flow_label = ipv6_get_flow_label(ip);
	dest[counter] = ((6 << 4) & 0xf0) | ((flow_label >> 16) & 0x0f);
	rohc_comp_debug(context, "version + flow label (msb) = 0x%02x\n",
	                dest[counter]);
	counter++;

	/* part 2 */
	dest[counter] = (flow_label >> 8) & 0xff;
	counter++;
	dest[counter] = flow_label & 0xff;
	counter++;
	rohc_comp_debug(context, "flow label (lsb) = 0x%02x%02x\n",
	                dest[counter - 2], dest[counter - 1]);

	/* part 3 */
	protocol = ip_get_protocol(ip);
	rohc_comp_debug(context, "next header = 0x%02x\n", protocol);
	dest[counter] = protocol;
	counter++;
	header_info->protocol_count++;

	/* part 4 */
	saddr = ipv6_get_saddr(ip);
	memcpy(&dest[counter], saddr, 16);
	rohc_comp_debug(context, "src addr = " IPV6_ADDR_FORMAT "\n",
	                IPV6_ADDR_IN6(saddr));
	counter += 16;

	/* part 5 */
	daddr = ipv6_get_daddr(ip);
	memcpy(&dest[counter], daddr, 16);
	rohc_comp_debug(context, "dst addr = " IPV6_ADDR_FORMAT "\n",
	                IPV6_ADDR_IN6(daddr));
	counter += 16;

	return counter;
}


/**
 * @brief Build the dynamic part of the IR and IR-DYN packets.
 *
 * @param context     The compression context
 * @param header_info The IP header info stored in the profile
 * @param ip          The IP header the dynamic part is built for
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer,
 *                    -1 in case of error
 */
int code_generic_dynamic_part(const struct c_context *context,
                              struct ip_header_info *const header_info,
                              const const struct ip_packet *ip,
                              unsigned char *const dest,
                              int counter)
{
	if(ip_get_version(ip) == IPV4)
	{
		counter = code_ipv4_dynamic_part(context, header_info,
		                                 ip, dest, counter);
	}
	else /* IPV6 */
	{
		counter = code_ipv6_dynamic_part(context, header_info,
		                                 ip, dest, counter);
	}

	return counter;
}


/**
 * @brief Build the IPv4 dynamic part of the IR and IR-DYN packets.
 *
 * \verbatim

 Dynamic part IPv4 (5.7.7.4):

    +---+---+---+---+---+---+---+---+
 1  |        Type of Service        |
   +---+---+---+---+---+---+---+---+
 2  |         Time to Live          |
    +---+---+---+---+---+---+---+---+
 3  /        Identification         /   2 octets
    +---+---+---+---+---+---+---+---+
 4  | DF|RND|NBO|         0         |
    +---+---+---+---+---+---+---+---+
 5  / Generic extension header list /  variable length
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context     The compression context
 * @param header_info The IP header info stored in the profile
 * @param ip          The IPv4 header the dynamic part is built for
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
int code_ipv4_dynamic_part(const struct c_context *const context,
                           struct ip_header_info *header_info,
                           const struct ip_packet *ip,
                           unsigned char *const dest,
                           int counter)
{
	unsigned int tos;
	unsigned int ttl;
	unsigned int df;
	unsigned char df_rnd_nbo;
	uint16_t id;

	/* part 1 */
	tos = ip_get_tos(ip);
	dest[counter] = tos;
	counter++;
	header_info->tos_count++;

	/* part 2 */
	ttl = ip_get_ttl(ip);
	dest[counter] = ttl;
	counter++;
	header_info->ttl_count++;

	/* part 3 */
	/* always transmit IP-ID in Network Byte Order */
	id = ipv4_get_id_nbo(ip, header_info->info.v4.nbo);
	memcpy(&dest[counter], &id, 2);
	counter += 2;

	/* part 4 */
	df = ipv4_get_df(ip);
	df_rnd_nbo = df << 7;
	if(header_info->info.v4.rnd)
	{
		df_rnd_nbo |= 0x40;
	}
	if(header_info->info.v4.nbo)
	{
		df_rnd_nbo |= 0x20;
	}

	dest[counter] = df_rnd_nbo;
	counter++;

	header_info->info.v4.df_count++;
	header_info->info.v4.rnd_count++;
	header_info->info.v4.nbo_count++;

	/* part 5 is not supported for the moment, but the field is mandatory,
	   so add a zero byte */
	dest[counter] = 0x00;
	counter++;

	rohc_comp_debug(context, "TOS = 0x%02x, TTL = 0x%02x, IP-ID = 0x%04x, "
	                "df_rnd_nbo = 0x%02x (DF = %d, RND = %d, NBO = %d)\n",
	                tos, ttl, id, df_rnd_nbo, df, header_info->info.v4.rnd,
	                header_info->info.v4.nbo);

	return counter;
}


/**
 * @brief Build the IPv6 dynamic part of the IR and IR-DYN packets.
 *
 * \verbatim

 Dynamic part IPv6 (5.7.7.3):

    +---+---+---+---+---+---+---+---+
 1  |         Traffic Class         |   1 octet
    +---+---+---+---+---+---+---+---+
 2  |           Hop Limit           |   1 octet
    +---+---+---+---+---+---+---+---+
 3  / Generic extension header list /   variable length
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context     The compression context
 * @param header_info The IP header info stored in the profile
 * @param ip          The IPv6 header the dynamic part is built for
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer,
 *                    -1 in case of error
 */
int code_ipv6_dynamic_part(const struct c_context *context,
                           struct ip_header_info *const header_info,
                           const struct ip_packet *ip,
                           unsigned char *const dest,
                           int counter)
{
	unsigned int tos;
	unsigned int ttl;
	int counter_org;
	int size;
	int size_dyn_ip6_part = 0;

	counter_org = counter;

	/* part 1 */
	tos = ip_get_tos(ip);
	dest[counter] = tos;
	counter++;
	header_info->tos_count++;
	size_dyn_ip6_part++;

	/* part 2 */
	ttl = ip_get_ttl(ip);
	dest[counter] = ttl;
	counter++;
	header_info->ttl_count++;
	size_dyn_ip6_part++;

	/* part 3: Generic extension header list */
	if(!header_info->info.v6.ext_comp->is_present)
	{
		/* no extension, write a zero byte in packet */
		rohc_comp_debug(context, "extension header list: no extension to encode\n");
		dest[counter] = 0x00;
		counter++;
		size_dyn_ip6_part++;
	}
	else if(!header_info->info.v6.ext_comp->changed)
	{
		/* extension list is present, but did not change */
		size = list_get_size(header_info->info.v6.ext_comp->ref_list);
		rohc_comp_debug(context, "extension header list: same extension than "
		                "previously\n");
		counter = rohc_list_encode(header_info->info.v6.ext_comp, dest, counter,
		                           0, size);
		if(counter < 0)
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "failed to encode list\n");
			goto error;
		}
	}
	else
	{
		/* extension list is present, and changed */
		rohc_comp_debug(context, "extension header list: there is an extension "
		                "to encode\n");
		size = list_get_size(header_info->info.v6.ext_comp->curr_list);
		counter = rohc_list_encode(header_info->info.v6.ext_comp, dest, counter,
		                           0, size);
		if(counter < 0)
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "failed to encode list\n");
			goto error;
		}
		size_dyn_ip6_part += counter - 2;
		size_dyn_ip6_part -= counter_org;
		rohc_comp_debug(context, "extension header list: compressed list "
		                "size = %d\n", size_dyn_ip6_part - 2);
	}

	rohc_comp_debug(context, "TC = 0x%02x, HL = 0x%02x, size of dynamic IPv6 "
	                "part = %d\n", tos, ttl, size_dyn_ip6_part);

	return counter;

error:
	return -1;
}


/**
 * @brief Build the tail of the UO packet.
 *
 * \verbatim

 The general format for the UO packets is:

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :                    |
    +---+---+---+---+---+---+---+---+                    |
 2  |   first octet of base header  |                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 3  /   0, 1, or 2 octets of CID    /                    |
    :                               :                    |
    +---+---+---+---+---+---+---+---+                    |
 4  /   remainder of base header    /                    |
    +---+---+---+---+---+---+---+---+                    |
    :                               :                    |
 5  /           Extension           /                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 6  +   IP-ID of outer IPv4 header  +
    :                               :     (see section 5.7 or [RFC-3095])
     --- --- --- --- --- --- --- ---
 7  /    AH data for outer list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 8  +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 9  +   IP-ID of inner IPv4 header  +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---                     |
 10 /    AH data for inner list     /                    |
     --- --- --- --- --- --- --- ---                     |
    :                               :                    |
 11 +         GRE checksum          +                    |
    :                               :                    |
     --- --- --- --- --- --- --- ---
    :            List of            :
 12 /        Dynamic chains         /  variable, given by static chain
    :   for additional IP headers   :  (includes no SN)
     --- --- --- --- --- --- --- ---

     --- --- --- --- --- --- --- ---
    :                               :  RTP/UDP profiles only [RFC-3095]
 13 +         UDP Checksum          +  2 octets,
    :                               :  if context(UDP Checksum) != 0
     --- --- --- --- --- --- --- ---

\endverbatim
 *
 * Parts 7, 8, 10, 11 and 12 are not supported. Parts 1, 2, 3, 4 and 5 are
 * built in packet-specific functions. Parts 6 and 9 are built in this
 * function. Part 13 is built in profile-specific function.
 *
 * @param context     The compression context
 * @param ip          The outer IP header
 * @param ip2         The inner IP header
 * @param next_header The next header such as UDP or UDP-Lite
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
int code_uo_remainder(struct c_context *const context,
                      const struct ip_packet *ip,
                      const struct ip_packet *ip2,
                      const unsigned char *next_header,
                      unsigned char *const dest,
                      int counter)
{
	struct c_generic_context *g_context;
	uint16_t id;

	g_context = (struct c_generic_context *) context->specific;

	/* parts 6: only IPv4 */
	if(ip_get_version(ip) == IPV4 && g_context->ip_flags.info.v4.rnd == 1)
	{
		/* do not care of Network Byte Order because IP-ID is random */
		id = ipv4_get_id(ip);
		memcpy(&dest[counter], &id, 2);
		rohc_comp_debug(context, "outer IP-ID = 0x%04x\n", id);
		counter += 2;
	}

	/* parts 7 and 8 are not supported */

	/* step 9: only IPv4 */
	if(g_context->tmp.nr_of_ip_hdr > 1 && ip_get_version(ip2) == IPV4 &&
	   g_context->ip2_flags.info.v4.rnd == 1)
	{
		/* do not care of Network Byte Order because IP-ID is random */
		id = ipv4_get_id(ip2);
		memcpy(&dest[counter], &id, 2);
		rohc_comp_debug(context, "inner IP-ID = 0x%04x\n", id);
		counter += 2;
	}

	/* parts 10, 11 and 12 are not supported */

	/* part 13 */
	/* add fields related to the next header */
	if(g_context->code_uo_remainder != NULL && next_header != NULL)
	{
		counter = g_context->code_uo_remainder(context, next_header,
		                                         dest, counter);
	}

	return counter;
}


/**
 * @brief Build the UO-0 packet.
 *
 * \verbatim

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :
    +---+---+---+---+---+---+---+---+
 2  |   first octet of base header  |
    +---+---+---+---+---+---+---+---+
    :                               :
 3  /   0, 1, or 2 octets of CID    /
    :                               :
    +---+---+---+---+---+---+---+---+

 UO-0 (5.7.1)

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 0 |      SN       |    CRC    |
    +===+===+===+===+===+===+===+===+

\endverbatim
 *
 * @param context      The compression context
 * @param ip           The outer IP header
 * @param ip2          The inner IP header
 * @param next_header  The next header such as UDP or UDP-Lite
 * @param dest         The rohc-packet-under-build buffer
 * @return             The position in the rohc-packet-under-build buffer
 *                     if successful, -1 otherwise
 */
int code_UO0_packet(struct c_context *const context,
                    const struct ip_packet *ip,
                    const struct ip_packet *ip2,
                    const unsigned char *next_header,
                    unsigned char *const dest)
{
	int counter;
	int first_position;
	unsigned char f_byte;
	struct c_generic_context *g_context;
	unsigned int crc;
	const unsigned char *ip2_hdr;

	g_context = (struct c_generic_context *) context->specific;

	rohc_comp_debug(context, "code UO-0 packet (CID = %d)\n", context->cid);

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - part 4 will start at 'counter'
	 */
	counter = code_cid_values(context->compressor->medium.cid_type, context->cid,
	                          dest, g_context->tmp.max_size, &first_position);

	/* build the UO head if necessary */
	if(g_context->code_UO_packet_head != NULL && next_header != NULL)
	{
		counter = g_context->code_UO_packet_head(context, next_header,
		                                         dest, counter, &first_position);
	}

	/* part 2: SN + CRC
	 * TODO: The CRC should be computed only on the CRC-DYNAMIC fields
	 * if the CRC-STATIC fields did not change */
	f_byte = (g_context->sn & 0x0f) << 3;
	crc = CRC_INIT_3;
	ip2_hdr = (g_context->tmp.nr_of_ip_hdr > 1) ? ip2->data : NULL;
	crc = g_context->compute_crc_static(ip_get_raw_data(ip), ip2_hdr, next_header,
	                                    ROHC_CRC_TYPE_3, crc,
	                                    context->compressor->crc_table_3);
	crc = g_context->compute_crc_dynamic(ip_get_raw_data(ip), ip2_hdr, next_header,
	                                     ROHC_CRC_TYPE_3, crc,
	                                     context->compressor->crc_table_3);
	f_byte |= crc;
	rohc_comp_debug(context, "first byte = 0x%02x (CRC = 0x%x)\n", f_byte, crc);
	dest[first_position] = f_byte;

	/* build the UO tail */
	counter = code_uo_remainder(context, ip, ip2, next_header, dest, counter);

	return counter;
}


/**
 * @brief Build the UO-1 packet.
 *
 * UO-1 and UO-1-ID cannot be used if there is no IPv4 header in the context or
 * if value(RND) and value(RND2) are both 1.
 *
 * @todo Handle extension (X bit) for UO-1-ID packet
 *
 * \verbatim

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :
    +---+---+---+---+---+---+---+---+
 2  |   first octet of base header  |
    +---+---+---+---+---+---+---+---+
    :                               :
 3  /   0, 1, or 2 octets of CID    /
    :                               :
    +---+---+---+---+---+---+---+---+

 UO-1 (5.11.3):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   0 |         IP-ID         |
    +===+===+===+===+===+===+===+===+
 4  |        SN         |    CRC    |
    +---+---+---+---+---+---+---+---+

 UO-1-RTP (5.7.3):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   0 |          TS           |
    +===+===+===+===+===+===+===+===+
 4  | M |      SN       |    CRC    |
    +---+---+---+---+---+---+---+---+

 UO-1-ID (5.7.3):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   0 |T=0|      IP-ID        |
    +===+===+===+===+===+===+===+===+
 4  | X |      SN       |    CRC    |
    +---+---+---+---+---+---+---+---+

 UO-1-TS (5.7.3):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   0 |T=1|        TS         |
    +===+===+===+===+===+===+===+===+
 4  | M |      SN       |    CRC    |
    +---+---+---+---+---+---+---+---+

 X: X = 0 indicates that no extension is present;
    X = 1 indicates that an extension is present.

 T: T = 0 indicates format UO-1-ID;
    T = 1 indicates format UO-1-TS.

\endverbatim
 *
 * @param context      The compression context
 * @param ip           The outer IP header
 * @param ip2          The inner IP header
 * @param next_header  The next header such as UDP or UDP-Lite
 * @param dest         The rohc-packet-under-build buffer
 * @return             The position in the rohc-packet-under-build buffer
 *                     if successful, -1 otherwise
 */
int code_UO1_packet(struct c_context *const context,
                    const struct ip_packet *ip,
                    const struct ip_packet *ip2,
                    const unsigned char *next_header,
                    unsigned char *const dest)
{
	int counter;
	int first_position;
	unsigned char f_byte;
	unsigned char s_byte;
	struct c_generic_context *g_context;
	rohc_packet_t packet_type;
	int is_ip_v4;
	int is_rtp;
	struct sc_rtp_context *rtp_context;
	unsigned int crc;
	const unsigned char *ip2_hdr;

	g_context = (struct c_generic_context *) context->specific;
	packet_type = g_context->tmp.packet_type;
	is_ip_v4 = g_context->ip_flags.version == IPV4;
	is_rtp = context->profile->id == ROHC_PROFILE_RTP;
	rtp_context = (struct sc_rtp_context *) g_context->specific;

	switch(packet_type)
	{
		case PACKET_UO_1:
			rohc_comp_debug(context, "code UO-1 packet (CID = %d)\n", context->cid);
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            is_ip_v4, error, "UO-1 packet is for IPv4 only\n");
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            !is_rtp, error, "UO-1 packet is for non-RTP profiles\n");
			break;
		case PACKET_UO_1_RTP:
			rohc_comp_debug(context, "code UO-1-RTP packet (CID = %d)\n",
			                context->cid);
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            is_rtp, error, "UO-1-RTP packet is for RTP profile only\n");
			break;
		case PACKET_UO_1_ID:
			rohc_comp_debug(context, "code UO-1-ID packet (CID = %d)\n",
			                context->cid);
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            is_ip_v4, error, "UO-1-ID packet is for IPv4 only\n");
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            is_rtp, error, "UO-1-ID packet is for RTP profile only\n");
			/* TODO: when extensions are supported within the UO-1-ID packet,
			 * please check whether the "m_set != 0" condition could be removed
			 * or not */
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            rtp_context->tmp.m_set == 0, error,
			            "UO-1-ID packet without extension support does not "
			            "contain room for the RTP Marker (M) flag\n");
			break;
		case PACKET_UO_1_TS:
			rohc_comp_debug(context, "code UO-1-TS packet (CID = %d)\n",
			                context->cid);
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            is_rtp, error, "UO-1-TS packet is for RTP profile only\n");
			break;
		default:
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            false, error, "bad packet type (%d)\n", packet_type);
			goto error;
	}

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - part 4 will start at 'counter'
	 */
	counter = code_cid_values(context->compressor->medium.cid_type, context->cid,
	                          dest, g_context->tmp.max_size, &first_position);

	/* build the UO head if necessary */
	if(g_context->code_UO_packet_head != NULL && next_header != NULL)
	{
		counter = g_context->code_UO_packet_head(context, next_header,
		                                         dest, counter, &first_position);
	}

	/* part 2 */
	switch(packet_type)
	{
		case PACKET_UO_1:
			f_byte = g_context->ip_flags.info.v4.id_delta & 0x3f;
			break;
		case PACKET_UO_1_RTP:
			f_byte = rtp_context->tmp.ts_send & 0x3f;
			break;
		case PACKET_UO_1_ID:
			f_byte = g_context->ip_flags.info.v4.id_delta & 0x1f;
			break;
		case PACKET_UO_1_TS:
			f_byte = rtp_context->tmp.ts_send & 0x1f;
			f_byte |= 0x20;
			break;
		default:
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            false, error, "bad packet type (%d)\n", packet_type);
	}
	f_byte |= 0x80;
	dest[first_position] = f_byte;
	rohc_comp_debug(context, "1 0 + T + TS/IP-ID = 0x%02x\n", f_byte);

	/* part 4: (M / X +) SN + CRC
	 * TODO: The CRC should be computed only on the CRC-DYNAMIC fields
	 * if the CRC-STATIC fields did not change */
	crc = CRC_INIT_3;
	ip2_hdr = (g_context->tmp.nr_of_ip_hdr > 1) ? ip2->data : NULL;
	crc = g_context->compute_crc_static(ip_get_raw_data(ip), ip2_hdr, next_header,
	                                    ROHC_CRC_TYPE_3, crc,
	                                    context->compressor->crc_table_3);
	crc = g_context->compute_crc_dynamic(ip_get_raw_data(ip), ip2_hdr, next_header,
	                                     ROHC_CRC_TYPE_3, crc,
	                                     context->compressor->crc_table_3);
	s_byte = crc & 0x07;
	switch(packet_type)
	{
		case PACKET_UO_1:
			/* SN + CRC (CRC was added before) */
			s_byte |= (g_context->sn & 0x1f) << 3;
			rohc_comp_debug(context, "SN (%d) + CRC (%x) = 0x%02x\n",
			                g_context->sn, crc, s_byte);
			break;
		case PACKET_UO_1_RTP:
		case PACKET_UO_1_TS:
			/* M + SN + CRC (CRC was added before) */
			s_byte |= (rtp_context->tmp.m_set & 0x01) << 7;
			s_byte |= (g_context->sn & 0x0f) << 3;
			rohc_comp_debug(context, "M (%d) + SN (%d) + CRC (%x) = 0x%02x\n",
			                rtp_context->tmp.m_set, g_context->sn & 0x0f, crc,
			                s_byte);
			break;
		case PACKET_UO_1_ID:
			/* X + SN + CRC (CRC was added before) */
			s_byte |= (g_context->sn & 0x0f) << 3;
			s_byte |= (0 /* TODO: handle X bit */ & 0x01) << 7;
			rohc_comp_debug(context, "X (%d) + SN (%u) + CRC (0x%x) = 0x%02x\n",
			                0 /* TODO: handle X bit */, g_context->sn & 0x0f,
			                crc, s_byte);
			break;
		default:
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            false, error, "bad packet type (%d)\n", packet_type);
	}
	dest[counter] = s_byte;
	counter++;

	/* build the UO tail */
	counter = code_uo_remainder(context, ip, ip2, next_header, dest, counter);

	return counter;

error:
	return -1;
}


/**
 * @brief Build the UO-2 packet.
 *
 * \verbatim

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  :         Add-CID octet         :
    +---+---+---+---+---+---+---+---+
 2  |   first octet of base header  |
    +---+---+---+---+---+---+---+---+
    :                               :
 3  /   0, 1, or 2 octets of CID    /
    :                               :
    +---+---+---+---+---+---+---+---+

 UOR-2 (5.11.3):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   1   0 |        SN         |
    +===+===+===+===+===+===+===+===+
 5  | X |            CRC            |
    +---+---+---+---+---+---+---+---+

 UOR-2-RTP (5.7.4):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   1   0 |        TS         |
    +===+===+===+===+===+===+===+===+
 4  | TS| M |       SN              |
    +---+---+---+---+---+---+---+---+
 5  | X |            CRC            |
    +---+---+---+---+---+---+---+---+

 UOR-2-TS (5.7.4):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   1   0 |        TS         |
    +===+===+===+===+===+===+===+===+
 4  |T=1| M |          SN           |
    +---+---+---+---+---+---+---+---+
 5  | X |           CRC             |
    +---+---+---+---+---+---+---+---+

 UOR-2-ID (5.7.4):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   1   0 |      IP-ID        |
    +===+===+===+===+===+===+===+===+
 4  |T=0| M |          SN           |
    +---+---+---+---+---+---+---+---+
 5  | X |           CRC             |
    +---+---+---+---+---+---+---+---+

    +---+---+---+---+---+---+---+---+
    :                               :
 6  /           Extension           /
    :                               :
     --- --- --- --- --- --- --- ---

 X: X = 0 indicates that no extension is present;
    X = 1 indicates that an extension is present.

 T: T = 0 indicates format UOR-2-ID;
    T = 1 indicates format UOR-2-TS.

\endverbatim
 *
 * @param context      The compression context
 * @param ip           The outer IP header
 * @param ip2          The inner IP header
 * @param next_header  The next header such as UDP or UDP-Lite
 * @param dest         The rohc-packet-under-build buffer
 * @return             The position in the rohc-packet-under-build buffer
 *                     if successful, -1 otherwise
 */
int code_UO2_packet(struct c_context *const context,
                    const struct ip_packet *ip,
                    const struct ip_packet *ip2,
                    const unsigned char *next_header,
                    unsigned char *const dest)
{
	unsigned char f_byte;     /* part 2 */
	unsigned char s_byte = 0; /* part 4 */
	unsigned char t_byte = 0; /* part 5 */
	int counter;
	int first_position;
	int s_byte_position = 0;
	int t_byte_position;
	rohc_ext_t extension;
	struct c_generic_context *g_context;
	rohc_packet_t packet_type;
	int is_rtp;
	unsigned int crc;
	unsigned int crc_type;
	unsigned char *crc_table;
	const unsigned char *ip2_hdr;
	int (*code_bytes)(const struct c_context *context,
	                  const rohc_ext_t extension,
	                  unsigned char *const f_byte,
	                  unsigned char *const s_byte,
	                  unsigned char *const t_byte);

	g_context = (struct c_generic_context *) context->specific;
	is_rtp = context->profile->id == ROHC_PROFILE_RTP;
	packet_type = g_context->tmp.packet_type;

	switch(packet_type)
	{
		case PACKET_UOR_2:
			rohc_comp_debug(context, "code UOR-2 packet (CID = %d)\n",
			                context->cid);
			code_bytes = code_UOR2_bytes;
			break;
		case PACKET_UOR_2_RTP:
			rohc_comp_debug(context, "code UOR-2-RTP packet (CID = %d)\n",
			                context->cid);
			code_bytes = code_UOR2_RTP_bytes;
			break;
		case PACKET_UOR_2_ID:
			rohc_comp_debug(context, "code UOR-2-ID packet (CID = %d)\n",
			                context->cid);
			code_bytes = code_UOR2_ID_bytes;
			break;
		case PACKET_UOR_2_TS:
			rohc_comp_debug(context, "code UOR-2-TS packet (CID = %d)\n",
			                context->cid);
			code_bytes = code_UOR2_TS_bytes;
			break;
		default:
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            false, error, "bad packet type (%d)\n", packet_type);
	}

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - parts 4/5 will start at 'counter'
	 */
	counter = code_cid_values(context->compressor->medium.cid_type, context->cid,
	                          dest, g_context->tmp.max_size, &first_position);

	/* build the UO head if necessary */
	if(g_context->code_UO_packet_head != NULL && next_header != NULL)
	{
		counter = g_context->code_UO_packet_head(context, next_header,
		                                         dest, counter, &first_position);
	}

	/* part 2: to be continued, we need to add the 5 bits of SN */
	f_byte = 0xc0; /* 1 1 0 x x x x x */

	/* part 4: remember the position of the second byte for future completion
	 *         (RTP only) */
	if(is_rtp)
	{
		s_byte_position = counter;
		counter++;
	}

	/* part 5: partially calculate the third byte, then remember the position
	 *         of the third byte, its final value is currently unknown
	 *
	 * TODO: The CRC should be computed only on the CRC-DYNAMIC fields
	 * if the CRC-STATIC fields did not change */
	crc = CRC_INIT_7;
	crc_type = ROHC_CRC_TYPE_7;
	crc_table = context->compressor->crc_table_7;
#if defined(RTP_BIT_TYPE) && RTP_BIT_TYPE
	if(is_rtp)
	{
		crc = CRC_INIT_6;
		crc_type = ROHC_CRC_TYPE_6;
		crc_table = context->compressor->crc_table_6;
	}
#endif
	ip2_hdr = (g_context->tmp.nr_of_ip_hdr > 1) ? ip2->data : NULL;
	/* compute CRC on CRC-STATIC fields */
	crc = g_context->compute_crc_static(ip_get_raw_data(ip), ip2_hdr, next_header,
	                                    crc_type, crc, crc_table);
	/* compute CRC on CRC-DYNAMIC fields */
	crc = g_context->compute_crc_dynamic(ip_get_raw_data(ip), ip2_hdr, next_header,
	                                     crc_type, crc, crc_table);
	t_byte = crc;
	t_byte_position = counter;
	counter++;

	/* part 6: decide which extension to use */
	extension = g_context->decide_extension(context);
	if(extension == PACKET_EXT_UNKNOWN)
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "failed to determine the extension to code\n");
		goto error;
	}
	rohc_comp_debug(context, "extension '%s' chosen\n",
	                rohc_get_ext_descr(extension));

	/* parts 2, 4, 5: complete the three packet-specific bytes and copy them
	 * in packet */
	if(!code_bytes(context, extension, &f_byte, &s_byte, &t_byte))
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "cannot code some UOR-2-* fields\n");
		goto error;
	}

	dest[first_position] = f_byte;
	rohc_comp_debug(context, "f_byte = 0x%02x\n", f_byte);
	if(is_rtp)
	{
		dest[s_byte_position] = s_byte;
		rohc_comp_debug(context, "s_byte = 0x%02x\n", s_byte);
	}
	dest[t_byte_position] = t_byte;
	rohc_comp_debug(context, "t_byte = 0x%02x\n", t_byte);

	/* part 6: code extension */
	switch(extension)
	{
		case PACKET_NOEXT:
			break;
		case PACKET_EXT_0:
			counter = code_EXT0_packet(context, dest, counter);
			break;
		case PACKET_EXT_1:
			counter = code_EXT1_packet(context, dest, counter);
			break;
		case PACKET_EXT_2:
			counter = code_EXT2_packet(context, dest, counter);
			break;
		case PACKET_EXT_3:
			counter = code_EXT3_packet(context, ip, ip2, dest, counter);
			break;
		default:
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "unknown extension (%d)\n", extension);
			goto error;
	}

	if(counter < 0)
	{
		rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		             "cannot build extension\n");
		goto error;
	}

	/* build the UO tail */
	counter = code_uo_remainder(context, ip, ip2, next_header, dest, counter);

	return counter;

error:
	return -1;
}


/**
 * @brief Code some fields of the UOR-2 packet
 *
 * This function is called by code_UO2_packet. It should not be called
 * directly.
 *
 * @see code_UO2_packet
 *
 * \verbatim

 UOR-2 (5.11.3):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   1   0 |        SN         |
    +===+===+===+===+===+===+===+===+
 5  | X |            CRC            |
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context      The compression context
 * @param extension    The extension that will be appended to the packet
 * @param f_byte       IN/OUT: The first byte of the UOR-2 packet
 * @param s_byte       IN/OUT: Not used by the UOR-2 packet
 * @param t_byte       IN/OUT: The second byte of the UOR-2 packet
 * @return             1 if successful, 0 otherwise
 */
int code_UOR2_bytes(const struct c_context *context,
                    const rohc_ext_t extension,
                    unsigned char *const f_byte,
                    unsigned char *const s_byte,
                    unsigned char *const t_byte)
{
	struct c_generic_context *g_context;

	g_context = (struct c_generic_context *) context->specific;

	switch(extension)
	{
		case PACKET_NOEXT:
		{
			rohc_comp_debug(context, "code UOR-2 packet with no extension\n");

			/* part 2: SN bits */
			assert(g_context->tmp.nr_sn_bits <= 5);
			*f_byte |= g_context->sn & 0x1f;

			/* part 5: set the X bit to 0 */
			*t_byte &= ~0x80;

			break;
		}

		case PACKET_EXT_0:
		{
			rohc_comp_debug(context, "code UOR-2 packet with extension 0\n");

			/* part 2 */
			assert(g_context->tmp.nr_sn_bits <= (5 + 3));
			*f_byte |= (g_context->sn & 0xff) >> 3;

			/* part 5: set the X bit to 1 */
			*t_byte |= 0x80;

			break;
		}

		case PACKET_EXT_1:
		{
			rohc_comp_debug(context, "code UOR-2 packet with extension 1\n");

			/* part 2 */
			assert(g_context->tmp.nr_sn_bits <= (5 + 3));
			*f_byte |= (g_context->sn & 0xff) >> 3;

			/* part 5: set the X bit to 1 */
			*t_byte |= 0x80;

			break;
		}

		case PACKET_EXT_2:
		{
			rohc_comp_debug(context, "code UOR-2 packet with extension 2\n");

			/* part 2 */
			assert(g_context->tmp.nr_sn_bits <= (5 + 3));
			*f_byte |= (g_context->sn & 0xff) >> 3;

			/* part 5: set the X bit to 1 */
			*t_byte |= 0x80;

			break;
		}

		case PACKET_EXT_3:
		{
			rohc_comp_debug(context, "code UOR-2 packet with extension 3\n");

			/* part 2: check if the s-field needs to be used */
			if(g_context->tmp.nr_sn_bits <= 5)
			{
				*f_byte |= g_context->sn & 0x1f;
			}
			else
			{
				assert(g_context->tmp.nr_sn_bits <= (5 + 8));
				*f_byte |= g_context->sn >> 8;
			}

			/* part 5: set the X bit to 1 */
			*t_byte |= 0x80;

			break;
		}

		default:
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "unknown extension (%d)\n", extension);
			goto error;
		}
	}

	return 1;

error:
	return 0;
}


/**
 * @brief Code some fields of the UOR-2-RTP packet
 *
 * This function is called by code_UO2_packet. It should not be called
 * directly.
 *
 * @see code_UO2_packet
 *
 * \verbatim

 UOR-2-RTP (5.7.4):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   1   0 |        TS         |
    +===+===+===+===+===+===+===+===+
 4  | TS| M |       SN              |
    +---+---+---+---+---+---+---+---+
 5  | X |            CRC            |
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context    The compression context
 * @param extension  The extension that will be appended to the packet
 * @param f_byte     IN/OUT: The first byte of the UOR-2-RTP packet
 * @param s_byte     IN/OUT: The second byte of the UOR-2-RTP packet
 * @param t_byte     IN/OUT: The third byte of the UOR-2-RTP packet
 * @return           1 if successful, 0 otherwise
 */
int code_UOR2_RTP_bytes(const struct c_context *context,
                        const rohc_ext_t extension,
                        unsigned char *const f_byte,
                        unsigned char *const s_byte,
                        unsigned char *const t_byte)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
#if defined(RTP_BIT_TYPE) && RTP_BIT_TYPE
	const int rtp_type_bit = 0;
#endif
	uint32_t ts_send;
	uint32_t ts_mask;

	g_context = (struct c_generic_context *) context->specific;
	rtp_context = (struct sc_rtp_context *) g_context->specific;
	ts_send = rtp_context->tmp.ts_send;

	/* UOR-2-RTP cannot be used if the context contains at least one IPv4
	 * header with value(RND) = 0. */
	if(g_context->tmp.nr_of_ip_hdr == 1)
	{
		/* only one IP header: it must not be IPv4 with non-random IP-ID */
		assert(g_context->ip_flags.version != IPV4 ||
		       g_context->ip_flags.info.v4.rnd == 1);
	}
	else
	{
		/* 2 IP headers: none of them must be IPv4 with non-random IP-ID */
		assert(g_context->ip_flags.version != IPV4 ||
		       g_context->ip_flags.info.v4.rnd == 1);
		assert(g_context->ip2_flags.version != IPV4 ||
		       g_context->ip2_flags.info.v4.rnd == 1);
	}

	/* which extension to code? */
	switch(extension)
	{
		case PACKET_NOEXT:
		{
			rohc_comp_debug(context, "code UOR-2-RTP packet with no extension\n");

			/* part 2: 5 bits of 6-bit TS */
			/* (be sure not to send bad TS bits because of the shift) */
			ts_mask = 1 << (32 - 1);
			ts_mask -= 1;
			ts_mask = 0x1f & (((uint32_t) (1 << (32 - 1))) - 1);
			*f_byte |= (ts_send >> 1) & ts_mask;

			/* part 4: last TS bit + M flag + 6 bits of 6-bit SN */
			*s_byte |= (ts_send & 0x01) << 7;
			*s_byte |= (rtp_context->tmp.m_set & 0x01) << 6;
			assert(g_context->tmp.nr_sn_bits <= 6);
			*s_byte |= g_context->sn & 0x3f;
			rohc_comp_debug(context, "6 bits of 6-bit SN = 0x%x\n",
			                (*s_byte) & 0x3f);

			/* part 5: set the X bit to 0 + type_bit to 0 */
			*t_byte &= ~0x80;
#if defined(RTP_BIT_TYPE) && RTP_BIT_TYPE
			*t_byte |= (rtp_type_bit & 0x01) << 6;
#endif
			break;
		}

		case PACKET_EXT_0:
		{
			rohc_comp_debug(context, "code UOR-2-RTP packet with extension 0\n");

			/* part 2: 5 bits of 9-bit TS */
			/* (be sure not to send bad TS bits because of the shift) */
			ts_mask = 0x1f & ((1 << (32 - 3 - 1)) - 1);
			*f_byte |= (ts_send >> 4) & ts_mask;

			/* part 4: 1 more bit of TS + M flag + 6 bits of 9-bit SN */
			*s_byte |= ((ts_send >> 3) & 0x01) << 7;
			*s_byte |= (rtp_context->tmp.m_set & 0x01) << 6;
			assert(g_context->tmp.nr_sn_bits <= (6 + 3));
			*s_byte |= (g_context->sn >> 3) & 0x3f;
			rohc_comp_debug(context, "6 bits of 9-bit SN = 0x%x\n",
			                (*s_byte) & 0x3f);

			/* part 5: set the X bit to 1 + type_bit to 0 */
			*t_byte |= 0x80;
#if defined(RTP_BIT_TYPE) && RTP_BIT_TYPE
			*t_byte |= (rtp_type_bit & 0x01) << 6;
#endif
			break;
		}

		case PACKET_EXT_1:
		{
			rohc_comp_debug(context, "code UOR-2-RTP packet with extension 1\n");

			/* part 2: 5 bits of 17-bit TS */
			/* (be sure not to send bad TS bits because of the shift) */
			ts_mask = 0x1f & ((1 << (32 - 12 - 1)) - 1);
			*f_byte |= (ts_send >> 12) & ts_mask;

			/* part 4: 1 more bit of TS + M flag + 6 bits of 9-bit SN */
			*s_byte |= ((ts_send >> 11) & 0x01) << 7;
			*s_byte |= (rtp_context->tmp.m_set & 0x01) << 6;
			assert(g_context->tmp.nr_sn_bits <= (6 + 3));
			*s_byte |= (g_context->sn >> 3) & 0x3f;
			rohc_comp_debug(context, "6 bits of 9-bit SN = 0x%x\n",
			                (*s_byte) & 0x3f);

			/* part 5: set the X bit to 1 + type_bit to 0 */
			*t_byte |= 0x80;
#if defined(RTP_BIT_TYPE) && RTP_BIT_TYPE
			*t_byte |= (rtp_type_bit & 0x01) << 6;
#endif
			break;
		}

		case PACKET_EXT_2:
		{
			rohc_comp_debug(context, "code UOR-2-RTP packet with extension 2\n");

			/* part 2: 5 bits of 25-bit TS */
			/* (be sure not to send bad TS bits because of the shift) */
			ts_mask = 0x1f & ((1 << (32 - 19 - 1)) - 1);
			*f_byte |= (ts_send >> 20) & ts_mask;

			/* part 4: 1 more bit of TS + M flag + 6 bits of 9-bit SN */
			*s_byte |= ((ts_send >> 19) & 0x01) << 7;
			*s_byte |= (rtp_context->tmp.m_set & 0x01) << 6;
			assert(g_context->tmp.nr_sn_bits <= (6 + 3));
			*s_byte |= (g_context->sn >> 3) & 0x3f;
			rohc_comp_debug(context, "6 bits of 9-bit SN = 0x%x\n",
			                (*s_byte) & 0x3f);

			/* part 5: set the X bit to 1 + type_bit to 0 */
			*t_byte |= 0x80;
#if defined(RTP_BIT_TYPE) && RTP_BIT_TYPE
			*t_byte |= (rtp_type_bit & 0x01) << 6;
#endif
			break;
		}

		case PACKET_EXT_3:
		{
			const size_t nr_ts_bits = rtp_context->tmp.nr_ts_bits;
			size_t nr_ts_bits_ext3; /* number of bits to send in EXT 3 */
			uint8_t ts_bits_for_f_byte;

			rohc_comp_debug(context, "code UOR-2-RTP packet with extension 3\n");

			/* part 2: 5 bits of TS */
			rohc_comp_debug(context, "TS to send = 0x%x\n", ts_send);
			nr_ts_bits_ext3 = sdvl_get_min_len(nr_ts_bits, 6);
			assert(nr_ts_bits_ext3 <= nr_ts_bits);
			rohc_comp_debug(context, "%zd bits of TS (%zd in header, %zd in "
			                "EXT3)\n", nr_ts_bits, nr_ts_bits - nr_ts_bits_ext3,
			                nr_ts_bits_ext3);
			/* be sure not to send bad TS bits because of the shift, apply the two masks:
			 *  - the 5-bit mask (0x1f) for the 5-bit field
			 *  - the variable-length mask (depending on the number of TS bits in UOR-2-RTP)
			 *    to avoid sending more than 32 bits of TS in all TS fields */
			ts_mask = 0x1f & ((1 << (32 - nr_ts_bits_ext3 - 1)) - 1);
			ts_bits_for_f_byte = (ts_send >> (nr_ts_bits_ext3 + 1)) & ts_mask;
			*f_byte |= ts_bits_for_f_byte;
			rohc_comp_debug(context, "bits of TS in 1st byte = 0x%x "
			                "(mask = 0x%x)\n", ts_bits_for_f_byte, ts_mask);

			/* part 4: 1 more bit of TS + M flag + 6 bits of SN */
			*s_byte |= (ts_send >> nr_ts_bits_ext3 & 0x01) << 7;
			*s_byte |= (rtp_context->tmp.m_set & 0x01) << 6;
			if(g_context->tmp.nr_sn_bits <= 6)
			{
				*s_byte |= g_context->sn & 0x3f;
				rohc_comp_debug(context, "6 bits of %zd-bit SN = 0x%x\n",
				                g_context->tmp.nr_sn_bits, (*s_byte) & 0x3f);
			}
			else
			{
				assert(g_context->tmp.nr_sn_bits <= (6 + 8));
				*s_byte |= (g_context->sn >> 8) & 0x3f;
				rohc_comp_debug(context, "6 bits of %zd-bit SN = 0x%x\n",
				                g_context->tmp.nr_sn_bits, (*s_byte) & 0x3f);
			}

			/* part 5: set the X bit to 1 + type_bit to 0 */
			*t_byte |= 0x80;
#if defined(RTP_BIT_TYPE) && RTP_BIT_TYPE
			*t_byte |= (rtp_type_bit & 0x01) << 6;
#endif
			/* compute TS to send in extension 3 and its length */
			assert(nr_ts_bits_ext3 < 32);
			rtp_context->tmp.ts_send &= (1 << nr_ts_bits_ext3) - 1;
			rtp_context->tmp.nr_ts_bits_ext3 = nr_ts_bits_ext3;

			break;
		}

		default:
		{
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            false, error, "unknown extension (%d)\n", extension);
		}
	}

	return 1;

error:
	return 0;
}


/**
 * @brief Code some fields of the UOR-2-TS packet
 *
 * This function is called by code_UO2_packet. It should not be called
 * directly.
 *
 * @see code_UO2_packet
 *
 * \verbatim

 UOR-2-TS (5.7.4):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   1   0 |        TS         |
    +===+===+===+===+===+===+===+===+
 4  |T=1| M |          SN           |
    +---+---+---+---+---+---+---+---+
 5  | X |           CRC             |
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context    The compression context
 * @param extension  The extension that will be appended to the packet
 * @param f_byte     IN/OUT: The first byte of the UOR-2-TS packet
 * @param s_byte     IN/OUT: The second byte of the UOR-2-TS packet
 * @param t_byte     IN/OUT: The third byte of the UOR-2-TS packet
 * @return           1 if successful, 0 otherwise
 */
int code_UOR2_TS_bytes(const struct c_context *context,
                       const rohc_ext_t extension,
                       unsigned char *const f_byte,
                       unsigned char *const s_byte,
                       unsigned char *const t_byte)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
#if defined(RTP_BIT_TYPE) && RTP_BIT_TYPE
	const int rtp_type_bit = 0;
#endif
	uint32_t ts_send;

	g_context = (struct c_generic_context *) context->specific;
	rtp_context = (struct sc_rtp_context *) g_context->specific;
	ts_send = rtp_context->tmp.ts_send;

	/* UOR-2-TS cannot be used if there is no IPv4 header in the context or
	 * if value(RND) and value(RND2) are both 1. */
	if(g_context->tmp.nr_of_ip_hdr == 1)
	{
		/* only one IP header: it must be IPv4 with non-random IP-ID */
		assert(g_context->ip_flags.version == IPV4);
		assert(g_context->ip_flags.info.v4.rnd == 0);
	}
	else
	{
		/* 2 IP headers: at least one of them must be IPv4 with non-random
		 * IP-ID */
		if(g_context->ip2_flags.version == IPV4)
		{
			/* inner IP header is IPv4 */
			if(g_context->ip2_flags.info.v4.rnd == 0)
			{
				/* inner IPv4 header got a non-random IP-ID, that's fine */
			}
			else
			{
				/* inner IPv4 header got a random IP-ID, outer IP header must
				 * be IPv4 with non-random IP-ID */
				assert(g_context->ip_flags.version == IPV4);
				assert(!g_context->ip_flags.info.v4.rnd);
			}
		}
		else
		{
			/* inner IP header is not IPv4, outer IP header must be IPv4 with
			 * non-random IP-ID */
			assert(g_context->ip_flags.version == IPV4);
			assert(!g_context->ip_flags.info.v4.rnd);
		}
	}

	/* which extension to code? */
	switch(extension)
	{
		case PACKET_NOEXT:
		{
			rohc_comp_debug(context, "code UOR-2-TS packet with no extension\n");

			/* part 2: 5 bits of 6-bit TS */
			*f_byte |= ts_send & 0x1f;

			/* part 4: T = 1 + M flag + 6 bits of 6-bit SN */
			*s_byte |= 0x80;
			*s_byte |= (rtp_context->tmp.m_set & 0x01) << 6;
			assert(g_context->tmp.nr_sn_bits <= 6);
			*s_byte |= g_context->sn & 0x3f;
			rohc_comp_debug(context, "6 bits of 6-bit SN = 0x%x\n",
			                (*s_byte) & 0x3f);

			/* part 5: set the X bit to 0 + type_bit to 0*/
			*t_byte &= ~0x80;
#if defined(RTP_BIT_TYPE) && RTP_BIT_TYPE
			*t_byte |= (rtp_type_bit & 0x01) << 6;
#endif
			break;
		}

		case PACKET_EXT_0:
		{
			rohc_comp_debug(context, "code UOR-2-TS packet with extension 0\n");

			/* part 2: 5 bits of 8-bit TS */
			*f_byte |= (ts_send >> 3) & 0x1f;

			/* part 4: T = 1 + M flag + 6 bits of 9-bit SN */
			*s_byte |= 0x80;
			*s_byte |= (rtp_context->tmp.m_set & 0x01) << 6;
			assert(g_context->tmp.nr_sn_bits <= (6 + 3));
			*s_byte |= (g_context->sn >> 3) & 0x3f;
			rohc_comp_debug(context, "6 bits of 9-bit SN = 0x%x\n",
			                (*s_byte) & 0x3f);

			/* part 5: set the X bit to 1 + type_bit to 0 */
			*t_byte |= 0x80;
#if defined(RTP_BIT_TYPE) && RTP_BIT_TYPE
			*t_byte |= (rtp_type_bit & 0x01) << 6;
#endif
			break;
		}

		case PACKET_EXT_1:
		{
			rohc_comp_debug(context, "code UOR-2-TS packet with extension 1\n");

			/* part 2: 5 bits of 8-bit TS */
			*f_byte |= (ts_send >> 3) & 0x1f;

			/* part 4: T = 1 + M flag + 6 bits of 9-bit SN */
			*s_byte |= 0x80;
			*s_byte |= (rtp_context->tmp.m_set & 0x01) << 6;
			assert(g_context->tmp.nr_sn_bits <= (6 + 3));
			*s_byte |= (g_context->sn >> 3) & 0x3f;
			rohc_comp_debug(context, "6 bits of 9-bit SN = 0x%x\n",
			                (*s_byte) & 0x3f);

			/* part 5: set the X bit to 1 + type_bit to 0 */
			*t_byte |= 0x80;
#if defined(RTP_BIT_TYPE) && RTP_BIT_TYPE
			*t_byte |= (rtp_type_bit & 0x01) << 6;
#endif
			break;
		}

		case PACKET_EXT_2:
		{
			rohc_comp_debug(context, "code UOR-2-TS packet with extension 2\n");

			/* part 2: 5 bits of 16-bit TS */
			*f_byte |= (ts_send >> 11) & 0x1f;

			/* part 4: T = 1 + M flag + 6 bits of 9-bit SN */
			*s_byte |= 0x80;
			*s_byte |= (rtp_context->tmp.m_set & 0x01) << 6;
			assert(g_context->tmp.nr_sn_bits <= (6 + 3));
			*s_byte |= (g_context->sn >> 3) & 0x3f;
			rohc_comp_debug(context, "6 bits of 9-bit SN = 0x%x\n",
			                (*s_byte) & 0x3f);

			/* part 5: set the X bit to 1 + type_bit to 0 */
			*t_byte |= 0x80;
#if defined(RTP_BIT_TYPE) && RTP_BIT_TYPE
			*t_byte |= (rtp_type_bit & 0x01) << 6;
#endif
			break;
		}

		case PACKET_EXT_3:
		{
			const size_t nr_ts_bits = rtp_context->tmp.nr_ts_bits;
			size_t nr_ts_bits_ext3; /* number of bits to send in EXT 3 */
			uint32_t ts_mask;
			uint8_t ts_bits_for_f_byte;

			rohc_comp_debug(context, "code UOR-2-TS packet with extension 3\n");

			/* part 2: 5 bits of TS */
			rohc_comp_debug(context, "TS to send = 0x%x\n", ts_send);
			nr_ts_bits_ext3 = sdvl_get_min_len(nr_ts_bits, 5);
			rohc_comp_debug(context, "%zd bits of TS (%zd in header, %zd in "
			                "EXT3)\n", nr_ts_bits,
			                (nr_ts_bits_ext3 <= nr_ts_bits ?
			                 nr_ts_bits - nr_ts_bits_ext3 : 0),
			                rohc_min(nr_ts_bits_ext3, nr_ts_bits));
			/* compute the mask for the TS field in the 1st byte: this is the
			 * smaller mask in:
			 *  - the 5-bit mask (0x1f) for the 5-bit field
			 *  - the variable-length mask (depending on the number of TS bits in
			 *    UOR-2-RTP) to avoid sending more than 32 bits of TS in all TS
			 *    fields */
			if(nr_ts_bits_ext3 == 0)
			{
				ts_mask = 0x1f;
			}
			else
			{
				assert(nr_ts_bits_ext3 < 32);
				ts_mask = 0x1f & ((1 << (32 - nr_ts_bits_ext3)) - 1);
			}
			ts_bits_for_f_byte = (ts_send >> nr_ts_bits_ext3) & ts_mask;
			*f_byte |= ts_bits_for_f_byte;
			rohc_comp_debug(context, "bits of TS in 1st byte = 0x%x "
			                "(mask = 0x%x)\n", ts_bits_for_f_byte, ts_mask);

			/* part 4: T = 1 + M flag + 6 bits of SN */
			*s_byte |= 0x80;
			*s_byte |= (rtp_context->tmp.m_set & 0x01) << 6;
			rohc_comp_debug(context, "SN to send = 0x%x\n", g_context->sn);
			if(g_context->tmp.nr_sn_bits <= 6)
			{
				*s_byte |= g_context->sn & 0x3f;
				rohc_comp_debug(context, "6 bits of 6-bit SN = 0x%x\n",
				                (*s_byte) & 0x3f);
			}
			else
			{
				assert(g_context->tmp.nr_sn_bits <= (6 + 8));
				*s_byte |= (g_context->sn >> 8) & 0x3f;
				rohc_comp_debug(context, "6 bits of 14-bit SN = 0x%x\n",
				                (*s_byte) & 0x3f);
			}

			/* part 5: set the X bit to 1 + type_bit to 0 */
			*t_byte |= 0x80;
#if defined(RTP_BIT_TYPE) && RTP_BIT_TYPE
			*t_byte |= (rtp_type_bit & 0x01) << 6;
#endif
			/* compute TS to send in extension 3 and its length */
			assert(nr_ts_bits_ext3 < 32);
			rtp_context->tmp.ts_send &= (1 << nr_ts_bits_ext3) - 1;
			rtp_context->tmp.nr_ts_bits_ext3 = rohc_min(nr_ts_bits_ext3, nr_ts_bits);

			break;
		}

		default:
		{
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            false, error, "unknown extension (%d)\n", extension);
		}
	}

	return 1;

error:
	return 0;
}


/**
 * @brief Code some fields of the UOR-2-ID packet
 *
 * This function is called by code_UO2_packet. It should not be called
 * directly.
 *
 * @see code_UO2_packet
 *
 * \verbatim

 UOR-2-ID (5.7.4):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   1   0 |      IP-ID        |
    +===+===+===+===+===+===+===+===+
 4  |T=0| M |          SN           |
    +---+---+---+---+---+---+---+---+
 5  | X |           CRC             |
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context    The compression context
 * @param extension  The extension that will be appended to the packet
 * @param f_byte     IN/OUT: The first byte of the UOR-2-ID packet
 * @param s_byte     IN/OUT: The second byte of the UOR-2-ID packet
 * @param t_byte     IN/OUT: The third byte of the UOR-2-ID packet
 * @return           1 if successful, 0 otherwise
 */
int code_UOR2_ID_bytes(const struct c_context *context,
                       const rohc_ext_t extension,
                       unsigned char *const f_byte,
                       unsigned char *const s_byte,
                       unsigned char *const t_byte)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
#if defined(RTP_BIT_TYPE) && RTP_BIT_TYPE
	const int rtp_type_bit = 1;
#endif
	/* number of IP-ID bits and IP-ID offset to transmit  */
	ip_header_pos_t innermost_ip_hdr;
	size_t nr_innermost_ip_id_bits;
	uint16_t innermost_ip_id_delta;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;
	assert(g_context->specific != NULL);
	rtp_context = (struct sc_rtp_context *) g_context->specific;

	/* determine the number of IP-ID bits and the IP-ID offset of the
	 * innermost IPv4 header with non-random IP-ID */
	rohc_get_innermost_ipv4_non_rnd(context, &innermost_ip_hdr,
	                                &nr_innermost_ip_id_bits,
	                                &innermost_ip_id_delta);
	assert(innermost_ip_hdr != ROHC_IP_HDR_NONE);

	/* which extension to code? */
	switch(extension)
	{
		case PACKET_NOEXT:
		{
			rohc_comp_debug(context, "code UOR-2-ID packet with no extension\n");

			/* part 2: 5 bits of 5-bit innermost IP-ID with non-random IP-ID */
			*f_byte |= innermost_ip_id_delta & 0x1f;
			rohc_comp_debug(context, "5 bits of 5-bit innermost non-random "
			                "IP-ID = 0x%x\n", (*f_byte) & 0x1f);

			/* part 4: T = 0 + M flag + 6 bits of 6-bit SN */
			*s_byte &= ~0x80;
			*s_byte |= (rtp_context->tmp.m_set & 0x01) << 6;
			rohc_comp_debug(context, "1-bit M flag = %u\n", rtp_context->tmp.m_set);
			assert(g_context->tmp.nr_sn_bits <= 6);
			*s_byte |= g_context->sn & 0x3f;
			rohc_comp_debug(context, "6 bits of 6-bit SN = 0x%x\n",
			                (*s_byte) & 0x3f);

			/* part 5: set the X bit to 0 + type_bit to 1*/
			*t_byte &= ~0x80;
#if defined(RTP_BIT_TYPE) && RTP_BIT_TYPE
			*t_byte |= (rtp_type_bit & 0x01) << 6;
#endif
			break;
		}

		case PACKET_EXT_0:
		{
			rohc_comp_debug(context, "code UOR-2-ID packet with extension 0\n");

			/* part 2: 5 bits of 8-bit innermost IP-ID with non-random IP-ID */
			*f_byte |= (innermost_ip_id_delta >> 3) & 0x1f;
			rohc_comp_debug(context, "5 bits of 8-bit innermost non-random "
			                "IP-ID = 0x%x\n", (*f_byte) & 0x1f);

			/* part 4: T = 0 + M flag + 6 bits of 9-bit SN */
			*s_byte &= ~0x80;
			*s_byte |= (rtp_context->tmp.m_set & 0x01) << 6;
			rohc_comp_debug(context, "1-bit M flag = %u\n", rtp_context->tmp.m_set);
			assert(g_context->tmp.nr_sn_bits <= (6 + 3));
			*s_byte |= (g_context->sn >> 3) & 0x3f;
			rohc_comp_debug(context, "6 bits of 9-bit SN = 0x%x\n",
			                (*s_byte) & 0x3f);

			/* part 5: set the X bit to 1 + type_bit to 1 */
			*t_byte |= 0x80;
#if defined(RTP_BIT_TYPE) && RTP_BIT_TYPE
			*t_byte |= (rtp_type_bit & 0x01) << 6;
#endif
			break;
		}

		case PACKET_EXT_1:
		{
			rohc_comp_debug(context, "code UOR-2-ID packet with extension 1\n");

			/* part 2: 5 bits of 8-bit innermost IP-ID with non-random IP-ID */
			*f_byte |= (innermost_ip_id_delta >> 3) & 0x1f;
			rohc_comp_debug(context, "5 bits of 8-bit innermost non-random "
			                "IP-ID = 0x%x\n", (*f_byte) & 0x1f);

			/* part 4: T = 0 + M flag + 6 bits of 9-bit SN */
			*s_byte &= ~0x80;
			*s_byte |= (rtp_context->tmp.m_set & 0x01) << 6;
			rohc_comp_debug(context, "1-bit M flag = %u\n", rtp_context->tmp.m_set);
			assert(g_context->tmp.nr_sn_bits <= (6 + 3));
			*s_byte |= (g_context->sn >> 3) & 0x3f;
			rohc_comp_debug(context, "6 bits of 9-bit SN = 0x%x\n",
			                (*s_byte) & 0x3f);

			/* part 5: set the X bit to 1 + type_bit to 1 */
			*t_byte |= 0x80;
#if defined(RTP_BIT_TYPE) && RTP_BIT_TYPE
			*t_byte |= (rtp_type_bit & 0x01) << 6;
#endif
			break;
		}

		case PACKET_EXT_2:
		{
			rohc_comp_debug(context, "code UOR-2-ID packet with extension 2\n");

			/* part 2: 5 bits of 16-bit innermost IP-ID with non-random IP-ID */
			*f_byte |= (innermost_ip_id_delta >> 11) & 0x1f;
			rohc_comp_debug(context, "5 bits of 16-bit innermost non-random "
			                "IP-ID = 0x%x\n", (*f_byte) & 0x1f);

			/* part 4: T = 0 + M flag + 6 bits of 9-bit SN */
			*s_byte &= ~0x80;
			*s_byte |= (rtp_context->tmp.m_set & 0x01) << 6;
			rohc_comp_debug(context, "1-bit M flag = %u\n", rtp_context->tmp.m_set);
			assert(g_context->tmp.nr_sn_bits <= (6 + 3));
			*s_byte |= (g_context->sn >> 3) & 0x3f;
			rohc_comp_debug(context, "6 bits of 9-bit SN = 0x%x\n",
			                (*s_byte) & 0x3f);

			/* part 5: set the X bit to 1 + type_bit to 1 */
			*t_byte |= 0x80;
#if defined(RTP_BIT_TYPE) && RTP_BIT_TYPE
			*t_byte |= (rtp_type_bit & 0x01) << 6;
#endif
			break;
		}

		case PACKET_EXT_3:
		{
			/* number of TS bits to transmit overall and in extension 3 */
			const size_t nr_ts_bits = rtp_context->tmp.nr_ts_bits;
			size_t nr_ts_bits_ext3;

			rohc_comp_debug(context, "code UOR-2-ID packet with extension 3\n");

			/* part 2: 5 bits of innermost IP-ID with non-random IP-ID */
			if(nr_innermost_ip_id_bits <= 5)
			{
				/* transmit <= 5 bits of IP-ID, so use the 5-bit field in the UOR-2-ID
				   field and do not use the 16-bit field in the EXT3 header */
				*f_byte |= innermost_ip_id_delta & 0x1f;
				rohc_comp_debug(context, "5 bits of less-than-5-bit innermost "
				                "non-random IP-ID = 0x%x\n", (*f_byte) & 0x1f);
			}
			else
			{
				/* transmitting > 16 bits of IP-ID is not possible */
				assert(nr_innermost_ip_id_bits <= 16);

				/* transmit > 5 bits of IP-ID, so use the 16-bit field in the EXT3
				   header and fill the 5-bit field of UOR-2-ID with zeroes */
				*f_byte &= ~0x1f;
				rohc_comp_debug(context, "5 zero bits of more-than-5-bit "
				                "innermost non-random IP-ID = 0x%x\n",
				                (*f_byte) & 0x1f);
			}

			/* part 4: T = 0 + M flag + 6 bits of SN */
			*s_byte &= ~0x80;
			*s_byte |= (rtp_context->tmp.m_set & 0x01) << 6;
			rohc_comp_debug(context, "1-bit M flag = %u\n", rtp_context->tmp.m_set);
			nr_ts_bits_ext3 = sdvl_get_min_len(nr_ts_bits, 0);
			if(g_context->tmp.nr_sn_bits <= 6)
			{
				*s_byte |= g_context->sn & 0x3f;
				rohc_comp_debug(context, "6 bits of 6-bit SN = 0x%x\n",
				                (*s_byte) & 0x3f);
			}
			else
			{
				assert(g_context->tmp.nr_sn_bits <= (6 + 8));
				*s_byte |= (g_context->sn >> 8) & 0x3f;
				rohc_comp_debug(context, "6 bits of 14-bit SN = 0x%x\n",
				                (*s_byte) & 0x3f);
			}

			/* part 5: set the X bit to 1 + type_bit to 1 */
			*t_byte |= 0x80;
#if defined(RTP_BIT_TYPE) && RTP_BIT_TYPE
			*t_byte |= (rtp_type_bit & 0x01) << 6;
#endif

			/* compute TS to send in extension 3 and its length */
			assert(nr_ts_bits_ext3 < 32);
			rtp_context->tmp.ts_send &= (1 << nr_ts_bits_ext3) - 1;
			rtp_context->tmp.nr_ts_bits_ext3 = nr_ts_bits_ext3;
			rohc_comp_debug(context, "will put %zd bits of TS = 0x%x in EXT3\n",
			                nr_ts_bits_ext3, rtp_context->tmp.ts_send);

			break;
		}

		default:
		{
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            false, error, "unknown extension (%d)\n", extension);
		}
	}

	return 1;

error:
	return 0;
}


/**
 * @brief Build the extension 0 of the UO-2 packet.
 *
 * \verbatim

 Extension 0 for non-RTP profiles (5.11.4):

    +---+---+---+---+---+---+---+---+
 1  | 0   0 |    SN     |   IP-ID   |
    +---+---+---+---+---+---+---+---+

 Extension 0 for RTP profile (5.7.5):

    +---+---+---+---+---+---+---+---+
 1  | 0   0 |    SN     |    +T     |
    +---+---+---+---+---+---+---+---+

 if T = 0 -> +T = IP-ID
          -> -T = TS

 if T = 1 -> +T = TS
          -> -T = IP-ID

 no T bit -> +T = -T = TS

\endverbatim
 *
 * @param context  The compression context
 * @param dest     The rohc-packet-under-build buffer
 * @param counter  The current position in the rohc-packet-under-build buffer
 * @return         The new position in the rohc-packet-under-build buffer
 *                 if successful, -1 otherwise
 */
int code_EXT0_packet(const struct c_context *context,
                     unsigned char *const dest,
                     int counter)
{
	struct c_generic_context *g_context;
	unsigned char f_byte;
	rohc_packet_t packet_type;

	g_context = (struct c_generic_context *) context->specific;
	packet_type = g_context->tmp.packet_type;

	/* part 1: extension type + SN */
	f_byte = 0;
	f_byte = (g_context->sn & 0x07) << 3;

	/* part 1: IP-ID or TS ? */
	switch(packet_type)
	{
		case PACKET_UOR_2_RTP:
		case PACKET_UOR_2_TS:
		{
			const struct sc_rtp_context *const rtp_context = g_context->specific;
			f_byte |= rtp_context->tmp.ts_send & 0x07;
			break;
		}

		case PACKET_UOR_2_ID:
		case PACKET_UOR_2:
		{
			/* number of IP-ID bits and IP-ID offset to transmit  */
			ip_header_pos_t innermost_ip_hdr;
			size_t nr_innermost_ip_id_bits;
			uint16_t innermost_ip_id_delta;

			/* determine the number of IP-ID bits and the IP-ID offset of the
			 * innermost IPv4 header with non-random IP-ID */
			rohc_get_innermost_ipv4_non_rnd(context, &innermost_ip_hdr,
			                                &nr_innermost_ip_id_bits,
			                                &innermost_ip_id_delta);
			assert(innermost_ip_hdr != ROHC_IP_HDR_NONE);

			f_byte |= innermost_ip_id_delta & 0x07;
			break;
		}

		default:
		{
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            false, error, "bad packet type (%d)\n", packet_type);
		}
	}

	/* part 1: write the byte in the extension */
	dest[counter] = f_byte;
	counter++;

	return counter;

error:
	return -1;
}


/**
 * @brief Build the extension 1 of the UO-2 packet.
 *
 * \verbatim

 Extension 1 for non-RTP profiles (5.11.4):

    +---+---+---+---+---+---+---+---+
 1  | 0   1 |    SN     |   IP-ID   |
    +---+---+---+---+---+---+---+---+
 2  |             IP-ID             |
    +---+---+---+---+---+---+---+---+

 Extension 1 for RTP profile (5.7.5):

    +---+---+---+---+---+---+---+---+
 1  | 0   1 |    SN     |    +T     |
    +---+---+---+---+---+---+---+---+
 2  |               -T              |
    +---+---+---+---+---+---+---+---+

 if T = 0 -> +T = IP-ID
          -> -T = TS

 if T = 1 -> +T = TS
          -> -T = IP-ID

 no T bit -> +T = -T = TS

\endverbatim
 *
 * @param context  The compression context
 * @param dest     The rohc-packet-under-build buffer
 * @param counter  The current position in the rohc-packet-under-build buffer
 * @return         The new position in the rohc-packet-under-build buffer
 *                 if successful, -1 otherwise
 */
int code_EXT1_packet(const struct c_context *context,
                     unsigned char *const dest,
                     int counter)
{
	struct c_generic_context *g_context;
	rohc_packet_t packet_type;
	unsigned char f_byte;
	unsigned char s_byte;

	g_context = (struct c_generic_context *) context->specific;
	packet_type = g_context->tmp.packet_type;

	/* part 1: extension type + SN */
	f_byte = (g_context->sn & 0x07) << 3;
	f_byte |= 0x40;

	/* parts 1 & 2: IP-ID or TS ? */
	switch(packet_type)
	{
		case PACKET_UOR_2:
		{
			/* number of IP-ID bits and IP-ID offset to transmit  */
			ip_header_pos_t innermost_ip_hdr;
			size_t nr_innermost_ip_id_bits;
			uint16_t innermost_ip_id_delta;

			/* determine the number of IP-ID bits and the IP-ID offset of the
			 * innermost IPv4 header with non-random IP-ID */
			rohc_get_innermost_ipv4_non_rnd(context, &innermost_ip_hdr,
			                                &nr_innermost_ip_id_bits,
			                                &innermost_ip_id_delta);
			assert(innermost_ip_hdr != ROHC_IP_HDR_NONE);

			f_byte |= (innermost_ip_id_delta >> 8) & 0x07;
			s_byte = innermost_ip_id_delta & 0xff;
			break;
		}

		case PACKET_UOR_2_RTP:
		{
			const struct sc_rtp_context *const rtp_context = g_context->specific;
			f_byte |= (rtp_context->tmp.ts_send >> 8) &  0x07;
			s_byte = rtp_context->tmp.ts_send & 0xff;
			break;
		}

		case PACKET_UOR_2_TS:
		{
			/* number of IP-ID bits and IP-ID offset to transmit  */
			ip_header_pos_t innermost_ip_hdr;
			size_t nr_innermost_ip_id_bits;
			uint16_t innermost_ip_id_delta;
			const struct sc_rtp_context *const rtp_context = g_context->specific;

			/* determine the number of IP-ID bits and the IP-ID offset of the
			 * innermost IPv4 header with non-random IP-ID */
			rohc_get_innermost_ipv4_non_rnd(context, &innermost_ip_hdr,
			                                &nr_innermost_ip_id_bits,
			                                &innermost_ip_id_delta);
			assert(innermost_ip_hdr != ROHC_IP_HDR_NONE);

			f_byte |= rtp_context->tmp.ts_send & 0x07;
			s_byte = innermost_ip_id_delta & 0xff;
			break;
		}

		case PACKET_UOR_2_ID:
		{
			/* number of IP-ID bits and IP-ID offset to transmit  */
			ip_header_pos_t innermost_ip_hdr;
			size_t nr_innermost_ip_id_bits;
			uint16_t innermost_ip_id_delta;
			const struct sc_rtp_context *const rtp_context = g_context->specific;

			/* determine the number of IP-ID bits and the IP-ID offset of the
			 * innermost IPv4 header with non-random IP-ID */
			rohc_get_innermost_ipv4_non_rnd(context, &innermost_ip_hdr,
			                                &nr_innermost_ip_id_bits,
			                                &innermost_ip_id_delta);
			assert(innermost_ip_hdr != ROHC_IP_HDR_NONE);

			f_byte |= innermost_ip_id_delta & 0x07;
			s_byte = rtp_context->tmp.ts_send & 0xff;
			break;
		}

		default:
		{
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            false, error, "bad packet type (%d)\n", packet_type);
		}
	}

	/* write parts 1 & 2 in the packet */
	dest[counter] = f_byte;
	counter++;
	dest[counter] = s_byte;
	counter++;

	return counter;

error:
	return -1;
}


/**
 * @brief Build the extension 2 of the UO-2 packet.
 *
 * \verbatim

 Extension 2 for non-RTP profiles (5.11.4):

    +---+---+---+---+---+---+---+---+
 1  | 1   0 |    SN     |   IP-ID2  |
    +---+---+---+---+---+---+---+---+
 2  |            IP-ID2             |
    +---+---+---+---+---+---+---+---+
 3  |             IP-ID             |
    +---+---+---+---+---+---+---+---+

 IP-ID2 is for outer IP-ID field

 Extension 2 for RTP profile (5.7.5):

    +---+---+---+---+---+---+---+---+
 1  | 1   0 |    SN     |     +T    |
    +---+---+---+---+---+---+---+---+
 2  |               +T              |
    +---+---+---+---+---+---+---+---+
 3  |               -T              |
    +---+---+---+---+---+---+---+---+

 if T = 0 -> +T = IP-ID
          -> -T = TS

 if T = 1 -> +T = TS
          -> -T = IP-ID

 no T bit -> +T = -T = TS

\endverbatim
 *
 * @param context  The compression context
 * @param dest     The rohc-packet-under-build buffer
 * @param counter  The current position in the rohc-packet-under-build buffer
 * @return         The new position in the rohc-packet-under-build buffer
 *                 if successful, -1 otherwise
 */
int code_EXT2_packet(const struct c_context *context,
                     unsigned char *const dest,
                     int counter)
{
	struct c_generic_context *g_context;
	rohc_packet_t packet_type;
	unsigned char f_byte;
	unsigned char s_byte;
	unsigned char t_byte;

	g_context = (struct c_generic_context *) context->specific;
	packet_type = g_context->tmp.packet_type;

	/* part 1: extension type + SN */
	f_byte = (g_context->sn & 0x07) << 3;
	f_byte |= 0x80;
	rohc_comp_debug(context, "3 bits of SN = 0x%x\n", g_context->sn & 0x07);

	/* parts 1, 2 & 3: IP-ID or TS ? */
	switch(packet_type)
	{
		case PACKET_UOR_2:
		{
			/* To avoid confusion:
			 *  - IP-ID2 in the header description is related to the outer IP header
			 *    and thus to the g_context->ip_flags header info,
			 *  - IP-ID in the header description is related to the inner IP header
			 *    and thus to the g_context->ip2_flags header info.
			 */

			/* extension 2 for UOR-2 must contain two IPv4 headers with non-random
			   IP-IDs */
			assert(g_context->ip_flags.version == IPV4 &&
			       g_context->ip_flags.info.v4.rnd == 0 &&
			       g_context->is_ip2_initialized == 1 &&
			       g_context->ip2_flags.version == IPV4 &&
			       g_context->ip2_flags.info.v4.rnd == 0);

			f_byte |= (g_context->ip_flags.info.v4.id_delta >> 8) & 0x07;
			rohc_comp_debug(context, "3 bits of outer IP-ID = 0x%x\n",
			                f_byte & 0x07);
			s_byte = g_context->ip_flags.info.v4.id_delta & 0xff;
			rohc_comp_debug(context, "8 bits of outer IP-ID = 0x%x\n",
			                s_byte & 0xff);
			t_byte = g_context->ip2_flags.info.v4.id_delta & 0xff;
			rohc_comp_debug(context, "8 bits of inner IP-ID = 0x%x\n",
			                t_byte & 0xff);
			break;
		}

		case PACKET_UOR_2_RTP:
		{
			const struct sc_rtp_context *const rtp_context = g_context->specific;
			const uint32_t ts_send = rtp_context->tmp.ts_send;

			f_byte |= (ts_send >> 16) & 0x07;
			rohc_comp_debug(context, "3 bits of TS = 0x%x\n", f_byte & 0x07);
			s_byte = (ts_send >> 8) & 0xff;
			rohc_comp_debug(context, "8 bits of TS = 0x%x\n", s_byte & 0xff);
			t_byte = ts_send & 0xff;
			rohc_comp_debug(context, "8 bits of TS = 0x%x\n", t_byte & 0xff);
			break;
		}

		case PACKET_UOR_2_TS:
		{
			/* number of IP-ID bits and IP-ID offset to transmit  */
			ip_header_pos_t innermost_ip_hdr;
			size_t nr_innermost_ip_id_bits;
			uint16_t innermost_ip_id_delta;
			const struct sc_rtp_context *const rtp_context = g_context->specific;
			const uint32_t ts_send = rtp_context->tmp.ts_send;

			/* determine the number of IP-ID bits and the IP-ID offset of the
			 * innermost IPv4 header with non-random IP-ID */
			rohc_get_innermost_ipv4_non_rnd(context, &innermost_ip_hdr,
			                                &nr_innermost_ip_id_bits,
			                                &innermost_ip_id_delta);
			assert(innermost_ip_hdr != ROHC_IP_HDR_NONE);

			f_byte |= (ts_send >> 8) & 0x07;
			rohc_comp_debug(context, "3 bits of TS = 0x%x\n", f_byte & 0x07);
			s_byte = ts_send & 0xff;
			rohc_comp_debug(context, "8 bits of TS = 0x%x\n", s_byte & 0xff);
			t_byte = innermost_ip_id_delta & 0xff;
			rohc_comp_debug(context, "8 bits of innermost non-random "
			                "IP-ID = 0x%x\n", t_byte & 0xff);
			break;
		}

		case PACKET_UOR_2_ID:
		{
			/* number of IP-ID bits and IP-ID offset to transmit  */
			ip_header_pos_t innermost_ip_hdr;
			size_t nr_innermost_ip_id_bits;
			uint16_t innermost_ip_id_delta;
			const struct sc_rtp_context *const rtp_context = g_context->specific;

			/* determine the number of IP-ID bits and the IP-ID offset of the
			 * innermost IPv4 header with non-random IP-ID */
			rohc_get_innermost_ipv4_non_rnd(context, &innermost_ip_hdr,
			                                &nr_innermost_ip_id_bits,
			                                &innermost_ip_id_delta);
			assert(innermost_ip_hdr != ROHC_IP_HDR_NONE);

			f_byte |= (innermost_ip_id_delta >> 8) & 0x07;
			rohc_comp_debug(context, "3 bits of innermost non-random IP-ID "
			                "= 0x%x\n", f_byte & 0x07);
			s_byte = innermost_ip_id_delta & 0xff;
			rohc_comp_debug(context, "8 bits of innermost non-random IP-ID "
			                "= 0x%x\n", s_byte & 0xff);
			t_byte = rtp_context->tmp.ts_send & 0xff;
			rohc_comp_debug(context, "8 bits of TS = 0x%x\n", t_byte & 0xff);
			break;
		}

		default:
		{
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            false, error, "bad packet type (%d)\n", packet_type);
		}
	}

	/* write parts 1, 2 & 3 in the packet */
	dest[counter] = f_byte;
	counter++;
	dest[counter] = s_byte;
	counter++;
	dest[counter] = t_byte;
	counter++;
	rohc_comp_debug(context, "extension 2: 0x%02x 0x%02x 0x%02x\n", f_byte,
	                s_byte, t_byte);

	return counter;

error:
	return -1;
}


/**
 * @brief Build the extension 3 of the UO-2 packet.
 *
 * \verbatim

 Extension 3 for non-RTP profiles (5.7.5 & 5.11.4):

       0     1     2     3     4     5     6     7
    +-----+-----+-----+-----+-----+-----+-----+-----+
 1  |  1     1  |  S  |   Mode    |  I  | ip  | ip2 |
    +-----+-----+-----+-----+-----+-----+-----+-----+
 2  |            Inner IP header flags        |     |  if ip = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
 3  |            Outer IP header flags              |  if ip2 = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
 4  |                      SN                       |  if S = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
    |                                               |
 5  /            Inner IP header fields             /  variable,
    |                                               |  if ip = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
 6  |                     IP-ID                     |  2 octets, if I = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
    |                                               |
 7  /            Outer IP header fields             /  variable,
    |                                               |  if ip2 = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+

 Extension 3 for RTP profile (5.7.5):

       0     1     2     3     4     5     6     7
    +-----+-----+-----+-----+-----+-----+-----+-----+
 1  |  1     1  |  S  |R-TS | Tsc |  I  | ip  | rtp |
    +-----+-----+-----+-----+-----+-----+-----+-----+
 2  |            Inner IP header flags        | ip2 |  if ip = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
 3  |            Outer IP header flags              |  if ip2 = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
 4  |                      SN                       |  if S = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
    |                                               |
4.1 /                      TS                       / 1-4octets, if R-TS = 1
    |                                               |
    +-----+-----+-----+-----+-----+-----+-----+-----+
    |                                               |
 5  /            Inner IP header fields             /  variable,
    |                                               |  if ip = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
 6  |                     IP-ID                     |  2 octets, if I = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
    |                                               |
 7  /            Outer IP header fields             /  variable,
    |                                               |  if ip2 = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
    |                                               |  variable,
 8  /          RTP Header flags and fields          /  if rtp = 1
    |                                               |
    +-----+-----+-----+-----+-----+-----+-----+-----+

\endverbatim
 *
 * @param context  The compression context
 * @param ip       The outer IP header
 * @param ip2      The inner IP header
 * @param dest     The rohc-packet-under-build buffer
 * @param counter  The current position in the rohc-packet-under-build buffer
 * @return         The new position in the rohc-packet-under-build buffer
 *                 if successful, -1 otherwise
 */
int code_EXT3_packet(const struct c_context *context,
                     const struct ip_packet *ip,
                     const struct ip_packet *ip2,
                     unsigned char *const dest,
                     int counter)
{
	struct c_generic_context *g_context;
	unsigned char f_byte;
	int nr_of_ip_hdr;
	unsigned short changed_f;
	unsigned short changed_f2;
	size_t nr_sn_bits;
	size_t nr_ip_id_bits;
	size_t nr_ip_id_bits2;
	ip_header_pos_t innermost_ipv4_non_rnd;
	int have_inner = 0;
	int have_outer = 0;
	int S;
	int I;
	int I2 = 0;
	int is_rtp;
	int rtp = 0;     /* RTP bit */
	int rts = 0;     /* R-TS bit */
	rohc_packet_t packet_type;

	g_context = (struct c_generic_context *) context->specific;
	nr_of_ip_hdr = g_context->tmp.nr_of_ip_hdr;
	changed_f = g_context->tmp.changed_fields;
	changed_f2 = g_context->tmp.changed_fields2;
	nr_sn_bits = g_context->tmp.nr_sn_bits;
	nr_ip_id_bits = g_context->tmp.nr_ip_id_bits;
	nr_ip_id_bits2 = g_context->tmp.nr_ip_id_bits2;
	is_rtp = context->profile->id == ROHC_PROFILE_RTP;
	packet_type = g_context->tmp.packet_type;

	/* part 1: extension type */
	f_byte = 0xc0;

	/* part 1: S bit */
	switch(packet_type)
	{
		case PACKET_UO_1_ID:
			/* TODO: extension not supported in \ref code_UO1_packet yet */
			S = nr_sn_bits > 4;
			break;
		case PACKET_UOR_2:
			S = nr_sn_bits > 5;
			break;
		case PACKET_UOR_2_RTP:
		case PACKET_UOR_2_TS:
		case PACKET_UOR_2_ID:
			S = nr_sn_bits > 6;
			break;
		default:
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            false, error, "bad packet type (%d)\n", packet_type);
	}
	f_byte |= (S << 5) & 0x20;

	/* part 1: R-TS, Tsc & RTP bits if RTP
	 *         Mode bits otherwise */
	if(is_rtp)
	{
		const struct sc_rtp_context *rtp_context;
		size_t nr_ts_bits; /* nb of TS bits needed */
		uint8_t tsc; /* Tsc bit */

		rtp_context = (struct sc_rtp_context *) g_context->specific;
		nr_ts_bits = rtp_context->tmp.nr_ts_bits;

		/* R-TS bit */
		switch(packet_type)
		{
			/* TODO: handle PACKET_UO_1_ID packet once \ref code_UO1_packet
			 *       supports extensions */
			case PACKET_UOR_2_RTP:
				rts = nr_ts_bits > 6;
				break;
			case PACKET_UOR_2_TS:
				rts = nr_ts_bits > 5;
				break;
			case PACKET_UOR_2_ID:
				rts = nr_ts_bits > 0;
				break;
			default:
				rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
				            false, error, "bad packet type (%d)\n", packet_type);
		}
		f_byte |= (rts & 0x01) << 4;

		/* Tsc bit */
		tsc = (rtp_context->ts_sc.state == SEND_SCALED);
		f_byte |= (tsc & 0x01) << 3;

		/* rtp bit: set to 1 if RTP PT changed in this packet or changed
		 * in the last few packets or RTP TS and TS_STRIDE must be initialized */
		rtp = (rtp_context->tmp.rtp_pt_changed ||
		       rtp_context->rtp_pt_change_count < MAX_FO_COUNT ||
		       (rtp_context->ts_sc.state == INIT_STRIDE));
		f_byte |= rtp & 0x01;

		rohc_comp_debug(context, "S = %d, R-TS = %d, Tsc = %u, rtp = %d\n",
		                S, rts, tsc, rtp);
	}
	else /* non-RTP profiles */
	{
		f_byte |= (context->mode & 0x3) << 3;

		rohc_comp_debug(context, "S = %d, Mode = %d\n", S, context->mode & 0x3);
	}

	/* if random bit is set we have the IP-ID field outside this function */
	if(ip_get_version(ip) == IPV4)
	{
		rohc_comp_debug(context, "rnd_count_up = %d\n",
		                g_context->ip_flags.info.v4.rnd_count);
	}

	if(nr_of_ip_hdr == 1)
	{
		/* if the innermost IP header is IPv4 with non-random IP-ID, check if
		 * the I bit must be set */
		if(ip_get_version(ip) == IPV4 && g_context->ip_flags.info.v4.rnd == 0)
		{
			innermost_ipv4_non_rnd = ROHC_IP_HDR_FIRST;

			if(g_context->tmp.packet_type != PACKET_UOR_2_ID && nr_ip_id_bits > 0)
			{
				I = 1;
			}
			else if(g_context->tmp.packet_type == PACKET_UOR_2_ID && nr_ip_id_bits > 5)
			{
				I = 1;
			}
			else if(g_context->ip_flags.info.v4.rnd_count < MAX_FO_COUNT)
			{
				I = 1;
			}
			else
			{
				I = 0;
			}
		}
		else
		{
			/* the IP header is not 'IPv4 with non-random IP-ID' */
			innermost_ipv4_non_rnd = ROHC_IP_HDR_NONE;
			I = 0;
		}
		f_byte |= (I & 0x01) << 2;

		/* ip bit */
		rohc_comp_debug(context, "check for changed fields in the inner IP header\n");
		if(changed_dynamic_one_hdr(context, changed_f & 0x01FF, &g_context->ip_flags, ip) ||
		   changed_static_one_hdr(context, changed_f, &g_context->ip_flags, ip))
		{
			have_inner = 1;
			f_byte |= 0x02;
		}
	}
	else /* double IP headers */
	{
		/* set the I bit if some bits (depends on packet type) of the innermost
		 * IPv4 header with non-random IP-ID must be transmitted */
		if(ip_get_version(ip2) == IPV4 && g_context->ip2_flags.info.v4.rnd == 0)
		{
			/* inner IP header is IPv4 with non-random IP-ID */
			innermost_ipv4_non_rnd = ROHC_IP_HDR_SECOND;

			if(g_context->tmp.packet_type != PACKET_UOR_2_ID && nr_ip_id_bits2 > 0)
			{
				I = 1;
			}
			else if(g_context->tmp.packet_type == PACKET_UOR_2_ID && nr_ip_id_bits2 > 5)
			{
				I = 1;
			}
			else if(g_context->ip2_flags.info.v4.rnd_count < MAX_FO_COUNT)
			{
				I = 1;
			}
			else
			{
				I = 0;
			}

			/* the innermost IPv4 header with non-random IP-ID is the inner IP
			 * header, maybe there is a need for a second IP-ID for for the
			 * outer IP header */
			if(ip_get_version(ip) == IPV4 && g_context->ip_flags.info.v4.rnd == 0)
			{
				/* outer IP header is also IPv4 with non-random IP-ID */
				if(nr_ip_id_bits > 0)
				{
					I2 = 1;
				}
				else if(g_context->ip_flags.info.v4.rnd_count < MAX_FO_COUNT)
				{
					I2 = 1;
				}
				else
				{
					I2 = 0;
				}
			}
		}
		else if(ip_get_version(ip) == IPV4 && g_context->ip_flags.info.v4.rnd == 0)
		{
			/* inner IP header is not 'IPv4 with non-random IP-ID', but outer
			 * IP header is */
			innermost_ipv4_non_rnd = ROHC_IP_HDR_FIRST;

			if(g_context->tmp.packet_type != PACKET_UOR_2_ID && nr_ip_id_bits > 0)
			{
				I = 1;
			}
			else if(g_context->tmp.packet_type == PACKET_UOR_2_ID && nr_ip_id_bits > 5)
			{
				I = 1;
			}
			else if(g_context->ip_flags.info.v4.rnd_count < MAX_FO_COUNT)
			{
				I = 1;
			}
			else
			{
				I = 0;
			}

			/* the innermost IPv4 header with non-random IP-ID is the outer IP
			 * header, so there is no need for a second IP-ID field */
			I2 = 0;
		}
		else
		{
			/* none of the 2 IP headers are IPv4 with non-random IP-ID */
			innermost_ipv4_non_rnd = ROHC_IP_HDR_NONE;
			I = 0;
			I2 = 0;
		}
		f_byte |= (I & 0x01) << 2;

		/* ip2 bit if non-RTP
		 * (force ip2=1 if I2=1, otherwise I2 is not send) */
		rohc_comp_debug(context, "check for changed fields in the outer IP header\n");
		if(I2 ||
		   changed_dynamic_one_hdr(context, changed_f, &g_context->ip_flags, ip) ||
		   changed_static_one_hdr(context, changed_f, &g_context->ip_flags, ip))
		{
			have_outer = 1;
			if(!is_rtp)
			{
				f_byte |= 0x01;
			}
		}

		/* ip bit
		 * (force ip=1 if ip2=1 and RTP profile, otherwise ip2 is not send) */
		rohc_comp_debug(context, "check for changed fields in the inner IP header\n");
		if((is_rtp && ip2) ||
		   changed_dynamic_one_hdr(context, changed_f2, &g_context->ip2_flags, ip2) ||
		   changed_static_one_hdr(context, changed_f2, &g_context->ip2_flags, ip2))
		{
			have_inner = 1;
			f_byte = f_byte | 0x02;
		}
	}
	rohc_comp_debug(context, "I = %d, ip = %d, I2 = %d, ip2 = %d\n",
	                I, have_inner, I2, have_outer);

	rohc_comp_debug(context, "part 1 = 0x%02x\n", f_byte);
	dest[counter] = f_byte;
	counter++;

	if(nr_of_ip_hdr == 1)
	{
		/* part 2 */
		if(have_inner)
		{
			counter = header_flags(context, &g_context->ip_flags, changed_f, ip,
			                       have_outer, nr_ip_id_bits, dest, counter);
		}

		/* part 3: only one IP header */

		/* part 4 */
		if(S)
		{
			dest[counter] = g_context->sn & 0xff;
			rohc_comp_debug(context, "8 bits of %zd-bit SN = 0x%02x\n",
			                g_context->tmp.nr_sn_bits, dest[counter]);
			counter++;
		}

		/* part 4.1 */
		if(is_rtp && rts)
		{
			const struct sc_rtp_context *rtp_context;
			size_t nr_ts_bits_ext3; /* nb of TS bits needed in EXT3 */
			uint32_t ts_send; /* TS to send */
			size_t sdvl_size;

			rtp_context = (struct sc_rtp_context *) g_context->specific;
			nr_ts_bits_ext3 = rtp_context->tmp.nr_ts_bits_ext3;
			ts_send = rtp_context->tmp.ts_send;

			/* determine the size of the SDVL-encoded TS value */
			sdvl_size = c_bytesSdvl(ts_send, nr_ts_bits_ext3);
			assert(sdvl_size > 0 && sdvl_size <= 5);
			if(sdvl_size <= 0 || sdvl_size > 4)
			{
				rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
				             "failed to determine the number of bits required "
				             "to SDVL-encode %zd bits of TS\n", nr_ts_bits_ext3);
				goto error;
			}

			rohc_comp_debug(context, "ts_send = %u (0x%x) needs %zd bits in "
			                "EXT3, will be SDVL-coded on %zd bytes\n", ts_send,
			                ts_send, nr_ts_bits_ext3, sdvl_size);

			/* SDVL-encode the TS value */
			if(!c_encodeSdvl(&dest[counter], ts_send, nr_ts_bits_ext3))
			{
				rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
				             "TS length greater than 29 (value = %u, "
				             "length = %zd)\n", ts_send, nr_ts_bits_ext3);
				goto error;
			}
			counter += sdvl_size;
		}

		/* parts */
		if(have_inner)
		{
			counter = header_fields(context, &g_context->ip_flags, changed_f,
			                        ip, 0, ROHC_IP_HDR_FIRST, dest, counter);
		}

		/* part 6 */
		if(I)
		{
			uint16_t id_encoded;

			/* we only have one single IP header here, so if the I bit is set,
			 * the only one IP header must be the innermost IPv4 header with
			 * non-random IP-ID */
			assert(innermost_ipv4_non_rnd == ROHC_IP_HDR_FIRST);

			/* always transmit the IP-ID encoded, in Network Byte Order */
			id_encoded = htons(g_context->ip_flags.info.v4.id_delta);
			memcpy(&dest[counter], &id_encoded, 2);
			rohc_comp_debug(context, "IP ID of IP header #%u = 0x%02x 0x%02x\n",
			                innermost_ipv4_non_rnd, dest[counter],
			                dest[counter + 1]);
			counter += 2;
		}

		/* part 7: only one IP header */

		/* part 8 */
		if(is_rtp && rtp)
		{
			counter = rtp_header_flags_and_fields(context, changed_f, ip,
			                                      dest, counter);
			if(counter < 0)
			{
				goto error;
			}
		}
	}
	else /* double IP headers */
	{
		/* part 2 */
		if(have_inner)
		{
			counter = header_flags(context, &g_context->ip2_flags, changed_f2, ip2,
			                       have_outer, nr_ip_id_bits2, dest, counter);
		}

		/* part 3 */
		if(have_outer)
		{
			counter = header_flags(context, &g_context->ip_flags, changed_f, ip,
			                       I2, nr_ip_id_bits, dest, counter);
		}

		/* part 4 */
		if(S)
		{
			dest[counter] = g_context->sn & 0xff;
			counter++;
		}

		/* part 4.1 */
		if(is_rtp && rts)
		{
			const struct sc_rtp_context *rtp_context;
			size_t nr_ts_bits_ext3; /* nb of TS bits needed in EXT3 */
			uint32_t ts_send; /* TS to send */
			size_t sdvl_size;

			rtp_context = (struct sc_rtp_context *) g_context->specific;
			nr_ts_bits_ext3 = rtp_context->tmp.nr_ts_bits_ext3;
			ts_send = rtp_context->tmp.ts_send;

			/* determine the size of the SDVL-encoded TS value */
			sdvl_size = c_bytesSdvl(ts_send, nr_ts_bits_ext3);
			assert(sdvl_size > 0 && sdvl_size <= 5);
			if(sdvl_size <= 0 || sdvl_size > 4)
			{
				rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
				             "failed to determine the number of bits required "
				             "to SDVL-encode %zd bits of TS\n", nr_ts_bits_ext3);
				goto error;
			}

			rohc_comp_debug(context, "ts_send = %u (0x%x) needs %zd bits in "
			                "EXT3, will be SDVL-coded on %zd bytes\n", ts_send,
			                ts_send, nr_ts_bits_ext3, sdvl_size);

			/* SDVL-encode the TS value */
			if(!c_encodeSdvl(&dest[counter], ts_send, nr_ts_bits_ext3))
			{
				rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
				             "TS length greater than 29 (value = %u, "
				             "length = %zd)\n", ts_send, nr_ts_bits_ext3);
				goto error;
			}
			counter += sdvl_size;
		}

		/* part 5 */
		if(have_inner)
		{
			counter = header_fields(context, &g_context->ip2_flags, changed_f2,
			                        ip2, 0, ROHC_IP_HDR_SECOND, dest, counter);
		}

		/* part 6 */
		if(I)
		{
			uint16_t id_encoded;

			/* we have 2 IP headers here, so if the I bit is set, one of them
			 * must be the innermost IPv4 header with non-random IP-ID */
			assert(innermost_ipv4_non_rnd == ROHC_IP_HDR_FIRST ||
			       innermost_ipv4_non_rnd == ROHC_IP_HDR_SECOND);

			/* always transmit the IP-ID encoded, in Network Byte Order */
			if(innermost_ipv4_non_rnd == ROHC_IP_HDR_FIRST)
			{
				id_encoded = htons(g_context->ip_flags.info.v4.id_delta);
			}
			else
			{
				id_encoded = htons(g_context->ip2_flags.info.v4.id_delta);
			}
			memcpy(&dest[counter], &id_encoded, 2);
			rohc_comp_debug(context, "IP ID of IP header #%u = 0x%02x 0x%02x\n",
			                innermost_ipv4_non_rnd, dest[counter],
			                dest[counter + 1]);
			counter += 2;
		}

		/* part 7 */
		if(have_outer)
		{
			counter = header_fields(context, &g_context->ip_flags, changed_f,
			                        ip, I2, ROHC_IP_HDR_FIRST, dest, counter);
		}

		/* part 8 */
		if(is_rtp && rtp)
		{
			counter = rtp_header_flags_and_fields(context, changed_f2, ip2,
			                                      dest, counter);
			if(counter < 0)
			{
				goto error;
			}
		}
	}

	/* no IP extension until list compression */

	return counter;

error:
	return -1;
}


/*
 * @brief Build RTP header flags and fields
 *
 * This function is used to code the RTP header flags and fields of the
 * extension 3 of the UO-2 packet.
 *
 * @see code_EXT3_packet
 *
 * \verbatim

 RTP header flags and fields (5.7.5):

       0     1     2     3     4     5     6     7
     ..... ..... ..... ..... ..... ..... ..... .....
 1  |   Mode    |R-PT |  M  | R-X |CSRC | TSS | TIS |  if rtp = 1
     ..... ..... ..... ..... ..... ..... ..... .....
 2  | R-P |             RTP PT                      |  if R-PT = 1
     ..... ..... ..... ..... ..... ..... ..... .....
 3  /           Compressed CSRC list                /  if CSRC = 1
     ..... ..... ..... ..... ..... ..... ..... .....
 4  /                  TS_STRIDE                    /  1-4 oct if TSS = 1
     ..... ..... ..... ..... ..... ..... ..... ....
 5  /           TIME_STRIDE (milliseconds)          /  1-4 oct if TIS = 1
     ..... ..... ..... ..... ..... ..... ..... .....

 Mode: Compression mode. 0 = Reserved,
                         1 = Unidirectional,
                         2 = Bidirectional Optimistic,
                         3 = Bidirectional Reliable.

 Parts 3 & 5 are not supported yet.

\endverbatim
 *
 * @param context    The compression context
 * @param changed_f  The fields that changed, created by the function
 *                   changed_fields
 * @param ip         One inner or outer IP header
 * @param dest       The rohc-packet-under-build buffer
 * @param counter    The current position in the rohc-packet-under-build buffer
 * @return           The new position in the rohc-packet-under-build buffer
 *                   if successful, -1 otherwise
 *
 * @see changed_fields
 */
int rtp_header_flags_and_fields(const struct c_context *context,
                                const unsigned short changed_f,
                                const struct ip_packet *ip,
                                unsigned char *const dest,
                                int counter)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
	struct udphdr *udp;
	struct rtphdr *rtp;
	int tss;
	int rpt;
	unsigned char byte;

	g_context = (struct c_generic_context *) context->specific;
	rtp_context = (struct sc_rtp_context *) g_context->specific;

	/* get RTP header */
	udp = (struct udphdr *) ip_get_next_layer(ip);
	rtp = (struct rtphdr *) (udp + 1);

	/* part 1 */
	rpt = (rtp_context->tmp.rtp_pt_changed ||
	       rtp_context->rtp_pt_change_count < MAX_IR_COUNT);
	tss = rtp_context->ts_sc.state == INIT_STRIDE;
	byte = 0;
	byte |= (context->mode & 0x03) << 6;
	byte |= (rpt & 0x01) << 5;
	byte |= (rtp->m & 0x01) << 4;
	byte |= (rtp->extension & 0x01) << 3;
	byte |= (tss & 0x01) << 1;
	rohc_comp_debug(context, "RTP flags = 0x%x\n", byte);
	dest[counter] = byte;
	counter++;

	/* part 2 */
	if(rpt)
	{
		byte = 0;
		byte |= (rtp->padding & 0x01) << 7;
		byte |= rtp->pt & 0x7f;
		rohc_comp_debug(context, "part 2 = 0x%x\n", byte);
		dest[counter] = byte;
		counter++;
		rtp_context->rtp_pt_change_count++;
	}

	/* part 3: not supported yet */

	/* part 4 */
	if(tss)
	{
		uint32_t ts_stride;
		size_t sdvl_size;
		int success;

		/* determine the TS_STRIDE to transmit */
		ts_stride = get_ts_stride(rtp_context->ts_sc);

		/* determine the size of the SDVL-encoded TS_STRIDE value */
		sdvl_size = c_bytesSdvl(ts_stride, 0 /* length detection */);
		assert(sdvl_size > 0 && sdvl_size <= 5);
		if(sdvl_size <= 0 || sdvl_size > 4)
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "failed to determine the number of bits required to "
			             "SDVL-encode TS_STRIDE %u\n", ts_stride);
			goto error;
		}

		/* SDVL-encode the TS_STRIDE value */
		success = c_encodeSdvl(&dest[counter], ts_stride, 0 /* length detection */);
		if(!success)
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "TS stride length greater than 29 (%u)\n", ts_stride);
			goto error;
		}
		counter += sdvl_size;

		rohc_comp_debug(context, "TS_STRIDE %u (0x%x) is SDVL-encoded on %zd "
		                "bit(s)\n", ts_stride, ts_stride, sdvl_size);

		/* do we transmit the scaled RTP Timestamp (TS) in the next packet ? */
		if(rtp_context->ts_sc.state == INIT_STRIDE)
		{
			rtp_context->ts_sc.nr_init_stride_packets++;
			if(rtp_context->ts_sc.nr_init_stride_packets >= ROHC_INIT_TS_STRIDE_MIN)
			{
				rohc_comp_debug(context, "TS_STRIDE transmitted at least %u "
				                "times, so change from state INIT_STRIDE to "
				                "SEND_SCALED\n", ROHC_INIT_TS_STRIDE_MIN);
				rtp_context->ts_sc.state = SEND_SCALED;
			}
			else
			{
				rohc_comp_debug(context, "TS_STRIDE transmitted only %zd times, "
				                "so stay in state INIT_STRIDE (at least %u times "
				                "are required to change to state SEND_SCALED)\n",
				                rtp_context->ts_sc.nr_init_stride_packets,
				                ROHC_INIT_TS_STRIDE_MIN);
			}
		}
	}

	/* part 5: not supported yet */

	return counter;

error:
	return -1;
}


/**
 * @brief Build inner or outer IP header flags.
 *
 * This function is used to code the IP header fields of the extension 3 of
 * the UO-2 packet. The function is called twice (one for inner IP header and
 * one for outer IP header) with different arguments.
 *
 * @see code_EXT3_packet
 *
 * \verbatim

 Header flags for IP and UDP profiles (5.11.4):

 For inner flags:

    +-----+-----+-----+-----+-----+-----+-----+-----+
 1  |            Inner IP header flags        |     |  if ip = 1
    | TOS | TTL | DF  | PR  | IPX | NBO | RND | ip2 |  ip2 = 0 if non-RTP
    +-----+-----+-----+-----+-----+-----+-----+-----+

 or for outer flags:

    +-----+-----+-----+-----+-----+-----+-----+-----+
 2  |            Outer IP header flags              |
    | TOS2| TTL2| DF2 | PR2 |IPX2 |NBO2 |RND2 |  I2 |  if ip2 = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+

\endverbatim
 *
 * @param context        The compression context
 * @param header_info    The header info stored in the profile
 * @param changed_f      The fields that changed, created by the function
 *                       changed_fields
 * @param ip             One inner or outer IP header
 * @param ip2_or_I2      Whether the ip2 (inner, RTP only) or I2 (outer) flag
 *                       is set or not
 * @param nr_ip_id_bits  The number of bits needed to transmit the IP-ID field
 * @param dest           The rohc-packet-under-build buffer
 * @param counter        The current position in the rohc-packet-under-build
 *                       buffer
 * @return               The new position in the rohc-packet-under-build buffer
 *
 * @see changed_fields
 */
int header_flags(const struct c_context *context,
                 struct ip_header_info *const header_info,
                 const unsigned short changed_f,
                 const struct ip_packet *ip,
                 const int ip2_or_I2,
                 const size_t nr_ip_id_bits,
                 unsigned char *const dest,
                 int counter)
{
	int flags = 0;

	/* for inner and outer flags (1 & 2) */
	if(is_changed(changed_f, MOD_TOS) || header_info->tos_count < MAX_FO_COUNT)
	{
		flags |= 0x80;
	}
	if(is_changed(changed_f, MOD_TTL) || header_info->ttl_count < MAX_FO_COUNT)
	{
		flags |= 0x40;
	}
	if(is_changed(changed_f, MOD_PROTOCOL) || header_info->protocol_count < MAX_FO_COUNT)
	{
		flags |= 0x10;
	}

	/* DF, NBO, RND and I2 are IPv4 specific flags,
	 * there are always set to 0 for IPv6 */
	if(header_info->version == IPV4)
	{
		int df;

		df = ipv4_get_df(ip);
		header_info->info.v4.df_count++;
		flags |= df << 5;

		header_info->info.v4.nbo_count++;
		flags |= header_info->info.v4.nbo << 2;

		header_info->info.v4.rnd_count++;
		flags |= header_info->info.v4.rnd << 1;
	}

	/* the ip2 flag for inner IP flags if non-RTP profile,
	 * the I2 flag for outer IP flags */
	flags |= ip2_or_I2 & 0x01;

	rohc_comp_debug(context, "IPv%d header flags: TOS = %d, TTL = %d, "
	                "DF = %d, PR = %d, IPX = %d, NBO = %d, RND = %d, "
	                "ip2/I2 = %d\n", header_info->version, (flags >> 7) & 0x1,
	                (flags >> 6) & 0x1, (flags >> 5) & 0x1, (flags >> 4) & 0x1,
	                (flags >> 3) & 0x1, (flags >> 2) & 0x1, (flags >> 1) & 0x1,
	                flags & 0x1);

	/* for inner and outer flags (1 & 2) */
	dest[counter] = flags;
	counter++;

	return counter;
}


/**
 * @brief Build inner or outer IP header fields.
 *
 * This function is used to code the IP header fields of the extension 3 of
 * the UO-2 packet. The function is called twice (one for inner IP header and
 * one for outer IP header) with different arguments.
 *
 * @see code_EXT3_packet
 *
 * \verbatim

    +-----+-----+-----+-----+-----+-----+-----+-----+
 1  |         Type of Service/Traffic Class         |  if TOS = 1
     ..... ..... ..... ..... ..... ..... ..... .....
 2  |         Time to Live/Hop Limit                |  if TTL = 1
     ..... ..... ..... ..... ..... ..... ..... .....
 3  |         Protocol/Next Header                  |  if PR = 1
     ..... ..... ..... ..... ..... ..... ..... .....
 4  /         IP extension headers                  /  variable, if IPX = 1
     ..... ..... ..... ..... ..... ..... ..... .....

 For outer IP-ID:
     ..... ..... ..... ..... ..... ..... ..... .....
 5  |                  IP-ID                        |  2 octets,
     ..... ..... ..... ..... ..... ..... ..... .....    if I2 = 1

\endverbatim
 *
 * Part 4 is not supported.
 *
 * @param context        The compression context
 * @param header_info    The header info stored in the profile
 * @param changed_f      The fields that changed, created by the function
 *                       changed_fields
 * @param ip             One inner or outer IP header
 * @param I              The I flag of the IP header
 * @param ip_hdr_pos     The position of the IP header
 * @param dest           The rohc-packet-under-build buffer
 * @param counter        The current position in the rohc-packet-under-build
 *                       buffer
 * @return               The new position in the rohc-packet-under-build buffer
 *
 * @see changed_fields
 */
int header_fields(const struct c_context *context,
                  struct ip_header_info *const header_info,
                  const unsigned short changed_f,
                  const struct ip_packet *ip,
                  const int I,
                  const ip_header_pos_t ip_hdr_pos,
                  unsigned char *const dest,
                  int counter)
{
	unsigned int tos;
	unsigned int ttl;
	unsigned int protocol;

	/* part 1 */
	if(is_changed(changed_f, MOD_TOS) || header_info->tos_count < MAX_FO_COUNT)
	{
		tos = ip_get_tos(ip);
		rohc_comp_debug(context, "IP TOS/TC of IP header #%u = 0x%02x\n",
		                ip_hdr_pos, tos);
		header_info->tos_count++;
		dest[counter] = tos;
		counter++;
	}

	/* part 2 */
	if(is_changed(changed_f, MOD_TTL) || header_info->ttl_count < MAX_FO_COUNT)
	{
		ttl = ip_get_ttl(ip);
		rohc_comp_debug(context, "IP TTL/HL of IP header #%u = 0x%02x\n",
		                ip_hdr_pos, ttl);
		header_info->ttl_count++;
		dest[counter] = ttl;
		counter++;
	}

	/* part 3 */
	if(is_changed(changed_f, MOD_PROTOCOL) || header_info->protocol_count < MAX_FO_COUNT)
	{
		protocol = ip_get_protocol(ip);
		rohc_comp_debug(context, "IP Protocol/Next Header of IP header #%u "
		                "= 0x%02x\n", ip_hdr_pos, protocol);
		header_info->protocol_count++;
		dest[counter] = protocol;
		counter++;
	}

	/* part 5: only for outer IP header if IPv4 */
	if(ip_hdr_pos == ROHC_IP_HDR_FIRST && I == 1)
	{
		uint16_t id_encoded;

		/* always transmit the IP-ID encoded, in Network Byte Order */
		id_encoded = htons(header_info->info.v4.id_delta);
		memcpy(&dest[counter], &id_encoded, 2);
		rohc_comp_debug(context, "IP ID of IP header #%u = 0x%02x 0x%02x\n",
		                ip_hdr_pos, dest[counter], dest[counter + 1]);
		counter += 2;
	}

	return counter;
}


/**
 * @brief Check if the static parts of the context changed in any of the two
 *        IP headers.
 *
 * @param context The compression context
 * @param ip      The outer IP header
 * @param ip2     The inner IP header
 * @return        The number of fields that changed
 */
int changed_static_both_hdr(const struct c_context *context,
                            const struct ip_packet *ip,
                            const struct ip_packet *ip2)
{
	int nb_fields = 0; /* number of fields that changed */
	struct c_generic_context *g_context;

	g_context = (struct c_generic_context *) context->specific;

	nb_fields = changed_static_one_hdr(context, g_context->tmp.changed_fields,
	                                   &g_context->ip_flags, ip);

	if(g_context->tmp.nr_of_ip_hdr > 1)
	{
		nb_fields += changed_static_one_hdr(context,
		                                    g_context->tmp.changed_fields2,
		                                    &g_context->ip2_flags, ip2);
	}

	return nb_fields;
}


/**
 * @brief Check if the static part of the context changed in the new IP packet.
 *
 * The fields classified as STATIC-DEF by RFC do not need to be checked for
 * change. These fields are constant for all packets in a stream (ie. a
 * profile context). So, the Source Address and Destination Address fields are
 * not checked for change for both IPv4 and IPv6. The Flow Label is not checked
 * for IPv6.
 *
 * Althought not classified as STATIC-DEF, the Version field is the same for
 * all packets in a stream (ie. a profile context) and therefore does not need
 * to be checked for change neither for IPv4 nor IPv6.
 *
 * Althought classified as STATIC, the IPv4 Don't Fragment flag is not part of
 * the static initialization, but of the dynamic initialization.
 *
 * Summary:
 *  - For IPv4, check the Protocol field for change.
 *  - For IPv6, check the Next Header field for change.
 *
 * @param context        The compression context
 * @param changed_fields The fields that changed, created by the function
 *                       changed_fields
 * @param header_info    The header info stored in the profile
 * @param ip             The header of the new IP packet
 * @return               The number of fields that changed
 */
int changed_static_one_hdr(const struct c_context *const context,
                           const unsigned short changed_fields,
                           struct ip_header_info *const header_info,
                           const struct ip_packet *ip)
{
	int nb_fields = 0; /* number of fields that changed */
	struct c_generic_context *g_context;

	g_context = (struct c_generic_context *) context->specific;

	/* check the IPv4 Protocol / IPv6 Next Header field for change */
	if(is_changed(changed_fields, MOD_PROTOCOL) ||
	   header_info->protocol_count < MAX_FO_COUNT)
	{
		rohc_comp_debug(context, "protocol_count %d\n",
		                header_info->protocol_count);

		if(is_changed(changed_fields, MOD_PROTOCOL))
		{
			header_info->protocol_count = 0;
			g_context->fo_count = 0;
		}
		nb_fields += 1;
	}

	return nb_fields;
}


/**
 * @brief Check if the dynamic parts of the context changed in any of the two
 *        IP headers.
 *
 * @param context The compression context
 * @param ip      The outer IP header
 * @param ip2     The inner IP header
 * @return        The number of fields that changed
 */
int changed_dynamic_both_hdr(const struct c_context *context,
                             const struct ip_packet *ip,
                             const struct ip_packet *ip2)
{
	int nb_fields = 0; /* number of fields that changed */
	struct c_generic_context *g_context;

	g_context = (struct c_generic_context *) context->specific;

	rohc_comp_debug(context, "check for changed fields in the outer IP header\n");
	nb_fields = changed_dynamic_one_hdr(context, g_context->tmp.changed_fields,
	                                    &g_context->ip_flags, ip);

	if(g_context->tmp.nr_of_ip_hdr > 1)
	{
		rohc_comp_debug(context, "check for changed fields in the inner IP header\n");
		nb_fields += changed_dynamic_one_hdr(context,
		                                     g_context->tmp.changed_fields2,
		                                     &g_context->ip2_flags, ip2);
	}

	return nb_fields;
}


/**
 * @brief Check if the dynamic part of the context changed in the IP packet.
 *
 * The fields classified as CHANGING by RFC need to be checked for change. The
 * fields are:
 *  - the TOS, IP-ID and TTL fields for IPv4,
 *  - the TC and HL fields for IPv6.
 *
 * The IP-ID changes are managed outside of this function.
 *
 * Althought classified as STATIC, the IPv4 Don't Fragment flag is not part of
 * the static initialization, but of the dynamic initialization. It needs to be
 * checked for change.
 *
 * Other flags are checked for change for IPv4. There are IP-ID related flags:
 *  - RND: is the IP-ID random ?
 *  - NBO: is the IP-ID in Network Byte Order ?
 *
 * @param context        The compression context
 * @param changed_fields The fields that changed, created by the function
 *                       changed_fields
 * @param header_info    The header info stored in the profile
 * @param ip             The header of the new IP packet
 * @return               The number of fields that changed
 */
int changed_dynamic_one_hdr(const struct c_context *const context,
                            const unsigned short changed_fields,
                            struct ip_header_info *const header_info,
                            const struct ip_packet *ip)
{
	int nb_fields = 0; /* number of fields that changed */
	int nb_flags = 0; /* number of flags that changed */
	struct c_generic_context *g_context;

	g_context = (struct c_generic_context *) context->specific;

	/* check the Type Of Service / Traffic Class field for change */
	if(is_changed(changed_fields, MOD_TOS) ||
	   header_info->tos_count < MAX_FO_COUNT)
	{
		if(is_changed(changed_fields, MOD_TOS))
		{
			rohc_comp_debug(context, "TOS/TC changed in the current packet\n");
			header_info->tos_count = 0;
			g_context->fo_count = 0;
		}
		else
		{
			rohc_comp_debug(context, "TOS/TC changed in the last few packets\n");
		}
		nb_fields += 1;
	}

	/* check the Time To Live / Hop Limit field for change */
	if(is_changed(changed_fields, MOD_TTL) ||
	   header_info->ttl_count < MAX_FO_COUNT)
	{
		if(is_changed(changed_fields, MOD_TTL))
		{
			rohc_comp_debug(context, "TTL/HL changed in the current packet\n");
			header_info->ttl_count = 0;
			g_context->fo_count = 0;
		}
		else
		{
			rohc_comp_debug(context, "TTL/HL changed in the last few packets\n");
		}
		nb_fields += 1;
	}

	/* IPv4 only checks */
	if(ip_get_version(ip) == IPV4)
	{
		unsigned int df, old_df;

		/* check the Don't Fragment flag for change (IPv4 only) */
		df = ipv4_get_df(ip);
		old_df = IPV4_GET_DF(header_info->info.v4.old_ip);
		if(df != old_df || header_info->info.v4.df_count < MAX_FO_COUNT)
		{
			if(df != old_df)
			{
				rohc_comp_debug(context, "DF changed in the current packet\n");
				header_info->info.v4.df_count = 0;
				g_context->fo_count = 0;
			}
			else
			{
				rohc_comp_debug(context, "DF changed in the last few packets\n");
			}
			nb_fields += 1;
		}

		/* check the RND flag for change (IPv4 only) */
		if(header_info->info.v4.rnd != header_info->info.v4.old_rnd ||
		   header_info->info.v4.rnd_count < MAX_FO_COUNT)
		{
			if(header_info->info.v4.rnd != header_info->info.v4.old_rnd)
			{
				rohc_comp_debug(context, "RND changed (0x%x -> 0x%x) in the "
				                "current packet\n", header_info->info.v4.old_rnd,
				                header_info->info.v4.rnd);
				header_info->info.v4.rnd_count = 0;
				g_context->fo_count = 0;
			}
			else
			{
				rohc_comp_debug(context, "RND changed in the last few packets\n");
			}
			nb_flags += 1;
		}

		/*  check the NBO flag for change (IPv4 only) */
		if(header_info->info.v4.nbo != header_info->info.v4.old_nbo ||
		   header_info->info.v4.nbo_count < MAX_FO_COUNT)
		{
			if(header_info->info.v4.nbo != header_info->info.v4.old_nbo)
			{
				rohc_comp_debug(context, "NBO changed (0x%x -> 0x%x) in the "
				                "current packet\n", header_info->info.v4.old_nbo,
				                header_info->info.v4.nbo);
				header_info->info.v4.nbo_count = 0;
				g_context->fo_count = 0;
			}
			else
			{
				rohc_comp_debug(context, "NBO changed in the last few packets\n");
			}
			nb_flags += 1;
		}

		if(nb_flags > 0)
		{
			nb_fields += 1;
		}
	}

	return nb_fields;
}


/**
 * @brief Find the IP fields that changed between the profile and a new
 *        IP packet.
 *
 * Only some fields are checked for change in the compression process, so
 * only check these ones to avoid useless work. The fields to check are:
 * TOS/TC, TTL/HL and Protocol/Next Header.
 *
 * @param context        The compression context
 * @param header_info    The header info stored in the profile
 * @param ip             The header of the new IP packet
 * @return               The bitpattern that indicates which field changed
 */
unsigned short changed_fields(const struct c_context *const context,
                              const struct ip_header_info *header_info,
                              const struct ip_packet *ip)
{
	unsigned short ret_value = 0;
	uint8_t old_tos;
	uint8_t new_tos;
	uint8_t old_ttl;
	uint8_t new_ttl;
	uint8_t old_protocol;
	uint8_t new_protocol;

	assert(context != NULL);
	assert(header_info != NULL);
	assert(ip != NULL);

	if(ip_get_version(ip) == IPV4)
	{
		const struct ipv4_hdr *old_ip;

		old_ip = &header_info->info.v4.old_ip;
		old_tos = old_ip->tos;
		old_ttl = old_ip->ttl;
		old_protocol = old_ip->protocol;
	}
	else /* IPV6 */
	{
		const struct ipv6_hdr *old_ip;

		old_ip = &header_info->info.v6.old_ip;
		old_tos = IPV6_GET_TC(*old_ip);
		old_ttl = old_ip->ip6_hlim;
		old_protocol = old_ip->ip6_nxt;
	}

	new_tos = ip_get_tos(ip);
	if(old_tos != new_tos)
	{
		rohc_comp_debug(context, "TOS/TC changed from 0x%02x to 0x%02x\n",
		                old_tos, new_tos);
		ret_value |= MOD_TOS;
	}

	new_ttl = ip_get_ttl(ip);
	if(old_ttl != new_ttl)
	{
		rohc_comp_debug(context, "TTL/HL changed from 0x%02x to 0x%02x\n",
		                old_ttl, new_ttl);
		ret_value |= MOD_TTL;
	}

	new_protocol = ip_get_protocol(ip);
	if(old_protocol != new_protocol)
	{
		rohc_comp_debug(context, "Protocol/NH changed from 0x%02x to 0x%02x\n",
		                old_protocol, new_protocol);
		ret_value |= MOD_PROTOCOL;
	}

	return ret_value;
}


/**
 * @brief Detect the behaviour of the IP-ID fields of the IPv4 headers
 *
 * Detect how the IP-ID fields behave:
 *  - constant (not handled yet),
 *  - increase in Network Bit Order (NBO),
 *  - increase in Little Endian,
 *  - randomly.
 *
 * @param context      The compression context
 * @param header_info  The header info stored in the profile
 * @param ip           One IPv4 header
 */
static void detect_ip_id_behaviours(struct c_context *const context,
                                    const struct ip_packet *const outer_ip,
                                    const struct ip_packet *const inner_ip)
{
	struct c_generic_context *g_context;

	assert(context != NULL);
	assert(outer_ip != NULL);

	g_context = (struct c_generic_context *) context->specific;

	/* detect IP-ID behaviour for the outer IP header if IPv4 */
	if(ip_get_version(outer_ip) == IPV4)
	{
		detect_ip_id_behaviour(context, &g_context->ip_flags, outer_ip);
	}

	/* detect IP-ID behaviour for the inner IP header if present and IPv4 */
	if(g_context->tmp.nr_of_ip_hdr > 1 && ip_get_version(inner_ip) == IPV4)
	{
		detect_ip_id_behaviour(context, &g_context->ip2_flags, inner_ip);
	}
}


/**
 * @brief Detect the behaviour of the IP-ID field of the given IPv4 header
 *
 * Detect how the IP-ID field behave:
 *  - constant (not handled yet),
 *  - increase in Network Bit Order (NBO),
 *  - increase in Little Endian,
 *  - randomly.
 *
 * @param context      The compression context
 * @param header_info  The header info stored in the profile
 * @param ip           One IPv4 header
 */
static void detect_ip_id_behaviour(const struct c_context *const context,
                                   struct ip_header_info *const header_info,
                                   const struct ip_packet *const ip)
{
	rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
	            ip_get_version(ip) == IPV4, error,
	            "cannot check IP-ID behaviour with IPv6\n");

	if(header_info->is_first_header)
	{
		/* IP-ID behaviour cannot be detect for the first header (2 headers are
		 * needed), so consider that IP-ID is not random and in NBO. */
		rohc_comp_debug(context, "no previous IP-ID, consider non-random and NBO\n");
		header_info->info.v4.rnd = 0;
		header_info->info.v4.nbo = 1;
	}
	else
	{
		/* we have seen at least one header before this one, so we can (try to)
		 * detect IP-ID behaviour */

		uint16_t old_id; /* the IP-ID of the previous IPv4 header */
		uint16_t new_id; /* the IP-ID of the IPv4 header being compressed */

		old_id = ntohs(header_info->info.v4.old_ip.id);
		new_id = ntohs(ipv4_get_id(ip));

		rohc_comp_debug(context, "1) old_id = 0x%04x new_id = 0x%04x\n",
		                old_id, new_id);

		if(is_ip_id_nbo(old_id, new_id))
		{
			header_info->info.v4.rnd = 0;
			header_info->info.v4.nbo = 1;
		}
		else
		{
			/* change byte ordering and check NBO again */
			old_id = swab16(old_id);
			new_id = swab16(new_id);

			rohc_comp_debug(context, "2) old_id = 0x%04x new_id = 0x%04x\n",
			                old_id, new_id);

			if(is_ip_id_nbo(old_id, new_id))
			{
				header_info->info.v4.rnd = 0;
				header_info->info.v4.nbo = 1;
			}
			else
			{
				rohc_comp_debug(context, "RND detected\n");
				header_info->info.v4.rnd = 1;
				header_info->info.v4.nbo = 1; /* do not change bit order if RND */
			}
		}
	}

	rohc_comp_debug(context, "NBO = %d, RND = %d\n", header_info->info.v4.nbo,
	                header_info->info.v4.rnd);

error:
	;
}


/**
 * @brief Whether the new IP-ID is transmitted in NBO or not
 *
 * The new IP-ID is considered as transmitted in NBO if it increases by a
 * small delta from the previous IP-ID. Wraparound shall be taken into
 * account.
 *
 * @param old_id  The IP-ID of the previous IPv4 header
 * @param new_id  The IP-ID of the current IPv4 header
 * @return        Whether the IP-ID is transmitted in NBO or not
 */
static bool is_ip_id_nbo(const uint16_t old_id, const uint16_t new_id)
{
	/* The maximal delta accepted between two consecutive IPv4 ID so that it
	 * can be considered as coded in Network Byte Order (NBO) */
	const uint16_t max_id_delta = 20;
	bool is_nbo;

	/* the new IP-ID is transmitted in NBO if it belongs to:
	 *  - interval ]old_id ; old_id + IPID_MAX_DELTA[ (no wraparound)
	 *  - intervals ]old_id ; 0xffff] or
	 *    [0 ; (old_id + IPID_MAX_DELTA) % 0xffff[ (wraparound) */
	if(new_id > old_id && (new_id - old_id) < max_id_delta)
	{
		is_nbo = true;
	}
	else if(old_id > (0xffff - max_id_delta) &&
	        (new_id > old_id || new_id < (max_id_delta - (0xffff - old_id))))
	{
		is_nbo = true;
	}
	else
	{
		is_nbo = false;
	}

	return is_nbo;
}


/*
 * Definitions of main private functions
 */


/**
 * @brief Encode uncompressed fields with the corresponding encoding scheme
 *
 * @param context      The compression context
 * @param ip           The outer IP header
 * @param ip2          The inner IP header
 * @param next_header  The next header
 * @return             ROHC_OK in case of success,
 *                     ROHC_ERROR otherwise
 */
static int encode_uncomp_fields(struct c_context *const context,
                                const struct ip_packet *const ip,
                                const struct ip_packet *const ip2,
                                const unsigned char *const next_header)
{
	struct c_generic_context *g_context;
	bool wlsb_k_ok;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;
	assert(ip != NULL);
	assert((g_context->tmp.nr_of_ip_hdr == 1 && ip2 == NULL) ||
	       (g_context->tmp.nr_of_ip_hdr == 2 && ip2 != NULL));

	rohc_comp_debug(context, "compressor is in state %u\n", context->state);

	/* always update the info related to the SN */
	{
		rohc_comp_debug(context, "new SN = %u / 0x%x\n", g_context->sn,
		                g_context->sn);

		/* how many bits are required to encode the new SN ? */
		if(context->state == IR)
		{
			/* send all bits in IR state */
			g_context->tmp.nr_sn_bits = 16;
			rohc_comp_debug(context, "IR state: force using %zd bits to encode "
			                "new SN\n", g_context->tmp.nr_sn_bits);
		}
		else
		{
			/* send only required bits in FO or SO states */
			wlsb_k_ok = wlsb_get_k_32bits(g_context->sn_window, g_context->sn,
			                              &(g_context->tmp.nr_sn_bits));
			if(!wlsb_k_ok)
			{
				rohc_comp_debug(context, "failed to find the minimal number "
				                "of bits required for SN\n");
				goto error;
			}
		}
		rohc_comp_debug(context, "%zd bits are required to encode new SN\n",
		                g_context->tmp.nr_sn_bits);

		/* add the new SN to the W-LSB encoding object */
		c_add_wlsb(g_context->sn_window, g_context->sn, g_context->sn);
	}

	/* update info related to the IP-ID of the outer header
	 * only if header is IPv4 */
	if(ip_get_version(ip) == IPV4)
	{
		/* compute the new IP-ID / SN delta */
		if(g_context->ip_flags.info.v4.nbo)
		{
			g_context->ip_flags.info.v4.id_delta =
				ntohs(ipv4_get_id(ip)) - g_context->sn;
		}
		else
		{
			g_context->ip_flags.info.v4.id_delta = ipv4_get_id(ip) - g_context->sn;
		}
		rohc_comp_debug(context, "new outer IP-ID delta = 0x%x / %u (NBO = %d, "
		                "RND = %d)\n", g_context->ip_flags.info.v4.id_delta,
		                g_context->ip_flags.info.v4.id_delta,
		                g_context->ip_flags.info.v4.nbo,
		                g_context->ip_flags.info.v4.rnd);

		/* how many bits are required to encode the new IP-ID / SN delta ? */
		if(context->state == IR)
		{
			/* send all bits in IR state */
			g_context->tmp.nr_ip_id_bits = 16;
			rohc_comp_debug(context, "IR state: force using %zd bits to encode "
			                "new outer IP-ID delta\n", g_context->tmp.nr_ip_id_bits);
		}
		else
		{
			/* send only required bits in FO or SO states */
			wlsb_k_ok = wlsb_get_k_16bits(g_context->ip_flags.info.v4.ip_id_window,
			                              g_context->ip_flags.info.v4.id_delta,
			                              &(g_context->tmp.nr_ip_id_bits));
			if(!wlsb_k_ok)
			{
				rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
				             "failed to find the minimal number of bits required "
				             "for new outer IP-ID delta\n");
				goto error;
			}
		}
		rohc_comp_debug(context, "%zd bits are required to encode new outer "
		                "IP-ID delta\n", g_context->tmp.nr_ip_id_bits);

		/* add the new IP-ID / SN delta to the W-LSB encoding object */
		c_add_wlsb(g_context->ip_flags.info.v4.ip_id_window, g_context->sn,
		           g_context->ip_flags.info.v4.id_delta);
	}
	else /* IPV6 */
	{
		g_context->tmp.nr_ip_id_bits = 0;
	}

	/* update info related to the IP-ID of the inner header
	 * only if header is IPv4 */
	if(g_context->tmp.nr_of_ip_hdr > 1 && ip_get_version(ip2) == IPV4)
	{
		/* compute the new IP-ID / SN delta */
		if(g_context->ip2_flags.info.v4.nbo)
		{
			g_context->ip2_flags.info.v4.id_delta =
				ntohs(ipv4_get_id(ip2)) - g_context->sn;
		}
		else
		{
			g_context->ip2_flags.info.v4.id_delta = ipv4_get_id(ip2) - g_context->sn;
		}
		rohc_comp_debug(context, "new inner IP-ID delta = 0x%x / %u (NBO = %d, "
		                "RND = %d)\n", g_context->ip2_flags.info.v4.id_delta,
		                g_context->ip2_flags.info.v4.id_delta,
		                g_context->ip2_flags.info.v4.nbo,
		                g_context->ip2_flags.info.v4.rnd);

		/* how many bits are required to encode the new IP-ID / SN delta ? */
		if(context->state == IR)
		{
			/* send all bits in IR state */
			g_context->tmp.nr_ip_id_bits2 = 16;
			rohc_comp_debug(context, "IR state: force using %zd bits to encode "
			                "new inner IP-ID delta\n", g_context->tmp.nr_ip_id_bits2);
		}
		else
		{
			/* send only required bits in FO or SO states */
			wlsb_k_ok = wlsb_get_k_16bits(g_context->ip2_flags.info.v4.ip_id_window,
			                              g_context->ip2_flags.info.v4.id_delta,
			                              &(g_context->tmp.nr_ip_id_bits2));
			if(!wlsb_k_ok)
			{
				rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
				             "failed to find the minimal number of bits required "
				             "for new inner IP-ID delta\n");
				goto error;
			}
		}
		rohc_comp_debug(context, "%zd bits are required to encode new inner "
		                "IP-ID delta\n", g_context->tmp.nr_ip_id_bits2);

		/* add the new IP-ID / SN delta to the W-LSB encoding object */
		c_add_wlsb(g_context->ip2_flags.info.v4.ip_id_window, g_context->sn,
		           g_context->ip2_flags.info.v4.id_delta);
	}
	else /* IPV6 */
	{
		g_context->tmp.nr_ip_id_bits2 = 0;
	}

	/* update info related to transport header */
	if(g_context->encode_uncomp_fields != NULL)
	{
		int ret;

		ret = g_context->encode_uncomp_fields(context, ip, ip2, next_header);
		if(ret != ROHC_OK)
		{
			rohc_warning(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			             "failed to encode uncompressed next header fields\n");
			goto error;
		}
	}

	return ROHC_OK;

error:
	return ROHC_ERROR;
}


/**
 * @brief Decide what extension shall be used in the UO-1/UO-2 packet.
 *
 * Extensions 0, 1 & 2 are IPv4 only because of the IP-ID.
 *
 * @param context The compression context
 * @return        The extension code among PACKET_NOEXT, PACKET_EXT_0,
 *                PACKET_EXT_1 and PACKET_EXT_3 if successful,
 *                PACKET_EXT_UNKNOWN otherwise
 */
rohc_ext_t decide_extension(const struct c_context *context)
{
	struct c_generic_context *g_context;
	size_t nr_innermost_ip_id_bits;
	size_t nr_outermost_ip_id_bits;
	size_t nr_sn_bits;
	rohc_ext_t ext;

	g_context = (struct c_generic_context *) context->specific;
	nr_sn_bits = g_context->tmp.nr_sn_bits;

	/* force extension type 3 if at least one static or dynamic field changed */
	if(g_context->tmp.send_static > 0 || g_context->tmp.send_dynamic > 0)
	{
		rohc_comp_debug(context, "force EXT-3 because at least one static or "
		                "dynamic field changed\n");
		ext = PACKET_EXT_3;
		goto skip;
	}

	/* determine the number of IP-ID bits and the IP-ID offset of the
	 * innermost IPv4 header with non-random IP-ID */
	rohc_get_ipid_bits(context, &nr_innermost_ip_id_bits,
	                   &nr_outermost_ip_id_bits);

	switch(g_context->tmp.packet_type)
	{
		case PACKET_UOR_2:
		{
			if(nr_sn_bits < 5 &&
			   nr_innermost_ip_id_bits == 0 &&
			   nr_outermost_ip_id_bits == 0)
			{
				ext = PACKET_NOEXT;
			}
			else if(nr_sn_bits <= 8 &&
			        nr_innermost_ip_id_bits <= 3 &&
			        nr_outermost_ip_id_bits == 0)
			{
				ext = PACKET_EXT_0;
			}
			else if(nr_sn_bits <= 8 &&
			        nr_innermost_ip_id_bits <= 11 &&
			        nr_outermost_ip_id_bits == 0)
			{
				ext = PACKET_EXT_1;
			}
			else if(g_context->tmp.nr_of_ip_hdr > 1 &&
			        nr_sn_bits <= 3 &&
			        nr_innermost_ip_id_bits <= 8 &&
			        nr_outermost_ip_id_bits <= 11)
			{
				ext = PACKET_EXT_2;
			}
			else
			{
				ext = PACKET_EXT_3;
			}

			break;
		}

		case PACKET_UOR_2_RTP:
		{
			const struct sc_rtp_context *rtp_context;
			size_t nr_ts_bits;

			rtp_context = (struct sc_rtp_context *) g_context->specific;
			nr_ts_bits = rtp_context->tmp.nr_ts_bits;

			/* NO_EXT, EXT_0, EXT_1, EXT_2 and EXT_3 */
			if(nr_sn_bits <= 6 &&
			   nr_ts_bits <= 6 &&
			   nr_innermost_ip_id_bits == 0 &&
			   nr_outermost_ip_id_bits == 0)
			{
				ext = PACKET_NOEXT;
			}
			else if(nr_sn_bits <= 9 &&
			        nr_ts_bits <= 9 &&
			        nr_innermost_ip_id_bits == 0 &&
			        nr_outermost_ip_id_bits == 0)
			{
				ext = PACKET_EXT_0;
			}
			else if(nr_sn_bits <= 9 &&
			        nr_ts_bits <= 17 &&
			        nr_innermost_ip_id_bits == 0 &&
			        nr_outermost_ip_id_bits == 0)
			{
				ext = PACKET_EXT_1;
			}
			else if(nr_sn_bits <= 9 &&
			        nr_ts_bits <= 25 &&
			        nr_innermost_ip_id_bits == 0 &&
			        nr_outermost_ip_id_bits == 0)
			{
				ext = PACKET_EXT_2;
			}
			else
			{
				ext = PACKET_EXT_3;
			}

			break;
		}

		case PACKET_UOR_2_TS:
		{
			const struct sc_rtp_context *rtp_context;
			size_t nr_ts_bits;

			rtp_context = (struct sc_rtp_context *) g_context->specific;
			nr_ts_bits = rtp_context->tmp.nr_ts_bits;

			/* NO_EXT, EXT_0, EXT_1, EXT_2 and EXT_3 */
			if(nr_sn_bits <= 6 &&
			   nr_ts_bits <= 5 &&
			   nr_innermost_ip_id_bits == 0 &&
			   nr_outermost_ip_id_bits == 0)
			{
				ext = PACKET_NOEXT;
			}
			else if(nr_sn_bits <= 9 &&
			        nr_ts_bits <= 8 &&
			        nr_innermost_ip_id_bits == 0 &&
			        nr_outermost_ip_id_bits == 0)
			{
				ext = PACKET_EXT_0;
			}
			else if(nr_sn_bits <= 9 &&
			        nr_ts_bits <= 8 &&
			        nr_innermost_ip_id_bits <= 8 &&
			        nr_outermost_ip_id_bits == 0)
			{
				ext = PACKET_EXT_1;
			}
			else if(nr_sn_bits <= 9 &&
			        nr_ts_bits <= 16 &&
			        nr_innermost_ip_id_bits <= 8 &&
			        nr_outermost_ip_id_bits == 0)
			{
				ext = PACKET_EXT_2;
			}
			else
			{
				ext = PACKET_EXT_3;
			}

			break;
		}

		case PACKET_UOR_2_ID:
		{
			const struct sc_rtp_context *rtp_context;
			size_t nr_ts_bits;

			rtp_context = (struct sc_rtp_context *) g_context->specific;
			nr_ts_bits = rtp_context->tmp.nr_ts_bits;

			/* NO_EXT, EXT_0, EXT_1, EXT_2 and EXT_3 */
			if(nr_sn_bits <= 6 &&
			   nr_ts_bits == 0 &&
			   nr_innermost_ip_id_bits <= 5 &&
			   nr_outermost_ip_id_bits == 0)
			{
				ext = PACKET_NOEXT;
			}
			else if(nr_sn_bits <= 9 &&
			        nr_ts_bits == 0 &&
			        nr_innermost_ip_id_bits <= 8 &&
			        nr_outermost_ip_id_bits == 0)
			{
				ext = PACKET_EXT_0;
			}
			else if(nr_sn_bits <= 9 &&
			        nr_ts_bits <= 8 &&
			        nr_innermost_ip_id_bits <= 8 &&
			        nr_outermost_ip_id_bits == 0)
			{
				ext = PACKET_EXT_1;
			}
			else if(nr_sn_bits <= 9 &&
			        nr_ts_bits <= 8 &&
			        nr_innermost_ip_id_bits <= 16 &&
			        nr_outermost_ip_id_bits == 0)
			{
				ext = PACKET_EXT_2;
			}
			else
			{
				ext = PACKET_EXT_3;
			}

			break;
		}

		default:
		{
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            false, error, "bad packet type (%d)",
			            g_context->tmp.packet_type);
		}
	}

skip:
	return ext;

error:
	return PACKET_EXT_UNKNOWN;
}


/**
 * @brief Determine the number of IP-ID bits and the IP-ID offset of the
 *        innermost IPv4 header with non-random IP-ID
 *
 * @param context  The compression context
 * @param pos      OUT: The position of the header
 * @param nr_bits  OUT: the number of IP-ID bits of the found header
 * @param offset   OUT: the IP-ID offset of the found header
 */
static void rohc_get_innermost_ipv4_non_rnd(const struct c_context *context,
                                            ip_header_pos_t *const pos,
                                            size_t *const nr_bits,
                                            uint16_t *const offset)
{
	struct c_generic_context *g_context;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;

	assert(pos != NULL);
	assert(nr_bits != NULL);
	assert(offset != NULL);

	if(g_context->tmp.nr_of_ip_hdr > 1 &&
	   g_context->ip2_flags.version == IPV4 &&
	   g_context->ip2_flags.info.v4.rnd == 0)
	{
		/* inner IP header exists and is IPv4 with a non-random IP-ID */
		*pos = ROHC_IP_HDR_SECOND;
		*nr_bits = g_context->tmp.nr_ip_id_bits2;
		*offset = g_context->ip2_flags.info.v4.id_delta;
	}
	else if(g_context->ip_flags.version == IPV4 &&
	        g_context->ip_flags.info.v4.rnd == 0)
	{
		/* outer IP header is IPv4 with a non-random IP-ID */
		*pos = ROHC_IP_HDR_FIRST;
		*nr_bits = g_context->tmp.nr_ip_id_bits;
		*offset = g_context->ip_flags.info.v4.id_delta;
	}
	else
	{
		/* there is no IPv4 header with a non-random IP-ID */
		*pos = ROHC_IP_HDR_NONE;
		*nr_bits = 0;
		*offset = 0;
	}
}


/**
 * @brief Get the number of non-random outer/inner IP-ID bits
 *
 * @param context            The compression context
 * @param nr_innermost_bits  OUT: the maximum number of IP-ID bits
 *                                for the innermost IPv4 header
 * @param nr_outermost_bits  OUT: the maximum number of IP-ID bits
 *                                for the outermost IP header
 */
void rohc_get_ipid_bits(const struct c_context *context,
                        size_t *const nr_innermost_bits,
                        size_t *const nr_outermost_bits)
{
	struct c_generic_context *g_context;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;

	assert(nr_innermost_bits != NULL);
	assert(nr_outermost_bits != NULL);

	if(g_context->tmp.nr_of_ip_hdr > 1 &&
	   g_context->ip2_flags.version == IPV4 &&
	   g_context->ip2_flags.info.v4.rnd == 0)
	{
		/* inner IP header exists and is IPv4 with a non-random IP-ID */
		*nr_innermost_bits = g_context->tmp.nr_ip_id_bits2;

		/* how many bits for the outer IP-ID? */
		if(g_context->ip_flags.version == IPV4 &&
		   g_context->ip_flags.info.v4.rnd == 0)
		{
			*nr_outermost_bits = g_context->tmp.nr_ip_id_bits;
		}
		else
		{
			*nr_outermost_bits = 0;
		}
	}
	else if(g_context->ip_flags.version == IPV4 &&
	        g_context->ip_flags.info.v4.rnd == 0)
	{
		/* outer IP header is IPv4 with a non-random IP-ID */
		*nr_innermost_bits = 0;
		*nr_outermost_bits = g_context->tmp.nr_ip_id_bits;
	}
	else
	{
		/* there is no IPv4 header with a non-random IP-ID */
		*nr_innermost_bits = 0;
		*nr_outermost_bits = 0;
	}
}


/*
 * Definitions of private functions related to IPv6 extension headers
 */

/**
 * @brief Initialize the tables IPv6 extension in compressor
 *
 * @param comp The list compressor
 */
static void ip6_c_init_table(struct list_comp *const comp)
{
	unsigned int i;

	/* insert HBH type in table */
	comp->based_table[0].type = HBH;
	comp->based_table[0].length = 0;
	comp->based_table[0].data = NULL;
	comp->trans_table[0].known = 0;
	comp->trans_table[0].item = &comp->based_table[0];
	comp->trans_table[0].counter = 0;
	/* insert DEST type in table */
	comp->based_table[1].type = DEST;
	comp->based_table[1].length = 0;
	comp->based_table[1].data = NULL;
	comp->trans_table[1].known = 0;
	comp->trans_table[1].item = &comp->based_table[1];
	comp->trans_table[1].counter = 0;
	/* insert RTHDR type in table */
	comp->based_table[2].type = RTHDR;
	comp->based_table[2].length = 0;
	comp->based_table[2].data = NULL;
	comp->trans_table[2].known = 0;
	comp->trans_table[2].item = &comp->based_table[2];
	comp->trans_table[2].counter = 0;
	/* insert AHHDR type in table */
	comp->based_table[3].type = AH;
	comp->based_table[3].length = 0;
	comp->based_table[3].data = NULL;
	comp->trans_table[3].known = 0;
	comp->trans_table[3].item = &comp->based_table[4];
	comp->trans_table[3].counter = 0;
	/* reset other headers */
	for(i = 4; i < MAX_ITEM; i++)
	{
		comp->based_table[i].type = 0;
		comp->based_table[i].length = 0;
		comp->based_table[i].data = NULL;
		comp->trans_table[i].known = 0;
		comp->trans_table[i].item = NULL;
		comp->trans_table[i].counter = 0;
	}
}


/**
 * @brief Destory the tables of the given list compressor
 *
 * @param comp  The list compressor whose tables should be destroyed
 */
static void list_comp_ipv6_destroy_table(struct list_comp *const comp)
{
	int i;
	for(i = 0; i < 4; i++)
	{
		if(comp->based_table[i].data != NULL)
		{
			free(comp->based_table[i].data);
		}
	}
}


/**
 * @brief IPv6 extension comparison
 *
 * @param ext          The IPv6 extension to compare
 * @param comp         The list compressor
 * @param size         The size of the IPv6 extension to compare
 * @param index_table  The index of the IPv6 extention in based table
 * @return             1 if equal, 0 otherwise
 */
static int ipv6_compare(const struct list_comp *const comp,
                        const unsigned char *const ext,
                        const int size,
                        const int index_table)
{
	/* do not compare the Next Header field */
	assert(size > 2);
	return memcmp(ext + 2, comp->based_table[index_table].data + 2, size - 2);
}


/**
 * @brief Update an IPv6 item with the given extension
 *
 * @param comp         The list compressor
 * @param index_table  The index of this item in the based table
 * @param ext          The IPv6 extension
 * @param size         The size of the data (in bytes)
 */
static void create_ipv6_item(struct list_comp *const comp,
                             const unsigned int index_table,
                             const unsigned char *ext_data,
                             const size_t ext_size)
{
	assert(comp != NULL);
	assert(ext_data != NULL);
	assert(ext_size > 0);

	comp->based_table[index_table].length = ext_size;
	if(comp->based_table[index_table].data != NULL)
	{
		zfree(comp->based_table[index_table].data);
	}
	comp->based_table[index_table].data = malloc(ext_size);
	if(comp->based_table[index_table].data != NULL)
	{
		memcpy(comp->based_table[index_table].data, ext_data, ext_size);
	}
}


/**
 * @brief Extract the Nth IP extension of the IP packet
 *
 * Extract the IP extension at the given index.
 *
 * @param ip     The IP packet to analyse
 * @param index  The index of the extension to retrieve in the IP packet
 * @return       the extension
 */
static unsigned char * get_ipv6_extension(const struct ip_packet *ip,
                                          const int index)
{
	unsigned char *next_header;
	uint8_t next_header_type;
	int i = 0;

	/* get the next known IP extension in packet */
	next_header = ip_get_next_ext_from_ip(ip, &next_header_type);
	while(i < index && next_header != NULL)
	{
		/* get the next known IP extension */
		next_header = ip_get_next_ext_from_ext(next_header, &next_header_type);
		i++;
	}

	return next_header;
}


/**
 * @brief Return the based table index for the Nth IP extension of the IP packet
 *
 * @param ip     The IP packet to analyse
 * @param index  The index of the extension to retrieve in the IP packet
 * @return       the based table index
 */
static int get_index_ipv6_table(const struct ip_packet *ip, const int index)
{
	int index_table = -1;
	unsigned char *next_header;
	uint8_t next_header_type;
	int i = 0;

	/* get the next known IP extension in packet */
	next_header = ip_get_next_ext_from_ip(ip, &next_header_type);
	while(i < index && next_header != NULL)
	{
		/* get the next known IP extension */
		next_header = ip_get_next_ext_from_ext(next_header, &next_header_type);
		i++;
	}

	/* did we find the Nth extension ? */
	if(next_header == NULL)
	{
		goto error;
	}

	switch(next_header_type)
	{
		case IPV6_EXT_HOP_BY_HOP:
			index_table = 0;
			break;
		case IPV6_EXT_DESTINATION:
			index_table = 1;
			break;
		case IPV6_EXT_ROUTING:
			index_table = 2;
			break;
		case IPV6_EXT_AUTH:
			index_table = 3;
			break;
		default:
			goto error;
	}

	return index_table;

error:
	return -1;
}


/**
 * @brief Decide whether list of IPv6 extension headers shall be sent
 *        compressed
 *
 * @param comp  The list compressor which is specific to the extension type
 * @param ip    The IP packet to compress
 * @return      true if the decision was successful taken, false otherwise
 */
static bool rohc_list_decide_ipv6_compression(struct list_comp *const comp,
                                              const struct ip_packet *const ip)
{
	int i;
	int size;
	int j;
	int index_table;
	const unsigned char *ext;
	struct list_elt *elt;

	/* default the list does not change */
	comp->changed = false;

	ext = ip_get_raw_data(ip) + sizeof(struct ipv6_hdr);

#if ROHC_EXTRA_DEBUG == 1
	/* print current list before update */
	rc_list_debug(comp, "current list (gen_id = %d) before update:\n",
	              comp->curr_list->gen_id);
	i = 0;
	while((elt = list_get_elt_by_index(comp->curr_list, i)) != NULL)
	{
		rc_list_debug(comp, "   IPv6 extension of type 0x%02x / %d\n",
		              elt->item->type, elt->item->type);
		i++;
	}

	/* print reference list before update */
	rc_list_debug(comp, "reference list (gen_id = %d) before update:\n",
	              comp->ref_list->gen_id);
	i = 0;
	while((elt = list_get_elt_by_index(comp->ref_list, i)) != NULL)
	{
		rc_list_debug(comp, "   IPv6 extension of type 0x%02x / %d\n",
		              elt->item->type, elt->item->type);
		i++;
	}
#endif

	size = list_get_size(comp->curr_list);

	/* do we update the reference list ? we update it if a list was sent at
	 * least L times */
	if(comp->counter == (L + 1))
	{
		rc_list_debug(comp, "replace the reference list (gen_id = %d) by "
		              "current list (gen_id = %d) because it was transmitted "
		              "more than L = %d times\n", comp->ref_list->gen_id,
		              comp->curr_list->gen_id, L);

		list_empty(comp->ref_list);
		for(j = 0; j < size; j++)
		{
			elt = list_get_elt_by_index(comp->curr_list, j);
			if(!list_add_at_index(comp->ref_list, elt->item, j, elt->index_table))
			{
				goto error;
			}
		}
		comp->ref_list->gen_id = comp->curr_list->gen_id;
	}

	/* get the extensions */
	i = 0;
	index_table = comp->get_index_table(ip, i);
	if(index_table == -1)
	{
		/* there is no list of IPv6 extension headers */
		comp->is_present = false;
	}
	else
	{
		/* there is one extension or more */
		rc_list_debug(comp, "there is at least one IPv6 extension in packet\n");
		comp->is_present = true;

		/* add new extensions and update modified extensions in current list */
		ext = comp->get_extension(ip, i);
		while(index_table != -1)
		{
			if(!rohc_list_create_current(i, comp, ext, index_table))
			{
				goto error;
			}
			i++;
			index_table = comp->get_index_table(ip, i);
			ext = comp->get_extension(ip, i);
		}

		/* there are fewer extensions in the packet than in the current list,
		   delete them all */
		if(size > i)
		{
			int nb_deleted = 0;

			comp->counter = 0;
			for(j = i; j < size; j++)
			{
				elt = list_get_elt_by_index(comp->curr_list, j - nb_deleted);
				assert(elt != NULL);

				rc_list_debug(comp, "delete IPv6 extension of type %d from "
				              "current list because it is not transmitted "
				              "anymore\n", elt->item->type);
				list_remove(comp->curr_list, elt->item);
				nb_deleted++;
			}
		}

		/* list changed, so change the gen_id */
		if(comp->counter == 0)
		{
			comp->curr_list->gen_id++;
			rc_list_debug(comp, "list changed, use new gen_id %d\n",
			              comp->curr_list->gen_id);
		}

		/* send the list compressed until it was repeated at least L times */
		if(comp->counter < L)
		{
			rc_list_debug(comp, "list with gen_id %d was not sent at least "
			              "L = %d times (%d times), send it compressed\n",
			              comp->curr_list->gen_id, L, comp->counter);
			comp->changed = true;
		}

		/* list is sent another time */
		comp->counter++;

		/* mark extensions that were sent at least L times as known */
		for(j = 0; j < MAX_ITEM; j++)
		{
			if(!comp->trans_table[j].known)
			{
				comp->trans_table[j].counter++;
				if(comp->trans_table[j].counter >= L)
				{
					rc_list_debug(comp, "extension #%d was sent at least L = %d "
					              "times (%d times), mark it as known\n", j, L,
					              comp->trans_table[j].counter);
					comp->trans_table[j].known = 1;
				}
			}
		}
	}
	rc_list_debug(comp, "value of the counter for reference: %d\n",
	              comp->counter);

#if ROHC_EXTRA_DEBUG == 1
	/* print current list after update */
	rc_list_debug(comp, "current list (gen_id = %d) after update:\n",
	              comp->curr_list->gen_id);
	i = 0;
	while((elt = list_get_elt_by_index(comp->curr_list, i)) != NULL)
	{
		rc_list_debug(comp, "   IPv6 extension of type 0x%02x / %d\n",
		              elt->item->type, elt->item->type);
		i++;
	}

	/* print reference list after update */
	rc_list_debug(comp, "reference list (gen_id = %d) before update:\n",
	              comp->ref_list->gen_id);
	i = 0;
	while((elt = list_get_elt_by_index(comp->ref_list, i)) != NULL)
	{
		rc_list_debug(comp, "   IPv6 extension of type 0x%02x / %d\n",
		              elt->item->type, elt->item->type);
		i++;
	}
#endif

	return true;

error:
	return false;
}


/*
 * Definitions of private functions related to list compression
 */

/**
 * @brief Create the current list
 *
 * @param index        The number of the extension
 * @param comp         The list compressor
 * @param ext          The extension
 * @param index_table  The index of the item in the based table
 * @return             true if successful, false otherwise
 */
static bool rohc_list_create_current(const int index,
                                     struct list_comp *const comp,
                                     const unsigned char *ext,
                                     const int index_table)
{
	struct list_elt *elt;
	int curr_index;
	int i;
	int size;

	size = comp->get_size(ext);

	/* test if the extension is the same in tables */
	if(size == comp->based_table[index_table].length)
	{
		if(comp->compare(comp, ext, size, index_table) != 0)
		{
			/* the extension is modified */
			rc_list_debug(comp, "new extension to encode with same size than "
			              "previously\n");
			curr_index = list_get_index_by_elt(comp->curr_list,
			                                   &(comp->based_table[index_table]));
			comp->create_item(comp, index_table, ext, size);
			comp->trans_table[index_table].known = 0;
			comp->trans_table[index_table].counter = 0;

			/* are some elements not transmitted anymore ? */
			if(index < curr_index)
			{
				/* the elements not transmitted are deleted,
				   the extension which was modified is deleted */
				for(i = index; i < (curr_index + 1); i++)
				{
					elt = list_get_elt_by_index(comp->curr_list, i);
					rc_list_debug(comp, "delete IPv6 extension of type %d from "
					              "current list because it is not transmitted "
					              "anymore\n", elt->item->type);
					list_remove(comp->curr_list,elt->item);
				}
			}
			else if(index == curr_index)
			{
				/* the extension which was modified is deleted */
				elt = list_get_elt_by_index(comp->curr_list, index);
				rc_list_debug(comp, "delete IPv6 extension of type %d from "
				              "current list because it was modified\n",
				              elt->item->type);
				list_remove(comp->curr_list,elt->item);
			}

			comp->counter = 0;

			/* add the new version of the extension */
			rc_list_debug(comp, "add IPv6 extension of type %d to current "
			              "list to replace the one we deleted because it was "
			              "modified\n", comp->based_table[index_table].type);
			if(!list_add_at_index(comp->curr_list,
			                      &(comp->based_table[index_table]),
			                      index, index_table))
			{
				goto error;
			}
		}
		else
		{
			curr_index = list_get_index_by_elt(comp->curr_list,
			                                   &(comp->based_table[index_table]));
			if(curr_index < 0)
			{
				/* the element is not present in current list, add it */
				rc_list_debug(comp, "add IPv6 extension of type %d to current "
				              "list because it is a new extension not present "
				              "yet\n", comp->based_table[index_table].type);
				if(!list_add_at_index(comp->curr_list,
				                      &comp->based_table[index_table],
				                      index, index_table))
				{
					goto error;
				}
				comp->counter = 0;
			}
			else if(index < curr_index)
			{
				/* some elements are not transmitted anymore, delete them */
				for(i = index; i < curr_index; i++)
				{
					elt = list_get_elt_by_index(comp->curr_list, i);
					rc_list_debug(comp, "delete IPv6 extension of type %d from "
					              "current list because it is not transmitted "
					              "anymore\n", elt->item->type);
					list_remove(comp->curr_list,elt->item);
				}
				comp->counter = 0;
			}
		}
	}
	else
	{
		/* the extension is modified or new */
		rc_list_debug(comp, "new extension to encode with new size\n");
		curr_index = list_get_index_by_elt(comp->curr_list,
		                                   &(comp->based_table[index_table]));
		comp->create_item(comp, index_table, ext, size);
		comp->trans_table[index_table].known = 0;
		comp->trans_table[index_table].counter = 0;

		if(curr_index < 0)
		{
			/* the element is not present in the current list, add it */
			rc_list_debug(comp, "add IPv6 extension of type %d to current "
			              "list because it is a new extension not present "
			              "yet\n", comp->based_table[index_table].type);
			if(!list_add_at_end(comp->curr_list, &comp->based_table[index_table],
			                    index_table))
			{
				goto error;
			}

			curr_index = list_get_index_by_elt(comp->curr_list,
			                                   &(comp->based_table[index_table]));
			if(index < curr_index)
			{
				/* some elements are not transmitted anymore, delete them */
				for(i = index; i < curr_index; i++)
				{
					elt = list_get_elt_by_index(comp->curr_list, i);
					rc_list_debug(comp, "delete IPv6 extension of type %d from "
					              "current list because it is not transmitted "
					              "anymore\n", elt->item->type);
					list_remove(comp->curr_list,elt->item);
				}
			}
		}
		else /* extension modified */
		{
			/* are some elements not transmitted anymore ? */
			if(index < curr_index)
			{
				/* the elements not transmitted are deleted,
				   the extension which was modified is deleted */
				for(i = index; i < (curr_index + 1); i++)
				{
					elt = list_get_elt_by_index(comp->curr_list, i);
					rc_list_debug(comp, "delete IPv6 extension of type %d from "
					              "current list because it is not transmitted "
					              "anymore\n", elt->item->type);
					list_remove(comp->curr_list,elt->item);
				}
			}
			else if(index == curr_index)
			{
				/* the extension which was modified is deleted */
				elt = list_get_elt_by_index(comp->curr_list, index);
				rc_list_debug(comp, "delete IPv6 extension of type %d from "
				              "current list list because it was modified\n",
				              elt->item->type);
				list_remove(comp->curr_list,elt->item);
			}

			/* add the new version of the extension */
			rc_list_debug(comp, "add IPv6 extension of type %d to current "
			              "list to replace the one we deleted because it was "
			              "modified\n", comp->based_table[index_table].type);
			if(!list_add_at_index(comp->curr_list,
			                      &comp->based_table[index_table],
			                      index, index_table))
			{
				goto error;
			}
		}

		comp->counter = 0;
	}

	return true;

error:
	return false;
}


/**
 * @brief Decide the encoding type for compression list
 *
 * @param comp  The list compressor
 * @return      the encoding type among [0-3]
 */
static int rohc_list_decide_type(struct list_comp *const comp)
{
	int encoding_type;

	/* sanity checks */
	assert(comp != NULL);
	assert(comp->is_present == true);

	if(comp->ref_list->first_elt == NULL)
	{
		/* no reference list, so use encoding type 0 */
		rc_list_debug(comp, "use list encoding type 0 because there is no "
		              "reference list yet\n");
		encoding_type = 0;
	}
	else if(!comp->changed)
	{
		/* the list did not change, so use encoding type 0 */
		rc_list_debug(comp, "use list encoding type 0 because the list did "
		              "not change (items should not be sent)\n");
		encoding_type = 0;
	}
	else /* the list is modified */
	{
		bool are_all_items_present;
		int ref_size; /* size of reference list */
		int curr_size; /* size of current list */
		struct list_elt *elt;
		int i;

		/* determine the sizes of current and reference lists */
		ref_size = list_get_size(comp->ref_list);
		curr_size = list_get_size(comp->curr_list);

		if(curr_size <= ref_size)
		{
			/* there are fewer items in the current list than in the reference list */

			/* are all the items of the current list in the reference list ? */
			i = 0;
			are_all_items_present = true;
			while(are_all_items_present && i < curr_size)
			{
				elt = list_get_elt_by_index(comp->curr_list, i);
				if(!list_type_is_present(comp->ref_list, elt->item) ||
				   !comp->trans_table[elt->index_table].known)
				{
					are_all_items_present = false;
				}
				i++;
			}

			if(are_all_items_present)
			{
				/* all the items of the current list are present in the reference
				   list, so the 'Removal Only scheme' (type 2) may be used to encode
				   the current list */
				encoding_type = 2;
			}
			else
			{
				/* some items of the current list are not present in the reference
				   list, so the 'Remove Then Insert scheme' (type 3) is required to
				   encode the current list */
				encoding_type = 3;
			}
		}
		else
		{
			/* there are more items in the current list than in the reference list */

			/* are all the items of the current list in the reference list ? */
			i = 0;
			are_all_items_present = true;
			while(are_all_items_present && i < ref_size)
			{
				elt = list_get_elt_by_index(comp->ref_list, i);
				if(!list_type_is_present(comp->curr_list, elt->item) ||
				   !comp->trans_table[elt->index_table].known)
				{
					are_all_items_present = 0;
				}
				i++;
			}

			if(are_all_items_present)
			{
				/* all the items of the reference list are present in the current
				   list, so the 'Insertion Only scheme' (type 1) may be used to
				   encode the current list */
				encoding_type = 1;
			}
			else
			{
				/* some items of the reference list are not present in the current
				   list, so the 'Remove Then Insert scheme' (type 3) is required to
				   encode the current list */
				encoding_type = 3;
			}
		}
	}

	return encoding_type;
}


/**
 * @brief Generic encoding of compressed list
 *
 * @param comp     The list compressor
 * @param dest     The ROHC packet under build
 * @param counter  The current position in the rohc-packet-under-build buffer
 * @param ps       The size of the index
 * @param size     The number of element in current list
 * @return         The new position in the rohc-packet-under-build buffer,
 *                 -1 in case of error
 */
static int rohc_list_encode(struct list_comp *const comp,
                            unsigned char *const dest,
                            int counter,
                            const int ps,
                            const int size)
{
	int encoding_type;

	/* sanity checks */
	assert(comp != NULL);
	assert(dest != NULL);
	assert(size >= 0);

	/* determine which encoding type is required for the current list ? */
	encoding_type = rohc_list_decide_type(comp);
	assert(encoding_type >= 0 && encoding_type <= 3);
	rc_list_debug(comp, "use list encoding type %d\n", encoding_type);

	/* encode the current list according to the encoding type */
	switch(encoding_type)
	{
		case 0: /* Encoding type 0 (generic scheme) */
			counter = rohc_list_encode_type_0(comp, dest, counter, ps);
			break;
		case 1: /* Encoding type 1 (insertion only scheme) */
			counter = rohc_list_encode_type_1(comp, dest, counter, ps);
			break;
		case 2: /* Encoding type 2 (removal only scheme) */
			counter = rohc_list_encode_type_2(comp, dest, counter, ps);
			break;
		case 3: /* encoding type 3 (remove then insert scheme) */
			counter = rohc_list_encode_type_3(comp, dest, counter, ps);
			break;
		default:
			rohc_assert(comp, ROHC_TRACE_COMP, comp->profile_id,
			            false, error, "unknown encoding type for list "
			            "compression\n");
	}

	rc_list_debug(comp, "counter at the end of list encoding = %d\n", counter);

	return counter;

error:
	return -1;
}


/**
 * @brief Build encoding type 0 for list compression
 *
 * @todo this function is inefficient as it loops many times on the same list
 *       (see \ref list_get_elt_by_index especially)
 *
 * \verbatim

 Encoding type 0 (5.8.6.1):

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  | ET = 0| GP| PS|   CC = m      |
    +---+---+---+---+---+---+---+---+
 2  :            gen_id             : 1 octet, if GP = 1
    +---+---+---+---+---+---+---+---+
    |       XI 1, ..., XI m         | m octets, or m * 4 bits
 3  /               --- --- --- --- /
    |               :    Padding    : if PS = 0 and m is odd
    +---+---+---+---+---+---+---+---+
    |                               |
 4  /      item 1, ..., item n      / variable length
    |                               |
    +---+---+---+---+---+---+---+---+

 ET: Encoding type is zero.

 GP: Indicates presence of gen_id field.

 PS: Indicates size of XI fields:
     PS = 0 indicates 4-bit XI fields;
     PS = 1 indicates 8-bit XI fields.

 CC: CSRC counter from original RTP header.

 gen_id: Identifier for a sequence of identical lists.  It is
     present in U/O-mode when the compressor decides that it may use
     this list as a future reference list.

 XI 1, ..., XI m: m XI items. The format of an XI item is as
     follows:

              +---+---+---+---+
     PS = 0:  | X |   Index   |
              +---+---+---+---+

                0   1   2   3   4   5   6   7
              +---+---+---+---+---+---+---+---+
     PS = 1:  | X |           Index           |
              +---+---+---+---+---+---+---+---+

     X = 1 indicates that the item corresponding to the Index
           is sent in the item 0, ..., item n list.
     X = 0 indicates that the item corresponding to the Index is
               not sent.

     When 4-bit XI items are used and m > 1, the XI items are placed in
     octets in the following manner:

          0   1   2   3   4   5   6   7
        +---+---+---+---+---+---+---+---+
        |     XI k      |    XI k + 1   |
        +---+---+---+---+---+---+---+---+

 Padding: A 4-bit padding field is present when PS = 0 and m is
     odd.  The Padding field is set to zero when sending and ignored
     when receiving.

 Item 1, ..., item n:
     Each item corresponds to an XI with X = 1 in XI 1, ..., XI m.

\endverbatim
 *
 * @param comp     The list compressor
 * @param dest     The ROHC packet under build
 * @param counter  The current position in the rohc-packet-under-build buffer
 * @param ps       The size of the index
 * @return         The new position in the rohc-packet-under-build buffer
 */
static int rohc_list_encode_type_0(struct list_comp *const comp,
                                   unsigned char *const dest,
                                   int counter,
                                   const int ps)
{
	const uint8_t et = 0; /* list encoding type 0 */
	const uint8_t gp = 1; /* GP bit is always set */
	struct list_elt *elt; /* a list element */
	int m; /* the number of elements in current list = number of XIs */
	int k; /* the index of the current element in list */

	m = list_get_size(comp->curr_list);
	assert(m <= 15);

	/* part 1: ET, GP, PS, CC */
	rc_list_debug(comp, "ET = %d, GP = %d, PS = %d, CC = m = %d\n",
	              et, gp, ps, m);
	dest[counter] = (et & 0x03) << 6;
	dest[counter] |= (gp & 0x01) << 5;
	dest[counter] |= (ps & 0x01) << 4;
	dest[counter] |= m & 0x0f;
	counter++;

	/* part 2: gen_id */
	dest[counter] = comp->curr_list->gen_id & 0xff;
	rc_list_debug(comp, "gen_id = 0x%02x\n", dest[counter]);
	counter++;

	/* part 3: m XI (= X + Indexes) */
	if(ps)
	{
		/* each XI item is stored on 8 bits */
		rc_list_debug(comp, "use 8-bit format for the %d XIs\n", m);

		/* write all XIs in packet */
		for(k = 0; k < m; k++, counter++)
		{
			dest[counter] = 0;

			elt = list_get_elt_by_index(comp->curr_list, k);
			assert(elt != NULL);

			/* set the X bit if item is not already known */
			if(!comp->trans_table[elt->index_table].known)
			{
				dest[counter] |= 1 << 7;
			}

			/* 7-bit Index */
			dest[counter] |= elt->index_table & 0x7f;

			rc_list_debug(comp, "add 8-bit XI #%d = 0x%x\n", k, dest[counter]);
		}
	}
	else
	{
		/* each XI item is stored on 4 bits */
		rc_list_debug(comp, "use 4-bit format for the %d XIs\n", m);

		/* write all XIs in packet 2 by 2 */
		for(k = 0; k < m; k += 2, counter++)
		{
			dest[counter] = 0;

			elt = list_get_elt_by_index(comp->curr_list, k);
			assert(elt != NULL);

			/* first 4-bit XI */
			/* set the X bit if item is not already known */
			if(!comp->trans_table[elt->index_table].known)
			{
				dest[counter] |= 1 << 7;
			}
			/* 3-bit Index */
			dest[counter] |= (elt->index_table & 0x07) << 4;

			rc_list_debug(comp, "add 4-bit XI #%d in MSB = 0x%x\n", k,
			              (dest[counter] & 0xf0) >> 4);

			/* second 4-bit XI or padding? */
			if((k + 1) < m)
			{
				elt = list_get_elt_by_index(comp->curr_list, k + 1);
				assert(elt != NULL);

				/* set the X bit if item is not already known */
				if(!comp->trans_table[elt->index_table].known)
				{
					dest[counter] |= 1 << 3;
				}
				/* 3-bit Index */
				dest[counter] |= (elt->index_table & 0x07) << 0;

				rc_list_debug(comp, "add 4-bit XI #%d in LSB = 0x%x\n", k + 1,
				              dest[counter] & 0xf0);
			}
			else
			{
				/* zero the padding bits */
				rc_list_debug(comp, "add 4-bit padding in LSB\n");
				dest[counter] &= 0xf0;
			}
		}
	}

	/* part 4: n items (only unknown items) */
	for(k = 0; k < m; k++)
	{
		elt = list_get_elt_by_index(comp->curr_list, k);
		assert(elt != NULL);

		/* copy the list element if not known yet */
		if(!comp->trans_table[elt->index_table].known)
		{
			rc_list_debug(comp, "add %zd-byte unknown item #%d in packet\n",
			              elt->item->length, k);
			assert(elt->item->length > 1);
			dest[counter] = elt->item->type & 0xff;
			memcpy(dest + counter + 1, elt->item->data + 1, elt->item->length - 1);
			counter += elt->item->length;
		}
	}

	return counter;
}


/**
 * @brief Build encoding type 1 for list compression
 *
 * @todo this function is inefficient as it loops many times in the current
 *       and reference lists (see \ref list_get_elt_by_index and
 *       \ref list_type_is_present especially)
 *
 * \verbatim

 Encoding type 1 (5.8.6.2):

      0   1   2   3   4   5   6   7
     --- --- --- --- --- --- --- ---
 1  | ET = 1| GP| PS|     XI 1      |
    +---+---+---+---+---+---+---+---+
 2  :            gen_id             : 1 octet, if GP = 1
    +---+---+---+---+---+---+---+---+
 3  |            ref_id             |
    +---+---+---+---+---+---+---+---+
 4  /       insertion bit mask      / 1-2 octets
    +---+---+---+---+---+---+---+---+
    |           XI list             | k octets, or (k - 1) * 4 bits
 5  /               --- --- --- --- /
    |               :    Padding    : if PS = 0 and k is even
    +---+---+---+---+---+---+---+---+
    |                               |
 6  /      item 1, ..., item n      / variable
    |                               |
    +---+---+---+---+---+---+---+---+

 ET: Encoding type is one (1).

 GP: Indicates presence of gen_id field.

 PS: Indicates size of XI fields:
     PS = 0 indicates 4-bit XI fields;
     PS = 1 indicates 8-bit XI fields.

 XI 1: When PS = 0, the first 4-bit XI item is placed here.
       When PS = 1, the field is set to zero when sending, and
       ignored when receiving.

 ref_id: The identifier of the reference CSRC list used when the
       list was compressed.  It is the 8 least significant bits of
       the RTP Sequence Number in R-mode and gen_id (see section
       5.8.2) in U/O-mode.

 insertion bit mask: Bit mask indicating the positions where new
           items are to be inserted.  See Insertion Only scheme in
           section 5.8.3.  The bit mask can have either of the
           following two formats:

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
    | 0 |        7-bit mask         |  bit 1 is the first bit
    +---+---+---+---+---+---+---+---+

    +---+---+---+---+---+---+---+---+
    | 1 |                           |  bit 1 is the first bit
    +---+      15-bit mask          +
    |                               |  bit 7 is the last bit
    +---+---+---+---+---+---+---+---+

 XI list: XI fields for items to be inserted.  When the insertion
    bit mask has k ones, the total number of XI fields is k.  When
    PS = 1, all XI fields are in the XI list.  When PS = 0, the
    first XI field is in the XI 1 field, and the remaining k - 1
    XI fields are in the XI list.

 Padding: Present when PS = 0 and k is even.

 item 1, ..., item n: One item for each XI field with the X bit set.

\endverbatim
 *
 * @param comp     The list compressor
 * @param dest     The ROHC packet under build
 * @param counter  The current position in the rohc-packet-under-build buffer
 * @param ps       The size of the index
 * @return         The new position in the rohc-packet-under-build buffer
 */
static int rohc_list_encode_type_1(struct list_comp *const comp,
                                   unsigned char *const dest,
                                   int counter,
                                   const int ps)
{
	const uint8_t et = 1; /* list encoding type 1 */
	const uint8_t gp = 1; /* GP bit is always set */
	struct list_elt *elt;
	int mask_size;
	int m; /* the number of elements in current list = number of XIs */
	int k; /* the index of the current element in list */

	m = list_get_size(comp->curr_list);
	assert(m <= 15);

	/* part 1: ET, GP, PS, CC */
	rc_list_debug(comp, "ET = %d, GP = %d, PS = %d\n", et, gp, ps);
	dest[counter] = (et & 0x03) << 6;
	dest[counter] |= (gp & 0x01) << 5;
	dest[counter] |= (ps & 0x01) << 4;
	dest[counter] &= 0xf0; /* clear the 4 LSB bits reserved for 1st XI */
	counter++;

	/* part 2: gen_id */
	dest[counter] = comp->curr_list->gen_id & 0xff;
	rc_list_debug(comp, "gen_id = 0x%02x\n", dest[counter]);
	counter++;

	/* part 3: ref_id */
	dest[counter] = comp->ref_list->gen_id & 0xff;
	rc_list_debug(comp, "ref_id = 0x%02x\n", dest[counter]);
	counter++;

	/* part 4: insertion mask (first byte) */
	dest[counter] = 0;
	if(m <= 7)
	{
		/* 7-bit mask is enough, so set first bit to 0 */
		dest[counter] &= ~(1 << 7);
	}
	else
	{
		/* 15-bit mask is required, so set first bit to 1 */
		dest[counter] |= 1 << 7;
	}
	for(k = 0; k < m && k < 7; k++)
	{
		elt = list_get_elt_by_index(comp->curr_list, k);
		assert(elt != NULL);

		/* set bit to 1 in the insertion mask if the list item is not present
		   in the reference list */
		if(!list_type_is_present(comp->ref_list, elt->item))
		{
			dest[counter] |= 1 << (6 - k);
		}
	}
	mask_size = 1;
	rc_list_debug(comp, "insertion mask = 0x%02x\n", dest[counter]);
	counter++;

	/* part 4: insertion mask (second optional byte) */
	if(m > 7)
	{
		for(k = 7; k < m && k < 15; k++)
		{
			elt = list_get_elt_by_index(comp->curr_list, k);
			assert(elt != NULL);

			/* set bit to 1 in the insertion mask if the list item is not present
			   in the reference list */
			if(!list_type_is_present(comp->ref_list, elt->item))
			{
				dest[counter] |= 1 << (7 - (k - 7));
			}
		}
		mask_size = 2;
		rc_list_debug(comp, "insertion mask (2nd byte) = 0x%02x\n", dest[counter]);
		counter++;
	}

	/* part 5: k XI (= X + Indexes) */
	if(ps)
	{
		size_t xi_index = 0;

		/* each XI item is stored on 8 bits */
		rc_list_debug(comp, "use 8-bit format for the %d XIs\n", m);

		for(k = 0; k < m; k++)
		{
			elt = list_get_elt_by_index(comp->curr_list, k);
			assert(elt != NULL);

			/* skip element if it present in the reference list */
			if(list_type_is_present(comp->ref_list, elt->item) &&
			   comp->trans_table[elt->index_table].known)
			{
				rc_list_debug(comp, "ignore element #%d because it is present "
				              "in the reference list and already known\n", k);
				continue;
			}

			xi_index++;

			dest[counter] = 0;

			/* set the X bit if item is not already known */
			if(!comp->trans_table[elt->index_table].known)
			{
				dest[counter] |= 1 << 7;
			}
			/* 7-bit Index */
			dest[counter] |= elt->index_table & 0x7f;

			rc_list_debug(comp, "add 8-bit XI #%d = 0x%x\n", k, dest[counter]);

			/* byte is full, write to next one next time */
			counter++;
		}
	}
	else
	{
		size_t xi_index = 0;

		/* each XI item is stored on 4 bits */
		rc_list_debug(comp, "use 4-bit format for the %d XIs\n", m);

		for(k = 0; k < m; k++)
		{
			elt = list_get_elt_by_index(comp->curr_list, k);
			assert(elt != NULL);

			/* skip element if it present in the reference list */
			if(list_type_is_present(comp->ref_list, elt->item) &&
			   comp->trans_table[elt->index_table].known)
			{
				rc_list_debug(comp, "ignore element #%d because it is present "
				              "in the reference list and already known\n", k);
				continue;
			}

			xi_index++;

			if(xi_index == 1)
			{
				/* first XI goes in part 1 */

				/* set the X bit if item is not already known */
				if(!comp->trans_table[elt->index_table].known)
				{
					dest[counter - (3 + mask_size)] |= 1 << 3;
				}
				/* 3-bit Index */
				dest[counter - (3 + mask_size)] |= elt->index_table & 0x07;

				rc_list_debug(comp, "add 4-bit XI #%d in part 1 = 0x%x\n", k,
				              (dest[counter - (3 + mask_size)] & 0x0f) >> 4);
			}
			else
			{
				/* next XIs goes in part 5 */
				dest[counter] = 0;

				/* odd or even 4-bit XI ? */
				if((xi_index % 2) == 0)
				{
					/* use MSB part of the byte */

					/* set the X bit if item is not already known */
					if(!comp->trans_table[elt->index_table].known)
					{
						dest[counter] |= 1 << 7;
					}
					/* 3-bit Index */
					dest[counter] |= (elt->index_table & 0x07) << 4;

					rc_list_debug(comp, "add 4-bit XI #%d in MSB = 0x%x\n", k,
					              (dest[counter] & 0xf0) >> 4);
				}
				else
				{
					/* use LSB part of the byte */

					/* set the X bit if item is not already known */
					if(!comp->trans_table[elt->index_table].known)
					{
						dest[counter] |= 1 << 3;
					}
					/* 3-bit Index */
					dest[counter] |= (elt->index_table & 0x07) << 0;

					rc_list_debug(comp, "add 4-bit XI #%d = 0x%x in LSB\n",
					              k + 1, dest[counter] & 0xf0);

					/* byte is full, write to next one next time */
					counter++;
				}
			}
		}

		/* is padding required? */
		if(xi_index > 1 && (xi_index % 2) == 0)
		{
			/* zero the padding bits */
			rc_list_debug(comp, "add 4-bit padding in LSB\n");
			dest[counter] &= 0xf0;

			/* byte is full, write to next one next time */
			counter++;
		}
	}

	/* part 6: n items (only unknown items) */
	for(k = 0; k < m; k++)
	{
		elt = list_get_elt_by_index(comp->curr_list, k);
		assert(elt != NULL);

		/* skip element if it present in the reference list */
		if(list_type_is_present(comp->ref_list, elt->item) &&
		   comp->trans_table[elt->index_table].known)
		{
			rc_list_debug(comp, "ignore element #%d because it is present "
			              "in the reference list and already known\n", k);
			continue;
		}

		/* copy the list element if not known yet */
		if(!comp->trans_table[elt->index_table].known)
		{
			rc_list_debug(comp, "add %zd-byte unknown item #%d in packet\n",
			              elt->item->length, k);
			assert(elt->item->length > 1);
			dest[counter] = elt->item->type & 0xff;
			memcpy(dest + counter + 1, elt->item->data + 1, elt->item->length - 1);
			counter += elt->item->length;
		}
	}

	return counter;
}


/**
 * @brief Build encoding type 2 for list compression
 *
 * @todo this function is inefficient as it loops many times in the current
 *       and reference lists (see \ref list_get_elt_by_index and
 *       \ref list_type_is_present especially)
 *
 * \verbatim

 Encoding type 2 (5.8.6.3):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 1  | ET = 2| GP|res|    Count      |
    +---+---+---+---+---+---+---+---+
 2  :            gen_id             : 1 octet, if GP = 1
    +---+---+---+---+---+---+---+---+
 3  |            ref_id             |
    +---+---+---+---+---+---+---+---+
 4  /        removal bit mask       / 1-2 octets
    +---+---+---+---+---+---+---+---+

 ET: Encoding type is 2.

 GP: Indicates presence of gen_id field.

 res: Reserved.  Set to zero when sending, ignored when
      received.

 Count: Number of elements in ref_list.

 removal bit mask: Indicates the elements in ref_list to be
    removed in order to obtain the current list.  See section
    5.8.3.  The bit mask can have either of the following two
    formats:

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
    | 0 |        7-bit mask         |  bit 1 is the first bit
    +---+---+---+---+---+---+---+---+

    +---+---+---+---+---+---+---+---+
    | 1 |                           |  bit 1 is the first bit
    +---+      15-bit mask          +
    |                               |  bit 7 is the last bit
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param comp     The list compressor
 * @param dest     The ROHC packet under build
 * @param counter  The current position in the rohc-packet-under-build buffer
 * @param ps       The size of the index
 * @return         The new position in the rohc-packet-under-build buffer
 */
static int rohc_list_encode_type_2(struct list_comp *const comp,
                                   unsigned char *const dest,
                                   int counter,
                                   const int ps)
{
	const uint8_t et = 2; /* list encoding type 2 */
	const uint8_t gp = 1; /* GP bit is always set */
	struct list_elt *elt;
	int size_ref_list; /* size of reference list */
	int k; /* the index of the current element in list */

	size_ref_list = list_get_size(comp->ref_list);
	assert(size_ref_list <= 15);

	/* part 1: ET, GP, res and Count */
	rc_list_debug(comp, "ET = %d, GP = %d, Count = %d\n", et, gp, size_ref_list);
	dest[counter] = (et & 0x03) << 6;
	dest[counter] |= (gp & 0x01) << 5;
	dest[counter] &= ~(0x01 << 4); /* clear the reserved bit */
	assert((size_ref_list & 0x0f) == size_ref_list);
	dest[counter] |= size_ref_list & 0x0f;
	counter++;

	/* part 2: gen_id */
	dest[counter] = comp->curr_list->gen_id & 0xff;
	rc_list_debug(comp, "gen_id = 0x%02x\n", dest[counter]);
	counter++;

	/* part 3: ref_id */
	dest[counter] = comp->ref_list->gen_id & 0xff;
	rc_list_debug(comp, "ref_id = 0x%02x\n", dest[counter]);
	counter++;

	/* part 4: removal bit mask (first byte) */
	dest[counter] = 0xff;
	if(size_ref_list <= 7)
	{
		/* 7-bit mask is enough, so set first bit to 0 */
		dest[counter] &= ~(1 << 7);
	}
	else
	{
		/* 15-bit mask is required, so set first bit to 1 */
		dest[counter] |= 1 << 7;
	}
	for(k = 0; k < size_ref_list && k < 7; k++)
	{
		elt = list_get_elt_by_index(comp->ref_list, k);
		assert(elt != NULL);

		if(list_type_is_present(comp->curr_list, elt->item))
		{
			/* element shall not be removed, clear its corresponding bit in the
			   removal bit mask */
			rc_list_debug(comp, "mark element #%d of list as 'not to remove'\n", k);
			dest[counter] &= ~(1 << (6 - k));
		}
		else
		{
			rc_list_debug(comp, "mark element #%d of list as 'to remove'\n", k);
		}
	}
	rc_list_debug(comp, "removal bit mask (first byte) = 0x%02x\n",
	              dest[counter]);
	counter++;

	/* part 4: removal bit mask (second optional byte) */
	if(size_ref_list > 7)
	{
		dest[counter] = 0xff;
		for(k = 7; k < size_ref_list && k < 15; k++)
		{
			elt = list_get_elt_by_index(comp->ref_list, k);
			assert(elt != NULL);

			/* @bug: shouldn't the condition be inversed? */
			if(!list_type_is_present(comp->curr_list, elt->item))
			{
				/* element shall not be removed, clear its corresponding bit in
				   the removal bit mask */
				rc_list_debug(comp, "mark element #%d of list as 'not to "
				              "remove'\n", k);
				dest[counter] &= ~(1 << (7 - (k - 7)));
			}
			else
			{
				rc_list_debug(comp, "mark element #%d of list as 'to remove'\n", k);
			}
		}
		rc_list_debug(comp, "removal bit mask (second byte) = 0x%02x\n",
		              dest[counter]);
		counter++;
	}
	else
	{
		rc_list_debug(comp, "no second byte of removal bit mask\n");
	}

	return counter;
}


/**
 * @brief Build encoding type 3 for list compression
 *
 * @todo this function is inefficient as it loops many times in the current
 *       and reference lists (see \ref list_get_elt_by_index and
 *       \ref list_type_is_present especially)
 *
 * \verbatim

 Encoding type 3 (5.8.6.4):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 1  | ET=3  |GP |PS |     XI 1      |
    +---+---+---+---+---+---+---+---+
 2  :            gen_id             : 1 octet, if GP = 1
    +---+---+---+---+---+---+---+---+
 3  |            ref_id             |
    +---+---+---+---+---+---+---+---+
 4  /        removal bit mask       / 1-2 octets
    +---+---+---+---+---+---+---+---+
 5  /       insertion bit mask      / 1-2 octets
    +---+---+---+---+---+---+---+---+
    |           XI list             | k octets, or (k - 1) * 4 bits
 6  /               --- --- --- --- /
    |               :    Padding    : if PS = 0 and k is even
    +---+---+---+---+---+---+---+---+
    |                               |
 7  /      item 1, ..., item n      / variable
    |                               |
    +---+---+---+---+---+---+---+---+

 ET: Encoding type is 3.

 GP: Indicates presence of gen_id field.

 PS: Indicates size of XI fields:
     PS = 0 indicates 4-bit XI fields;
     PS = 1 indicates 8-bit XI fields.

 gen_id: Identifier for a sequence of identical lists.  It is
     present in U/O-mode when the compressor decides that it may use
     this list as a future reference list.

 ref_id: The identifier of the reference CSRC list used when the
       list was compressed.  It is the 8 least significant bits of
       the RTP Sequence Number in R-mode and gen_id (see section
       5.8.2) in U/O-mode.

 removal bit mask: Indicates the elements in ref_list to be
    removed in order to obtain the current list.  See section
    5.8.3.  The bit mask can have either of the following two
    formats:

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
    | 0 |        7-bit mask         |  bit 1 is the first bit
    +---+---+---+---+---+---+---+---+

    +---+---+---+---+---+---+---+---+
    | 1 |                           |  bit 1 is the first bit
    +---+      15-bit mask          +
    |                               |  bit 7 is the last bit
    +---+---+---+---+---+---+---+---+

 insertion bit mask: Bit mask indicating the positions where new
           items are to be inserted.  See Insertion Only scheme in
           section 5.8.3.  The bit mask can have either of the
           following two formats:

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
    | 0 |        7-bit mask         |  bit 1 is the first bit
    +---+---+---+---+---+---+---+---+

    +---+---+---+---+---+---+---+---+
    | 1 |                           |  bit 1 is the first bit
    +---+      15-bit mask          +
    |                               |  bit 7 is the last bit
    +---+---+---+---+---+---+---+---+

 XI list: XI fields for items to be inserted.  When the insertion
    bit mask has k ones, the total number of XI fields is k.  When
    PS = 1, all XI fields are in the XI list.  When PS = 0, the
    first XI field is in the XI 1 field, and the remaining k - 1
    XI fields are in the XI list.

 Padding: Present when PS = 0 and k is even.

 item 1, ..., item n: One item for each XI field with the X bit set.

\endverbatim
 *
 * @param comp     The list compressor
 * @param dest     The ROHC packet under build
 * @param counter  The current position in the rohc-packet-under-build buffer
 * @param ps       The size of the index
 * @return         The new position in the rohc-packet-under-build buffer
 */
static int rohc_list_encode_type_3(struct list_comp *const comp,
                                   unsigned char *const dest,
                                   int counter,
                                   const int ps)
{
	const uint8_t et = 3; /* list encoding type 3 */
	const uint8_t gp = 1; /* GP bit is always set */
	struct list_elt *elt;
	int size_ref_list; /* size of reference list */
	int m; /* the number of elements in current list = number of XIs */
	int k; /* the index of the current element in list */
	int mask_size = 0; /* the cumulative size of insertion/removal masks */

	/* part 1: ET, GP, PS, CC */
	rc_list_debug(comp, "ET = %d, GP = %d, PS = %d\n", et, gp, ps);
	dest[counter] = (et & 0x03) << 6;
	dest[counter] |= (gp & 0x01) << 5;
	dest[counter] |= (ps & 0x01) << 4;
	dest[counter] &= 0xf0; /* clear the 4 LSB bits reserved for 1st XI */
	counter++;

	/* part 2: gen_id */
	dest[counter] = comp->curr_list->gen_id & 0xff;
	rc_list_debug(comp, "gen_id = 0x%02x\n", dest[counter]);
	counter++;

	/* part 3: ref_id */
	dest[counter] = comp->ref_list->gen_id & 0xff;
	rc_list_debug(comp, "ref_id = 0x%02x\n", dest[counter]);
	counter++;

	/* part 4: removal bit mask (first byte) */
	size_ref_list = list_get_size(comp->ref_list);
	assert(size_ref_list <= 15);
	dest[counter] = 0xff;
	if(size_ref_list <= 7)
	{
		/* 7-bit mask is enough, so set first bit to 0 */
		dest[counter] &= ~(1 << 7);
	}
	else
	{
		/* 15-bit mask is required, so set first bit to 1 */
		dest[counter] |= 1 << 7;
	}
	for(k = 0; k < size_ref_list && k < 7; k++)
	{
		elt = list_get_elt_by_index(comp->ref_list, k);
		assert(elt != NULL);

		if(list_type_is_present(comp->curr_list, elt->item) &&
		   comp->trans_table[elt->index_table].known)
		{
			/* element shall not be removed, clear its corresponding bit in the
			   removal bit mask */
			dest[counter] &= ~(1 << (6 - k));
		}
	}
	rc_list_debug(comp, "removal bit mask (first byte) = 0x%02x\n",
	              dest[counter]);
	counter++;
	mask_size++;

	/* part 4: removal bit mask (second optional byte) */
	if(size_ref_list > 7)
	{
		dest[counter] = 0xff;
		for(k = 7; k < size_ref_list && k < 15; k++)
		{
			elt = list_get_elt_by_index(comp->ref_list, k);
			assert(elt != NULL);

			if(list_type_is_present(comp->curr_list, elt->item) &&
			   comp->trans_table[elt->index_table].known)
			{
				/* element shall not be removed, clear its corresponding bit in
				   the removal bit mask */
				dest[counter] &= ~(1 << (7 - (k - 7)));
			}
		}
		rc_list_debug(comp, "removal bit mask (second byte) = 0x%02x\n",
		              dest[counter]);
		counter++;
		mask_size++;
	}
	else
	{
		rc_list_debug(comp, "no second byte of removal bit mask\n");
	}

	/* part 5: insertion mask */
	m = list_get_size(comp->curr_list);
	assert(m <= 15);
	dest[counter] = 0;
	if(m <= 7)
	{
		/* 7-bit mask is enough, so set first bit to 0 */
		dest[counter] &= ~(1 << 7);
	}
	else
	{
		/* 15-bit mask is required, so set first bit to 1 */
		dest[counter] |= 1 << 7;
	}
	for(k = 0; k < m && k < 7; k++)
	{
		elt = list_get_elt_by_index(comp->curr_list, k);
		assert(elt != NULL);

		/* set bit to 1 in the insertion mask if the list item is not present
		   in the reference list */
		if(!list_type_is_present(comp->ref_list, elt->item) ||
		   !comp->trans_table[elt->index_table].known)
		{
			dest[counter] |= 1 << (6 - k);
		}
	}
	rc_list_debug(comp, "insertion bit mask (first byte) = 0x%02x\n",
	              dest[counter]);
	counter++;
	mask_size++;

	/* part 4: insertion mask (second optional byte) */
	if(m > 7)
	{
		for(k = 7; k < m && k < 15; k++)
		{
			elt = list_get_elt_by_index(comp->curr_list, k);
			assert(elt != NULL);

			/* set bit to 1 in the insertion mask if the list item is not present
			   in the reference list */
			if(!list_type_is_present(comp->ref_list, elt->item) ||
			   !comp->trans_table[elt->index_table].known)
			{
				dest[counter] |= 1 << (7 - (k - 7));
			}
		}
		rc_list_debug(comp, "insertion bit mask (second byte) = 0x%02x\n",
		              dest[counter]);
		counter++;
		mask_size++;
	}
	else
	{
		rc_list_debug(comp, "no second byte of insertion bit mask\n");
	}

	/* part 6: k XI (= X + Indexes) */
	/* next bytes: indexes */
	if(ps)
	{
		size_t xi_index = 0;

		/* each XI item is stored on 8 bits */
		rc_list_debug(comp, "use 8-bit format for the %d XIs\n", m);

		for(k = 0; k < m; k++)
		{
			elt = list_get_elt_by_index(comp->curr_list, k);
			assert(elt != NULL);

			/* skip element if it present in the reference list and already known */
			if(list_type_is_present(comp->ref_list, elt->item) &&
			   comp->trans_table[elt->index_table].known)
			{
				rc_list_debug(comp, "ignore element #%d because it is present "
				              "in the reference list and already known\n", k);
				continue;
			}

			xi_index++;

			dest[counter]  = 0;

			/* set the X bit if item is not already known */
			if(!comp->trans_table[elt->index_table].known)
			{
				dest[counter] |= 1 << 7;
			}
			/* 7-bit Index */
			dest[counter] |= (elt->index_table & 0x7f);

			rc_list_debug(comp, "add 8-bit XI #%d = 0x%x\n", k, dest[counter]);

			/* byte is full, write to next one next time */
			counter++;
		}
	}
	else
	{
		size_t xi_index = 0;

		/* each XI item is stored on 4 bits */
		rc_list_debug(comp, "use 4-bit format for the %d XIs\n", m);

		for(k = 0; k < m; k++)
		{
			elt = list_get_elt_by_index(comp->curr_list, k);
			assert(elt != NULL);

			/* skip element if it present in the reference list and already known */
			if(list_type_is_present(comp->ref_list, elt->item) &&
			   comp->trans_table[elt->index_table].known)
			{
				rc_list_debug(comp, "ignore element #%d because it is present "
				              "in the reference list and already known\n", k);
				continue;
			}

			xi_index++;

			if(xi_index == 1)
			{
				/* first XI goes in part 1 */

				/* set the X bit if item is not already known */
				if(!comp->trans_table[elt->index_table].known)
				{
					dest[counter - (3 + mask_size)] |= 1 << 3;
				}
				/* 3-bit Index */
				dest[counter - (3 + mask_size)] |= elt->index_table & 0x07;

				rc_list_debug(comp, "add 4-bit XI #%d in part 1 = 0x%x\n", k,
				              (dest[counter - (3 + mask_size)] & 0x0f) >> 4);
			}
			else
			{
				/* next XIs goes in part 6 */
				dest[counter] = 0;

				/* odd or even 4-bit XI ? */
				if((xi_index % 2) == 0)
				{
					/* use MSB part of the byte */

					/* set the X bit if item is not already known */
					if(!comp->trans_table[elt->index_table].known)
					{
						dest[counter] |= 1 << 7;
					}
					/* 3-bit Index */
					dest[counter] |= (elt->index_table & 0x07) << 4;

					rc_list_debug(comp, "add 4-bit XI #%d in MSB = 0x%x\n", k,
					              (dest[counter] & 0xf0) >> 4);
				}
				else
				{
					/* use LSB part of the byte */

					/* set the X bit if item is not already known */
					if(!comp->trans_table[elt->index_table].known)
					{
						dest[counter] |= 1 << 3;
					}
					/* 3-bit Index */
					dest[counter] |= (elt->index_table & 0x07) << 0;

					rc_list_debug(comp, "add 4-bit XI #%d in LSB = 0x%x\n",
					              k + 1, dest[counter] & 0xf0);

					/* byte is full, write to next one next time */
					counter++;
				}
			}
		}

		/* is padding required? */
		if(xi_index > 1 && (xi_index % 2) == 0)
		{
			/* zero the padding bits */
			rc_list_debug(comp, "add 4-bit padding in LSB\n");
			dest[counter] &= 0xf0;

			/* byte is full, write to next one next time */
			counter++;
		}
	}

	/* part 7: n items (only unknown items) */
	for(k = 0; k < m; k++)
	{
		elt = list_get_elt_by_index(comp->curr_list, k);
		assert(elt != NULL);

		/* skip element if it present in the reference list */
		if(list_type_is_present(comp->ref_list, elt->item) &&
		   comp->trans_table[elt->index_table].known)
		{
			rc_list_debug(comp, "ignore element #%d because it is present "
			              "in the reference list and already known\n", k);
			continue;
		}

		/* copy the list element if not known yet */
		if(!comp->trans_table[elt->index_table].known)
		{
			rc_list_debug(comp, "add %zd-byte unknown item #%d in packet\n",
			              elt->item->length, k);
			assert(elt->item->length > 1);
			dest[counter] = elt->item->type & 0xff;
			memcpy(dest + counter + 1, elt->item->data + 1, elt->item->length - 1);
			counter += elt->item->length;
		}
	}

	return counter;
}

