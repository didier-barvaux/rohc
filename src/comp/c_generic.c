/**
 * @file c_generic.c
 * @brief ROHC generic compression context for IP-only, UDP and UDP Lite
 *        profiles.
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author David Moreau from TAS
 * @author The hackers from ROHC for Linux
 */

#include "c_generic.h"
#include "c_rtp.h"

#include <netinet/ip.h>
#include <netinet/udp.h>

/**
 * @brief The description of the different ROHC packets.
 */
const char *generic_packet_types[] =
{
	"IR",
	"IRDYN",
	"OU-0",
	"OU-1",
	"OU-2",
};


/**
 * @brief The description of the different extensions for the UO-2 packet.
 */
const char *generic_extension_types[] =
{
	"NOEXT",
	"EXT0",
	"EXT1",
	"EXT2",
	"EXT3",
};


/*
 * Function prototypes.
 */

int code_packet(struct c_context *context,
                const struct ip_packet ip,
                const struct ip_packet ip2,
                const unsigned char *next_header,
                unsigned char *dest);

int code_IR_packet(struct c_context *context,
                   const struct ip_packet ip,
                   const struct ip_packet ip2,
                   const unsigned char *next_header,
                   unsigned char *dest);

int code_IR_DYN_packet(struct c_context *context,
                       const struct ip_packet ip,
                       const struct ip_packet ip2,
                       const unsigned char *next_header,
                       unsigned char *dest);

int code_generic_static_part(struct c_context *context,
                     struct ip_header_info *header_info,
                     const struct ip_packet ip,
                     unsigned char *dest,
                     int counter);

int code_ipv4_static_part(struct c_context *context,
                          struct ip_header_info *header_info,
                          const struct ip_packet ip,
                          unsigned char *dest,
                          int counter);

int code_ipv6_static_part(struct c_context *context,
                          struct ip_header_info *header_info,
                          struct ip_packet ip,
                          unsigned char *dest,
                          int counter);

int code_generic_dynamic_part(struct c_context *context,
                      struct ip_header_info *header_info,
                      const struct ip_packet ip,
                      unsigned char *dest,
                      int counter);

int code_ipv4_dynamic_part(struct c_context *context,
                           struct ip_header_info *header_info,
                           const struct ip_packet ip,
                           unsigned char *dest,
                           int counter);

int code_ipv6_dynamic_part(struct c_context *context,
                           struct ip_header_info *header_info,
                           const struct ip_packet ip,
                           unsigned char *dest,
                           int counter);

int code_UO_packet_tail(struct c_context *context,
                        const struct ip_packet ip,
                        const struct ip_packet ip2,
                        const unsigned char *next_header,
                        unsigned char *dest,
                        int counter);

int code_UO0_packet(struct c_context *context,
                    const struct ip_packet ip,
                    const struct ip_packet ip2,
                    const unsigned char *next_header,
                    unsigned char *dest);

int code_UO1_packet(struct c_context *context,
                    const struct ip_packet ip,
                    const struct ip_packet ip2,
                    const unsigned char *next_header,
                    unsigned char *dest);

int code_UO2_packet(struct c_context *context,
                    const struct ip_packet ip,
                    const struct ip_packet ip2,
                    const unsigned char *next_header,
                    unsigned char *dest);

int code_UOR2_bytes(struct c_context *context,
                    int extension,
                    unsigned char *f_byte,
                    unsigned char *s_byte,
                    unsigned char *t_byte);

int code_UOR2_RTP_bytes(struct c_context *context,
                        int extension,
                        unsigned char *f_byte,
                        unsigned char *s_byte,
                        unsigned char *t_byte);

int code_UOR2_TS_bytes(struct c_context *context,
                       int extension,
                       unsigned char *f_byte,
                       unsigned char *s_byte,
                       unsigned char *t_byte);

int code_UOR2_ID_bytes(struct c_context *context,
                       int extension,
                       unsigned char *f_byte,
                       unsigned char *s_byte,
                       unsigned char *t_byte);

int code_EXT0_packet(struct c_context *context,
                     unsigned char *dest,
                     int counter);

int code_EXT1_packet(struct c_context *context,
                     unsigned char *dest,
                     int counter);

int code_EXT2_packet(struct c_context *context,
                     unsigned char *dest,
                     int counter);

int code_EXT3_packet(struct c_context *context,
                     const struct ip_packet ip,
                     const struct ip_packet ip2,
                     unsigned char *dest,
                     int counter);

boolean is_changed(unsigned short changed_fields, unsigned short check_field);

void decide_state(struct c_context *context);

int decide_packet(struct c_context *context);

void update_variables(struct c_context *context,
                      const struct ip_packet ip,
                      const struct ip_packet ip2);

int decide_extension(struct c_context *context);

int rtp_header_flags_and_fields(struct c_context *context,
                                unsigned short changed_f,
                                const struct ip_packet ip,
                                unsigned char *dest,
                                int counter);

int header_flags(struct c_context *context,
                 struct ip_header_info *header_info,
                 unsigned short changed_f,
                 const struct ip_packet ip,
                 boolean is_outer,
                 int nr_ip_id_bits,
                 unsigned char *dest,
                 int counter);

int header_fields(struct c_context *context,
                  struct ip_header_info *header_info,
                  unsigned short changed_f,
                  const struct ip_packet ip,
                  boolean is_outer,
                  int nr_ip_id_bits,
                  unsigned char *dest,
                  int counter);

int changed_static_both_hdr(struct c_context *context,
                            const struct ip_packet ip,
                            const struct ip_packet ip2);

int changed_static_one_hdr(unsigned short changed_fields,
                           struct ip_header_info *header_info,
                           const struct ip_packet ip,
                           struct c_context *context);

int changed_dynamic_both_hdr(struct c_context *context,
                             const struct ip_packet ip,
                             const struct ip_packet ip2);

int changed_dynamic_one_hdr(unsigned short changed_fields,
                            struct ip_header_info *header_info,
                            const struct ip_packet ip,
                            struct c_context *context);

unsigned short changed_fields(struct ip_header_info *header_info,
                              const struct ip_packet ip,
                              int check_rtp);

void check_ip_identification(struct ip_header_info *header_info,
                             const struct ip_packet ip);


/**
 * @brief Initialize the inner or outer IP header info stored in the context.
 *
 * @param header_info The inner or outer IP header info to initialize
 * @param ip          The inner or outer IP header
 * @return            1 if successful, 0 otherwise
 */
int c_init_header_info(struct ip_header_info *header_info,
                       const struct ip_packet ip)
{
	/* store the IP version in the header info */
	header_info->version = ip_get_version(ip);

	/* version specific initialization */
	if(header_info->version == IPV4)
	{
		/* init the parameters to encode the IP-ID with W-LSB encoding */
		header_info->info.v4.ip_id_window = c_create_wlsb(16, C_WINDOW_WIDTH, 0);
		if(header_info->info.v4.ip_id_window == NULL)
		{
			rohc_debugf(0, "no memory to allocate W-LSB encoding for IP-ID\n");
			goto error;
		}
	
		/* store the IP packet and the random and NBO parameters
		 * in the header info */
		header_info->info.v4.old_ip = *(ipv4_get_header(ip));
		header_info->info.v4.rnd = 0;
		header_info->info.v4.old_rnd = header_info->info.v4.rnd;
		header_info->info.v4.nbo = 1;
		header_info->info.v4.old_nbo = header_info->info.v4.nbo;

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
		/* store the IP header in the header info */
		header_info->info.v6.old_ip = *(ipv6_get_header(ip));
	}

	return 1;

error:
	return 0;
}


/**
 * @brief Initialize all temporary variables stored in the context.
 *
 * @param tmp_variables The temporary variables to initialize
 */
void c_init_tmp_variables(struct generic_tmp_variables *tmp_variables)
{
	tmp_variables->nr_of_ip_hdr = -1;
	tmp_variables->changed_fields = -1;
	tmp_variables->changed_fields2 = -1;
	tmp_variables->send_static = -1;
	tmp_variables->send_dynamic = -1;
	tmp_variables->nr_ip_id_bits = -1;
	tmp_variables->nr_sn_bits = -1;
	tmp_variables->nr_ip_id_bits2 = -1;
	tmp_variables->packet_type = -1;
	tmp_variables->max_size = -1;
}


/**
 * @brief Create a new context and initialize it thanks to the given IP packet.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 * @param ip      The IP packet given to initialize the new context
 * @return        1 if successful, 0 otherwise
 */
int c_generic_create(struct c_context *context, const struct ip_packet ip)
{
	struct c_generic_context *g_context;
	unsigned int ip_proto;
	int p; /* parameter for W-LSB encoding of SN */

	/* check the IP header(s) */
	ip_proto = ip_get_protocol(ip);
	if(ip_proto == IPPROTO_IPIP || ip_proto == IPPROTO_IPV6)
	{
		struct ip_packet ip2;

		if(!ip_get_inner_packet(ip, &ip2))
		{
			rohc_debugf(0, "cannot create the inner IP header\n");
			goto quit;
		}
	}

	/* allocate memory for the generic part of the context */
	g_context =
		(struct c_generic_context *) malloc(sizeof(struct c_generic_context));
	if(g_context == NULL)
	{
	  rohc_debugf(0, "no memory for generic part of the profile context\n");
	  goto quit;
	}
	bzero(g_context, sizeof(struct c_generic_context));
	context->specific = g_context;

	/* initialize some context variables:
	 *  1. init the Sequence Number (SN) to 0
	 *  2. init the parameters to encode the SN with W-LSB encoding
	 *  3. init the counters of packet types
	 *  4. init the counters for the periodic transition to lower states
	 *  5. init the info related to the outer IP header, the info related to the
	 *     inner IP header will be initialized later if necessary
	 *  6. init the temporary variables
	 *  7. init the profile-specific variables to safe values
	 */

	/* step 1 */
	// TODO: should be initialized to a random value according
	//       to 5.11.1 in RFC 3095, but 0 simplifies testing
	g_context->sn = 0;

	/* step 2 */
	switch(context->profile->id)
	{
		case ROHC_PROFILE_RTP:
			p = 3;
			break;
		case ROHC_PROFILE_UNCOMPRESSED:
		case ROHC_PROFILE_UDP:
		case ROHC_PROFILE_IP:
		case ROHC_PROFILE_UDPLITE:
			p = -1;
			break;
		default:
			rohc_debugf(0, "bad profile ID (0x%04x)\n", context->profile->id);
			goto clean;
	}
	g_context->sn_window = c_create_wlsb(16, C_WINDOW_WIDTH, p);
	if(g_context->sn_window == NULL)
	{
		rohc_debugf(0, "no memory to allocate W-LSB encoding for SN\n");
		goto clean;
	}

	/* step 3 */
	g_context->ir_count = 0;
	g_context->fo_count = 0;
	g_context->so_count = 0;

	/* step 4 */
	g_context->go_back_fo_count = 0;
	g_context->go_back_ir_count = 0;
	g_context->ir_dyn_count = 0;

	/* step 5 */
	if(!c_init_header_info(&g_context->ip_flags, ip))
		goto clean;
	g_context->is_ip2_initialized = 0;

	/* step 6 */
	c_init_tmp_variables(&g_context->tmp_variables);

	/* step 7 */
	g_context->specific = NULL;
	g_context->next_header_proto = 0;
	g_context->next_header_len = 0;
	g_context->decide_state = decide_state;
	g_context->init_at_IR = NULL;
	g_context->code_static_part = NULL;
	g_context->code_dynamic_part = NULL;
	g_context->code_UO_packet_head = NULL;
	g_context->code_UO_packet_tail = NULL;

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
void c_generic_destroy(struct c_context *context)
{
	struct c_generic_context *g_context =
		(struct c_generic_context *) context->specific;

	if(g_context != NULL)
	{
		if(g_context->ip_flags.version == IPV4 &&
		   g_context->ip_flags.info.v4.ip_id_window != NULL)
			c_destroy_wlsb(g_context->ip_flags.info.v4.ip_id_window);
		if(g_context->is_ip2_initialized &&
		   g_context->ip2_flags.version == IPV4 &&
		   g_context->ip2_flags.info.v4.ip_id_window != NULL)
			c_destroy_wlsb(g_context->ip2_flags.info.v4.ip_id_window);
		if(g_context->sn_window != NULL)
			c_destroy_wlsb(g_context->sn_window);

		if(g_context->specific != NULL)
			zfree(g_context->specific);

		zfree(g_context);
	}
}


/**
 * @brief Change the mode of the context.
 *
 * @param context  The compression context
 * @param new_mode The new mode the context must enter in
 */
void change_mode(struct c_context *context, rohc_mode new_mode)
{
	if(context->mode != new_mode)
	{
		/* change mode and go back to IR state */
		rohc_debugf(1, "change from mode %d to mode %d\n",
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
void change_state(struct c_context *context, rohc_c_state new_state)
{
	struct c_generic_context *g_context;
	
	g_context = (struct c_generic_context *) context->specific;

	if(context->state != new_state)
	{
		rohc_debugf(1, "change from state %d to state %d\n",
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
 * @param payload_offset The offset for the payload in the IP packet
 * @return               The length of the created ROHC packet
 *                       or -1 in case of failure
 */
int c_generic_encode(struct c_context *context,
                     const struct ip_packet ip,
                     int packet_size,
                     unsigned char *dest,
                     int dest_size,
                     int *payload_offset)
{
	struct c_generic_context *g_context;
	struct ip_packet ip2, last_ip_header;
	unsigned char *next_header;
	unsigned int ip_proto;
	int size;
	int is_rtp;
	
	g_context = (struct c_generic_context *) context->specific;
	if(g_context == NULL)
	{
	 	 rohc_debugf(0, "generic context not valid\n");
	 	 return -1;
	}

	g_context->tmp_variables.changed_fields2 = 0;
	g_context->tmp_variables.nr_ip_id_bits2 = 0;
	g_context->tmp_variables.packet_type = PACKET_IR;
	g_context->tmp_variables.max_size = dest_size;
	
	/* STEP 1:
	 *  - check double IP headers
	 *  - check the next header protocol if necessary
	 *  - compute the payload offset
	 *  - discard IP fragments
	 */
	ip_proto = ip_get_protocol(ip);
	if(ip_proto == IPPROTO_IPIP || ip_proto == IPPROTO_IPV6)
	{
		/* there are 2 IP headers */
		if(!ip_get_inner_packet(ip, &ip2))
			return -1;

		g_context->tmp_variables.nr_of_ip_hdr = 2;
		last_ip_header = ip2;

		/* initialize IPv4 header info if the inner header is IPv4 */
		if(!g_context->is_ip2_initialized)
		{
			if(!c_init_header_info(&g_context->ip2_flags, ip2))
				return -1;
			g_context->is_ip2_initialized = 1;
		}
	}
	else
	{
		/* there is only one IP header */
		g_context->tmp_variables.nr_of_ip_hdr = 1;
		last_ip_header = ip;
	}
	
	/* check the next header protocol if necessary */
	if(g_context->next_header_proto != 0 &&
	   ip_get_protocol(last_ip_header) != g_context->next_header_proto)
	{
		/* the IP protocol field does not match the attended
		 * next header protocol */
		return -1;
	}
	next_header = ip_get_next_header(last_ip_header);

	/* find the offset of the payload */
	*payload_offset =
		ip_get_hdrlen(ip) + (g_context->tmp_variables.nr_of_ip_hdr > 1 ?
		ip_get_hdrlen(ip2) : 0) + g_context->next_header_len;

	/* discard IP fragments */
	if(ip_is_fragment(ip))
	{
		rohc_debugf(0, "fragment error in outer IP header\n");
		return -1;
	}

	if(g_context->tmp_variables.nr_of_ip_hdr > 1 && ip_is_fragment(ip2))
	{
		rohc_debugf(0, "fragment error in inner IP header\n");
		return -1;
	}

	/* STEP 2:
	 *  - check NBO and RND of the IP-ID of the outer and inner IP headers
	 *    (IPv4 only)
	 *  - increase the Sequence Number (SN)
	 *  - find how many static and dynamic IP fields changed
	 */
	if(g_context->sn != 0) /* skip first packet (sn == 0) */
	{
		if(ip_get_version(ip) == IPV4)
			check_ip_identification(&g_context->ip_flags, ip);
		if(g_context->tmp_variables.nr_of_ip_hdr > 1 &&
		   ip_get_version(ip2) == IPV4)
			check_ip_identification(&g_context->ip2_flags, ip2);
	}

	is_rtp = context->profile->id == ROHC_PROFILE_RTP;
	if(is_rtp)
	{
		/* RTP profile: SN is the RTP SN */
		struct udphdr *udp;
		struct rtphdr *rtp;
		struct sc_rtp_context *rtp_context;;
		rtp_context = (struct sc_rtp_context *) g_context->specific;

		if(g_context->tmp_variables.nr_of_ip_hdr > 1)
			udp = (struct udphdr *) ip_get_next_header(ip2);
		else
			udp = (struct udphdr *) ip_get_next_header(ip);

		/* initialisation of SN with the SN field of the RTP packet */
		rtp = (struct rtphdr *) (udp + 1);
		g_context->sn = ntohs(rtp->sn);
		c_add_ts(&rtp_context->ts_sc, rtp_context->tmp_variables.timestamp,
		         g_context->sn);
	}
	else
	{
		/* increase the SN every time we encode something */
		g_context->sn++;
	}

	rohc_debugf(3, "SN = %d\n",g_context->sn);

	/* find IP fields that changed */
	if(g_context->tmp_variables.nr_of_ip_hdr == 1)
		g_context->tmp_variables.changed_fields = changed_fields(&g_context->ip_flags, ip, is_rtp);
	else
	{
		g_context->tmp_variables.changed_fields = changed_fields(&g_context->ip_flags, ip, 0);
		g_context->tmp_variables.changed_fields2 = changed_fields(&g_context->ip2_flags, ip2, is_rtp);
	}

	/* how many changed fields are static ones? */
	g_context->tmp_variables.send_static = changed_static_both_hdr(context, ip, ip2);
	/* how many changed fields are dynamic ones? */
	g_context->tmp_variables.send_dynamic = changed_dynamic_both_hdr(context, ip, ip2);

	rohc_debugf(2, "send_static = %d, send_dynamic = %d\n",
	            g_context->tmp_variables.send_static,
	            g_context->tmp_variables.send_dynamic);

	/* STEP 3: decide in which state to go */
	if(g_context->decide_state != NULL)
		g_context->decide_state(context);

	if(ip_get_version(ip) == IPV4)
		rohc_debugf(2, "ip_id = 0x%04x, context_sn = %d\n",
		            ntohs(ipv4_get_id(ip)), g_context->sn);
	else /* IPV6 */
		rohc_debugf(2, "context_sn = %d\n", g_context->sn);

	/* STEP 4:
	 *  - compute how many bits are needed to send the IP-ID and SN fields
	 *  - update the sliding windows
	 */
	update_variables(context, ip, ip2);

	/* STEP 5: decide which packet to send */
	g_context->tmp_variables.packet_type = decide_packet(context);

	/* STEP 6: code the packet (and the extension if needed) */
	size = code_packet(context, ip, ip2, next_header, dest);
	if(size < 0)
		return -1;

	/* update the context with the new headers */
	if(ip_get_version(ip) == IPV4)
	{
		g_context->ip_flags.info.v4.old_ip = *(ipv4_get_header(ip));
		g_context->ip_flags.info.v4.old_rnd = g_context->ip_flags.info.v4.rnd;
		g_context->ip_flags.info.v4.old_nbo = g_context->ip_flags.info.v4.nbo;
	}
	else /* IPV6 */
		g_context->ip_flags.info.v6.old_ip = *(ipv6_get_header(ip));

	if(g_context->tmp_variables.nr_of_ip_hdr > 1)
	{
		if(ip_get_version(ip2) == IPV4)
		{
			g_context->ip2_flags.info.v4.old_ip = *(ipv4_get_header(ip2));
			g_context->ip2_flags.info.v4.old_rnd = g_context->ip2_flags.info.v4.rnd;
			g_context->ip2_flags.info.v4.old_nbo = g_context->ip2_flags.info.v4.nbo;
		}
		else /* IPV6 */
			g_context->ip2_flags.info.v6.old_ip = *(ipv6_get_header(ip2));
	}

	/* update packet counters */
	if(g_context->tmp_variables.packet_type == PACKET_IR)
		context->num_sent_ir++;
	else if (g_context->tmp_variables.packet_type == PACKET_IR_DYN)
		context->num_sent_ir_dyn++;

	/* return the length of the ROHC packet */
	return size;
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
void c_generic_feedback(struct c_context *context,
                        struct c_feedback *feedback)
{
	struct c_generic_context *g_context;
	unsigned char *p; /* pointer to the profile-specific data
	                     in the feedback packet */
	unsigned int sn;
	
	g_context = (struct c_generic_context *) context->specific;
	p = feedback->data + feedback->specific_offset;

	switch(feedback->type)
	{
		case 1: /* FEEDBACK-1 */
			rohc_debugf(2, "feedback 1\n");
			sn = p[0];
		
			/* ack IP-ID only if IPv4, but always ack SN */
			if(g_context->ip_flags.version == IPV4)
				c_ack_sn_wlsb(g_context->ip_flags.info.v4.ip_id_window, sn);
			c_ack_sn_wlsb(g_context->sn_window, sn);
			break;

		case 2: /* FEEDBACK-2 */
		{
			unsigned int crc = 0, crc_used = 0;
			int sn_not_valid = 0;
			unsigned char mode = (p[0] >> 4) & 3;
			int remaining = feedback->specific_size - 2;
			int opt, optlen;

			rohc_debugf(2, "feedback 2\n");

			sn = ((p[0] & 15) << 8) + p[1];
			p += 2;
			
			while(remaining > 0)
			{
				opt = p[0] >> 4;
				optlen = p[0] & 0x0f;
				
				switch(opt)
				{
					case 1: /* CRC */
						crc = p[1];
						crc_used = 1;
						p[1] = 0; /* set to zero for crc computation */
						break;
					case 3: /* SN-Not-Valid */
						sn_not_valid = 1;
						break;
					case 4: /* SN */
						/* TODO: how are several SN options combined? */
						sn = (sn << 8) + p[1];
						break;
					case 2: /* Reject */
					case 7: /* Loss */
					default:
						rohc_debugf(0, "unknown feedback type: %d\n", opt);
						break;
				}
				
				remaining -= 1 + optlen;
				p += 1 + optlen;
			}
			
			/* check CRC if used */
			if(crc_used && crc_calculate(CRC_TYPE_8, feedback->data, feedback->size) != crc)
			{
				rohc_debugf(0, "CRC check failed (size = %d)\n", feedback->size);
				return;
			}

			if(mode != 0)
			{
				if(crc_used)
					change_mode(context, mode);
				else
					rohc_debugf(0, "mode change requested but no crc was given\n");
			}
			
			switch(feedback->acktype)
			{
				case ACK:
					rohc_debugf(2, "ack\n");
					if(sn_not_valid == 0)
					{
						/* ack IP-ID only if IPv4, but always ack SN */
						if(g_context->ip_flags.version == IPV4)
							c_ack_sn_wlsb(g_context->ip_flags.info.v4.ip_id_window, sn);
						c_ack_sn_wlsb(g_context->sn_window, sn);
					}
					break;
				
				case NACK:
					rohc_debugf(2, "nack\n");
					if(context->state == SO)
					{
						change_state(context, FO);
						g_context->ir_dyn_count = 0;
					}
					else if(context->state == FO)
						g_context->ir_dyn_count = 0;
					break;
					
				case STATIC_NACK:
					rohc_debugf(2, "static nack\n");
					change_state(context, IR);
					break;
					
				case RESERVED:
					rohc_debugf(0, "reserved field used\n");
					break;

				default:
					/* impossible value */
					rohc_debugf(0, "unknown ack type\n");
			}	
		}
		break;

		default: /* not FEEDBACK-1 nor FEEDBACK-2 */
			rohc_debugf(0, "feedback type not implemented (%d)\n",
			            feedback->type);
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

	if(g_context->go_back_fo_count >= CHANGE_TO_FO_COUNT)
	{
		rohc_debugf(1, "periodic change to FO state\n");
		g_context->go_back_fo_count = 0;
		g_context->ir_dyn_count = 0;
		change_state(context, FO);
	}
	else if(g_context->go_back_ir_count >= CHANGE_TO_IR_COUNT)
	{
		rohc_debugf(1, "periodic change to IR state\n");
		g_context->go_back_ir_count = 0;
		change_state(context, IR);
	}

	if(context->state == SO)
		g_context->go_back_fo_count++;
	if(context->state == SO || context->state == FO)
		g_context->go_back_ir_count++;
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
void decide_state(struct c_context *context)
{
	struct c_generic_context *g_context;
	int ir_count, fo_count, send_static, send_dynamic;
	rohc_c_state curr_state, next_state;
	
	curr_state = context->state;
	next_state = curr_state;

	g_context = (struct c_generic_context *) context->specific;
	ir_count = g_context->ir_count;
	fo_count = g_context->fo_count;
	send_static = g_context->tmp_variables.send_static;
	send_dynamic = g_context->tmp_variables.send_dynamic;

	if(curr_state == IR && send_dynamic && ir_count >= MAX_IR_COUNT)
		next_state = FO;
	else if(curr_state == IR && send_static && ir_count >= MAX_IR_COUNT)
		next_state = FO;
	else if(curr_state == IR && ir_count >= MAX_IR_COUNT)
		next_state = SO;
	else if(curr_state == FO && send_dynamic && fo_count >= MAX_FO_COUNT)
		next_state = FO;
	else if(curr_state == FO && send_static && fo_count >= MAX_FO_COUNT)
		next_state = FO;
	else if(curr_state == FO && fo_count >= MAX_FO_COUNT)
		next_state = SO;
	else if(curr_state == SO && send_dynamic)
		next_state = FO;
	else if(curr_state == SO && send_static)
		next_state = FO;

	change_state(context, next_state);
	
	if(context->mode == U_MODE)
		periodic_down_transition(context);
}


/**
 * @brief Update some context variables.
 *
 * This function is only used in encode. Everything in this function could
 * be in encode but to make it more readable we have it here instead.
 *
 * @param context The compression context
 * @param ip      The outer IP header
 * @param ip2     The inner IP header
 */
void update_variables(struct c_context *context,
                      const struct ip_packet ip,
                      const struct ip_packet ip2)
{
	struct c_generic_context *g_context;
	
	g_context = (struct c_generic_context *) context->specific;

	/* update info related to the IP-ID of the outer header
	 * only if header is IPv4 */
	if(ip_get_version(ip) == IPV4)
	{
		if(g_context->ip_flags.info.v4.nbo)
			g_context->ip_flags.info.v4.id_delta = ntohs(ipv4_get_id(ip)) - g_context->sn;
		else
			g_context->ip_flags.info.v4.id_delta = ipv4_get_id(ip) - g_context->sn;

		g_context->tmp_variables.nr_ip_id_bits =
			c_get_k_wlsb(g_context->ip_flags.info.v4.ip_id_window,
			             g_context->ip_flags.info.v4.id_delta);
		rohc_debugf(3, "ip_id delta = 0x%x / %u\n",
		            g_context->ip_flags.info.v4.id_delta,
		            g_context->ip_flags.info.v4.id_delta);
		rohc_debugf(2, "ip_id bits = %d\n", g_context->tmp_variables.nr_ip_id_bits);

		c_add_wlsb(g_context->ip_flags.info.v4.ip_id_window, g_context->sn, 0,
		           g_context->ip_flags.info.v4.id_delta);
	}
	else /* IPV6 */
		g_context->tmp_variables.nr_ip_id_bits = 0;
	
	/* always update the info related to the SN */
	g_context->tmp_variables.nr_sn_bits = c_get_k_wlsb(g_context->sn_window, g_context->sn);
	rohc_debugf(2, "sn bits=%d\n", g_context->tmp_variables.nr_sn_bits);
	c_add_wlsb(g_context->sn_window, g_context->sn, 0, g_context->sn);
	
	/* update info related to the IP-ID of the inner header
	 * only if header is IPv4 */
	if(g_context->tmp_variables.nr_of_ip_hdr > 1 && ip_get_version(ip2) == IPV4)
	{
		if(g_context->ip2_flags.info.v4.nbo)
			g_context->ip2_flags.info.v4.id_delta = ntohs(ipv4_get_id(ip2)) - g_context->sn;
		else
			g_context->ip2_flags.info.v4.id_delta = ipv4_get_id(ip2) - g_context->sn;

		g_context->tmp_variables.nr_ip_id_bits2 =
			c_get_k_wlsb(g_context->ip2_flags.info.v4.ip_id_window,
			             g_context->ip2_flags.info.v4.id_delta);
		rohc_debugf(2, "ip_id bits2=%d\n", g_context->tmp_variables.nr_ip_id_bits2);

		c_add_wlsb(g_context->ip2_flags.info.v4.ip_id_window, g_context->sn, 0,
		           g_context->ip2_flags.info.v4.id_delta);
	}
	else /* IPV6 */
		g_context->tmp_variables.nr_ip_id_bits2 = 0;

	/* update info related to RTP header */
	if(context->profile->id == ROHC_PROFILE_RTP)
	{
		struct rtphdr *rtp;
		struct udphdr *udp;
		struct sc_rtp_context *rtp_context;

		if(g_context->tmp_variables.nr_of_ip_hdr > 1)
			udp = (struct udphdr *) ip_get_next_header(ip2);
		else
			udp = (struct udphdr *) ip_get_next_header(ip);

		rtp = (struct rtphdr *) (udp + 1);
		rtp_context = g_context->specific;

		if(rtp_context->ts_sc.state == SEND_SCALED)
		{
			/* TS_SCALED value will be send */
			rtp_context->tmp_variables.ts_send = get_ts_scaled(rtp_context->ts_sc);
			rtp_context->tmp_variables.nr_ts_bits = nb_bits_scaled(rtp_context->ts_sc);

			/* save the new TS_SCALED value */
			add_scaled(&rtp_context->ts_sc, g_context->sn);
			rohc_debugf(3, "ts_scaled = %u on %d bits\n",
			            rtp_context->tmp_variables.ts_send,
			            rtp_context->tmp_variables.nr_ts_bits);
		}
		else if(rtp_context->ts_sc.state == INIT_STRIDE)
		{
			/* TS and TS_STRIDE will be send */
			rtp_context->tmp_variables.ts_send = ntohl(rtp->timestamp);
			rtp_context->tmp_variables.nr_ts_bits = 32;
		}

		rtp_context->tmp_variables.m = rtp->m;
	}
}


/**
 * @brief Decide which packet to send when in First Order (FO) state.
 *
 * Packets that can be used are the IR-DYN and UO-2 packets.
 *
 * @see decide_packet
 *
 * @param context The compression context
 * @return        The packet type among PACKET_IR_DYN and PACKET_UOR_2
 */
int decide_FO_packet(struct c_context *context)
{
	struct c_generic_context *g_context;
	int nr_of_ip_hdr, send_static, send_dynamic;
	int packet;
	int is_rtp;
	int is_rnd;
	int is_ip_v4;
	int nr_ip_id_bits;

	g_context = (struct c_generic_context *) context->specific;
	nr_of_ip_hdr = g_context->tmp_variables.nr_of_ip_hdr;
	send_static = g_context->tmp_variables.send_static;
	send_dynamic = g_context->tmp_variables.send_dynamic;
	is_rtp = context->profile->id == ROHC_PROFILE_RTP;
	is_rnd = g_context->ip_flags.info.v4.rnd;
	is_ip_v4 = g_context->ip_flags.version == IPV4;
	nr_ip_id_bits = g_context->tmp_variables.nr_ip_id_bits;

	if(send_static)
	{
		g_context->ir_dyn_count = 0;
		packet = PACKET_UOR_2;
	}
	else if(g_context->ir_dyn_count < MAX_FO_COUNT)
	{
		g_context->ir_dyn_count++;
		packet = PACKET_IR_DYN;
	}
	else if(nr_of_ip_hdr == 1 && send_dynamic > 2)
		packet = PACKET_IR_DYN;
	else if(nr_of_ip_hdr > 1 && send_dynamic > 4)
		packet = PACKET_IR_DYN;
	else if(is_rtp) /* RTP profile */
	{
		int nr_ts_bits;
		struct sc_rtp_context *rtp_context;
		rtp_context = (struct sc_rtp_context *) g_context->specific;
		nr_ts_bits = rtp_context->tmp_variables.nr_ts_bits; /* nb of bits needed */

		if(nr_of_ip_hdr == 1) /* single IP header */
		{
			if(!is_ip_v4 || is_rnd)
				packet = PACKET_UOR_2_RTP;
			else if(is_ip_v4 && !is_rnd && nr_ip_id_bits > 0 && nr_ts_bits <= 28)
				/* a UOR-2-ID packet can only carry 28 bits of TS (with ext 3) */
				packet = PACKET_UOR_2_ID;
			else
				packet = PACKET_UOR_2_TS;
		}
		else /* double IP headers */
		{
			int is_ip2_v4 = g_context->ip2_flags.version == IPV4;
			int is_rnd2 = g_context->ip2_flags.info.v4.rnd;
			int nr_ip_id_bits2 = g_context->tmp_variables.nr_ip_id_bits2;

			if( (!is_ip_v4 || is_rnd) && (!is_ip2_v4 || is_rnd2))
				packet = PACKET_UOR_2_RTP;
			else if(nr_ts_bits <= 28 &&
			        (is_ip_v4 && nr_ip_id_bits > 0 &&
			         (!is_ip_v4 || is_rnd2 || nr_ip_id_bits2 == 0)))
				packet = PACKET_UOR_2_ID;
			else
				packet = PACKET_UOR_2_TS;
		}
	}
	else /* non-RTP profiles */
		packet = PACKET_UOR_2;

	return packet;
}


/**
 * @brief Decide which packet to send when in Second Order (SO) state.
 *
 * Packets that can be used are the UO-0, UO-1 and UO-2 (with or without
 * extensions) packets.
 *
 * @see decide_packet
 *
 * @param context The compression context
 * @return        The packet type among PACKET_UO_0, PACKET_UO_1 and
 *                PACKET_UOR_2
 */
int decide_SO_packet(const struct c_context *context)
{
	struct c_generic_context *g_context;
	int nr_of_ip_hdr, nr_sn_bits, nr_ip_id_bits;
	int packet;
	int is_rtp;
	int is_rnd;
	int is_ip_v4;

	g_context = (struct c_generic_context *) context->specific;
	nr_of_ip_hdr = g_context->tmp_variables.nr_of_ip_hdr;
	nr_sn_bits = g_context->tmp_variables.nr_sn_bits;
	nr_ip_id_bits = g_context->tmp_variables.nr_ip_id_bits;
	is_rtp = context->profile->id == ROHC_PROFILE_RTP;
	is_rnd = g_context->ip_flags.info.v4.rnd;
	is_ip_v4 = g_context->ip_flags.version == IPV4;

	rohc_debugf(3, "nr_ip_bits=%d nr_sn_bits=%d nr_of_ip_hdr=%d rnd=%d\n",
	            nr_ip_id_bits, nr_sn_bits, nr_of_ip_hdr, is_rnd);

	if(is_rtp) /* RTP profile */
	{
		struct sc_rtp_context *rtp_context;
		rtp_context = (struct sc_rtp_context *) g_context->specific;
		int nr_ts_bits = rtp_context->tmp_variables.nr_ts_bits;

		if(nr_of_ip_hdr == 1) /* single IP header */
		{
			if(is_rnd || !is_ip_v4)
			{
				packet = PACKET_UOR_2_RTP; /* default packet */

				if(nr_sn_bits <= 4 && (nr_ts_bits == 0 || is_deductible(rtp_context->ts_sc)))
					packet = PACKET_UO_0;
				else if(nr_sn_bits <= 4 && nr_ts_bits <= 6)
					packet = PACKET_UO_1_RTP;
			}
			else
			{
				packet = PACKET_UOR_2_TS; /* default packet */

				if(nr_sn_bits <= 4 && nr_ip_id_bits == 0 &&
				   (nr_ts_bits == 0 || is_deductible(rtp_context->ts_sc)))
					packet = PACKET_UO_0;
				else if(nr_sn_bits <= 4 && nr_ip_id_bits == 0 && nr_ts_bits <= 5)
					packet = PACKET_UO_1_TS;
				else if(nr_sn_bits <= 4 && nr_ip_id_bits <= 5 && nr_ts_bits == 0)
					packet = PACKET_UO_1_ID;
				else if(nr_ip_id_bits != 0 && nr_ts_bits <= 28)
					packet = PACKET_UOR_2_ID;
			}
		}
		else /* double IP headers */
		{
			int is_ip2_v4 = g_context->ip2_flags.version == IPV4;
			int is_rnd2 = g_context->ip2_flags.info.v4.rnd;
			int nr_ip_id_bits2 = g_context->tmp_variables.nr_ip_id_bits2;
			rohc_debugf(3, "nr_ip_id_bits2 = %d rnd2 = %d\n",
			            nr_ip_id_bits2, is_rnd2);

			if((nr_sn_bits <= 4) &&
			   (!is_ip_v4 || is_rnd || nr_ip_id_bits == 0) &&
			   (!is_ip2_v4 || is_rnd2 || nr_ip_id_bits2 == 0) &&
			   nr_ts_bits == 0)
				packet = PACKET_UO_0;
			else if((!is_ip_v4 || is_rnd) &&
			        (!is_ip2_v4 || is_rnd2) &&
			        nr_sn_bits <= 4 &&
			        nr_ts_bits <= 6)
				packet = PACKET_UO_1_RTP;
			else if((is_ip_v4 && nr_ip_id_bits <= 5) &&
			        (!is_ip2_v4 || is_rnd2 || nr_ip_id_bits2 == 0) &&
			        nr_sn_bits <= 4 &&
			        nr_ts_bits == 0)
				packet = PACKET_UO_1_ID;
			else if((!is_ip_v4 || is_rnd || nr_ip_id_bits == 0) &&
			        (!is_ip2_v4 || is_rnd2 || nr_ip_id_bits2 == 0) &&
			        nr_sn_bits <= 4 &&
			        nr_ts_bits <= 5)
				packet = PACKET_UO_1_TS;
			else if((!is_ip_v4 || is_rnd) &&
			        (!is_ip2_v4 || is_rnd2))
				packet = PACKET_UOR_2_RTP;
			else if((is_ip_v4 && nr_ip_id_bits > 0) &&
			        (!is_ip2_v4 || is_rnd2 || nr_ip_id_bits2 == 0) &&
			        nr_ts_bits <= 28)
				packet = PACKET_UOR_2_ID;
			else
				packet = PACKET_UOR_2_TS;
		}
	}
	else /* non-RTP profiles */
	{
		packet = PACKET_UOR_2; /* default packet type */

		if(nr_of_ip_hdr == 1) /* single IP header */
		{
			if(nr_sn_bits <= 4 &&
			   (!is_ip_v4 || (is_ip_v4 && (is_rnd == 1 || nr_ip_id_bits == 0))))
				packet = PACKET_UO_0;
			else if(nr_sn_bits == 5 && (!is_ip_v4 || (is_ip_v4 && nr_ip_id_bits == 0)))
				packet = PACKET_UOR_2;
			else if(nr_sn_bits <= 5 && (is_ip_v4 && nr_ip_id_bits <= 6))
				packet = PACKET_UO_1; /* IPv4 only */
			/* else PACKET_UOR_2 */
		}
		else /* double IP headers */
		{
			int is_ip2_v4 = g_context->ip2_flags.version == IPV4;
			int is_rnd2 = g_context->ip2_flags.info.v4.rnd;
			int nr_ip_id_bits2 = g_context->tmp_variables.nr_ip_id_bits2;

			if(nr_sn_bits <= 4 &&
			   (!is_ip_v4 || (is_ip_v4 && (is_rnd == 1 || nr_ip_id_bits == 0))) &&
			   (!is_ip2_v4 || (is_ip2_v4 && (is_rnd2 == 1 || nr_ip_id_bits2 == 0))))
				packet = PACKET_UO_0;
			else if(nr_sn_bits <= 5 && (is_ip_v4 && nr_ip_id_bits <= 6) &&
			        (!is_ip2_v4 || (is_ip2_v4 && (is_rnd2 == 1 || nr_ip_id_bits2 == 0))))
				packet = PACKET_UO_1; /* IPv4 only for outer header */
			/* else PACKET_UOR_2 */
		}
	}

	return packet;
}


/**
 * @brief Decide which packet to send when in the different states.
 *
 * In IR state, IR packets are used. In FO and SO, the decide_FO_packet and
 * decide_SO_packet are used to decide which packet to send.
 *
 * @see decide_FO_packet
 * @see decide_SO_packet
 *
 * @param context The compression context
 * @return        The packet type among PACKET_IR, PACKET_IR_DYN, PACKET_UO_0,
 *                PACKET_UO_1 and PACKET_UOR_2
 */
int decide_packet(struct c_context *context)
{
	struct c_generic_context *g_context;
	int packet;
	
	g_context = (struct c_generic_context *) context->specific;

	packet = PACKET_IR; /* default packet type */

	switch(context->state)
	{
		case IR:
			rohc_debugf(2, "IR state\n");
			g_context->ir_count++;
			packet = PACKET_IR;
			break;

		case FO:
			rohc_debugf(2, "FO state\n");
			g_context->fo_count++;
			packet = decide_FO_packet(context);
			break;

		case SO:
			rohc_debugf(2, "SO state\n");
			g_context->so_count++;
			packet = decide_SO_packet(context);
			break;

		default:
			/* impossible value */
			rohc_debugf(2, "unknown state (%d) => IR packet\n", context->state);
	}

	return packet;
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
int code_packet(struct c_context *context,
                const struct ip_packet ip,
                const struct ip_packet ip2,
                const unsigned char *next_header,
                unsigned char *dest)
{
	struct c_generic_context *g_context;
	int nr_of_ip_hdr, packet_type;
	int (*code_packet_type)(struct c_context *context,
	                        const struct ip_packet ip,
	                        const struct ip_packet ip2,
	                        const unsigned char *next_header,
	                        unsigned char *dest);
	int counter;

	g_context = (struct c_generic_context *) context->specific;
	nr_of_ip_hdr = g_context->tmp_variables.nr_of_ip_hdr;
	packet_type = g_context->tmp_variables.packet_type;

	code_packet_type = NULL;
	counter = -1;

	switch(packet_type)
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
			rohc_debugf(0, "unknown packet, failure\n");
			break;
	}

	if(code_packet != NULL)
		counter = code_packet_type(context, ip, ip2, next_header, dest);
	else
		counter = -1;

	return counter;
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
 8  |             SN                |  2 octets if not RTP
    +---+---+---+---+---+---+---+---+
    |                               |
    |           Payload             |  variable length
    |                               |
     - - - - - - - - - - - - - - - -

\endverbatim
 *
 * @param context        The compression context
 * @param ip             The outer IP header
 * @param ip2            The inner IP header
 * @param next_header    The next header data used to code the static and
 *                       dynamic parts of the next header for some profiles such
 *                       as UDP, UDP-Lite, and so on.
 * @param dest           The rohc-packet-under-build buffer
 * @return               The position in the rohc-packet-under-build buffer 
 */
int code_IR_packet(struct c_context *context,
                   const struct ip_packet ip,
                   const struct ip_packet ip2,
                   const unsigned char *next_header,
                   unsigned char *dest)
{
	struct c_generic_context *g_context;
	int nr_of_ip_hdr;
	unsigned char type;
	int counter;
	int first_position, crc_position;

	g_context = (struct c_generic_context *) context->specific;
	nr_of_ip_hdr = g_context->tmp_variables.nr_of_ip_hdr;

	rohc_debugf(2, "code IR packet (CID = %d)\n", context->cid);

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - part 4 will start at 'counter'
	 */
	counter = code_cid_values(context, dest, g_context->tmp_variables.max_size,
	                          &first_position);

	/* initialize some profile-specific things when building an IR
	 * or IR-DYN packet */
	if(g_context->init_at_IR != NULL)
		g_context->init_at_IR(context, next_header);

	/* part 2: type of packet and D flag if dynamic part is included */
	type = 0xfc;
	type |= 1; /* D flag */
	rohc_debugf(3, "type of packet + D flag = 0x%02x\n", type);
	dest[first_position] = type;

	/* part 4 */
	rohc_debugf(3, "profile ID = 0x%02x\n", context->profile->id);
	dest[counter] = context->profile->id;
	counter++;

	/* part 5: the CRC is computed later since it must be computed
	 * over the whole packet with an empty CRC field */
	rohc_debugf(3, "CRC = 0x00 for CRC calculation\n");
	crc_position = counter;
	dest[counter] = 0;
	counter++;

	/* part 6: static part */
	counter = code_generic_static_part(context, &g_context->ip_flags,
	                                   ip, dest, counter);
	if(counter < 0)
		goto error;

	if(nr_of_ip_hdr > 1)
	{
		counter = code_generic_static_part(context, &g_context->ip2_flags,
		                                   ip2, dest, counter);
		if(counter < 0)
			goto error;
	}

	if(g_context->code_static_part != NULL && next_header != NULL)
	{
		/* static part of next header */
		counter = g_context->code_static_part(context, next_header,
		                                      dest, counter);
		if(counter < 0)
			goto error;
	}

	/* part 7: if we do not want dynamic part in IR packet, we should not
	 * send the following */
	counter = code_generic_dynamic_part(context, &g_context->ip_flags,
	                                    ip, dest, counter);
	if(counter < 0)
		goto error;

	if(nr_of_ip_hdr > 1)
	{
		counter = code_generic_dynamic_part(context, &g_context->ip2_flags,
		                                    ip2, dest, counter);
		if(counter < 0)
			goto error;
	}

	if(g_context->code_dynamic_part != NULL && next_header != NULL)
	{
		/* dynamic part of next header */
		counter = g_context->code_dynamic_part(context, next_header,
		                                       dest, counter);
		if(counter < 0)
			goto error;
	}

	/* part 8 */
	if(context->profile->id != ROHC_PROFILE_RTP)
	{
		dest[counter] = g_context->sn >> 8;
		counter++;
		dest[counter] = g_context->sn & 0xff;
		counter++;
		rohc_debugf(3, "SN = %d -> 0x%02x%02x\n", g_context->sn, dest[counter-2], dest[counter-1]);
	}

	/* part 5 */
	dest[crc_position] = crc_calculate(CRC_TYPE_8, dest, counter);
	rohc_debugf(3, "CRC (header length = %d, crc = 0x%x)\n",
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
 7  |             SN                | 2 octets if not RTP
    +---+---+---+---+---+---+---+---+
    :                               :
    /           Payload             / variable length
    :                               :
     - - - - - - - - - - - - - - - -

\endverbatim
 *
 * @param context        The compression context
 * @param ip             The outer IP header
 * @param ip2            The inner IP header
 * @param next_header    The next header data used to code the dynamic part
 *                       of the next header for some profiles such as UDP,
 *                       UDP-Lite, etc.
 * @param dest           The rohc-packet-under-build buffer
 * @return               The position in the rohc-packet-under-build buffer 
 */
int code_IR_DYN_packet(struct c_context *context,
                       const struct ip_packet ip,
                       const struct ip_packet ip2,
                       const unsigned char *next_header,
                       unsigned char *dest)
{
	struct c_generic_context *g_context;
	int nr_of_ip_hdr;
	int counter;
	int first_position, crc_position;

	g_context = (struct c_generic_context *) context->specific;
	nr_of_ip_hdr = g_context->tmp_variables.nr_of_ip_hdr;

	rohc_debugf(2, "code IR-DYN packet (CID = %d)\n", context->cid);

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - part 4 will start at 'counter'
	 */
	counter = code_cid_values(context, dest, g_context->tmp_variables.max_size,
	                          &first_position);

	/* initialize some profile-specific things when building an IR
	 * or IR-DYN packet */
	if(g_context->init_at_IR != NULL)
		g_context->init_at_IR(context, next_header);

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
		goto error;

	if(nr_of_ip_hdr > 1)
	{
		counter = code_generic_dynamic_part(context, &g_context->ip2_flags,
		                                    ip2, dest, counter);
		if(counter < 0)
			goto error;
	}

	if(g_context->code_dynamic_part != NULL && next_header != NULL)
	{
		/* dynamic part of next header */
		counter = g_context->code_dynamic_part(context, next_header, dest, counter);
		if(counter < 0)
			goto error;
	}

	/* part 7 */
	if(context->profile->id != ROHC_PROFILE_RTP)
	{
		rohc_debugf(3, "SN = %d\n", g_context->sn);
		dest[counter] = g_context->sn >> 8;
		counter++;
		dest[counter] = g_context->sn & 0xff;
		counter++;
	}

	/* part 5 */
	dest[crc_position] = crc_calculate(CRC_TYPE_8, dest, counter);
	rohc_debugf(3, "CRC (header length = %d, crc = 0x%x)\n",
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
int code_generic_static_part(struct c_context *context,
                             struct ip_header_info *header_info,
                             const struct ip_packet ip,
                             unsigned char *dest,
                             int counter)
{
	if(ip_get_version(ip) == IPV4)
		counter = code_ipv4_static_part(context, header_info,
		                                ip, dest, counter);
	else /* IPV6 */
		counter = code_ipv6_static_part(context, header_info,
		                                ip, dest, counter);

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
int code_ipv4_static_part(struct c_context *context,
                          struct ip_header_info *header_info,
                          const struct ip_packet ip,
                          unsigned char *dest,
                          int counter)
{
	unsigned int protocol;
	uint32_t saddr;
	uint32_t daddr;

	/* part 1 */
	dest[counter] = 0x40;
	rohc_debugf(3, "version = 0x40\n");
	counter++;

	/* part 2 */
	protocol = ip_get_protocol(ip);
	rohc_debugf(3, "protocol = 0x%02x\n", protocol);
	dest[counter] = protocol;
	counter++;
	header_info->protocol_count++;

	/* part 3 */
	saddr = ipv4_get_saddr(ip);
	memcpy(&dest[counter], &saddr, 4);
	rohc_debugf(3, "src addr = %02x %02x %02x %02x\n",
	            dest[counter], dest[counter + 1],
	            dest[counter + 2], dest[counter + 3]);
	counter += 4;

	/* part 4 */
	daddr = ipv4_get_daddr(ip);
	memcpy(&dest[counter], &daddr, 4);
	rohc_debugf(3, "dst addr = %02x %02x %02x %02x\n",
	            dest[counter], dest[counter + 1],
	            dest[counter + 2], dest[counter + 3]);
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
int code_ipv6_static_part(struct c_context *context,
                          struct ip_header_info *header_info,
                          struct ip_packet ip,
                          unsigned char *dest,
                          int counter)
{
	unsigned int flow_label;
	unsigned int protocol;
	struct in6_addr *saddr;
	struct in6_addr *daddr;

	/* part 1 */
	flow_label = ipv6_get_flow_label(ip);
	dest[counter] = ((6 << 4) & 0xf0) | ((flow_label >> 16) & 0x0f);
	rohc_debugf(3, "version + flow label (msb) = 0x%02x\n", dest[counter]);
	counter++;

	/* part 2 */
	dest[counter] = (flow_label >> 8) & 0xff;
	counter++;
	dest[counter] = flow_label & 0xff;
	counter++;
	rohc_debugf(3, "flow label (lsb) = 0x%02x%02x\n",
	            dest[counter - 2], dest[counter - 1]);

	/* part 3 */
	protocol = ip_get_protocol(ip);
	rohc_debugf(3, "next header = 0x%02x\n", protocol);
	dest[counter] = protocol;
	counter++;
	header_info->protocol_count++;

	/* part 4 */
	saddr = ipv6_get_saddr(&ip);
	memcpy(&dest[counter], saddr, 16);
	rohc_debugf(3, "src addr = " IPV6_ADDR_FORMAT "\n",
	            IPV6_ADDR(saddr));
	counter += 16;

	/* part 5 */
	daddr = ipv6_get_daddr(&ip);
	memcpy(&dest[counter], daddr, 16);
	rohc_debugf(3, "dst addr = " IPV6_ADDR_FORMAT "\n",
	            IPV6_ADDR(daddr));
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
 * @return            The new position in the rohc-packet-under-build buffer 
 */
int code_generic_dynamic_part(struct c_context *context,
                              struct ip_header_info *header_info,
                              const struct ip_packet ip,
                              unsigned char *dest,
                              int counter)
{
	if(ip_get_version(ip) == IPV4)
		counter = code_ipv4_dynamic_part(context, header_info,
		                                 ip, dest, counter);
	else /* IPV6 */
		counter = code_ipv6_dynamic_part(context, header_info,
		                                 ip, dest, counter);

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
int code_ipv4_dynamic_part(struct c_context *context,
                           struct ip_header_info *header_info,
                           const struct ip_packet ip,
                           unsigned char *dest,
                           int counter)
{
	unsigned int tos, ttl, id, df;
	unsigned char df_rnd_nbo;

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
	id = ipv4_get_id(ip);
	memcpy(&dest[counter], &id, 2);
	counter += 2;

	/* part 4 */
	df = ipv4_get_df(ip);
	df_rnd_nbo = df << 7;
	if(header_info->info.v4.rnd)
		df_rnd_nbo |= 0x40;
	if(header_info->info.v4.nbo)
		df_rnd_nbo |= 0x20;

	dest[counter] = df_rnd_nbo;
	counter++;

	header_info->info.v4.df_count++;
	header_info->info.v4.rnd_count++;
	header_info->info.v4.nbo_count++;

	/* part 5 is not supported for the moment */

	rohc_debugf(3, "TOS = 0x%02x, TTL = 0x%02x, IP-ID = 0x%04x, df_rnd_nbo = "
	            "0x%02x (DF = %d, RND = %d, NBO = %d)\n", tos, ttl, id,
	            df_rnd_nbo, df, header_info->info.v4.rnd,
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
 * @return            The new position in the rohc-packet-under-build buffer 
 */
int code_ipv6_dynamic_part(struct c_context *context,
                           struct ip_header_info *header_info,
                           const struct ip_packet ip,
                           unsigned char *dest,
                           int counter)
{
	unsigned int tos, ttl;

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

	/* part 3 is not supported for the moment */

	rohc_debugf(3, "TC = 0x%02x, HL = 0x%02x\n", tos, ttl);

	return counter;
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
int code_UO_packet_tail(struct c_context *context,
                        const struct ip_packet ip,
                        const struct ip_packet ip2,
                        const unsigned char *next_header,
                        unsigned char *dest,
								int counter)
{
	struct c_generic_context *g_context;
	int nr_of_ip_hdr;
	unsigned int id;

	g_context = (struct c_generic_context *) context->specific;
	nr_of_ip_hdr = g_context->tmp_variables.nr_of_ip_hdr;

	/* parts 6: only IPv4 */
	if(ip_get_version(ip) == IPV4 && g_context->ip_flags.info.v4.rnd == 1)
	{
		id = ipv4_get_id(ip);
		memcpy(&dest[counter], &id, 2);
		rohc_debugf(3, "outer IP-ID = 0x%04x\n", id);
		counter += 2;
	}

	/* parts 7 and 8 are not supported */

	/* step 9: only IPv4 */
	if(nr_of_ip_hdr > 1 && ip_get_version(ip2) == IPV4 &&
	   g_context->ip2_flags.info.v4.rnd == 1)
	{
		id = ipv4_get_id(ip2);
		memcpy(&dest[counter], &id, 2);
		rohc_debugf(3, "inner IP-ID = 0x%04x\n", id);
		counter += 2;
	}
	
	/* parts 10, 11 and 12 are not supported */

	/* part 13 */
	/* add fields related to the next header */
	if(g_context->code_UO_packet_tail != NULL && next_header != NULL)
		counter = g_context->code_UO_packet_tail(context, next_header,
		                                         dest, counter);

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
 * @param context        The compression context
 * @param ip             The outer IP header
 * @param ip2            The inner IP header
 * @param next_header    The next header such as UDP or UDP-Lite
 * @param dest           The rohc-packet-under-build buffer
 * @return               The position in the rohc-packet-under-build buffer 
 *                       if successful, -1 otherwise
 */
int code_UO0_packet(struct c_context *context,
                    const struct ip_packet ip,
                    const struct ip_packet ip2,
                    const unsigned char *next_header,
                    unsigned char *dest)
{
	int counter;
	int first_position;
	unsigned char f_byte;
	struct c_generic_context *g_context;
	int nr_of_ip_hdr;

	g_context = (struct c_generic_context *) context->specific;
	nr_of_ip_hdr = g_context->tmp_variables.nr_of_ip_hdr;

	rohc_debugf(2, "code UO-0 packet (CID = %d)\n", context->cid);

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - part 4 will start at 'counter'
	 */
	counter = code_cid_values(context, dest, g_context->tmp_variables.max_size,
	                          &first_position);

	/* build the UO head if necessary */
	if(g_context->code_UO_packet_head != NULL && next_header != NULL)
		counter = g_context->code_UO_packet_head(context, next_header,
		                                         dest, counter, &first_position);

	/* part 2 */
	f_byte = (g_context->sn & 0x0f) << 3;
	f_byte |= crc_calculate(CRC_TYPE_3, ip_get_raw_data(ip), ip_get_hdrlen(ip) +
	                        (nr_of_ip_hdr > 1  ? ip_get_hdrlen(ip2) : 0) +
	                        g_context->next_header_len);
	rohc_debugf(2, "F byte = 0x%02x (CRC = 0x%x on %d bytes)\n", f_byte,
	            f_byte & 0x07, ip_get_hdrlen(ip) + (nr_of_ip_hdr > 1  ?
	            ip_get_hdrlen(ip2) : 0) + g_context->next_header_len);

	dest[first_position] = f_byte;

	/* build the UO tail */
	counter = code_UO_packet_tail(context, ip, ip2, next_header, dest, counter);

	return counter;
}


/**
 * @brief Build the UO-1 packet.
 *
 * UO-1 and UO-1-ID cannot be used if there is no IPv4 header in the context or
 * if value(RND) and value(RND2) are both 1.
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
 4  | M |      SN       |    CRC    |
    +---+---+---+---+---+---+---+---+

 UO-1-TS (5.7.3):

      0   1   2   3   4   5   6   7
    +---+---+---+---+---+---+---+---+
 2  | 1   0 |T=1|        TS         |
    +===+===+===+===+===+===+===+===+
 4  | M |      SN       |    CRC    |
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * @param context        The compression context
 * @param ip             The outer IP header
 * @param ip2            The inner IP header
 * @param next_header    The next header such as UDP or UDP-Lite
 * @param dest           The rohc-packet-under-build buffer
 * @return               The position in the rohc-packet-under-build buffer 
 *                       if successful, -1 otherwise
 */
int code_UO1_packet(struct c_context *context,
                    const struct ip_packet ip,
                    const struct ip_packet ip2,
                    const unsigned char *next_header,
                    unsigned char *dest)
{
	int counter;
	int first_position;
	unsigned char f_byte;
	unsigned char s_byte;
	struct c_generic_context *g_context;
	int nr_of_ip_hdr;
	int packet_type;
	int is_ip_v4;
	int is_rtp;
	struct sc_rtp_context *rtp_context;
	int crc;

	g_context = (struct c_generic_context *) context->specific;
	nr_of_ip_hdr = g_context->tmp_variables.nr_of_ip_hdr;
	packet_type = g_context->tmp_variables.packet_type;
	is_ip_v4 = g_context->ip_flags.version == IPV4;
	is_rtp = context->profile->id == ROHC_PROFILE_RTP;
	rtp_context = (struct sc_rtp_context *) g_context->specific;

	switch(packet_type)
	{
		case PACKET_UO_1:
			rohc_debugf(2, "code UO-1 packet (CID = %d)\n", context->cid);
			if(!is_ip_v4)
			{
				rohc_debugf(0, "UO-1 packet is for IPv4 only\n");
				goto error;
			}
			else if(is_rtp)
			{
				rohc_debugf(0, "UO-1 packet is for non-RTP profiles\n");
				goto error;
			}
			break;
		case PACKET_UO_1_RTP:
			rohc_debugf(2, "code UO-1-RTP packet (CID = %d)\n", context->cid);
			if(!is_rtp)
			{
				rohc_debugf(0, "UO-1-RTP packet is for RTP profile only\n");
				goto error;
			}
			break;
		case PACKET_UO_1_ID:
			rohc_debugf(2, "code UO-1-ID packet (CID = %d)\n", context->cid);
			if(!is_ip_v4)
			{
				rohc_debugf(0, "UO-1-ID packet is for IPv4 only\n");
				goto error;
			}
			if(!is_rtp)
			{
				rohc_debugf(0, "UO-1-ID packet is for RTP profile only\n");
				goto error;
			}
			break;
		case PACKET_UO_1_TS:
			rohc_debugf(2, "code UO-1-TS packet (CID = %d)\n", context->cid);
			if(!is_rtp)
			{
				rohc_debugf(0, "UO-1-TS packet is for RTP profile only\n");
				goto error;
			}
			break;
		default:
			rohc_debugf(0, "bad packet type (%d)\n", packet_type);
			goto error;
	}

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - part 4 will start at 'counter'
	 */
	counter = code_cid_values(context, dest, g_context->tmp_variables.max_size,
	                          &first_position);

	/* build the UO head if necessary */
	if(g_context->code_UO_packet_head != NULL && next_header != NULL)
		counter = g_context->code_UO_packet_head(context, next_header,
		                                         dest, counter, &first_position);

	/* part 2 */
	switch(packet_type)
	{
		case PACKET_UO_1:
			f_byte = g_context->ip_flags.info.v4.id_delta & 0x3f;
			break;
		case PACKET_UO_1_RTP:
			f_byte = rtp_context->tmp_variables.ts_send & 0x3f;
			break;
		case PACKET_UO_1_ID:
			f_byte = g_context->ip_flags.info.v4.id_delta & 0x1f;
			break;
		case PACKET_UO_1_TS:
			f_byte = rtp_context->tmp_variables.ts_send & 0x1f;
			f_byte |= 0x20;
			break;
		default:
			rohc_debugf(0, "bad packet type (%d)\n", packet_type);
			goto error;
	}
	f_byte |= 0x80;
	dest[first_position] = f_byte;
	rohc_debugf(3, "1 0 + T + TS/IP-ID = 0x%02x\n", f_byte);

	/* part 4 */
	if(!is_rtp)
		s_byte = (g_context->sn & 0x1f) << 3;
	else
	{
		s_byte = (g_context->sn & 0x0f) << 3;
		s_byte |= (rtp_context->tmp_variables.m & 0x01) << 7;
	}
	crc = crc_calculate(CRC_TYPE_3, ip_get_raw_data(ip), ip_get_hdrlen(ip) +
	                    (nr_of_ip_hdr > 1  ? ip_get_hdrlen(ip2) : 0) +
	                    g_context->next_header_len);
	s_byte |= crc & 0x07;
	dest[counter] = s_byte;
	counter++;
	rohc_debugf(3, "M (%d) + SN (%d) + CRC (%x) = 0x%02x\n",
	            rtp_context->tmp_variables.m, g_context->sn, crc, s_byte);

	/* build the UO tail */
	counter = code_UO_packet_tail(context, ip, ip2, next_header, dest, counter);

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

\endverbatim
 *
 * @param context        The compression context
 * @param ip             The outer IP header
 * @param ip2            The inner IP header
 * @param next_header    The next header such as UDP or UDP-Lite
 * @param dest           The rohc-packet-under-build buffer
 * @return               The position in the rohc-packet-under-build buffer 
 *                       if successful, -1 otherwise
 */
int code_UO2_packet(struct c_context *context,
                    const struct ip_packet ip,
                    const struct ip_packet ip2,
                    const unsigned char *next_header,
                    unsigned char *dest)
{
	unsigned char f_byte;     /* part 2 */
	unsigned char s_byte = 0; /* part 4 */
	unsigned char t_byte = 0; /* part 5 */
	int counter;
	int first_position, s_byte_position = 0, t_byte_position;
	int extension;
	struct c_generic_context *g_context;
	int nr_of_ip_hdr;
	int packet_type;
	int is_rtp;
	int (*code_bytes)(struct c_context *context,
	                   int extension,
	                   unsigned char *f_byte,
                      unsigned char *s_byte,
                      unsigned char *t_byte);

	g_context = (struct c_generic_context *) context->specific;
	nr_of_ip_hdr = g_context->tmp_variables.nr_of_ip_hdr;
	is_rtp = context->profile->id == ROHC_PROFILE_RTP;
	packet_type = g_context->tmp_variables.packet_type;

	switch(packet_type)
	{
		case PACKET_UOR_2:
			rohc_debugf(2, "code UOR-2 packet (CID = %d)\n", context->cid);
			code_bytes = code_UOR2_bytes;
			break;
		case PACKET_UOR_2_RTP:
			rohc_debugf(2, "code UOR-2-RTP packet (CID = %d)\n", context->cid);
			code_bytes = code_UOR2_RTP_bytes;
			break;
		case PACKET_UOR_2_ID:
			rohc_debugf(2, "code UOR-2-ID packet (CID = %d)\n", context->cid);
			code_bytes = code_UOR2_ID_bytes;
			break;
		case PACKET_UOR_2_TS:
			rohc_debugf(2, "code UOR-2-TS packet (CID = %d)\n", context->cid);
			code_bytes = code_UOR2_TS_bytes;
			break;
		default:
			rohc_debugf(0, "bad packet type (%d)\n", packet_type);
			goto error;
	}

	/* parts 1 and 3:
	 *  - part 2 will be placed at 'first_position'
	 *  - parts 4/5 will start at 'counter'
	 */
	counter = code_cid_values(context, dest, g_context->tmp_variables.max_size,
	                          &first_position);

	/* build the UO head if necessary */
	if(g_context->code_UO_packet_head != NULL && next_header != NULL)
		counter = g_context->code_UO_packet_head(context, next_header,
		                                         dest, counter, &first_position);

	/* part 2: to be continued, we need to add the 5 bits of SN */
	f_byte = 0xc0; /* 1 1 0 x x x x x */

	/* part 4: remember the position of the second byte for future completion
	 * (RTP only) */
	if(is_rtp)
	{
		s_byte_position = counter;
		counter++;
	}

	/* part 5: partially calculate the third byte, then remember the position
	 * of the third byte, its final value is currently unknown */
	t_byte = crc_calculate(CRC_TYPE_7,
	                       ip_get_raw_data(ip), ip_get_hdrlen(ip) +
	                       (nr_of_ip_hdr > 1  ? ip_get_hdrlen(ip2) : 0) +
	                       g_context->next_header_len);
	t_byte_position = counter;
	counter++;

	/* part 6: decide which extension to use */
	extension = decide_extension(context);

	/* parts 2, 4, 5: complete the three packet-specific bytes and copy them
	 * in packet */
	if(!code_bytes(context, extension, &f_byte, &s_byte, &t_byte))
	{
		rohc_debugf(0, "cannot code some UOR-2-* fields\n");
		goto error;
	}

	dest[first_position] = f_byte;
	rohc_debugf(3, "f_byte = 0x%02x\n", f_byte);
	if(is_rtp)
	{
		dest[s_byte_position] = s_byte;
		rohc_debugf(3, "s_byte = 0x%02x\n", s_byte);
	}
	dest[t_byte_position] = t_byte;
	rohc_debugf(3, "t_byte = 0x%02x\n", t_byte);

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
			rohc_debugf(0, "unknown extension (%d)\n", extension);
			goto error;
	}

	if(counter < 0)
	{
		rohc_debugf(0, "cannot build extension\n");
		goto error;
	}

	/* build the UO tail */
	counter = code_UO_packet_tail(context, ip, ip2, next_header, dest, counter);

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
int code_UOR2_bytes(struct c_context *context,
                    int extension,
                    unsigned char *f_byte,
                    unsigned char *s_byte,
                    unsigned char *t_byte)
{
	struct c_generic_context *g_context;

	g_context = (struct c_generic_context *) context->specific;

	switch(extension)
	{
		case PACKET_NOEXT:
		{
			rohc_debugf(3, "code UOR-2 packet with no extension\n");

			/* part 2: SN bits */
			*f_byte |= g_context->sn & 0x1f;

			/* part 5: set the X bit to 0 */
			*t_byte &= ~0x80;

			break;
		}

		case PACKET_EXT_0:
		{
			rohc_debugf(3, "code UOR-2 packet with extension 0\n");

			/* part 2 */
			*f_byte |= (g_context->sn & 0xff) >> 3;

			/* part 5: set the X bit to 1 */
			*t_byte |= 0x80;

			break;
		}

		case PACKET_EXT_1:
		{
			rohc_debugf(3, "code UOR-2 packet with extension 1\n");

			/* part 2 */
			*f_byte |= (g_context->sn & 0xff) >> 3;

			/* part 5: set the X bit to 1 */
			*t_byte |= 0x80;

			break;
		}

		case PACKET_EXT_2:
		{
			rohc_debugf(3, "code UOR-2 packet with extension 2\n");

			/* part 2 */
			*f_byte |= (g_context->sn & 0xff) >> 3;

			/* part 5: set the X bit to 1 */
			*t_byte |= 0x80;

			break;
		}

		case PACKET_EXT_3:
		{
			int nr_sn_bits;
			nr_sn_bits = g_context->tmp_variables.nr_sn_bits;

			rohc_debugf(3, "code UOR-2 packet with extension 3\n");

			/* part 2: check if the s-field needs to be used */
			if(nr_sn_bits > 5)
				*f_byte |= g_context->sn >> 8;
			else
				*f_byte |= g_context->sn & 0x1f;

			/* part 5: set the X bit to 1 */
			*t_byte |= 0x80;

			break;
		}

		default:
		{
			rohc_debugf(0, "unknown extension (%d)\n", extension);
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
 * @param context      The compression context
 * @param extension    The extension that will be appended to the packet
 * @param f_byte       IN/OUT: The first byte of the UOR-2-RTP packet
 * @param s_byte       IN/OUT: The second byte of the UOR-2-RTP packet
 * @param t_byte       IN/OUT: The third byte of the UOR-2-RTP packet
 * @return             1 if successful, 0 otherwise
 */
int code_UOR2_RTP_bytes(struct c_context *context,
                        int extension,
                        unsigned char *f_byte,
                        unsigned char *s_byte,
                        unsigned char *t_byte)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
	int nr_ts_bits;
	int ts_send;
	int m;

	g_context = (struct c_generic_context *) context->specific;
	rtp_context = (struct sc_rtp_context *) g_context->specific;
	nr_ts_bits = rtp_context->tmp_variables.nr_ts_bits;
	ts_send = rtp_context->tmp_variables.ts_send;
	m = rtp_context->tmp_variables.m;

	switch(extension)
	{
		case PACKET_NOEXT:
		{
			rohc_debugf(3, "code UOR-2-RTP packet with no extension\n");

			/* part 2: 5 bits of 6-bit TS */
			*f_byte |= (ts_send >> 1) & 0x1f;

			/* part 4: last TS bit + M flag + 6 bits of 6-bit SN */
			*s_byte |= (ts_send & 0x01) << 7;
			*s_byte |= (m & 0x01) << 6;
			*s_byte |= g_context->sn & 0x3f;

			/* part 5: set the X bit to 0 */
			*t_byte &= ~0x80;

			break;
		}

		case PACKET_EXT_0:
		{
			rohc_debugf(3, "code UOR-2-RTP packet with extension 0\n");

			/* part 2: 5 bits of 9-bit TS */
			*f_byte |= (ts_send >> 4) & 0x1f;

			/* part 4: 1 more bit of TS + M flag + 6 bits of 9-bit SN */
			*s_byte |= ((ts_send >> 3) & 0x01) << 7;
			*s_byte |= (m & 0x01) << 6;
			*s_byte |= (g_context->sn >> 3) & 0x3f;

			/* part 5: set the X bit to 1 */
			*t_byte |= 0x80;

			break;
		}

		case PACKET_EXT_1:
		{
			rohc_debugf(3, "code UOR-2-RTP packet with extension 1\n");

			/* part 2: 5 bits of 17-bit TS */
			*f_byte |= (ts_send >> 12) & 0x1f;

			/* part 4: 1 more bit of TS + M flag + 6 bits of 9-bit SN */
			*s_byte |= ((ts_send >> 11) & 0x01) << 7;
			*s_byte |= (m & 0x01) << 6;
			*s_byte |= (g_context->sn >> 3) & 0x3f;

			/* part 5: set the X bit to 1 */
			*t_byte |= 0x80;

			break;
		}

		case PACKET_EXT_2:
		{
			rohc_debugf(3, "code UOR-2-RTP packet with extension 2\n");

			/* part 2: 5 bits of 25-bit TS */
			*f_byte |= (ts_send >> 20) & 0x1f;

			/* part 4: 1 more bit of TS + M flag + 6 bits of 9-bit SN */
			*s_byte |= ((ts_send >> 19) & 0x01) << 7;
			*s_byte |= (m & 0x01) << 6;
			*s_byte |= (g_context->sn >> 3) & 0x3f;

			/* part 5: set the X bit to 1 */
			*t_byte |= 0x80;

			break;
		}

		case PACKET_EXT_3:
		{
			int nb_bits_ext3; /* number of bits to send in EXT 3 */
			int nr_sn_bits;
			nr_sn_bits = g_context->tmp_variables.nr_sn_bits;

			rohc_debugf(3, "code UOR-2-RTP packet with extension 3\n");

			/* part 2: 5 bits of TS */
			if(nr_ts_bits <= 6)
				nb_bits_ext3 = 0;
			else if(nr_ts_bits <= 13)
				nb_bits_ext3 = 7;
			else if(nr_ts_bits <= 20)
				nb_bits_ext3 = 14;
			else if(nr_ts_bits <= 27)
				nb_bits_ext3 = 21;
			else
				nb_bits_ext3 = 28;
			*f_byte |= (ts_send >> (nb_bits_ext3 + 1)) & 0x1f;

			/* part 4: 1 more bit of TS + M flag + 6 bits of SN */
			*s_byte |= (ts_send >> nb_bits_ext3 & 0x01) << 7;
			*s_byte |= (m & 0x01) << 6;
			if(nr_sn_bits <= 6)
				*s_byte |= g_context->sn & 0x3f;
			else
				*s_byte |= (g_context->sn >> 8) & 0x3F;

			/* part 5: set the X bit to 1 */
			*t_byte |= 0x80;

			/* compute TS to send in extension 3 */
			rtp_context->tmp_variables.ts_send &= (1 << nb_bits_ext3) - 1;

			break;
		}

		default:
		{
			rohc_debugf(0, "unknown extension (%d)\n", extension);
			goto error;
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
 * @param context      The compression context
 * @param extension    The extension that will be appended to the packet
 * @param f_byte       IN/OUT: The first byte of the UOR-2-TS packet
 * @param s_byte       IN/OUT: The second byte of the UOR-2-TS packet
 * @param t_byte       IN/OUT: The third byte of the UOR-2-TS packet
 * @return             1 if successful, 0 otherwise
 */
int code_UOR2_TS_bytes(struct c_context *context,
                       int extension,
                       unsigned char *f_byte,
                       unsigned char *s_byte,
                       unsigned char *t_byte)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
	int nr_ts_bits;
	int ts_send;
	int m;

	g_context = (struct c_generic_context *) context->specific;
	rtp_context = (struct sc_rtp_context *) g_context->specific;
	nr_ts_bits = rtp_context->tmp_variables.nr_ts_bits;
	ts_send = rtp_context->tmp_variables.ts_send;
	m = rtp_context->tmp_variables.m;

	switch(extension)
	{
		case PACKET_NOEXT:
		{
			rohc_debugf(3, "code UOR-2-TS packet with no extension\n");

			/* part 2: 5 bits of 6-bit TS */
			*f_byte |= ts_send & 0x1f;

			/* part 4: T = 1 + M flag + 6 bits of 6-bit SN */
			*s_byte |= 0x80;
			*s_byte |= (m & 0x01) << 6;
			*s_byte |= g_context->sn & 0x3f;

			/* part 5: set the X bit to 0 */
			*t_byte &= ~0x80;

			break;
		}

		case PACKET_EXT_0:
		{
			rohc_debugf(3," code UOR-2-TS packet with extension 0\n");

			/* part 2: 5 bits of 8-bit TS */
			*f_byte |= (ts_send >> 3) & 0x1f;

			/* part 4: T = 1 + M flag + 6 bits of 9-bit SN */
			*s_byte |= 0x80;
			*s_byte |= (m & 0x01) << 6;
			*s_byte |= (g_context->sn >> 3) & 0x3f;

			/* part 5: set the X bit to 1 */
			*t_byte |= 0x80;

			break;
		}

		case PACKET_EXT_1:
		{
			rohc_debugf(3," code UOR-2-TS packet with extension 1\n");

			/* part 2: 5 bits of 8-bit TS */
			*f_byte |= (ts_send >> 3) & 0x1f;

			/* part 4: T = 1 + M flag + 6 bits of 9-bit SN */
			*s_byte |= 0x80;
			*s_byte |= (m & 0x01) << 6;
			*s_byte |= (g_context->sn >> 3) & 0x3f;

			/* part 5: set the X bit to 1 */
			*t_byte |= 0x80;

			break;
		}

		case PACKET_EXT_2:
		{
			rohc_debugf(3," code UOR-2-TS packet with extension 2\n");

			/* part 2: 5 bits of 16-bit TS */
			*f_byte |= (ts_send >> 11) & 0x1f;

			/* part 4: T = 1 + M flag + 6 bits of 9-bit SN */
			*s_byte |= 0x80;
			*s_byte |= (m & 0x01) << 6;
			*s_byte |= (g_context->sn >> 3) & 0x3f;

			/* part 5: set the X bit to 1 */
			*t_byte |= 0x80;

			break;
		}

		case PACKET_EXT_3:
		{
			int nb_bits_ext3; /* number of bits to send in EXT 3 */
			int nr_sn_bits;
			nr_sn_bits = g_context->tmp_variables.nr_sn_bits;

			rohc_debugf(3," code UOR-2-TS packet with extension 3\n");

			/* part 2: 5 bits of TS */
			if(nr_ts_bits <= 5)
				nb_bits_ext3 = 0;
			else if(nr_ts_bits <= 12)
				nb_bits_ext3 = 7;
			else if(nr_ts_bits <= 19)
				nb_bits_ext3 = 14;
			else if(nr_ts_bits <= 26)
				nb_bits_ext3 = 21;
			else
				nb_bits_ext3 = 28;
			*f_byte |= (ts_send >> nb_bits_ext3) & 0x1f;

			/* part 4: T = 1 + M flag + 6 bits of SN */
			*s_byte |= 0x80;
			*s_byte |= (m & 0x01) << 6;
			if(nr_sn_bits <= 6)
				*s_byte |= g_context->sn & 0x3f;
			else
				*s_byte |= (g_context->sn >> 8) & 0x3f;

			/* part 5: set the X bit to 1 */
			*t_byte |= 0x80;

			/* compute TS to send in extension 3 */
			rtp_context->tmp_variables.ts_send &= (1 << nb_bits_ext3) - 1;

			break;
		}

		default:
		{
			rohc_debugf(0, "unknown extension (%d)\n", extension);
			goto error;
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
 * @param context      The compression context
 * @param extension    The extension that will be appended to the packet
 * @param f_byte       IN/OUT: The first byte of the UOR-2-ID packet
 * @param s_byte       IN/OUT: The second byte of the UOR-2-ID packet
 * @param t_byte       IN/OUT: The third byte of the UOR-2-ID packet
 * @return             1 if successful, 0 otherwise
 */
int code_UOR2_ID_bytes(struct c_context *context,
                       int extension,
                       unsigned char *f_byte,
                       unsigned char *s_byte,
                       unsigned char *t_byte)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
	int nr_ip_id_bits;
	int nr_ts_bits;
	int ts_send;
	int m;

	g_context = (struct c_generic_context *) context->specific;
	nr_ip_id_bits = g_context->tmp_variables.nr_ip_id_bits;
	rtp_context = (struct sc_rtp_context *) g_context->specific;
	nr_ts_bits = rtp_context->tmp_variables.nr_ts_bits;
	ts_send = rtp_context->tmp_variables.ts_send;
	m = rtp_context->tmp_variables.m;

	switch(extension)
	{
		case PACKET_NOEXT:
		{
			rohc_debugf(3, "code UOR-2-ID packet with no extension\n");

			/* part 2: 5 bits of 5-bit IP-ID */
			*f_byte |= g_context->ip_flags.info.v4.id_delta & 0x1f;

			/* part 4: T = 0 + M flag + 6 bits of 6-bit SN */
			*s_byte &= ~0x80;
			*s_byte |= (m & 0x01) << 6;
			*s_byte |= g_context->sn & 0x3f;

			/* part 5: set the X bit to 0 */
			*t_byte &= ~0x80;

			break;
		}

		case PACKET_EXT_0:
		{
			rohc_debugf(3, "code UOR-2-ID packet with extension 0\n");

			/* part 2: 5 bits of 8-bit IP-ID */
			*f_byte |= (g_context->ip_flags.info.v4.id_delta >> 3) & 0x1f;

			/* part 4: T = 0 + M flag + 6 bits of 9-bit SN */
			*s_byte &= ~0x80;
			*s_byte |= (m & 0x01) << 6;
			*s_byte |= (g_context->sn >> 3) & 0x3f;

			/* part 5: set the X bit to 1 */
			*t_byte |= 0x80;

			break;
		}

		case PACKET_EXT_1:
		{
			rohc_debugf(3, "code UOR-2-ID packet with extension 1\n");

			/* part 2: 5 bits of 8-bit IP-ID */
			*f_byte |= (g_context->ip_flags.info.v4.id_delta >> 3) & 0x1f;

			/* part 4: T = 0 + M flag + 6 bits of 9-bit SN */
			*s_byte &= ~0x80;
			*s_byte |= (m & 0x01) << 6;
			*s_byte |= (g_context->sn >> 3) & 0x3f;

			/* part 5: set the X bit to 1 */
			*t_byte |= 0x80;

			break;
		}

		case PACKET_EXT_2:
		{
			rohc_debugf(3, "code UOR-2-ID packet with extension 2\n");

			/* part 2: 5 bits of 16-bit IP-ID */
			*f_byte |= (g_context->ip_flags.info.v4.id_delta >> 11) & 0x1f;

			/* part 4: T = 0 + M flag + 6 bits of 9-bit SN */
			*s_byte &= ~0x80;
			*s_byte |= (m & 0x01) << 6;
			*s_byte |= (g_context->sn >> 3) & 0x3f;

			/* part 5: set the X bit to 1 */
			*t_byte |= 0x80;

			break;
		}

		case PACKET_EXT_3:
		{
			int nb_bits_ext3; /* number of bits to send in EXT 3 */
			int nr_sn_bits;
			nr_sn_bits = g_context->tmp_variables.nr_sn_bits;

			rohc_debugf(3, "code UOR-2-ID packet with extension 3\n");

			/* part 2: 5 bits of IP-ID */
			if(nr_ip_id_bits <= 5)
				*f_byte |= g_context->ip_flags.info.v4.id_delta & 0x1f;
			else if(nr_ts_bits <= 13)
				*f_byte |= (g_context->ip_flags.info.v4.id_delta >> 8) & 0x1f;
			else
				*f_byte |= 0;

			/* part 4: T = 0 + M flag + 6 bits of SN */
			*s_byte &= ~0x80;
			*s_byte |= (m << 6) & 0x40;
			if(nr_ts_bits > 0 && !is_deductible(rtp_context->ts_sc))
			{
				if(nr_ts_bits <= 7)
					nb_bits_ext3 = 7;
				else if(nr_ts_bits <= 14)
					nb_bits_ext3 = 14;
				else if(nr_ts_bits <= 21)
					nb_bits_ext3 = 21;
				else
					nb_bits_ext3 = 28;
			}
			else
				nb_bits_ext3 = 0;
			if(nr_sn_bits <= 6)
				*s_byte |= g_context->sn & 0x3f;
			else
				*s_byte |= (g_context->sn >> 8) & 0x3f;

			/* part 5: set the X bit to 1 */
			*t_byte |= 0x80;

			/* compute TS to send in extension 3 */
			rtp_context->tmp_variables.ts_send &= (1 << nb_bits_ext3) - 1;

			break;
		}

		default:
		{
			rohc_debugf(0, "unknown extension (%d)\n", extension);
			goto error;
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
 * @param context    The compression context
 * @param dest       The rohc-packet-under-build buffer
 * @param counter    The current position in the rohc-packet-under-build buffer
 * @return           The new position in the rohc-packet-under-build buffer 
 *                   if successful, -1 otherwise
 */
int code_EXT0_packet(struct c_context *context,
                     unsigned char *dest,
                     int counter)
{
	struct c_generic_context *g_context;
	unsigned char f_byte;
	int packet_type;

	g_context = (struct c_generic_context *) context->specific;
	packet_type = g_context->tmp_variables.packet_type;

	/* part 1: extension type + SN */
	f_byte = 0;
	f_byte = (g_context->sn & 0x07) << 3;

	/* part 1: IP-ID or TS ? */
	switch(packet_type)
	{
		case PACKET_UOR_2_RTP:
		case PACKET_UOR_2_TS:
		{
			struct sc_rtp_context *rtp_context = g_context->specific;
			int ts_send = rtp_context->tmp_variables.ts_send;

			f_byte |= ts_send & 0x07;
			break;
		}

		case PACKET_UOR_2_ID:
		case PACKET_UOR_2:
		{
			if(g_context->ip_flags.version != IPV4)
			{
				rohc_debugf(0, "extension 0 for UOR-2 or UOR-2-ID is "
				               "for IPv4 only\n");
				goto error;
			}

			f_byte |= g_context->ip_flags.info.v4.id_delta & 0x07;
			break;
		}

		default:
			rohc_debugf(0, "bad packet type (%d)\n", packet_type);
			goto error;
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
 * @param context    The compression context
 * @param dest       The rohc-packet-under-build buffer
 * @param counter    The current position in the rohc-packet-under-build buffer
 * @return           The new position in the rohc-packet-under-build buffer 
 *                   if successful, -1 otherwise
 */
int code_EXT1_packet(struct c_context *context,
                     unsigned char *dest,
                     int counter)
{
	struct c_generic_context *g_context;
	int packet_type;
	unsigned char f_byte;
	unsigned char s_byte;

	g_context = (struct c_generic_context *) context->specific;
	packet_type = g_context->tmp_variables.packet_type;

	/* part 1: extension type + SN */
	f_byte = (g_context->sn & 0x07) << 3;
	f_byte |= 0x40;

	/* parts 1 & 2: IP-ID or TS ? */
	switch(packet_type)
	{
		case PACKET_UOR_2:
		{
			if(g_context->ip_flags.version != IPV4)
			{
				rohc_debugf(0, "extension 1 for UOR-2 is for IPv4 only\n");
				goto error;
			}

			f_byte |= (g_context->ip_flags.info.v4.id_delta >> 8) & 0x07;
			s_byte = g_context->ip_flags.info.v4.id_delta & 0xff;
			break;
		}

		case PACKET_UOR_2_RTP:
		{
			struct sc_rtp_context *rtp_context = g_context->specific;
			int ts_send = rtp_context->tmp_variables.ts_send;

			f_byte |= (ts_send >> 8) &  0x07;
			s_byte = ts_send & 0xff;
			break;
		}

		case PACKET_UOR_2_TS:
		{
			struct sc_rtp_context *rtp_context = g_context->specific;
			int ts_send = rtp_context->tmp_variables.ts_send;

			if(g_context->ip_flags.version != IPV4)
			{
				rohc_debugf(0, "extension 1 for UOR-2-TS is for IPv4 only\n");
				goto error;
			}

			f_byte |= ts_send & 0x07;
			s_byte = g_context->ip_flags.info.v4.id_delta & 0xff;
			break;
		}

		case PACKET_UOR_2_ID:
		{
			struct sc_rtp_context *rtp_context = g_context->specific;
			int ts_send = rtp_context->tmp_variables.ts_send;

			if(g_context->ip_flags.version != IPV4)
			{
				rohc_debugf(0, "extension 1 for UOR-2-ID is for IPv4 only\n");
				goto error;
			}

			f_byte |= g_context->ip_flags.info.v4.id_delta & 0x07;
			s_byte = ts_send & 0xff;
			break;
		}

		default:
			rohc_debugf(0, "bad packet type (%d)\n", packet_type);
			goto error;
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
 * @param context    The compression context
 * @param dest       The rohc-packet-under-build buffer
 * @param counter    The current position in the rohc-packet-under-build buffer
 * @return           The new position in the rohc-packet-under-build buffer 
 *                   if successful, -1 otherwise
 */
int code_EXT2_packet(struct c_context *context,
                     unsigned char *dest,
                     int counter)
{
	struct c_generic_context *g_context;
	int packet_type;
	unsigned char f_byte;
	unsigned char s_byte;
	unsigned char t_byte;

	g_context = (struct c_generic_context *) context->specific;
	packet_type = g_context->tmp_variables.packet_type;

	/* part 1: extension type + SN */
	f_byte = (g_context->sn & 0x07) << 3;
	f_byte |= 0x80;

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

			if(g_context->ip_flags.version != IPV4 ||
			   g_context->ip2_flags.version != IPV4)
			{
				rohc_debugf(0, "extension 2 for UOR-2 is for IPv4 only\n");
				goto error;
			}

			f_byte |= (g_context->ip_flags.info.v4.id_delta >> 8) & 0x07;
			s_byte = g_context->ip_flags.info.v4.id_delta & 0xff;
			t_byte = g_context->ip2_flags.info.v4.id_delta & 0xff;
			break;
		}

		case PACKET_UOR_2_RTP:
		{
			struct sc_rtp_context *rtp_context = g_context->specific;
			int ts_send = rtp_context->tmp_variables.ts_send;

			f_byte |= (ts_send >> 16) &  0x07;
			s_byte = (ts_send >> 8) & 0xff;
			t_byte = ts_send && 0xff;
			break;
		}

		case PACKET_UOR_2_TS:
		{
			struct sc_rtp_context *rtp_context = g_context->specific;
			int ts_send = rtp_context->tmp_variables.ts_send;

			if(g_context->ip_flags.version != IPV4)
			{
				rohc_debugf(0, "extension 2 for UOR-2-TS is for IPv4 only\n");
				goto error;
			}

			f_byte |= g_context->ip_flags.info.v4.id_delta & 0x07;
			f_byte |= (ts_send >> 8) & 0x07;
			s_byte = ts_send & 0xff;
			t_byte = g_context->ip_flags.info.v4.id_delta & 0xff;
			break;
		}

		case PACKET_UOR_2_ID:
		{
			struct sc_rtp_context *rtp_context = g_context->specific;
			int ts_send = rtp_context->tmp_variables.ts_send;

			if(g_context->ip_flags.version != IPV4)
			{
				rohc_debugf(0, "extension 2 for UOR-2-ID is for IPv4 only\n");
				goto error;
			}

			f_byte |= (g_context->ip_flags.info.v4.id_delta >> 8) & 0x07;
			s_byte = g_context->ip_flags.info.v4.id_delta & 0xff;
			t_byte = ts_send & 0xff;
			break;
		}

		default:
			rohc_debugf(0, "bad packet type (%d)\n", packet_type);
			goto error;
	}

	/* write parts 1, 2 & 3 in the packet */
	dest[counter] = f_byte;
	counter++;
	dest[counter] = s_byte;
	counter++;
	dest[counter] = t_byte;
	counter++;

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
 3  |            Outer IP header flags              |
    +-----+-----+-----+-----+-----+-----+-----+-----+
 4  |                      SN                       |  if S = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
    |                                               |
 5  /            Inner IP header fields             /  variable,
    |                                               |
    +-----+-----+-----+-----+-----+-----+-----+-----+
 6  |                     IP-ID                     |  2 octets, if I = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
    |                                               |
 7  /            Outer IP header fields             /  variable,
    |                                               |
    +-----+-----+-----+-----+-----+-----+-----+-----+

 Extension 3 for RTP profile (5.7.5):

       0     1     2     3     4     5     6     7
    +-----+-----+-----+-----+-----+-----+-----+-----+
 1  |  1     1  |  S  |R-TS | Tsc |  I  | ip  | rtp |
    +-----+-----+-----+-----+-----+-----+-----+-----+
 2  |            Inner IP header flags        | ip2 |  if ip = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+
 3  |            Outer IP header flags              |
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
 * @param context    The compression context
 * @param ip         The outer IP header
 * @param ip2        The inner IP header
 * @param dest       The rohc-packet-under-build buffer
 * @param counter    The current position in the rohc-packet-under-build buffer
 * @return           The new position in the rohc-packet-under-build buffer
 *                   if successful, -1 otherwise
 */
int code_EXT3_packet(struct c_context *context,
                     const struct ip_packet ip,
                     const struct ip_packet ip2,
                     unsigned char *dest,
                     int counter)
{
	struct c_generic_context *g_context;
	unsigned char f_byte;
	int nr_of_ip_hdr;
	int nr_sn_bits;
	unsigned short changed_f, changed_f2;
	int nr_ip_id_bits, nr_ip_id_bits2;
	boolean have_inner = 0;
	boolean have_outer = 0;
	unsigned int id;
	int is_rtp;
	int rtp = 0;     /* RTP bit */
	int rts = 0;     /* R-TS bit */
	int ts_send = 0; /* TS to send */
	int packet_type;

	g_context = (struct c_generic_context *) context->specific;
	nr_of_ip_hdr = g_context->tmp_variables.nr_of_ip_hdr;
	nr_sn_bits = g_context->tmp_variables.nr_sn_bits;
	changed_f = g_context->tmp_variables.changed_fields;
	changed_f2 = g_context->tmp_variables.changed_fields2;
	nr_ip_id_bits = g_context->tmp_variables.nr_ip_id_bits;
	nr_ip_id_bits2 = g_context->tmp_variables.nr_ip_id_bits2;
	is_rtp = context->profile->id == ROHC_PROFILE_RTP;
	packet_type = g_context->tmp_variables.packet_type;

	/* part 1: extension type + S bit */
	f_byte = 0xc0;
	if(nr_sn_bits > 5)
		f_byte |= 0x20;

	/* part 1: R-TS, Tsc & RTP bits if RTP
	 *         Mode bits otherwise */
	if(is_rtp)
	{
		struct sc_rtp_context *rtp_context;
		int nr_ts_bits; /* nb of TS bits needed */
		int tsc; /* Tsc bit */

		rtp_context = (struct sc_rtp_context *) g_context->specific;
		nr_ts_bits = rtp_context->tmp_variables.nr_ts_bits;
		ts_send = rtp_context->tmp_variables.ts_send;

		/* R-TS bit */
		switch(packet_type)
		{
			case PACKET_UOR_2_RTP:
				rts = nr_ts_bits > 6;
				break;
			case PACKET_UOR_2_TS:
				rts = nr_ts_bits > 5;
				break;
			case PACKET_UOR_2_ID:
				rts = nr_ts_bits > 0 && !is_deductible(rtp_context->ts_sc);
				break;
			default:
				rohc_debugf(0, "bad packet type (%d)\n", packet_type);
				goto error;
		}
		f_byte |= (rts & 0x01) << 4;

		/* Tsc bit */
		tsc = rtp_context->ts_sc.state == SEND_SCALED &&
		      !(packet_type == PACKET_UOR_2_ID && is_deductible(rtp_context->ts_sc));
		f_byte |= (tsc & 0x01) << 3;

		/* rtp bit */
		if(nr_of_ip_hdr == 1)
			rtp = is_changed(changed_f, MOD_RTP_PT);
		else
			rtp = is_changed(changed_f2, MOD_RTP_PT);
		rtp = rtp || (rtp_context->ts_sc.state == INIT_STRIDE && !is_ts_constant(rtp_context->ts_sc));
		f_byte |= rtp & 0x01;

		rohc_debugf(3, "R-TS = %d, Tsc = %d, rtp = %d\n", rts, tsc, rtp);
	}
	else /* non-RTP profiles */
	{
		f_byte |= (context->mode & 0x3) << 3;
	}

	/* if random bit is set we have the IP-ID field outside this function */
	if(ip_get_version(ip) == IPV4)
		rohc_debugf(1, "rnd_count_up: %d \n", g_context->ip_flags.info.v4.rnd_count);

	if(nr_of_ip_hdr == 1)
	{
		/* if the innermost IP header is IPv4, check if the I bit must be set,
		 * otherwise I is always set to 0 */
		if(ip_get_version(ip) == IPV4)
		{
			if((nr_ip_id_bits > 0 && g_context->ip_flags.info.v4.rnd == 0) ||
			   (g_context->ip_flags.info.v4.rnd_count < MAX_FO_COUNT &&
			    g_context->ip_flags.info.v4.rnd == 0))
				f_byte |= 0x04;
		}

		/* ip bit */
		rohc_debugf(3, "check for changed fields in the inner IP header\n");
		if(changed_dynamic_one_hdr(changed_f & 0x01FF, &g_context->ip_flags, ip, context) ||
		   changed_static_one_hdr(changed_f, &g_context->ip_flags, ip, context))
		{
			have_inner = 1;
			f_byte |= 0x02;
		}
	}
	else /* double IP headers */
	{
		/* if the innermost IP header is IPv4, check if the I bit must be set,
		 * otherwise I is always set to 0 */
		if(ip_get_version(ip2) == IPV4)
		{
			if((nr_ip_id_bits2 > 0 && g_context->ip2_flags.info.v4.rnd == 0) ||
			   (g_context->ip2_flags.info.v4.rnd_count < MAX_FO_COUNT &&
			    g_context->ip2_flags.info.v4.rnd == 0))
				f_byte |= 0x04;
		}

		/* ip2 bit if non-RTP */
		if(!is_rtp)
		{
			rohc_debugf(3, "check for changed fields in the outer IP header\n");
			if(changed_dynamic_one_hdr(changed_f, &g_context->ip_flags, ip, context) ||
			   changed_static_one_hdr(changed_f, &g_context->ip_flags, ip, context))
			{
				have_outer = 1;
				f_byte |= 0x01;
			}
		}

		/* ip bit */
		rohc_debugf(3, "check for changed fields in the inner IP header\n");
		if(changed_dynamic_one_hdr(changed_f2, &g_context->ip2_flags, ip2, context) ||
		   changed_static_one_hdr(changed_f2, &g_context->ip2_flags, ip2, context))
		{
			have_inner = 1;
			f_byte = f_byte | 0x02;
		}
	}

	rohc_debugf(3, "part 1 = 0x%02x\n", f_byte);
	dest[counter] = f_byte;
	counter++;

	if(nr_of_ip_hdr == 1)
	{
		/* part 2 */
		if(have_inner)
			counter = header_flags(context, &g_context->ip_flags, changed_f, ip,
			                       0, nr_ip_id_bits, dest, counter);

		/* part 3: only one IP header */

		/* part 4 */
		if(nr_sn_bits > 5)
		{
			dest[counter] = g_context->sn & 0xff;
			rohc_debugf(3, "SN = 0x%02x\n", dest[counter]);
			counter++;
		}

		/* part 4.1 */
		if(is_rtp && rts)
		{
			rohc_debugf(3, "ts_send = %u (0x%x) on %d bytes\n",
			            ts_send, ts_send, c_bytesSdvl(ts_send));
			if(!c_encodeSdvl(&dest[counter], ts_send))
			{
				rohc_debugf(0, "ts_send greater than 2^29 (%d)\n", ts_send);
				goto error;
			}
			counter += c_bytesSdvl(ts_send);
		}

		/* part 5 */
		if(have_inner)
			counter = header_fields(context, &g_context->ip_flags, changed_f, ip,
			                        0, nr_ip_id_bits, dest, counter);

		/* part 6 */
		if(ip_get_version(ip) == IPV4)
		{
			if((nr_ip_id_bits > 0 && g_context->ip_flags.info.v4.rnd == 0) ||
			   (g_context->ip_flags.info.v4.rnd_count-1 < MAX_FO_COUNT &&
			    g_context->ip_flags.info.v4.rnd == 0))
			{
				id = ipv4_get_id(ip);
				memcpy(&dest[counter], &id, 2);
				rohc_debugf(3, "IP ID = 0x%02x 0x%02x\n",
				            dest[counter], dest[counter + 1]);
				counter += 2;
			}
		}

		/* part 7: only one IP header */

		/* part 8 */
		if(is_rtp && rtp)
		{
			counter = rtp_header_flags_and_fields(context, changed_f, ip,
			                                      dest, counter);
			if(counter < 0)
				goto error;
		}
	}
	else /* double IP headers */
	{
		/* part 2 */
		if(have_inner)
		{
			counter = header_flags(context, &g_context->ip2_flags, changed_f2, ip2,
			                       0, nr_ip_id_bits2, dest, counter);

			/* add ip2 flag in inner IP header flags if needed */
			if(is_rtp && have_outer)
				dest[counter - 1] |= 0x01;
		}

		/* part 3 */
		if(have_outer)
			counter = header_flags(context, &g_context->ip_flags, changed_f, ip,
			                       1, nr_ip_id_bits, dest, counter);

		/* part 4 */
		if(nr_sn_bits > 5)
		{
			dest[counter] = g_context->sn & 0xff;
			counter++;
		}

		/* part 4.1 */
		if(is_rtp && rts)
		{
			rohc_debugf(3, "ts_send = %u (0x%x) on %d bytes\n",
			            ts_send, ts_send, c_bytesSdvl(ts_send));
			if(!c_encodeSdvl(&dest[counter], ts_send))
			{
				rohc_debugf(0, "ts_send greater than 2^29 (%d)\n", ts_send);
				goto error;
			}
			counter += c_bytesSdvl(ts_send);
		}

		/* part 5 */
		if(have_inner)
			counter = header_fields(context, &g_context->ip2_flags, changed_f2, ip2,
			                        0, nr_ip_id_bits2, dest, counter);

		/* part 6 */
		if(ip_get_version(ip2) == IPV4)
		{
			if((nr_ip_id_bits2 > 0 && g_context->ip2_flags.info.v4.rnd == 0) ||
			   (g_context->ip2_flags.info.v4.rnd_count-1 < MAX_FO_COUNT &&
			    g_context->ip2_flags.info.v4.rnd == 0))
			{
				id = ipv4_get_id(ip2);
				memcpy(&dest[counter], &id, 2);
				rohc_debugf(3, "IP ID = 0x%02x 0x%02x\n",
				            dest[counter], dest[counter + 1]);
				counter += 2;
			}
		}

		/* part 7 */
		if(have_outer)
			counter = header_fields(context, &g_context->ip_flags, changed_f, ip,
			                        1, nr_ip_id_bits, dest, counter);

		/* part 8 */
		if(is_rtp && rtp)
		{
			counter = rtp_header_flags_and_fields(context, changed_f2, ip2,
			                                      dest, counter);
			if(counter < 0)
				goto error;
		}
	}

	/* no IP extension until list compression */

	return counter;

error:
	return -1;
}


/**
 * @brief Check if a specified IP field has changed.
 *
 * @param changed_fields The fields that changed, created by the function
 *                       changed_fields
 * @param check_field    The field for which to check a change
 * @return               Whether the field changed or not
 *
 * @see changed_fields 
 */
boolean is_changed(unsigned short changed_fields, unsigned short check_field)
{
	return (changed_fields & check_field);
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
int rtp_header_flags_and_fields(struct c_context *context,
                                unsigned short changed_f,
                                const struct ip_packet ip,
                                unsigned char *dest,
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
	udp = (struct udphdr *) ip_get_next_header(ip);
	rtp = (struct rtphdr *) (udp + 1);

	/* part 1 */
	rpt = is_changed(changed_f, MOD_RTP_PT);
	tss = rtp_context->ts_sc.state == INIT_STRIDE;
	byte = 0;
	byte |= (context->mode & 0x03) << 6;
	byte |= (rpt & 0x01) << 5;
	byte |= (rtp->m & 0x01) << 4;
	byte |= (rtp->extension & 0x01) << 3;
	byte |= (tss & 0x01) << 1;
	rohc_debugf(3, "RTP flags = 0x%x\n", byte);
	dest[counter] = byte;
	counter++;

	/* part 2 */
	if(rpt)
	{
		byte = 0;
		byte |= (rtp->padding & 0x01) << 7;
		byte |= rtp->pt & 0x7f;
		rohc_debugf(3, "part 2 = 0x%x\n", byte);
		dest[counter] = byte;
		counter++;
	}

	/* part 3: not supported yet */

	/* part 4 */
	if(tss)
	{
		int ts_stride, nb_bits;
		int success;

		ts_stride = get_ts_stride(rtp_context->ts_sc);
		nb_bits = nb_bits_stride(rtp_context->ts_sc);

		success = c_encodeSdvl(&dest[counter], ts_stride);
		if(!success)
		{
			rohc_debugf(0, "ts_stride greater than 2^29 (%d)\n", ts_stride);
			goto error;
		}
		counter += c_bytesSdvl(ts_stride);

		rohc_debugf(3, "ts_stride %u (0x%x) needs %d bit(s)\n",
		            ts_stride, ts_stride, nb_bits);
		rohc_debugf(3, "ts_stride coded on %d bytes\n",
		            c_bytesSdvl(ts_stride));

		add_stride(&rtp_context->ts_sc, ntohs(rtp->sn));
		if(rtp_context->ts_sc.state == INIT_STRIDE)
			rtp_context->ts_sc.state = SEND_SCALED;
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
    | TOS | TTL | DF  | PR  | IPX | NBO | RND | 0** |  0** reserved
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
 * @param is_outer       Whether the IP header is the outer header or not
 * @param nr_ip_id_bits  The number of bits needed to transmit the IP-ID field
 * @param dest           The rohc-packet-under-build buffer
 * @param counter        The current position in the rohc-packet-under-build
 *                       buffer
 * @return               The new position in the rohc-packet-under-build buffer 
 *
 * @see changed_fields
 */
int header_flags(struct c_context *context,
                 struct ip_header_info *header_info,
                 unsigned short changed_f,
                 const struct ip_packet ip,
                 boolean is_outer,
                 int nr_ip_id_bits,
                 unsigned char *dest,
                 int counter)
{
	int flags = 0;

	/* for inner and outer flags (1 & 2) */
	if(is_changed(changed_f, MOD_TOS) || header_info->tos_count < MAX_FO_COUNT)
		flags |= 0x80;
	if(is_changed(changed_f, MOD_TTL) || header_info->ttl_count < MAX_FO_COUNT)
		flags |= 0x40;
	if(is_changed(changed_f, MOD_PROTOCOL) || header_info->protocol_count < MAX_FO_COUNT)
		flags |= 0x10;

	/* DF, NBO, RND and I2 are IPv4 specific flags,
	 * there are always set to 0 for IPv6 */
	if(header_info->version == IPV4)
	{
		int df;

		df = ipv4_get_df(ip);
		rohc_debugf(1, "DF = %d\n", df);
		header_info->info.v4.df_count++;
		flags |= df << 5;

		header_info->info.v4.nbo_count++;
		flags |= header_info->info.v4.nbo << 2;

		header_info->info.v4.rnd_count++;
		flags |= header_info->info.v4.rnd << 1;

		/* only for outer flags (only 2) */
		if(is_outer)
		{
			if((nr_ip_id_bits > 0 && header_info->info.v4.rnd == 0) ||
			   (header_info->info.v4.rnd_count-1 < MAX_FO_COUNT &&
			    header_info->info.v4.rnd == 0))
				flags |= 0x01;
		}
	}

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
 
    IP-ID is coded here for outer header fields although it doesn't look that
    way in the extension 3 picture in 5.7.5 and 5.11.4 of RFC 3095.
    +-----+-----+-----+-----+-----+-----+-----+-----+
 5  |                  IP-ID                        |  2 octets, if I = 1
    +-----+-----+-----+-----+-----+-----+-----+-----+

\endverbatim
 *
 * Part 4 is not supported.
 *
 * @param context        The compression context
 * @param header_info    The header info stored in the profile
 * @param changed_f      The fields that changed, created by the function
 *                       changed_fields
 * @param ip             One inner or outer IP header
 * @param is_outer       Whether the IP header is the outer header or not
 * @param nr_ip_id_bits  The number of bits needed to transmit the IP-ID field
 * @param dest           The rohc-packet-under-build buffer
 * @param counter        The current position in the rohc-packet-under-build
 *                       buffer
 * @return               The new position in the rohc-packet-under-build buffer 
 *
 * @see changed_fields
 */
int header_fields(struct c_context *context,
                  struct ip_header_info *header_info,
                  unsigned short changed_f,
                  const struct ip_packet ip,
                  boolean is_outer,
                  int nr_ip_id_bits,
                  unsigned char *dest,
                  int counter)
{
	unsigned int tos, ttl, protocol, id;

	/* part 1 */
	if(is_changed(changed_f, MOD_TOS) || header_info->tos_count < MAX_FO_COUNT)
	{
		tos = ip_get_tos(ip);
		rohc_debugf(3, "(outer = %d) IP TOS/TC = 0x%02x\n", is_outer, tos);
		header_info->tos_count++;
		dest[counter] = tos;
		counter++;
	}

	/* part 2 */
	if(is_changed(changed_f, MOD_TTL) || header_info->ttl_count < MAX_FO_COUNT)
	{
		ttl = ip_get_ttl(ip);
		rohc_debugf(3, "(outer = %d) IP TTL/HL = 0x%02x\n", is_outer, ttl);
		header_info->ttl_count++;
		dest[counter] = ttl;
		counter++;
	}

	/* part 3 */
	if(is_changed(changed_f, MOD_PROTOCOL) || header_info->protocol_count < MAX_FO_COUNT)
	{
		protocol = ip_get_protocol(ip);
		rohc_debugf(3, "(outer = %d) IP Protocol/Next Header = 0x%02x\n",
		            is_outer, protocol);
		header_info->protocol_count++;
		dest[counter] = protocol;
		counter++;
	}

	/* part 5: only if IPv4 */
	if(is_outer && header_info->version == IPV4)
	{
		if((nr_ip_id_bits > 0 && header_info->info.v4.rnd == 0) ||
		   (header_info->info.v4.rnd_count - 1 < MAX_FO_COUNT &&
		    header_info->info.v4.rnd == 0))
		{
			id = ipv4_get_id(ip);
			memcpy(&dest[counter], &id, 2);
			rohc_debugf(3, "(outer = %d) IP ID = 0x%02x 0x%02x\n", is_outer,
			            dest[counter], dest[counter + 1]);
			counter += 2;
		}
	}

	return counter;
}


/**
 * @brief Decide what extension shall be used in the UO-2 packet.
 * 
 * Extentions 0, 1 & 2 are IPv4 only because of the IP-ID.
 *
 * @param context The compression context
 * @return        The extension code among PACKET_NOEXT, PACKET_EXT_0,
 *                PACKET_EXT_1 and PACKET_EXT_3 if successful, -1 otherwise
 */
int decide_extension(struct c_context *context)
{
	struct c_generic_context *g_context;
	int send_static;
	int send_dynamic;
	int nr_ip_id_bits;
	int nr_ip_id_bits2;
	int nr_sn_bits;
	int ext;
	int is_rtp;
	int packet_type;
	
	g_context = (struct c_generic_context *) context->specific;
	send_static = g_context->tmp_variables.send_static;
	send_dynamic = g_context->tmp_variables.send_dynamic;
	nr_ip_id_bits = g_context->tmp_variables.nr_ip_id_bits;
	nr_ip_id_bits2 = g_context->tmp_variables.nr_ip_id_bits2;
	nr_sn_bits = g_context->tmp_variables.nr_sn_bits;
	is_rtp = context->profile->id == ROHC_PROFILE_RTP;
	packet_type = g_context->tmp_variables.packet_type;

	ext = PACKET_EXT_3; /* default extension */

	if (send_static > 0 || send_dynamic > 0 )
		return ext;

	switch(packet_type)
	{
		case PACKET_UOR_2:
		{
			int is_ip_v4, is_rnd;

			is_ip_v4 = g_context->ip_flags.version == IPV4;
			is_rnd = g_context->ip_flags.info.v4.rnd;

			if(g_context->tmp_variables.nr_of_ip_hdr == 1)
			{
				if(nr_sn_bits < 5 &&
				   (!is_ip_v4 || (is_ip_v4 && (nr_ip_id_bits == 0 || is_rnd == 1))))
					ext = PACKET_NOEXT;
				else if(nr_sn_bits <= 8 && (is_ip_v4 && nr_ip_id_bits <= 3))
					ext = PACKET_EXT_0;
				else if(nr_sn_bits <= 8 && (is_ip_v4 && nr_ip_id_bits <= 11))
					ext = PACKET_EXT_1;
			}
			else /* double IP headers */
			{
				int is_ip2_v4, is_rnd2;

				is_ip2_v4 = g_context->ip2_flags.version == IPV4;
				is_rnd2 = g_context->ip2_flags.info.v4.rnd;

				if(nr_sn_bits < 5 &&
				   (!is_ip_v4 || (is_ip_v4 && (nr_ip_id_bits == 0 || is_rnd == 1))) &&
				   (!is_ip2_v4 || (is_ip2_v4 && (nr_ip_id_bits2 == 0 || is_rnd2 == 1))))
					ext = PACKET_NOEXT;
				else if(nr_sn_bits <= 8 &&
				        (is_ip_v4 && nr_ip_id_bits <= 3) &&
				        (!is_ip2_v4 || (is_ip2_v4 && (nr_ip_id_bits2 == 0 || is_rnd2 == 1))))
					ext = PACKET_EXT_0; /* IPv4 only for outer header */
				else if(nr_sn_bits <= 8 &&
				        (is_ip_v4 && nr_ip_id_bits <= 11) &&
				        (!is_ip2_v4 || (is_ip2_v4 && (nr_ip_id_bits2 == 0 || is_rnd2 == 1))))
					ext = PACKET_EXT_1; /* IPv4 only for outer header */
				else if(nr_sn_bits <= 3 &&
				        (is_ip_v4 && nr_ip_id_bits <= 11) &&
				        (is_ip2_v4 && nr_ip_id_bits2 <= 8))
					ext = PACKET_EXT_2; /* IPv4 only for both outer and inner header */
			}

			break;
		}
			case PACKET_UOR_2_RTP:
			{
				struct sc_rtp_context *rtp_context;
				int nr_ts_bits;

				rtp_context = (struct sc_rtp_context *) g_context->specific;
				nr_ts_bits = rtp_context->tmp_variables.nr_ts_bits;

				/* NO_EXT, EXT_0, EXT_1, EXT_2 and EXT_3 */
				if(nr_sn_bits <= 6 && nr_ts_bits <= 6)
					ext = PACKET_NOEXT;
				else if(nr_sn_bits <= 9 && nr_ts_bits <= 9)
					ext = PACKET_EXT_0;
				else if(nr_sn_bits <= 9 && nr_ts_bits <= 17)
					ext = PACKET_EXT_1;
				else if(nr_sn_bits <= 9 && nr_ts_bits <= 25)
					ext = PACKET_EXT_2;

				break;
			}

			case PACKET_UOR_2_TS:
			{
				struct sc_rtp_context *rtp_context;
				int nr_ts_bits;

				rtp_context = (struct sc_rtp_context *) g_context->specific;
				nr_ts_bits = rtp_context->tmp_variables.nr_ts_bits;

				/* NO_EXT, EXT_0 and EXT_3 */
				if(nr_sn_bits <= 6 && nr_ts_bits <= 5)
					ext = PACKET_NOEXT;
				else if(nr_sn_bits <= 9 && nr_ts_bits <= 8)
					ext = PACKET_EXT_0;

				break;
			}

			case PACKET_UOR_2_ID:
			{
				struct sc_rtp_context *rtp_context;
				int nr_ts_bits;

				rtp_context = (struct sc_rtp_context *) g_context->specific;
				nr_ts_bits = rtp_context->tmp_variables.nr_ts_bits;

				/* NO_EXT, EXT_0, EXT_1, EXT_2 and EXT_3 */
				if(nr_sn_bits <= 6 && nr_ip_id_bits <= 5 && nr_ts_bits == 0)
					ext = PACKET_NOEXT;
				else if(nr_sn_bits <= 9 && nr_ip_id_bits <= 8 && nr_ts_bits == 0)
					ext = PACKET_EXT_0;
				else if(nr_sn_bits <= 9 && nr_ip_id_bits <= 8 && nr_ts_bits <= 8)
					ext = PACKET_EXT_1;
				else if(nr_sn_bits <= 9 && nr_ip_id_bits <= 16 && nr_ts_bits <= 8)
					ext = PACKET_EXT_2;

				break;
			}

			default:
				rohc_debugf(3, "bad packet type (%d)\n", packet_type);
				goto error;
		}

	return ext;

error:
	return -1;
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
int changed_static_both_hdr(struct c_context *context,
                            const struct ip_packet ip,
                            const struct ip_packet ip2)
{
	int nb_fields = 0; /* number of fields that changed */
	unsigned short changed_fields;
	unsigned short changed_fields2;
	struct c_generic_context *g_context;

	g_context = (struct c_generic_context *) context->specific;
	changed_fields = g_context->tmp_variables.changed_fields;
	changed_fields2 = g_context->tmp_variables.changed_fields2;

	nb_fields = changed_static_one_hdr(changed_fields,
	                                   &g_context->ip_flags,
	                                   ip, context);

	if(g_context->tmp_variables.nr_of_ip_hdr > 1)
		nb_fields += changed_static_one_hdr(changed_fields2,
		                                    &g_context->ip2_flags,
		                                    ip2, context);

	return nb_fields;
}


/**
 * @brief Check if the static part of the context changed in the new IP packet.
 *
 *	The fields classified as STATIC-DEF by RFC do not need to be checked for
 *	change. These fields are constant for all packets in a stream (ie. a
 *	profile context). So, the Source Address and Destination Address fields are
 *	not checked for change for both IPv4 and IPv6. The Flow Label is not checked
 *	for IPv6.
 *
 *	Althought not classified as STATIC-DEF, the Version field is the same for
 *	all packets in a stream (ie. a profile context) and therefore does not need
 *	to be checked for change neither for IPv4 nor IPv6.
 *
 *	Althought classified as STATIC, the IPv4 Don't Fragment flag is not part of
 *	the static initialization, but of the dynamic initialization.
 *
 *	Summary:
 *	 - For IPv4, check the Protocol field for change.
 *	 - For IPv6, check the Next Header field for change.
 *
 * @param changed_fields The fields that changed, created by the function
 *                       changed_fields
 * @param header_info    The header info stored in the profile
 * @param ip             The header of the new IP packet
 * @param context        The compression context
 * @return               The number of fields that changed
 */
int changed_static_one_hdr(unsigned short changed_fields,
                           struct ip_header_info *header_info,
                           const struct ip_packet ip,
                           struct c_context *context)
{
	int nb_fields = 0; /* number of fields that changed */
	struct c_generic_context *g_context;

	g_context = (struct c_generic_context *) context->specific;

	/* check the IPv4 Protocol / IPv6 Next Header field for change */
	if(is_changed(changed_fields, MOD_PROTOCOL) ||
	   header_info->protocol_count < MAX_FO_COUNT)
	{
		rohc_debugf(2, "protocol_count %d\n", header_info->protocol_count);
		
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
int changed_dynamic_both_hdr(struct c_context *context,
                             const struct ip_packet ip,
                             const struct ip_packet ip2)
{
	int nb_fields = 0; /* number of fields that changed */
	unsigned short changed_fields;
	unsigned short changed_fields2;
	struct c_generic_context *g_context;

	g_context = (struct c_generic_context *) context->specific;
	changed_fields = g_context->tmp_variables.changed_fields;
	changed_fields2 = g_context->tmp_variables.changed_fields2;

	rohc_debugf(3, "check for changed fields in the outer IP header\n");
	nb_fields = changed_dynamic_one_hdr(changed_fields, &g_context->ip_flags,
	                                    ip, context);

	if(g_context->tmp_variables.nr_of_ip_hdr > 1)
	{
		rohc_debugf(3, "check for changed fields in the inner IP header\n");
		nb_fields += changed_dynamic_one_hdr(changed_fields2,
		                                     &g_context->ip2_flags,
		                                     ip2, context);
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
 *	Althought classified as STATIC, the IPv4 Don't Fragment flag is not part of
 *	the static initialization, but of the dynamic initialization. It needs to be
 *	checked for change.
 *
 *	Other flags are checked for change for IPv4. There are IP-ID related flags:
 *	 - RND: is the IP-ID random ?
 *	 - NBO: is the IP-ID in Network Byte Order ?
 *
 * @param changed_fields The fields that changed, created by the function
 *                       changed_fields
 * @param header_info    The header info stored in the profile
 * @param ip             The header of the new IP packet
 * @param context        The compression context
 * @return               The number of fields that changed
 */
int changed_dynamic_one_hdr(unsigned short changed_fields,
                            struct ip_header_info *header_info,
                            const struct ip_packet ip,
                            struct c_context *context)
{
	int nb_fields = 0; /* number of fields that changed */
	int nb_flags = 0; /* number of flags that changed */
	struct c_generic_context *g_context;
	int is_rtp;

	g_context = (struct c_generic_context *) context->specific;
	is_rtp = context->profile->id == ROHC_PROFILE_RTP;

	/* check the Type Of Service / Traffic Class field for change */
	if(is_changed(changed_fields, MOD_TOS) ||
	   header_info->tos_count < MAX_FO_COUNT)
	{
		if(is_changed(changed_fields, MOD_TOS))
		{
			header_info->tos_count = 0;
			g_context->fo_count = 0;
		}
		nb_fields += 1;
	}

	/* check the Time To Live / Hop Limit field for change */
	if(is_changed(changed_fields, MOD_TTL) ||
	   header_info->ttl_count < MAX_FO_COUNT)
	{
		if(is_changed(changed_fields, MOD_TTL))
		{
			header_info->ttl_count = 0;
			g_context->fo_count = 0;
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
				header_info->info.v4.df_count = 0;
				g_context->fo_count = 0;
			}
			nb_fields += 1;
		}

		/* check the RND flag for change (IPv4 only) */
		if(header_info->info.v4.rnd != header_info->info.v4.old_rnd ||
		   header_info->info.v4.rnd_count < MAX_FO_COUNT)
		{
			if(header_info->info.v4.rnd != header_info->info.v4.old_rnd)
			{
				rohc_debugf(1, "RND changed (%x -> %x), reset counter\n",
				            header_info->info.v4.old_rnd,
				            header_info->info.v4.rnd);
				header_info->info.v4.rnd_count = 0;
				g_context->fo_count = 0;
			}
			nb_flags += 1;
		}

		/*  check the NBO flag for change (IPv4 only) */
		if(header_info->info.v4.nbo != header_info->info.v4.old_nbo ||
		   header_info->info.v4.nbo_count < MAX_FO_COUNT)
		{
			if(header_info->info.v4.nbo != header_info->info.v4.old_nbo)
			{
				rohc_debugf(1, "NBO changed (%x -> %x), reset counter\n",
				            header_info->info.v4.old_nbo,
				            header_info->info.v4.nbo);
				header_info->info.v4.nbo_count = 0;
				g_context->fo_count = 0;
			}
			nb_flags += 1;
		}

		if(nb_flags > 0)
			nb_fields += 1;
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
 * @param header_info    The header info stored in the profile
 * @param ip             The header of the new IP packet
 * @param check_rtp      Whether the function must check for RTP fields or not
 * @return               The bitpattern that indicates which field changed
 */
unsigned short changed_fields(struct ip_header_info *header_info,
                              const struct ip_packet ip,
                              int check_rtp)
{
	unsigned short ret_value = 0;
	unsigned int old_tos, old_ttl, old_protocol, old_pt;

	if(ip_get_version(ip) == IPV4)
	{
		struct iphdr *old_ip;
	
		old_ip = &header_info->info.v4.old_ip;
		old_tos = old_ip->tos;
		old_ttl = old_ip->ttl;
		old_protocol = old_ip->protocol;
	}
	else /* IPV6 */
	{
		struct ip6_hdr *old_ip;

		old_ip = &header_info->info.v6.old_ip;
		old_tos = IPV6_GET_TC(*old_ip);
		old_ttl = old_ip->ip6_hlim;
		old_protocol = old_ip->ip6_nxt;
	}

	if(old_tos != ip_get_tos(ip))
		ret_value |= MOD_TOS;
	if(old_ttl != ip_get_ttl(ip))
		ret_value |= MOD_TTL;
	if(old_protocol != ip_get_protocol(ip))
		ret_value |= MOD_PROTOCOL;

	if(check_rtp)
	{
		struct udphdr *old_udp, *udp;
		struct rtphdr *old_rtp, *rtp;

		if(ip_get_version(ip) == IPV4)
		{
			struct iphdr *old_ip_v4;
			old_ip_v4 = &header_info->info.v4.old_ip;
			old_udp = (struct udphdr *) (old_ip_v4 + 1);
		}
		else
		{
			struct ip6_hdr *old_ip_v6;
			old_ip_v6 = &header_info->info.v6.old_ip;
			old_udp = (struct udphdr *) (old_ip_v6 + 1);
		}
		old_rtp = (struct rtphdr *) (old_udp + 1);
		old_pt = old_rtp->pt;

		udp = (struct udphdr *) ip_get_next_header(ip);
		rtp = (struct rtphdr *) (udp + 1);
		if(old_pt != rtp->pt)
			ret_value |= MOD_RTP_PT;
	}

	return ret_value;
}


/**
 * @brief Determine whether the IPv4 Identification field of one IPv4 header is
 *        random and/or in Network Bit Order (NBO).
 *
 * @param header_info  The header info stored in the profile
 * @param ip           One IPv4 header
 */
void check_ip_identification(struct ip_header_info *header_info,
                             const struct ip_packet ip)
{
	int old_id, new_id;
	int nbo = -1;

	if(ip_get_version(ip) != IPV4)
	{
		rohc_debugf(0, "cannot check IP-ID behaviour with IPv6\n");
		return;
	}

	old_id = ntohs(header_info->info.v4.old_ip.id);
	new_id = ntohs(ipv4_get_id(ip));

	rohc_debugf(2, "1) old_id = 0x%04x new_id = 0x%04x\n", old_id, new_id);

	if((new_id - old_id) < IPID_MAX_DELTA && (new_id - old_id) > 0)
		nbo = 1;
	else if((old_id + IPID_MAX_DELTA) > 0xffff &&
	        new_id < ((old_id + IPID_MAX_DELTA) & 0xffff))
		nbo = 1;

	if(nbo == -1)
	{
		/* change byte ordering and check nbo = 0 */
		old_id = (old_id >> 8) | ((old_id << 8) & 0xff00);
		new_id = (new_id >> 8) | ((new_id << 8) & 0xff00);

		rohc_debugf(2, "2) old_id = 0x%04x new_id = 0x%04x\n", old_id, new_id);

		if((new_id - old_id) < IPID_MAX_DELTA && (new_id - old_id) > 0)
			nbo = 0;
		else if((old_id + IPID_MAX_DELTA) > 0xffff &&
		        new_id < ((old_id + IPID_MAX_DELTA) & 0xffff))
			nbo = 0;
	}

	if(nbo == -1)
	{
		rohc_debugf(2, "RND detected\n");
		header_info->info.v4.rnd = 1;
	}
	else
	{
		rohc_debugf(2, "NBO = %d\n", nbo);
		header_info->info.v4.rnd = 0;
		header_info->info.v4.nbo = nbo;
	}
}

