/*
 * Copyright 2013,2014 Didier Barvaux
 * Copyright 2009,2010 Thales Communications
 * Copyright 2013 Viveris Technologies
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/**
 * @file    kmod_test.c
 * @brief   A small module for the Linux kernel to test ROHC (de)compression
 * @author  Thales Communications
 * @author  Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>

#include "config.h"
#include "rohc.h"
#include "rohc_comp.h"
#include "rohc_decomp.h"


/** The name of the file to write IP packets on to compressor */
#define PROC_COMP_IN_NAME "rohc_comp%d_in"
/** The name of the file to read ROHC packets from compressor */
#define PROC_COMP_OUT_NAME "rohc_comp%d_out"

/** The name of the file to write ROHC packets on to decompressor */
#define PROC_DECOMP_IN_NAME "rohc_decomp%d_in"
/** The name of the file to read IP packets from decompressor */
#define PROC_DECOMP_OUT_NAME "rohc_decomp%d_out"

/** The maximal size for the ROHC packets */
#define MAX_ROHC_SIZE   10000


/** Custom pr_info() macro for the module */
#define rohc_info(format, ...) \
	pr_info("[%s] " format, THIS_MODULE->name, ##__VA_ARGS__)

/** Custom pr_err() macro for the module */
#define rohc_err(format, ...) \
	pr_err("[%s] " format, THIS_MODULE->name, ##__VA_ARGS__)


/** A couple of ROHC compressor/decompressor and the related buffers */
struct rohc_couple {

	/** The ROHC compressor created by the module */
	struct rohc_comp *comp;

	/** The ROHC decompressor created by the module */
	struct rohc_decomp *decomp;

	/** The buffer in which to store the compressed ROHC packet */
	unsigned char *rohc_pkt_out;
	/** The size of the compressed ROHC packet */
	size_t rohc_size_out;
	/** The buffer in which to store the IP packet to compress */
	unsigned char *ip_pkt_in;
	/** The total size of the IP packet to compress */
	size_t ip_size_total_in;
	/** The size of data currently stored in the buffer \ref ip_pkt_in */
	size_t ip_size_current_in;

	/** The buffer in which to store the decompressed IP packet */
	unsigned char *ip_pkt_out;
	/** The size of the decompressed IP packet */
	size_t ip_size_out;
	/** The buffer in which to store the ROHC packet to decompress */
	unsigned char *rohc_pkt_in;
	/** The total size of the ROHC packet to decompress */
	size_t rohc_size_total_in;
	/** The size of data currently stored in the buffer \ref rohc_pkt_in */
	size_t rohc_size_curr_in;

	/** The file to write IP packets on to compressor */
	struct proc_dir_entry *proc_file_comp_in;
	/** The file to read ROHC packets from compressor */
	struct proc_dir_entry *proc_file_comp_out;

	/** The file to write ROHC packets on to decompressor */
	struct proc_dir_entry *proc_file_decomp_in;
	/** The file to read IP packets from decompressor */
	struct proc_dir_entry *proc_file_decomp_out;
};


/** The two couples of ROHC compressor and decompressor */
static struct rohc_couple couples[2];


/**
 * @brief References on the couples of ROHC compressor/decompressor
 *
 * This number of references is used to create (or not create) the couples when
 * one of the /proc files is opened. The couples are created only when the
 * first /proc file is opened.
 */
static unsigned int couples_ref_nr;


/**
 * @brief Generate a false random number for testing the ROHC library
 *
 * @param comp          The ROHC compressor
 * @param user_context  Should always be NULL
 * @return              Always 0
 */
static int gen_false_random_num(const struct rohc_comp *const comp,
				void *const user_context)
{
	return 0;
}


/**
 * @brief Print traces emitted by the ROHC library
 *
 * @param priv_ctxt  An optional private context, may be NULL
 * @param level      The priority level of the trace
 * @param entity     The entity that emitted the trace among:
 *                    \li ROHC_TRACE_COMP
 *                    \li ROHC_TRACE_DECOMP
 * @param profile    The ID of the ROHC compression/decompression profile
 *                   the trace is related to
 * @param format     The format string of the trace
 */
static void rohc_print_traces(void *const priv_ctxt __attribute__((unused)),
			      const rohc_trace_level_t level,
			      const rohc_trace_entity_t entity,
			      const int profile,
			      const char *const format,
			      ...)
{
	va_list args;

	va_start(args, format);
	vprintk(format, args);
	va_end(args);
}


/**
 * @brief The RTP detection callback
 *
 * @param ip           The innermost IP packet
 * @param udp          The UDP header of the packet
 * @param payload      The UDP payload of the packet
 * @param payload_size The size of the UDP payload (in bytes)
 * @return             true if the packet is an RTP packet, false otherwise
 */
bool rohc_comp_rtp_cb(const unsigned char *const ip __attribute__((unused)),
		      const unsigned char *const udp,
		      const unsigned char *const payload
				__attribute__((unused)),
		      const unsigned int payload_size __attribute__((unused)),
		      void *const rtp_private __attribute__((unused)))
{
	const size_t default_rtp_ports_nr = 5;
	unsigned int default_rtp_ports[] = { 1234, 36780, 33238, 5020, 5002 };
	uint16_t udp_dport;
	bool is_rtp = false;
	size_t i;

	if (udp == NULL)
		return false;

	/* get the UDP destination port */
	memcpy(&udp_dport, udp + 2, sizeof(uint16_t));

	/* is the UDP destination port in the list of ports reserved for RTP
	 * traffic by default (for compatibility reasons)
	 */
	for (i = 0; i < default_rtp_ports_nr; i++) {
		if (ntohs(udp_dport) == default_rtp_ports[i]) {
			is_rtp = true;
			break;
		}
	}

	return is_rtp;
}


/**
 * @brief Init a ROHC couple (part 1)
 *
 * In part 1, only the compressor is initialized.
 *
 * @param couple  The couple of ROHC compressor/decompressor to initialize
 * @param index   The index of the couple: 0 or 1
 * @return        0 in case of success, non-zero otherwise
 */
int rohc_couple_init_phase1(struct rohc_couple *couple, int index)
{
	bool is_ok;

	rohc_info("init ROHC couple #%d (phase 1)\n", index + 1);

	memset(couple, 0, sizeof(struct rohc_couple));

	/* create the compressor */
	couple->comp = rohc_comp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX,
				      gen_false_random_num, NULL);
	if (couple->comp == NULL) {
		rohc_err("\tcannot create the ROHC compressor\n");
		goto error;
	}
	rohc_info("\tROHC compressor successfully created\n");

	/* link the compressor to the appropriate log function */
	is_ok = rohc_comp_set_traces_cb2(couple->comp, rohc_print_traces, NULL);
	if (!is_ok) {
		rohc_err("\tcannot set trace callback for compressor\n");
		goto free_compressor;
	}
	rohc_info("\ttrace callback for ROHC compressor successfully set\n");

	/* activate all the compression profiles */
	is_ok = rohc_comp_enable_profiles(couple->comp,
			ROHC_PROFILE_UNCOMPRESSED, ROHC_PROFILE_RTP,
			ROHC_PROFILE_UDP, ROHC_PROFILE_ESP, ROHC_PROFILE_IP,
			ROHC_PROFILE_UDPLITE, -1);
	if (!is_ok) {
		rohc_err("\tfailed to enabled all compression profiles\n");
		goto free_compressor;
	}
	rohc_info("\tUncompressed, RTP, UDP, ESP, IP and UDP-Lite profiles enabled for ROHC compressor successfully set\n");

	/* set UDP ports dedicated to RTP traffic */
	if (!rohc_comp_set_rtp_detection_cb(couple->comp, rohc_comp_rtp_cb,
					    NULL)) {
		goto free_compressor;
	}
	rohc_info("\tRTP ports successfully configured for ROHC compressor\n");

	rohc_info("\tROHC couple #%d successfully initialized (phase 1)\n",
		  index + 1);

	return 0;

free_compressor:
	rohc_comp_free(couple->comp);
error:
	return 1;
}


/**
 * @brief Init a ROHC couple (part 2)
 *
 * In part 2, the decompressor and the buffers are initialized.
 *
 * @param couple  The couple of ROHC compressor/decompressor to initialize
 * @param index   The index of the couple: 0 or 1
 * @return        0 in case of success, non-zero otherwise
 */
int rohc_couple_init_phase2(struct rohc_couple *couple, int index)
{
	bool is_ok;

	rohc_info("init ROHC couple #%d (phase 2)\n", index + 1);

	/* create the decompressor and associate it with the compressor
	 * of the other ROHC couple
	 */
	couple->decomp = rohc_decomp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX,
					  ROHC_O_MODE);
	if (couple->decomp == NULL) {
		rohc_err("\tcannot create the ROHC decompressor\n");
		goto free_compressor;
	}
	rohc_info("\tROHC decompressor successfully created\n");

	/* link the decompressor to the appropriate log function */
	is_ok = rohc_decomp_set_traces_cb2(couple->decomp, rohc_print_traces,
					   NULL);
	if (!is_ok) {
		rohc_err("\tcannot set trace callback for decompressor\n");
		goto free_decompressor;
	}
	rohc_info("\ttrace callback for ROHC decompressor successfully set\n");

	/* allocate memory for the ROHC packet generated from IP packet and
	 * init all the related lengths and pointers
	 */
	couple->rohc_pkt_out = kmalloc(MAX_ROHC_SIZE, GFP_KERNEL);
	if (couple->rohc_pkt_out == NULL)
		goto free_decompressor;
	couple->rohc_size_out = 0;
	couple->ip_pkt_in = NULL;
	couple->ip_size_total_in = 0;
	couple->ip_size_current_in = 0;

	/* allocate memory for the IP packet generated from ROHC packet and
	 * init all the related lengths and pointers
	 */
	couple->ip_pkt_out = kmalloc(MAX_ROHC_SIZE, GFP_KERNEL);
	if (couple->ip_pkt_out == NULL)
		goto free_rohc_packet;
	couple->ip_size_out = 0;
	couple->rohc_pkt_in = NULL;
	couple->rohc_size_total_in = 0;
	couple->rohc_size_curr_in = 0;

	rohc_info("\tROHC couple #%d successfully initialized (phase 2)\n",
		  index + 1);

	return 0;

free_rohc_packet:
	kfree(couple->rohc_pkt_out);
free_decompressor:
	rohc_decomp_free(couple->decomp);
free_compressor:
	rohc_comp_free(couple->comp);
	return 1;
}


/**
 * @brief Release a ROHC couple
 *
 * @param couple  The couple of ROHC compressor/decompressor to initialize
 * @param index   The index of the couple: 0 or 1
 */
void rohc_couple_release(struct rohc_couple *couple, int index)
{
	rohc_info("release ROHC couple #%d...\n", index + 1);

	/* free/reset resources for generated ROHC packets */
	if (couple->rohc_pkt_out != NULL) {
		kfree(couple->rohc_pkt_out);
		couple->rohc_pkt_out = NULL;
	}
	couple->rohc_size_out = 0;
	if (couple->ip_pkt_in != NULL) {
		kfree(couple->ip_pkt_in);
		couple->ip_pkt_in = NULL;
	}
	couple->ip_size_total_in = 0;
	couple->ip_size_current_in = 0;

	/* free/reset resources for generated IP packets */
	if (couple->ip_pkt_out != NULL) {
		kfree(couple->ip_pkt_out);
		couple->ip_pkt_out = NULL;
	}
	couple->ip_size_out = 0;
	if (couple->rohc_pkt_in != NULL) {
		kfree(couple->rohc_pkt_in);
		couple->rohc_pkt_in = NULL;
	}
	couple->rohc_size_total_in = 0;
	couple->rohc_size_curr_in = 0;

	/* free (de)compressor */
	if (couple->comp != NULL)
		rohc_comp_free(couple->comp);
	if (couple->decomp != NULL)
		rohc_decomp_free(couple->decomp);

	rohc_info("ROHC couple #%d successfully released\n", index + 1);
}


/**
 * @brief Called when a /proc file is opened by userspace
 *
 * Initialize the ROHC couples if not already done upon another /proc open.
 *
 * Initialization is done in 2 separate phases since creating decompressors
 * requires the compressors to be already created and we can not achieve that
 * in one shot: the 1st couple would not get access to the decompressor of the
 * 2nd couple since it would not be created yet.
 *
 * @param inode  The inode information on the /proc file
 * @param file   The file information on the /proc file
 * @param        0 in case of success, -EFAULT in case of error
 */
static int rohc_proc_open(struct inode *inode, struct file *file)
{
	rohc_info("proc file '%s' opened\n", file->f_path.dentry->d_name.name);

	/* initialize the ROHC couples only if this is the first /proc file
	 * opened since the last close()
	 */
	if (couples_ref_nr == 0) {
		int ret;

		/* phase 1: initialize the compressor of the 1st ROHC couple */
		ret = rohc_couple_init_phase1(&couples[0], 0);
		if (ret != 0) {
			rohc_err("\tfailed to init ROHC couple #1 (phase 1)\n");
			goto error;
		}

		/* phase 1: initialize the compressor of the 2nd ROHC couple */
		ret = rohc_couple_init_phase1(&couples[1], 1);
		if (ret != 0) {
			rohc_err("\tfailed to init ROHC couple #2 (phase 2)\n");
			goto free_couple1;
		}

		/* phase 2: initialize the rest of the 1st ROHC couple */
		ret = rohc_couple_init_phase2(&couples[0], 0);
		if (ret != 0) {
			rohc_err("failed to init ROHC couple #1 (phase 2)\n");
			goto free_couple2;
		}

		/* phase 2: initialize the rest of the 2nd ROHC couple */
		ret = rohc_couple_init_phase2(&couples[1], 1);
		if (ret != 0) {
			rohc_err("failed to init ROHC couple #2 (phase 2)\n");
			goto free_couple2;
		}
	}
	couples_ref_nr++;

	/* give the right couple object as private data for file operations */
	if (!strcmp(file->f_path.dentry->d_name.name, "rohc_comp1_in") ||
	    !strcmp(file->f_path.dentry->d_name.name, "rohc_comp1_out") ||
	    !strcmp(file->f_path.dentry->d_name.name, "rohc_decomp1_in") ||
	    !strcmp(file->f_path.dentry->d_name.name, "rohc_decomp1_out")) {
		file->private_data = &couples[0];
	} else {
		file->private_data = &couples[1];
	}

	return 0;

free_couple2:
	rohc_couple_release(&couples[1], 1);
free_couple1:
	rohc_couple_release(&couples[0], 0);
error:
	return -EFAULT;
}


/**
 * @brief Handle a write to /proc/rohc_comp%d_in file from userspace
 *
 * @param file    The /proc file userspace writes to
 * @param buffer  The data userspace writes
 * @param count   The number of bytes of data
 * @param ppos    TODO
 * @return        The number of bytes of data handled by the function,
 *                -ENOMEM if memory allocation fails,
 *                -EFAULT if another error occurs
 */
ssize_t rohc_proc_comp_write(struct file *file,
			     const char __user *buffer,
			     size_t count,
			     loff_t *ppos)
{
	struct rohc_couple *couple = file->private_data;
	size_t ip_chunk_size;
	rohc_status_t status;
	int err = -ENOMEM;

	WARN_ON(couples_ref_nr == 0);

	/* do we receive data of a new packet or
	 * a chunk of a yet-partially-received packet ?
	 */
	if (couple->ip_size_total_in == 0) {
		/* new packet */
		couple->ip_size_total_in = *((uint16_t *) buffer);

		rohc_info("start receiving a %zd-byte IP packet\n",
			  couple->ip_size_total_in);

		couple->ip_pkt_in =
		   kmalloc(couple->ip_size_total_in, GFP_KERNEL);
		if (couple->ip_pkt_in == NULL) {
			rohc_err("failed allocate %zd bytes of memory\n",
				 couple->ip_size_total_in);
			goto error;
		}

		buffer += sizeof(uint16_t);
		ip_chunk_size = count - sizeof(uint16_t);
	} else {
		/* new chunk of packet */
		ip_chunk_size = count;
	}
	err = -EFAULT;

	rohc_info("receive a %zd-byte IP chunk\n", ip_chunk_size);

	/* sanity check for too large packets */
	if ((couple->ip_size_current_in + ip_chunk_size) >
	    couple->ip_size_total_in) {
		rohc_err("IP chunk is larger than expected (%zd bytes while only %zd are expected)\n",
			 ip_chunk_size, couple->ip_size_total_in -
			 couple->ip_size_current_in);
		goto error;
	}

	/* add the chunk to the context */
	if (copy_from_user(couple->ip_pkt_in + couple->ip_size_current_in,
			   buffer, ip_chunk_size)) {
		rohc_err("failed to copy %zd-byte IP chunk from userspace to kernel\n",
			 ip_chunk_size);
		goto error;
	}
	couple->ip_size_current_in += ip_chunk_size;

	/* compress the IP packet if it is complete */
	if (couple->ip_size_current_in == couple->ip_size_total_in) {
		const struct rohc_ts arrival_time = { .sec = 0, .nsec = 0 };
		struct rohc_buf ip_packet =
			rohc_buf_init_full(couple->ip_pkt_in,
					   couple->ip_size_total_in,
					   arrival_time);
		struct rohc_buf rohc_packet =
			rohc_buf_init_empty(couple->rohc_pkt_out,
					    MAX_ROHC_SIZE);

		rohc_info("IP packet is complete, compress it now\n");

		status = rohc_compress4(couple->comp, ip_packet, &rohc_packet);
		if (status != ROHC_STATUS_OK) {
			rohc_err("failed to compress the IP packet\n");
			goto error;
		}
		couple->rohc_size_out = rohc_packet.len;

		rohc_info("IP packet successfully compressed\n");

		kfree(couple->ip_pkt_in);
		couple->ip_pkt_in = NULL;
		couple->ip_size_total_in = 0;
		couple->ip_size_current_in = 0;
	} else {
		rohc_info("IP packet is not complete yet, wait for more data\n");
		couple->rohc_size_out = 0;
	}

	/* everything went fine */
	return count;

error:
	couple->rohc_size_out = 0;
	if (couple->ip_pkt_in != NULL) {
		kfree(couple->ip_pkt_in);
		couple->ip_pkt_in = NULL;
	}
	couple->ip_size_total_in = 0;
	couple->ip_size_current_in = 0;
	return err;
}


/**
 * @brief Handle a write to /proc/rohc_decomp%d_in file from userspace
 *
 * @param file    The /proc file userspace writes to
 * @param buffer  The data userspace writes
 * @param count   The number of bytes of data
 * @param ppos    TODO
 * @return        The number of bytes of data handled by the function,
 *                -ENOMEM if memory allocation fails,
 *                -EFAULT if another error occurs
 */
ssize_t rohc_proc_decomp_write(struct file *file,
			       const char __user *buffer,
			       size_t count,
			       loff_t *ppos)
{
	struct rohc_couple *couple = file->private_data;
	size_t rohc_chunk_size;
	int status;
	int err = -ENOMEM;

	WARN_ON(couples_ref_nr == 0);

	/* do we receive data of a new packet or
	 * a chunk of a yet-partially-received packet ?
	 */
	if (couple->rohc_size_total_in == 0) {
		/* new packet */
		couple->rohc_size_total_in = *((uint16_t *) buffer);

		rohc_info("start receiving a %zd-byte ROHC packet\n",
			  couple->rohc_size_total_in);

		couple->rohc_pkt_in =
			kmalloc(couple->rohc_size_total_in, GFP_KERNEL);
		if (couple->rohc_pkt_in == NULL) {
			rohc_err("failed allocate %zd bytes of memory\n",
				 couple->rohc_size_total_in);
			goto error;
		}

		buffer += sizeof(uint16_t);
		rohc_chunk_size = count - sizeof(uint16_t);
	} else {
		/* new chunk of packet */
		rohc_chunk_size = count;
	}
	err = -EFAULT;

	rohc_info("receive a %zd-byte ROHC chunk\n", rohc_chunk_size);

	/* sanity check for too large packets */
	if ((couple->rohc_size_curr_in + rohc_chunk_size) >
	    couple->rohc_size_total_in) {
		rohc_err("ROHC chunk is larger than expected (%zd bytes while only %zd are expected)\n",
			 rohc_chunk_size, couple->rohc_size_total_in -
			 couple->rohc_size_curr_in);
		goto error;
	}

	/* add the chunk to the context */
	if (copy_from_user(couple->rohc_pkt_in + couple->rohc_size_curr_in,
			   buffer, rohc_chunk_size)) {
		rohc_err("failed to copy %zd-byte ROHC chunk from userspace to kernel\n",
			 rohc_chunk_size);
		goto error;
	}
	couple->rohc_size_curr_in += rohc_chunk_size;

	/* decompress the ROHC packet if it is complete */
	if (couple->rohc_size_curr_in == couple->rohc_size_total_in) {
		const struct rohc_ts arrival_time = { .sec = 0, .nsec = 0 };
		struct rohc_buf rohc_packet =
			rohc_buf_init_full(couple->rohc_pkt_in,
					   couple->rohc_size_total_in,
					   arrival_time);
		struct rohc_buf ip_packet =
			rohc_buf_init_empty(couple->ip_pkt_out,
					    MAX_ROHC_SIZE);

		rohc_info("ROHC packet is complete, decompress it now\n");

		status = rohc_decompress3(couple->decomp, rohc_packet,
					  &ip_packet, NULL, NULL);
		if (status != ROHC_STATUS_OK) {
			rohc_err("failed to decompress the ROHC packet\n");
			goto error;
		}
		couple->ip_size_out = ip_packet.len;

		rohc_info("ROHC packet successfully decompressed\n");

		kfree(couple->rohc_pkt_in);
		couple->rohc_pkt_in = NULL;
		couple->rohc_size_total_in = 0;
		couple->rohc_size_curr_in = 0;
	} else {
		rohc_info("ROHC packet is not complete yet, wait for more data\n");
		couple->ip_size_out = 0;
	}

	/* everything went fine */
	return count;

error:
	couple->ip_size_out = 0;
	if (couple->rohc_pkt_in != NULL) {
		kfree(couple->rohc_pkt_in);
		couple->rohc_pkt_in = NULL;
	}
	couple->rohc_size_total_in = 0;
	couple->rohc_size_curr_in = 0;
	return err;
}


/**
 * @brief Handle a read from /proc/rohc_comp%d_out file from userspace
 *
 * @param file    The /proc file userspace reads from
 * @param buffer  The data userspace reads
 * @param count   The number of bytes of data
 * @param ppos    TODO
 * @return        The number of bytes of data handled by the function,
 *                -ENOMEM if memory allocation fails,
 *                -EFAULT if another error occurs
 */
ssize_t rohc_proc_comp_read(struct file *file,
			    char __user *buffer,
			    size_t count,
			    loff_t *ppos)
{
	struct rohc_couple *couple = file->private_data;
	int err = -EFAULT;

	WARN_ON(couples_ref_nr == 0);

	/* if one reads a packet when none is available, return an error */
	if (couple->rohc_size_out == 0) {
		rohc_err("cannot send ROHC packet to userspace: no ROHC packet available\n");
		goto error;
	}

	/* userspace should provides a buffer that is large enough
	 * for the whole compressed packet
	 */
	if (count < couple->rohc_size_out) {
		rohc_err("cannot send ROHC packet to userspace: too large\n");
		goto error;
	}

	/* send data to userspace */
	if (copy_to_user(buffer, couple->rohc_pkt_out, couple->rohc_size_out)) {
		rohc_err("cannot send ROHC packet to userspace: copy_to_user failed\n");
		goto error;
	}

	/* everything went fine */
	err = couple->rohc_size_out;

error:
	couple->rohc_size_out = 0;
	return err;
}


/**
 * @brief Handle a read from /proc/rohc_decomp%d_out file from userspace
 *
 * @param file    The /proc file userspace reads from
 * @param buffer  The data userspace reads
 * @param count   The number of bytes of data
 * @param ppos    TODO
 * @return        The number of bytes of data handled by the function,
 *                -ENOMEM if memory allocation fails,
 *                -EFAULT if another error occurs
 */
ssize_t rohc_proc_decomp_read(struct file *file,
			      char __user *buffer,
			      size_t count,
			      loff_t *ppos)
{
	struct rohc_couple *couple = file->private_data;
	int err = -EFAULT;

	WARN_ON(couples_ref_nr == 0);

	/* if one reads a packet when none is available, return an error */
	if (couple->ip_size_out == 0) {
		rohc_err("cannot send decompressed IP packet to userspace: no IP packet available\n");
		goto error;
	}

	/* userspace should provides a buffer that is large enough
	 * for the whole compressed packet
	 */
	if (count < couple->ip_size_out) {
		rohc_err("cannot send decompressed IP packet to userspace: too large\n");
		goto error;
	}

	/* send data to userspace */
	if (copy_to_user(buffer, couple->ip_pkt_out, couple->ip_size_out)) {
		rohc_err("cannot send decompressed IP packet to userspace: copy_to_user failed\n");
		goto error;
	}

	/* everything went fine */
	err = couple->ip_size_out;

error:
	couple->ip_size_out = 0;
	return err;
}


/**
 * @brief Handle a close() from userspace on a /proc file
 *
 * First close on one /proc entry, release the resources of the module,
 * so userspace should avoid using the /proc files after one of them
 * is closed. This could be improved by releasing resources when
 * the last /proc file is closed.
 *
 * @param inode  The inode information on the /proc file
 * @param file   The file information on the /proc file
 * @param        Always return 0 (success)
 */
static int rohc_proc_close(struct inode *inode, struct file *file)
{
	WARN_ON(couples_ref_nr == 0);
	couples_ref_nr--;

	if (couples_ref_nr == 0) {
		rohc_couple_release(&couples[0], 0);
		rohc_couple_release(&couples[1], 1);
	}

	return 0;
}


/** File operations for /proc/rohc_comp%d_in */
static const struct file_operations rohc_proc_comp_in_fops = {
	.owner   = THIS_MODULE,
	.open    = rohc_proc_open,
	.write   = rohc_proc_comp_write,
	.release = rohc_proc_close,
};


/** File operations for /proc/rohc_comp%d_out */
static const struct file_operations rohc_proc_comp_out_fops = {
	.owner   = THIS_MODULE,
	.open    = rohc_proc_open,
	.read   = rohc_proc_comp_read,
	.release = rohc_proc_close,
};


/** File operations for /proc/rohc_decomp%d_in */
static const struct file_operations rohc_proc_decomp_in_fops = {
	.owner   = THIS_MODULE,
	.open    = rohc_proc_open,
	.write   = rohc_proc_decomp_write,
	.release = rohc_proc_close,
};


/** File operations for /proc/rohc_decomp%d_out */
static const struct file_operations rohc_proc_decomp_out_fops = {
	.owner   = THIS_MODULE,
	.open    = rohc_proc_open,
	.read   = rohc_proc_decomp_read,
	.release = rohc_proc_close,
};


/**
 * @brief Create /proc/rohc_(de)?comp[12]_(in|out) entries
 *
 * @param couple  The ROHC couple for which to create the /proc entries
 * @param index   The index of the couple: 0 or 1
 * @return        0 in case of success, 1 in case of error
 */
int rohc_proc_init(struct rohc_couple *couple, int index)
{
	char proc_comp_in_name[100];
	char proc_comp_out_name[100];
	char proc_decomp_in_name[100];
	char proc_decomp_out_name[100];

	/* create the name of the /proc files according to the couple index */
	sprintf(proc_comp_in_name, PROC_COMP_IN_NAME, index + 1);
	sprintf(proc_comp_out_name, PROC_COMP_OUT_NAME, index + 1);
	sprintf(proc_decomp_in_name, PROC_DECOMP_IN_NAME, index + 1);
	sprintf(proc_decomp_out_name, PROC_DECOMP_OUT_NAME, index + 1);

	rohc_info("\tcreate interface /proc/%s...\n", proc_comp_in_name);
	couple->proc_file_comp_in =
		proc_create(proc_comp_in_name, S_IFREG|S_IRUSR|S_IWUSR,
			    NULL, &rohc_proc_comp_in_fops);
	if (couple->proc_file_comp_in == NULL) {
		rohc_err("\tfailed to create /proc/%s\n", proc_comp_in_name);
		goto err;
	}

	rohc_info("\tcreate interface /proc/%s...\n", proc_comp_out_name);
	couple->proc_file_comp_out =
		proc_create(proc_comp_out_name, S_IFREG|S_IRUSR|S_IWUSR,
			    NULL, &rohc_proc_comp_out_fops);
	if (couple->proc_file_comp_out == NULL) {
		rohc_err("\tfailed to create /proc/%s\n", proc_comp_out_name);
		goto err_free_comp_in;
	}

	rohc_info("\tcreate interface /proc/%s...\n", proc_decomp_in_name);
	couple->proc_file_decomp_in =
		proc_create(proc_decomp_in_name, S_IFREG|S_IRUSR|S_IWUSR,
			    NULL, &rohc_proc_decomp_in_fops);
	if (couple->proc_file_decomp_in == NULL) {
		rohc_err("\tfailed to create /proc/%s\n", proc_decomp_in_name);
		goto err_free_comp_out;
	}

	rohc_info("\tcreate interface /proc/%s...\n", proc_decomp_out_name);
	couple->proc_file_decomp_out =
		proc_create(proc_decomp_out_name, S_IFREG|S_IRUSR|S_IWUSR,
			    NULL, &rohc_proc_decomp_out_fops);
	if (couple->proc_file_decomp_out == NULL) {
		rohc_err("\tfailed to create /proc/%s\n", proc_decomp_out_name);
		goto err_free_decomp_in;
	}

	return 0;

err_free_decomp_in:
	remove_proc_entry(proc_decomp_in_name, NULL);
err_free_comp_out:
	remove_proc_entry(proc_comp_out_name, NULL);
err_free_comp_in:
	remove_proc_entry(proc_comp_in_name, NULL);
err:
	return 1;
}


/**
 * @brief Release the /proc/rohc_(de)?comp[12]_(in|out) entries
 *
 * @param index   The index of the couple: 0 or 1
 */
void rohc_proc_release(int index)
{
	char proc_comp_in_name[100];
	char proc_comp_out_name[100];
	char proc_decomp_in_name[100];
	char proc_decomp_out_name[100];

	/* create the name of the /proc files according to the couple index */
	sprintf(proc_comp_in_name, PROC_COMP_IN_NAME, index + 1);
	sprintf(proc_comp_out_name, PROC_COMP_OUT_NAME, index + 1);
	sprintf(proc_decomp_in_name, PROC_DECOMP_IN_NAME, index + 1);
	sprintf(proc_decomp_out_name, PROC_DECOMP_OUT_NAME, index + 1);

	/* remove the /proc entries of the couple */
	remove_proc_entry(proc_comp_in_name, NULL);
	remove_proc_entry(proc_comp_out_name, NULL);
	remove_proc_entry(proc_decomp_in_name, NULL);
	remove_proc_entry(proc_decomp_out_name, NULL);
}


/**
 * @brief The entry point of the kernel module
 *
 * @return  0 in case of success, non-zero otherwise
 */
int __init rohc_test_init(void)
{
	int ret;

	rohc_info("loading ROHC test module...\n");

	/* create /proc entries for the 1st ROHC couple */
	ret = rohc_proc_init(&couples[0], 0);
	if (ret != 0) {
		rohc_err("failed to create /proc entries\n");
		goto error;
	}

	/* create /proc entries for the 2nd ROHC couple */
	ret = rohc_proc_init(&couples[1], 1);
	if (ret != 0) {
		rohc_err("failed to create /proc entries\n");
		goto release_proc;
	}

	rohc_info("ROHC test module successfully loaded\n");

	return 0;

release_proc:
	rohc_proc_release(0);
error:
	return 1;
}


/**
 * @brief The exit point of the kernel module
 */
void __exit rohc_test_exit(void)
{
	rohc_info("unloading ROHC test module...\n");
	rohc_proc_release(0);
	rohc_proc_release(1);
	rohc_info("ROHC test module successfully unloaded\n");
}


MODULE_VERSION(PACKAGE_VERSION PACKAGE_REVNO);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Didier Barvaux, Thales Communications, Viveris Technologies");
MODULE_DESCRIPTION("Module for testing " PACKAGE_NAME " "
	PACKAGE_VERSION PACKAGE_REVNO " (" PACKAGE_URL ")");

module_init(rohc_test_init);
module_exit(rohc_test_exit);

