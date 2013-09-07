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
 * @file   linux/include/assert.h
 * @brief  Export the ROHC library to the Linux kernel
 * @author Mikhail Gruzdev <michail.gruzdev@gmail.com>
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include <linux/module.h>
#include <linux/slab.h>
#include "config.h"
#include "rohc.h"
#include "rohc_comp.h"
#include "rohc_decomp.h"


MODULE_VERSION(PACKAGE_VERSION);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mikhail Gruzdev, Viveris Technologies");
MODULE_DESCRIPTION(PACKAGE_NAME ", version " PACKAGE_VERSION " (" PACKAGE_URL ")");


/*
 * General API
 */

EXPORT_SYMBOL_GPL(rohc_version);
EXPORT_SYMBOL_GPL(rohc_get_mode_descr);
EXPORT_SYMBOL_GPL(rohc_get_packet_descr);
EXPORT_SYMBOL_GPL(rohc_get_ext_descr);


/*
 * Compression API
 */

/* general */
EXPORT_SYMBOL_GPL(rohc_comp_new);
EXPORT_SYMBOL_GPL(rohc_comp_free);
EXPORT_SYMBOL_GPL(rohc_compress3);
EXPORT_SYMBOL_GPL(rohc_comp_force_contexts_reinit);

/* segment */
EXPORT_SYMBOL_GPL(rohc_comp_get_segment);

/* feedback */
EXPORT_SYMBOL_GPL(rohc_feedback_flush);
EXPORT_SYMBOL_GPL(rohc_comp_piggyback_feedback);
EXPORT_SYMBOL_GPL(rohc_feedback_remove_locked);
EXPORT_SYMBOL_GPL(rohc_feedback_unlock);

/* statistics */
EXPORT_SYMBOL_GPL(rohc_comp_get_state_descr);
EXPORT_SYMBOL_GPL(rohc_comp_get_general_info);
EXPORT_SYMBOL_GPL(rohc_comp_get_last_packet_info2);

/* configuration */
EXPORT_SYMBOL_GPL(rohc_comp_enable_profile);
EXPORT_SYMBOL_GPL(rohc_comp_disable_profile);
EXPORT_SYMBOL_GPL(rohc_comp_enable_profiles);
EXPORT_SYMBOL_GPL(rohc_comp_disable_profiles);
EXPORT_SYMBOL_GPL(rohc_comp_set_mrru);
EXPORT_SYMBOL_GPL(rohc_comp_get_mrru);
EXPORT_SYMBOL_GPL(rohc_c_set_max_cid);
EXPORT_SYMBOL_GPL(rohc_comp_get_max_cid);
EXPORT_SYMBOL_GPL(rohc_c_set_large_cid);
EXPORT_SYMBOL_GPL(rohc_comp_get_cid_type);
EXPORT_SYMBOL_GPL(rohc_comp_set_wlsb_window_width);
EXPORT_SYMBOL_GPL(rohc_comp_set_periodic_refreshes);
EXPORT_SYMBOL_GPL(rohc_comp_set_traces_cb);
EXPORT_SYMBOL_GPL(rohc_comp_set_random_cb);

/* RTP-specific configuration */
EXPORT_SYMBOL_GPL(rohc_comp_add_rtp_port);
EXPORT_SYMBOL_GPL(rohc_comp_remove_rtp_port);
EXPORT_SYMBOL_GPL(rohc_comp_reset_rtp_ports);
EXPORT_SYMBOL_GPL(rohc_comp_set_rtp_detection_cb);


/*
 * Decompression API
 */

/* general */
EXPORT_SYMBOL_GPL(rohc_alloc_decompressor);
EXPORT_SYMBOL_GPL(rohc_free_decompressor);
EXPORT_SYMBOL_GPL(rohc_decompress2);

/* statistics */
EXPORT_SYMBOL_GPL(rohc_decomp_get_state_descr);
EXPORT_SYMBOL_GPL(rohc_decomp_get_last_packet_info);

/* configuration */
EXPORT_SYMBOL_GPL(rohc_decomp_set_cid_type);
EXPORT_SYMBOL_GPL(rohc_decomp_set_max_cid);
EXPORT_SYMBOL_GPL(rohc_decomp_set_mrru);
EXPORT_SYMBOL_GPL(rohc_decomp_set_traces_cb);

