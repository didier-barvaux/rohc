/**
 * @file wlsb.h
 * @brief Window-based Least Significant Bits (W-LSB) encoding
 * @author Didier Barvaux <didier.barvaux@b2i-toulouse.com>
 * @author The hackers from ROHC for Linux
 */

#ifndef WLSB_H
#define WLSB_H

#include <strings.h>

#include "rohc.h"


/// Default window width for W-LSB encoding
#define C_WINDOW_WIDTH 16


/**
 * @brief Defines a W-LSB window entry
 */
struct c_window
{
	/// @brief The Sequence Number (SN) associated with the entry (used to
	///        acknowledge the entry)
	int sn;

	/// @brief The time stamp associated with the entry (used to acknowledge
	///        the entry)
	int time;

	/// The value stored in the window entry
	int value;

	/// Whether the window entry is used or not
	boolean used;
};


/**
 * @brief Defines a W-LSB encoding object
 */
struct c_wlsb
{
	/// @brief The window in which numerous previous values of the encoded value
	///        are stored to help recreate the value
 	struct c_window *window;
	/// The width of the window
 	int window_width;

	/// A pointer on the oldest entry in the window (change on acknowledgement)
	int oldest;
	/// A pointer on the current entry in the window  (change on add and ack)
	int next;

	/// The maximal number of bits for representing the value
 	int bits;
	/// Shift parameter (see 4.5.2 in the RFC 3095)
 	int p;
};


/*
 * Public function prototypes:
 */

struct c_wlsb *c_create_wlsb(int bits, int window_width, int p);
void c_destroy_wlsb(struct c_wlsb *s);

void c_add_wlsb(struct c_wlsb *s, int sn, int time, int value);
int c_get_k_wlsb(struct c_wlsb *s, int value);

void c_ack_sn_wlsb(struct c_wlsb *s, int sn);
void c_ack_time_wlsb(struct c_wlsb *s, int time);

int c_sum_wlsb(struct c_wlsb *s);
int c_mean_wlsb(struct c_wlsb *s);
void c_print_wlsb(struct c_wlsb *s);

void print_wlsb_stats(struct c_wlsb *s);


#endif

