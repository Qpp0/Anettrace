// SPDX-License-Identifier: MulanPSL-2.0

#ifndef ANETTRACE_TRAFFIC_DISPLAY_H
#define ANETTRACE_TRAFFIC_DISPLAY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <termios.h>

struct traffic_display_row {
	uint32_t pid, tid, flow_count;
	char comm[17], protocol[8], local[64], remote[64];
	uint64_t rx_bytes, tx_bytes;
	double rx_rate, tx_rate, idle_seconds;
};

struct traffic_display_snapshot {
	const struct traffic_display_row *rows;
	size_t row_count;
	uint64_t rx_bytes, tx_bytes;
	double rx_rate, tx_rate, elapsed_seconds;
	unsigned int interval_seconds;
	const char *protocol, *filter, *warning;
	bool flows;
};

/* Zero-initialize before open; close is safe even when open was unsuccessful. */
struct traffic_display {
	bool active, input_saved;
	size_t first_row;
	struct termios saved_input;
};

double traffic_bytes_per_second(uint64_t delta, uint64_t elapsed_ns);
bool traffic_display_open(struct traffic_display *display);
/* Returns 'p', 'f', 'j', 'k', 'q', or zero; never reads redirected input. */
int traffic_display_read_key(struct traffic_display *display);
void traffic_display_render(struct traffic_display *display,
			    const struct traffic_display_snapshot *snapshot);
void traffic_display_close(struct traffic_display *display,
			   const struct traffic_display_snapshot *snapshot);

#endif
