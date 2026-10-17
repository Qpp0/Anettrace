// SPDX-License-Identifier: MulanPSL-2.0

#ifndef ANETTRACE_TRAFFIC_DISPLAY_H
#define ANETTRACE_TRAFFIC_DISPLAY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <termios.h>

struct traffic_history_record;
struct traffic_history;

struct traffic_display_row {
	uint32_t pid, tid, flow_count;
	char comm[17], protocol[8], local[64], remote[64];
	char last_seen[20];
	uint64_t rx_bytes, tx_bytes;
	uint64_t rx_delta, tx_delta, first_seen_ns, last_seen_ns;
	const struct traffic_history_record *record;
	double rx_rate, tx_rate, idle_seconds;
	bool sample_valid, archived;
};

struct traffic_display_snapshot {
	const struct traffic_display_row *rows;
	size_t row_count;
	uint64_t rx_bytes, tx_bytes;
	double rx_rate, tx_rate, elapsed_seconds;
	unsigned int interval_seconds;
	char timestamp[20];
	const char *protocol, *filter, *warning;
	const struct traffic_history *history;
	bool flows;
};

/* Zero-initialize before open; close is safe even when open was unsuccessful. */
struct traffic_display {
	bool active, input_saved;
	size_t first_row;
	size_t history_scroll;
	const struct traffic_history_record *history_record;
	struct termios saved_input;
};

double traffic_bytes_per_second(uint64_t delta, uint64_t elapsed_ns);
bool traffic_display_open(struct traffic_display *display);
/* Returns a supported key or zero; never reads redirected input. */
int traffic_display_read_key(struct traffic_display *display);
bool traffic_display_key(struct traffic_display *display,
			 struct traffic_display_snapshot *snapshot, int key);
void traffic_display_render(struct traffic_display *display,
			    const struct traffic_display_snapshot *snapshot);
void traffic_display_close(struct traffic_display *display,
			   const struct traffic_display_snapshot *snapshot);

#endif
