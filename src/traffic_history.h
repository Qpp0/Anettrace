// SPDX-License-Identifier: MulanPSL-2.0
#ifndef ANETTRACE_TRAFFIC_HISTORY_H
#define ANETTRACE_TRAFFIC_HISTORY_H

#include "traffic_display.h"

#define TRAFFIC_HISTORY_SAMPLES 60
#define TRAFFIC_HISTORY_KEY_BYTES 128

struct traffic_history_sample {
	uint64_t rx_bytes, tx_bytes;
	bool available;
};

struct traffic_history_frame {
	uint64_t sequence, elapsed_ns;
	char timestamp[20];
};

struct traffic_history_record {
	unsigned char key[TRAFFIC_HISTORY_KEY_BYTES];
	struct traffic_display_row row;
	struct traffic_history_sample samples[TRAFFIC_HISTORY_SAMPLES];
	uint64_t born_sequence, rx_base, tx_base, rx_counter, tx_counter, generation;
};

struct traffic_history {
	struct traffic_history_record *records;
	uint32_t *index;
	size_t count, capacity, key_size, index_size;
	uint64_t sequence;
	struct traffic_history_frame frames[TRAFFIC_HISTORY_SAMPLES];
	bool full;
};

bool traffic_history_open(struct traffic_history *history, size_t capacity, size_t key_size);
void traffic_history_close(struct traffic_history *history);
void traffic_history_begin(struct traffic_history *history, const char *timestamp,
			   uint64_t now_ns, uint64_t elapsed_ns);
struct traffic_history_record *traffic_history_update(struct traffic_history *history,
				const void *key, const struct traffic_display_row *row);

#endif
