// SPDX-License-Identifier: MulanPSL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "traffic_history.h"

bool traffic_history_open(struct traffic_history *history, size_t capacity, size_t key_size)
{
	if (!capacity || capacity > 16384 || !key_size || key_size > TRAFFIC_HISTORY_KEY_BYTES)
		return false;
	history->index_size = 1;
	while (history->index_size < capacity * 2)
		history->index_size *= 2;
	history->records = calloc(capacity, sizeof(*history->records));
	history->index = calloc(history->index_size, sizeof(*history->index));
	if (!history->records || !history->index) {
		traffic_history_close(history);
		return false;
	}
	history->capacity = capacity;
	history->key_size = key_size;
	return true;
}

void traffic_history_close(struct traffic_history *history)
{
	free(history->records);
	free(history->index);
	memset(history, 0, sizeof(*history));
}

void traffic_history_begin(struct traffic_history *history, const char *timestamp,
			   uint64_t now_ns, uint64_t elapsed_ns)
{
	size_t slot = history->sequence++ % TRAFFIC_HISTORY_SAMPLES;
	struct traffic_history_frame *frame = &history->frames[slot];

	frame->sequence = history->sequence;
	frame->elapsed_ns = elapsed_ns;
	snprintf(frame->timestamp, sizeof(frame->timestamp), "%s", timestamp);
	for (size_t i = 0; i < history->count; i++) {
		struct traffic_history_record *record = &history->records[i];

		memset(&record->samples[slot], 0, sizeof(record->samples[slot]));
		record->row.rx_rate = record->row.tx_rate = 0;
		record->row.archived = true;
		record->row.idle_seconds = now_ns > record->row.last_seen_ns ?
			(now_ns - record->row.last_seen_ns) / 1000000000.0 : 0;
	}
}

/* Stable record addresses keep a selected thread fixed while live rows sort. */
struct traffic_history_record *traffic_history_update(struct traffic_history *history,
				const void *key, const struct traffic_display_row *row)
{
	const unsigned char *bytes = key;
	uint64_t hash = 14695981039346656037ULL;
	struct traffic_history_record *record;
	size_t slot, sample = (history->sequence - 1) % TRAFFIC_HISTORY_SAMPLES;
	bool valid = row->sample_valid;

	for (size_t i = 0; i < history->key_size; i++)
		hash = (hash ^ bytes[i]) * 1099511628211ULL;
	slot = hash & (history->index_size - 1);
	while (history->index[slot]) {
		record = &history->records[history->index[slot] - 1];
		if (!memcmp(record->key, key, history->key_size))
			goto found;
		slot = (slot + 1) & (history->index_size - 1);
	}
	if (history->count == history->capacity) {
		history->full = true;
		return NULL;
	}
	record = &history->records[history->count++];
	memcpy(record->key, key, history->key_size);
	record->born_sequence = history->sequence;
	history->index[slot] = history->count;
found:
	/* Ignore a late snapshot of a generation that has already been replaced. */
	if (record->generation && row->first_seen_ns < record->generation) {
		record->row.archived = false;
		record->row.sample_valid = false;
		return record;
	}
	if (record->generation && record->generation != row->first_seen_ns) {
		record->rx_base = record->row.rx_bytes;
		record->tx_base = record->row.tx_bytes;
		record->rx_counter = record->tx_counter = 0;
	}
	if (row->rx_bytes < record->rx_counter || row->tx_bytes < record->tx_counter)
		valid = false;
	if (row->rx_bytes > record->rx_counter)
		record->rx_counter = row->rx_bytes;
	if (row->tx_bytes > record->tx_counter)
		record->tx_counter = row->tx_bytes;
	record->generation = row->first_seen_ns;
	record->row = *row;
	record->row.rx_bytes = record->rx_base + record->rx_counter;
	record->row.tx_bytes = record->tx_base + record->tx_counter;
	record->row.record = record;
	record->row.archived = false;
	record->row.sample_valid = valid;
	record->samples[sample] = (struct traffic_history_sample) {
		.rx_bytes = row->rx_delta, .tx_bytes = row->tx_delta, .available = valid,
	};
	return record;
}
