// SPDX-License-Identifier: MulanPSL-2.0

#include <errno.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "traffic_display.h"

#define COLOR_TITLE "\033[1;36m"
#define COLOR_RX "\033[32m"
#define COLOR_TX "\033[94m"
#define COLOR_MUTED "\033[90m"
#define COLOR_RESET "\033[0m"

struct traffic_frame {
	unsigned int width, limit, used;
};

static int traffic_set_input(const struct termios *input)
{
	int result;

	do {
		result = tcsetattr(STDIN_FILENO, TCSANOW, input);
	} while (result && errno == EINTR);
	return result;
}

double traffic_bytes_per_second(uint64_t delta, uint64_t elapsed_ns)
{
	return elapsed_ns ? (double)delta * 1000000000.0 / elapsed_ns : 0;
}

static void traffic_format_bytes(double bytes, bool rate, char *text, size_t size)
{
	static const char *const units[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"};
	unsigned int unit = 0;
	int precision;

	if (!isfinite(bytes) || bytes < 0)
		bytes = 0;
	while (bytes >= 1024 && unit + 1 < sizeof(units) / sizeof(units[0])) {
		bytes /= 1024;
		unit++;
	}
	precision = !unit ? 0 : bytes < 10 ? 2 : bytes < 100 ? 1 : 0;
	snprintf(text, size, "%.*f %s%s", precision, bytes, units[unit], rate ? "/s" : "");
}

/* Recognize the CJK block used by labels without changing the process locale. */
static unsigned int traffic_character_cells(const char *text, size_t length,
					     unsigned int *bytes)
{
	unsigned char c = text[0];

	*bytes = 1;
	if (c >= 0xe4 && c <= 0xe9 && length >= 3 &&
	    ((unsigned char)text[1] & 0xc0) == 0x80 &&
	    ((unsigned char)text[2] & 0xc0) == 0x80) {
		unsigned int codepoint = ((c & 0x0f) << 12) |
			(((unsigned char)text[1] & 0x3f) << 6) |
			((unsigned char)text[2] & 0x3f);

		if (codepoint >= 0x4e00 && codepoint <= 0x9fff) {
			*bytes = 3;
			return 2;
		}
	}
	return 1;
}

/* printf pads bytes, while the terminal displays CJK names using two cells. */
static int traffic_comm_field_width(const char *comm)
{
	size_t length = strlen(comm), i = 0;
	int width = 16;

	while (i < length) {
		unsigned int bytes, cells = traffic_character_cells(comm + i, length - i, &bytes);

		width += bytes - cells;
		i += bytes;
	}
	return width;
}

/* ASCII uses one cell, CJK labels use two; escape other/control bytes. */
static void traffic_line(struct traffic_frame *frame, const char *color,
			 const char *format, ...)
{
	char text[1024], clean[1024];
	size_t length, i = 0, used = 0, columns = 0, fit = 0, ellipsis = 0, available;
	va_list args;

	if (frame->used >= frame->limit)
		return;
	va_start(args, format);
	vsnprintf(text, sizeof(text), format, args);
	va_end(args);
	length = strlen(text);
	available = frame->width ? frame->width - 1 : 0;
	while (i < length) {
		unsigned char c = text[i];
		unsigned int bytes, cells = traffic_character_cells(text + i, length - i, &bytes);
		bool printable = cells == 2 || (c >= 32 && c <= 126);
		if (printable)
			memcpy(clean + used, text + i, bytes);
		else
			clean[used] = '?';
		used += bytes;
		i += bytes;
		columns += cells;
		if (columns <= available)
			fit = used;
		if (columns + 3 <= available)
			ellipsis = used;
	}
	if (columns > available) {
		used = available >= 3 ? ellipsis : fit;
		if (available >= 3) {
			memcpy(clean + used, "...", 3);
			used += 3;
		}
	}
	clean[used] = '\0';
	fputs("\033[2K", stdout);
	if (color)
		fputs(color, stdout);
	fputs(clean, stdout);
	fputs(COLOR_RESET "\r\n", stdout);
	frame->used++;
}

bool traffic_display_open(struct traffic_display *display)
{
	const char *term = getenv("TERM");
	struct termios input;

	if (display->active)
		return true;
	if (!isatty(STDOUT_FILENO) || !term || !*term || !strcmp(term, "dumb"))
		return false;
	if (isatty(STDIN_FILENO) && !tcgetattr(STDIN_FILENO, &display->saved_input)) {
		input = display->saved_input;
		input.c_lflag &= ~(ECHO | ICANON);
		input.c_cc[VMIN] = 0;
		input.c_cc[VTIME] = 0;
		display->input_saved = !traffic_set_input(&input);
	}
	display->active = true;
	fputs("\033[?1049h\033[?25l\033[2J\033[H", stdout);
	fflush(stdout);
	return true;
}

int traffic_display_read_key(struct traffic_display *display)
{
	unsigned char key;
	unsigned int consumed = 0;

	if (!display->active || !display->input_saved)
		return 0;
	while (consumed++ < 64 && read(STDIN_FILENO, &key, 1) == 1)
		if (key == 'p' || key == 'f' || key == 'j' || key == 'k' || key == 'q')
			return key;
	return 0;
}

/* Keep complete IPv6 addresses and ports, including in a phone terminal. */
static unsigned int traffic_endpoint_lines(const char *endpoint, unsigned int width)
{
	size_t length = strlen(endpoint);
	unsigned int chunk = width - 8;

	return length ? (unsigned int)((length + chunk - 1) / chunk) : 1;
}

static void traffic_render_endpoint(struct traffic_frame *frame,
				    const char *label, const char *endpoint)
{
	unsigned int chunk = frame->width - 8;
	size_t offset = 0, length = strlen(endpoint);

	do {
		traffic_line(frame, COLOR_MUTED, "%-7s%.*s", offset ? "" : label,
			     (int)chunk, endpoint + offset);
		offset += length - offset < chunk ? length - offset : chunk;
	} while (offset < length);
}

static unsigned int traffic_row_lines(const struct traffic_display_row *row,
				     bool flows, bool wide, bool spacing,
				     unsigned int width)
{
	unsigned int lines = wide ? 1 : 3;

	if (flows) {
		lines = wide ? 1 : 4;
		lines += traffic_endpoint_lines(row->local, width);
		lines += traffic_endpoint_lines(row->remote, width);
	}
	if (!wide && width < 40)
		lines += 2;
	return lines + spacing;
}

static void traffic_render_row(struct traffic_frame *frame,
			       const struct traffic_display_row *row, bool flows,
			       bool wide, bool spacing)
{
	char rx[32], tx[32], rx_total[32], tx_total[32], status[40];

	traffic_format_bytes(row->rx_rate, true, rx, sizeof(rx));
	traffic_format_bytes(row->tx_rate, true, tx, sizeof(tx));
	traffic_format_bytes((double)row->rx_bytes, false, rx_total, sizeof(rx_total));
	traffic_format_bytes((double)row->tx_bytes, false, tx_total, sizeof(tx_total));
	if (row->idle_seconds >= 1)
		snprintf(status, sizeof(status), "idle %.0fs", row->idle_seconds);
	else
		snprintf(status, sizeof(status), "%u recent flows", row->flow_count);
	if (wide) {
		if (flows) {
			traffic_line(frame, NULL, "%-7u %-*.16s %-7u %-3.3s %12s %12s %11s %11s",
				     row->tid, traffic_comm_field_width(row->comm), row->comm,
				     row->pid, row->protocol,
				     rx, tx, rx_total, tx_total);
			traffic_render_endpoint(frame, "Local", row->local);
			traffic_render_endpoint(frame, "Remote", row->remote);
		} else {
			traffic_line(frame, NULL, "%-7u %-*.16s %12s %12s %11s %11s %s",
				     row->pid, traffic_comm_field_width(row->comm), row->comm,
				     rx, tx, rx_total, tx_total, status);
		}
	} else {
		if (flows) {
			traffic_line(frame, NULL, "TID %u %.16s", row->tid, row->comm);
			traffic_line(frame, COLOR_MUTED, "PID %u %.7s%s", row->pid,
				     row->protocol, row->idle_seconds >= 1 ? " | idle" : "");
		} else {
			traffic_line(frame, NULL, "%u %.16s | %s", row->pid, row->comm, status);
		}
		if (flows) {
			traffic_render_endpoint(frame, "Local", row->local);
			traffic_render_endpoint(frame, "Remote", row->remote);
		}
		if (frame->width < 40) {
			traffic_line(frame, COLOR_RX, "接收速率  %s", rx);
			traffic_line(frame, COLOR_TX, "发送速率  %s", tx);
			traffic_line(frame, NULL, "累计接收  %s", rx_total);
			traffic_line(frame, NULL, "累计发送  %s", tx_total);
		} else {
			traffic_line(frame, COLOR_RX, "RX %-12s | 累计接收 %s", rx, rx_total);
			traffic_line(frame, COLOR_TX, "TX %-12s | 累计发送 %s", tx, tx_total);
		}
	}
	if (spacing)
		traffic_line(frame, NULL, "");
}

static unsigned int traffic_warning_lines(const char *warning, unsigned int width)
{
	size_t length = warning ? strlen(warning) : 0;
	unsigned int count;

	if (!length || width < 2)
		return 0;
	count = (unsigned int)((length + width - 2) / (width - 1));
	return count > 3 ? 3 : count;
}

void traffic_display_render(struct traffic_display *display,
			    const struct traffic_display_snapshot *snapshot)
{
	struct winsize window = {0};
	struct traffic_frame frame = {.width = 80, .limit = 23};
	char rx[32], tx[32], rx_total[32], tx_total[32];
	unsigned int warning_lines, footer_lines, available, shown, i;
	bool wide, spacing;

	if (!display->active || !snapshot)
		return;
	if (!ioctl(STDOUT_FILENO, TIOCGWINSZ, &window)) {
		if (window.ws_col)
			frame.width = window.ws_col;
		if (window.ws_row)
			frame.limit = window.ws_row - 1;
	}
	/* Reserve complete Chinese footer lines before admitting any detail rows. */
	footer_lines = (frame.width < 64 ? 4 : 2) +
		(display->input_saved && frame.width < 44 ? 2 : 1);
	fputs("\033[H", stdout);
	traffic_line(&frame, COLOR_TITLE, "ANETTRACE / TRAFFIC LAB");
	if (frame.width < 32 || frame.limit < 12 + footer_lines) {
		traffic_line(&frame, COLOR_MUTED, "请放大终端");
		traffic_line(&frame, COLOR_MUTED, display->input_saved ? "q 退出" : "Ctrl-C 停止");
		goto done;
	}
	traffic_line(&frame, COLOR_TITLE, "%s  %s  %.0fs",
		     snapshot->flows ? "THREAD VIEW" : "PROCESS VIEW",
		     snapshot->protocol ? snapshot->protocol : "TCP/UDP", snapshot->elapsed_seconds);
	traffic_line(&frame, COLOR_MUTED, "%s | every %us",
		     snapshot->filter ? snapshot->filter : "All processes", snapshot->interval_seconds);
	traffic_line(&frame, NULL, "");
	traffic_format_bytes(snapshot->rx_rate, true, rx, sizeof(rx));
	traffic_format_bytes(snapshot->tx_rate, true, tx, sizeof(tx));
	traffic_format_bytes((double)snapshot->rx_bytes, false, rx_total, sizeof(rx_total));
	traffic_format_bytes((double)snapshot->tx_bytes, false, tx_total, sizeof(tx_total));
	traffic_line(&frame, COLOR_TITLE, "当前速率");
	traffic_line(&frame, COLOR_RX, "RX  %s", rx);
	traffic_line(&frame, COLOR_TX, "TX  %s", tx);
	traffic_line(&frame, COLOR_MUTED, "本次累计");
	traffic_line(&frame, NULL, "累计接收  %s", rx_total);
	traffic_line(&frame, NULL, "累计发送  %s", tx_total);
	traffic_line(&frame, NULL, "");
	wide = frame.width >= (snapshot->flows ? 110 : 100);
	spacing = !wide && frame.limit >= 30;
	if (wide && snapshot->flows)
		traffic_line(&frame, COLOR_MUTED,
			     "%-7s %-16s %-7s %-3s     接收速率     发送速率    累计接收    累计发送",
			     "TID", "THREAD", "PID", "P");
	else if (wide)
		traffic_line(&frame, COLOR_MUTED,
			     "%-7s %-16s     接收速率     发送速率    累计接收    累计发送 %s",
			     "PID", "COMMAND", "RECENT");
	else
		traffic_line(&frame, COLOR_MUTED, "明细: 当前速率 | 累计量");
	warning_lines = traffic_warning_lines(snapshot->warning, frame.width);
	/* A short terminal must still leave room for every footer control. */
	if (warning_lines > frame.limit - frame.used - footer_lines)
		warning_lines = frame.limit - frame.used - footer_lines;
	available = frame.limit > frame.used + warning_lines + footer_lines ?
		frame.limit - frame.used - warning_lines - footer_lines : 0;
	if (!snapshot->row_count)
		display->first_row = 0;
	else if (display->first_row >= snapshot->row_count)
		display->first_row = snapshot->row_count - 1;
	shown = 0;
	while (display->first_row + shown < snapshot->row_count) {
		const struct traffic_display_row *row = &snapshot->rows[display->first_row + shown];
		unsigned int lines = traffic_row_lines(row, snapshot->flows, wide, spacing,
						       frame.width);

		if (lines > available)
			break;
		traffic_render_row(&frame, row, snapshot->flows, wide, spacing);
		available -= lines;
		shown++;
	}
	if (!snapshot->row_count && available)
		traffic_line(&frame, COLOR_MUTED, "等待 Socket 收发...");
	if (frame.width < 64) {
		traffic_line(&frame, COLOR_MUTED, "记录 %zu-%zu/%zu",
			     shown ? display->first_row + 1 : 0,
			     shown ? display->first_row + shown : 0, snapshot->row_count);
		traffic_line(&frame, COLOR_MUTED, "未显示 %zu 条", snapshot->row_count - shown);
	} else {
		traffic_line(&frame, COLOR_MUTED, "记录 %zu-%zu/%zu | 未显示 %zu 条",
			     shown ? display->first_row + 1 : 0,
			     shown ? display->first_row + shown : 0,
			     snapshot->row_count, snapshot->row_count - shown);
	}
	for (i = 0; i < warning_lines; i++) {
		size_t offset = (size_t)i * (frame.width - 1);
		const char *suffix = snapshot->warning + offset;

		if (i + 1 == warning_lines)
			traffic_line(&frame, COLOR_MUTED, "%s", suffix);
		else
			traffic_line(&frame, COLOR_MUTED, "%.*s", (int)frame.width - 1, suffix);
	}
	if (frame.width < 64) {
		traffic_line(&frame, COLOR_MUTED, "统计: Socket 收发字节");
		traffic_line(&frame, COLOR_MUTED, "含 TLS 开销及 PEEK 读取");
	} else {
		traffic_line(&frame, COLOR_MUTED, "统计: Socket 收发字节; 含 TLS 开销及 PEEK 读取");
	}
	if (display->input_saved && frame.width < 44) {
		traffic_line(&frame, COLOR_MUTED, "p 进程 | f 线程 | q 退出");
		traffic_line(&frame, COLOR_MUTED, "j/k 滚动");
	} else {
		traffic_line(&frame, COLOR_MUTED, display->input_saved ?
			     "p 进程 | f 线程 | j/k 滚动 | q 退出" : "Ctrl-C 停止");
	}
done:
	fputs("\033[J", stdout);
	fflush(stdout);
}

void traffic_display_close(struct traffic_display *display,
			   const struct traffic_display_snapshot *snapshot)
{
	char rx[32], tx[32], rx_average[32], tx_average[32];
	bool was_active = display->active;
	double elapsed;

	if (display->input_saved) {
		traffic_set_input(&display->saved_input);
		display->input_saved = false;
	}
	display->active = false;
	if (!was_active)
		return;
	fputs(COLOR_RESET "\033[?25h\033[?1049l", stdout);
	if (snapshot) {
		elapsed = snapshot->elapsed_seconds;
		traffic_format_bytes((double)snapshot->rx_bytes, false, rx, sizeof(rx));
		traffic_format_bytes((double)snapshot->tx_bytes, false, tx, sizeof(tx));
		traffic_format_bytes(elapsed > 0 ? snapshot->rx_bytes / elapsed : 0,
				     true, rx_average, sizeof(rx_average));
		traffic_format_bytes(elapsed > 0 ? snapshot->tx_bytes / elapsed : 0,
				     true, tx_average, sizeof(tx_average));
		printf("Traffic session complete\nRX session  %s\nTX session  %s\n"
		       "RX average  %s\nTX average  %s\n", rx, tx, rx_average, tx_average);
	}
	fflush(stdout);
}
