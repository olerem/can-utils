// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2023 Oleksij Rempel <linux@rempel-privat.de>


#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <limits.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <stdarg.h>

#include <linux/errqueue.h>
#include <linux/netlink.h>
#include <linux/net_tstamp.h>
#include <linux/socket.h>
#include <linux/can.h>

#include "isobusfs_cmn.h"
#include "isobusfs_srv.h"
#include "../libj1939.h"

#include "isobusfs_cmn.h"

static log_level_t log_level = LOG_LEVEL_DEBUG;

void isobusfs_log(log_level_t level, const char *fmt, ...)
{
	const char *level_str;
	struct timeval tv;
	struct tm *time_info;
	char time_buffer[64];
	int milliseconds;
	va_list args;

	if (level > log_level)
		return;

	switch (level) {
	case LOG_LEVEL_DEBUG:
		level_str = "DEBUG";
		break;
	case LOG_LEVEL_INFO:
		level_str = "INFO";
		break;
	case LOG_LEVEL_WARN:
		level_str = "WARNING";
		break;
	case LOG_LEVEL_ERROR:
		level_str = "ERROR";
		break;
	default:
		level_str = "UNKNOWN";
		break;
	}

	gettimeofday(&tv, NULL);
	time_info = localtime(&tv.tv_sec);
	milliseconds = tv.tv_usec / 1000;
	strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S",
		 time_info);
	snprintf(time_buffer + strlen(time_buffer),
		 sizeof(time_buffer) - strlen(time_buffer),
		 ".%03d", milliseconds);

	fprintf(stdout, "[%s] [%s]: ", time_buffer, level_str);

	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	va_end(args);

	fprintf(stdout, "\n");
}

/* set log level */
void isobusfs_log_level_set(log_level_t level)
{
	log_level = level;
}

/* Calculate timespec difference in milliseconds. Return negative difference
 * if in the past
 */
int64_t isobusfs_timespec_diff_ms(struct timespec *ts1,
					  struct timespec *ts2)
{
	int64_t diff = (ts1->tv_sec - ts2->tv_sec) * 1000;

	diff += (ts1->tv_nsec - ts2->tv_nsec) / 1000000;

	return diff;
}

void isobusfs_timespec_add_ms(struct timespec *ts, uint64_t milliseconds)
{
    uint64_t total_ns = ts->tv_nsec + (milliseconds * 1000000);

    ts->tv_sec += total_ns / 1000000000;
    ts->tv_nsec = total_ns % 1000000000;
}

int isobusfs_get_timeout_ms(struct timespec *ts)
{
	struct timespec curr_time;
	int64_t time_diff;
	int timeout_ms;

	clock_gettime(CLOCK_MONOTONIC, &curr_time);
	time_diff = isobusfs_timespec_diff_ms(ts, &curr_time);
 	if (time_diff < 0) {
		/* Too late to send next message. Send it now */
		timeout_ms = 0;
	} else {
		if (time_diff > INT_MAX) {
			warn("timeout too long: %ld ms", time_diff);
			time_diff = INT_MAX;
		}

		timeout_ms = time_diff;
	}

	return timeout_ms;
}

const char *isobusfs_error_to_str(enum isobusfs_error err)
{
	switch (err) {
	case ISOBUSFS_ERR_ACCESS_DENIED:
		return "Access Denied";
	case ISOBUSFS_ERR_INVALID_ACCESS:
		return "Invalid Access";
	case ISOBUSFS_ERR_TOO_MANY_FILES_OPEN:
		return "Too many files open";
	case ISOBUSFS_ERR_FILE_ORPATH_NOT_FOUND:
		return "File or path not found";
	case ISOBUSFS_ERR_INVALID_HANDLE:
		return "Invalid handle";
	case ISOBUSFS_ERR_INVALID_SRC_NAME:
		return "Invalid given source name";
	case ISOBUSFS_ERR_INVALID_DST_NAME:
		return "Invalid given destination name";
	case ISOBUSFS_ERR_NO_SPACE:
		return "Volume out of free space";
	case ISOBUSFS_ERR_ON_WRITE:
		return "Failure during a write operation";
	case ISOBUSFS_ERR_VOLUME_NOT_INITIALIZED:
		return "Volume is possibly not initialized";
	case ISOBUSFS_ERR_ON_READ:
		return "Failure during a read operation";
	case ISOBUSFS_ERR_FUNC_NOT_SUPPORTED:
		return "Function not supported";
	case ISOBUSFS_ERR_INVALID_REQUESTED_LENGHT:
		return "Invalid request length";
	case ISOBUSFS_ERR_OUT_OF_MEM:
		return "Out of memory";
	case ISOBUSFS_ERR_OTHER:
		return "Any other error";
	case ISOBUSFS_ERR_END_OF_FILE:
		return "End of file reached, will only be reported when file pointer is at end of file";
	default:
		return "<unknown>";
	}
}

void isobusfs_init_sockaddr_can(struct sockaddr_can *sac, uint32_t pgn)
{
	sac->can_family = AF_CAN;
	sac->can_addr.j1939.addr = J1939_NO_ADDR;
	sac->can_addr.j1939.name = J1939_NO_NAME;
	sac->can_addr.j1939.pgn = pgn;
}

static void isobusfs_print_timestamp(struct isobusfs_err_msg *emsg,
				     const char *name, struct timespec *cur)
{
	struct isobusfs_stats *stats = emsg->stats;

	/* TODO: make it configurable */
	return;

	if (!(cur->tv_sec | cur->tv_nsec))
		return;

	fprintf(stderr, "  %s: %lu s %lu us (seq=%u/%u, send=%u)",
			name, cur->tv_sec, cur->tv_nsec / 1000,
			stats->tskey_sch, stats->tskey_ack, stats->send);

	fprintf(stderr, "\n");
}

static const char *isobusfs_tstype_to_str(int tstype)
{
	switch (tstype) {
	case SCM_TSTAMP_SCHED:
		return "  ENQ";
	case SCM_TSTAMP_SND:
		return "  SND";
	case SCM_TSTAMP_ACK:
		return "  ACK";
	default:
		return "  unk";
	}
}

/* Check the stats of SCM_TIMESTAMPING_OPT_STATS */
static void isobusfs_scm_opt_stats(struct isobusfs_err_msg *emsg, void *buf, int len)
{
	struct isobusfs_stats *stats = emsg->stats;
	int offset = 0;

	while (offset < len) {
		struct nlattr *nla = (struct nlattr *) ((char *)buf + offset);

		switch (nla->nla_type) {
		case J1939_NLA_BYTES_ACKED:
			stats->send = *(uint32_t *)((char *)nla + NLA_HDRLEN);
			break;
		default:
			warnx("not supported J1939_NLA field\n");
		}

		offset += NLA_ALIGN(nla->nla_len);
	}
}

static int isobusfs_extract_serr(struct isobusfs_err_msg *emsg)
{
	struct isobusfs_stats *stats = emsg->stats;
	struct sock_extended_err *serr = emsg->serr;
	struct scm_timestamping *tss = emsg->tss;

	switch (serr->ee_origin) {
	case SO_EE_ORIGIN_TIMESTAMPING:
		/*
		 * We expect here following patterns:
		 *   serr->ee_info == SCM_TSTAMP_ACK
		 *     Activated with SOF_TIMESTAMPING_TX_ACK
		 * or
		 *   serr->ee_info == SCM_TSTAMP_SCHED
		 *     Activated with SOF_TIMESTAMPING_SCHED
		 * and
		 *   serr->ee_data == tskey
		 *     session message counter which is activate
		 *     with SOF_TIMESTAMPING_OPT_ID
		 * the serr->ee_errno should be ENOMSG
		 */
		if (serr->ee_errno != ENOMSG)
			warnx("serr: expected ENOMSG, got: %i",
			      serr->ee_errno);

		if (serr->ee_info == SCM_TSTAMP_SCHED)
			stats->tskey_sch = serr->ee_data;
		else
		 	stats->tskey_ack = serr->ee_data;

		isobusfs_print_timestamp(emsg, isobusfs_tstype_to_str(serr->ee_info),
				     &tss->ts[0]);

		if (serr->ee_info == SCM_TSTAMP_SCHED)
			return -EINTR;
		else
			return 0;
	case SO_EE_ORIGIN_LOCAL:
		/*
		 * The serr->ee_origin == SO_EE_ORIGIN_LOCAL is
		 * currently used to notify about locally
		 * detected protocol/stack errors.
		 * Following patterns are expected:
		 *   serr->ee_info == J1939_EE_INFO_TX_ABORT
		 *     is used to notify about session TX
		 *     abort.
		 *   serr->ee_data == tskey
		 *     session message counter which is activate
		 *     with SOF_TIMESTAMPING_OPT_ID
		 *   serr->ee_errno == actual error reason
		 *     error reason is converted from J1939
		 *     abort to linux error name space.
		 */
		if (serr->ee_info != J1939_EE_INFO_TX_ABORT)
			warnx("serr: unknown ee_info: %i",
			      serr->ee_info);

		isobusfs_print_timestamp(emsg, "  ABT", &tss->ts[0]);
		warnx("serr: tx error: %i, %s", serr->ee_errno, strerror(serr->ee_errno));

		return serr->ee_errno;
	default:
		warnx("serr: wrong origin: %u", serr->ee_origin);
	}

	return 0;
}

static int isobusfs_parse_cm(struct isobusfs_err_msg *emsg,
			     struct cmsghdr *cm)
{
	const size_t hdr_len = CMSG_ALIGN(sizeof(struct cmsghdr));

	if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_TIMESTAMPING) {
		emsg->tss = (void *)CMSG_DATA(cm);
	} else if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_TIMESTAMPING_OPT_STATS) {
		void *jstats = (void *)CMSG_DATA(cm);

		/* Activated with SOF_TIMESTAMPING_OPT_STATS */
		isobusfs_scm_opt_stats(emsg, jstats, cm->cmsg_len - hdr_len);
	} else if (cm->cmsg_level == SOL_CAN_J1939 &&
		   cm->cmsg_type == SCM_J1939_ERRQUEUE) {
		emsg->serr = (void *)CMSG_DATA(cm);
	} else
		warnx("serr: not supported type: %d.%d",
		      cm->cmsg_level, cm->cmsg_type);

	return 0;
}

int isobusfs_recv_err(int sock, struct isobusfs_err_msg *emsg)
{
	char control[200];
	struct cmsghdr *cm;
	int ret;
	struct msghdr msg = {
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};

	ret = recvmsg(sock, &msg, MSG_ERRQUEUE);
	if (ret == -1)
		err(EXIT_FAILURE, "recvmsg error notification: %i", errno);
	if (msg.msg_flags & MSG_CTRUNC)
		err(EXIT_FAILURE, "recvmsg error notification: truncated");

	emsg->serr = NULL;
	emsg->tss = NULL;

	for (cm = CMSG_FIRSTHDR(&msg); cm && cm->cmsg_len;
	     cm = CMSG_NXTHDR(&msg, cm)) {
		isobusfs_parse_cm(emsg, cm);
		if (emsg->serr && emsg->tss)
			return isobusfs_extract_serr(emsg);
	}

	return 0;
}

/* send NACK message. function should use src, dst and socket as parameters */
void isobusfs_send_nack(int sock, struct isobusfs_msg *msg,
			uint8_t address_nack)
{
	struct sockaddr_can addr = msg->peername;
	struct isobusfs_nack nack;
	int ret;

	nack.ctrl = ISOBUS_ACK_CTRL_NACK;
	nack.pgn_nack = msg->peername.can_addr.j1939.pgn & 0xffff;
	nack.address_nack = address_nack;

	addr.can_addr.j1939.pgn = ISOBUS_PGN_ACK;

	ret = sendto(sock, &nack, sizeof(nack), MSG_DONTWAIT,
			  (struct sockaddr *)&addr,
			   sizeof(addr));
	if (ret == -1)
		pr_warn("failed to send NACK: %i (%s)", errno, strerror(errno));

	return;
}

/* store data to a recursive buffer */
void isobufs_store_tx_data(struct isobusfs_buf_log *buffer, uint8_t *data) {
	struct isobusfs_buf *entry = &buffer->entries[buffer->index];

	/* we assume :) that data is at least 8 bytes long */
	memcpy(entry->data, data, sizeof(entry->data));
	clock_gettime(CLOCK_REALTIME, &entry->ts);

	buffer->index = (buffer->index + 1) % ISOBUSFS_MAX_BUF_ENTRIES;
}

void isobusfs_dump_tx_data(const struct isobusfs_buf_log *buffer) {
	uint i;

	for (i = 0; i < ISOBUSFS_MAX_BUF_ENTRIES; ++i) {
		const struct isobusfs_buf *entry = &buffer->entries[i];
		char data_str[ISOBUSFS_MIN_TRANSFER_LENGH * 3] = {0};
		uint j;

		for (j = 0; j < ISOBUSFS_MIN_TRANSFER_LENGH; ++j) {
			 snprintf(data_str + j * 3, 4, "%02X ", entry->data[j]);
		}

		pr_debug("Entry %u: %s Timestamp: %ld.%09ld\n", i, data_str,
			 entry->ts.tv_sec, entry->ts.tv_nsec);
	}
}

/* wrapper for sendto() */
int isobusfs_sendto(int sock, const void *data, size_t len,
		    const struct sockaddr_can *addr,
		    struct isobusfs_buf_log *isobusfs_tx_buffer)
{
	int ret;

	/* store to tx buffer */
	isobufs_store_tx_data(isobusfs_tx_buffer, (uint8_t *)data);

	ret = sendto(sock, data, len, MSG_DONTWAIT,
		     (struct sockaddr *)addr, sizeof(*addr));
	if (ret == -1)
		pr_warn("failed to send data: %i (%s)", errno, strerror(errno));

	return ret;
}

/* wrapper for send() */
int isobusfs_send(int sock, const void *data, size_t len,
		  struct isobusfs_buf_log *isobusfs_tx_buffer)
{
	int ret;

	/* store to tx buffer */
	isobufs_store_tx_data(isobusfs_tx_buffer, (uint8_t *)data);

	ret = send(sock, data, len, MSG_DONTWAIT);
	if (ret == -1)
		pr_warn("failed to send data: %i (%s)", errno, strerror(errno));

	return ret;
}
