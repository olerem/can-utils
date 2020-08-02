// SPDX-License-Identifier: GPL-2.0-only

#ifndef ISOBUSFS_SRV_H
#define ISOBUSFS_SRV_H

#include <sys/epoll.h>

#include "isobusfs_cmn.h"

#define ISOBUSFS_SRV_MAX_CTRL_SOCKETS		1
#define ISOBUSFS_SRV_MAX_CLIENT_SOCKETS		255
#define ISOBUSFS_SRV_MAX_EPOLL_EVENTS		(ISOBUSFS_SRV_MAX_CTRL_SOCKETS + \
						 ISOBUSFS_SRV_MAX_CLIENT_SOCKETS)

/*
 * ISO 11783-13:2021 standard does not explicitly specify a maximum number of
 * clients that can be supported on the network. However, the ISO 11783 standard
 * is built on top of the SAE J1939 protocol, which has a maximum of 238
 * available addresses for nodes. This number is calculated from the available
 * address range for assignment to nodes on the network, which includes 127
 * addresses in the range 1-127 and 111 addresses in the range 248-254,
 * inclusive. Some addresses in the total range (0-255) are reserved for
 * specific purposes, such as broadcast messages and null addresses.
 *
 * The maximum number of 238 nodes includes both clients and servers, so the
 * actual number of clients that can be supported will be less than 238.
 *
 * It is important to note that the practical limit of clients in an ISO
 * 11783-13 network could be lower due to factors such as network bandwidth,
 * performance constraints of the individual devices, and the complexity of the
 * network.
 */
#define ISOBUSFS_SRV_MAX_CLIENTS			237

enum isobusfs_srv_fss_state {
	ISOBUSFS_SRV_STATE_IDLE = 0, /* send status with 2000ms interval */
	ISOBUSFS_SRV_STATE_STAT_CHANGE_1, /* send status with 200ms interval */
	ISOBUSFS_SRV_STATE_STAT_CHANGE_2, /* send status with 200ms interval */
	ISOBUSFS_SRV_STATE_STAT_CHANGE_3, /* send status with 200ms interval */
	ISOBUSFS_SRV_STATE_STAT_CHANGE_4, /* send status with 200ms interval */
	ISOBUSFS_SRV_STATE_STAT_CHANGE_5, /* send status with 200ms interval */
	ISOBUSFS_SRV_STATE_BUSY, /* send status with 200ms interval */
};

struct isobusfs_srv_client {
	int sock;
	struct timespec last_received;
	uint8_t addr;
	uint8_t tan;
};

struct isobusfs_srv_priv {
	int ctrl_sock;
	int epoll_fd;
	struct sockaddr_can addr;

	/* fs status related variables */
	struct isobusfs_cm_fs_status st; /* file server status message */
	struct sockaddr_can st_name;
	enum isobusfs_srv_fss_state st_state;
	struct isobusfs_stats st_msg_stats;
	struct timespec st_next_send_time;

	struct epoll_event epoll_events[ISOBUSFS_SRV_MAX_EPOLL_EVENTS];

	/* client related variables */
 	struct isobusfs_srv_client clients[ISOBUSFS_SRV_MAX_CLIENTS];
	int clients_count;
	struct timespec last_time;
	struct isobusfs_buf_log tx_buf_log;
};

/* isobusfs_srv.c */
int isobusfs_srv_send_error(struct isobusfs_srv_priv *priv, struct isobusfs_msg *msg,
			 enum isobusfs_error err);
int isobusfs_srv_sendto(struct isobusfs_srv_priv *priv, struct isobusfs_msg *msg,
		     const void *buf, size_t buf_size);

/* isobusfs_srv_cm_fss.c */
void isobusfs_srv_fss_init(struct isobusfs_srv_priv *priv);
int isobusfs_srv_fss_send(struct isobusfs_srv_priv *priv);

/* isobusfs_srv_cm.c */
int isobusfs_srv_rx_cg_cm(struct isobusfs_srv_priv *priv, struct isobusfs_msg *msg);
void isobusfs_srv_remove_timeouted_clients(struct isobusfs_srv_priv *priv);
void isobusfs_srv_init_clients(struct isobusfs_srv_priv *priv);

#endif /* ISOBUSFS_SRV_H */
