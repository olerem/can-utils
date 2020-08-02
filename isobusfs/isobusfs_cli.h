// SPDX-License-Identifier: GPL-2.0-only


#ifndef ISOBUSFS_CLI_H
#define ISOBUSFS_CLI_H

#include <sys/epoll.h>
#include <stdbool.h>

#include "isobusfs_cmn.h"
#include "isobusfs_cmn_cm.h"

#define ISOBUSFS_CLI_MAX_EPOLL_EVENTS		2

enum isobusfs_cli_state {
	ISOBUSFS_CLI_STATE_CONNECTING,
	ISOBUSFS_CLI_STATE_IDLE,
	ISOBUSFS_CLI_STATE_SELFTEST,
	ISOBUSFS_CLI_STATE_WAIT_FS_PROPERTIES,
	ISOBUSFS_CLI_STATE_WAIT_CURRENT_DIR,
	ISOBUSFS_CLI_STATE_WAIT_CCD_RESP,
	ISOBUSFS_CLI_STATE_WAIT_OF_RESP,
	ISOBUSFS_CLI_STATE_WAIT_FILE_SIZE,
	ISOBUSFS_CLI_STATE_WAIT_FILE,
	ISOBUSFS_CLI_STATE_WAIT_VOLUME_STATUS,
	ISOBUSFS_CLI_STATE_WAIT_CF_RESP,
	ISOBUSFS_CLI_STATE_MAX_WAITING,

	ISOBUSFS_CLI_STATE_CONNECTING_DONE,
	ISOBUSFS_CLI_STATE_GET_FS_PROPERTIES_DONE,
	ISOBUSFS_CLI_STATE_GET_CURRENT_DIR_DONE,
	ISOBUSFS_CLI_STATE_GET_FILE_SIZE_DONE,
	ISOBUSFS_CLI_STATE_GET_FILE_DONE,
	ISOBUSFS_CLI_STATE_VOLUME_STATUS_DONE,
	ISOBUSFS_CLI_STATE_CCD_DONE,
	ISOBUSFS_CLI_STATE_CCD_FAIL,
	ISOBUSFS_CLI_STATE_OF_DONE,
	ISOBUSFS_CLI_STATE_OF_FAIL,
	ISOBUSFS_CLI_STATE_CF_DONE,
	ISOBUSFS_CLI_STATE_CF_FAIL,
	ISOBUSFS_CLI_STATE_MAX_DONE,

	ISOBUSFS_CLI_STATE_GET_FS_PROPERTIES,
	ISOBUSFS_CLI_STATE_GET_CURRENT_DIR,
	ISOBUSFS_CLI_STATE_GET_FILE_SIZE,
	ISOBUSFS_CLI_STATE_GET_FILE,
	ISOBUSFS_CLI_STATE_VOLUME_STATUS,
	ISOBUSFS_CLI_STATE_MAX_ACTIVE,
};

struct isobusfs_priv {
	int sock_ccm;
	int sock_nack;
	int sock_main;
	int sock_bcast_rx;
	int infile;
	int outfile;
	size_t max_transfer;
	unsigned long repeat;
	unsigned long round;
	int prio;
	struct isobusfs_cm_ccm ccm; /* file server status message */

	bool todo_recv;
	bool todo_filesize;
	bool todo_connect;

	unsigned long polltimeout;

	struct sockaddr_can sockname;
	struct sockaddr_can peername;

	struct sock_extended_err *serr;
	struct scm_timestamping *tss;
	struct isobusfs_stats stats;

	uint8_t tan;
	bool server;
	uint8_t cl_buf[1];

	/* file server specific variables */
	bool fs_is_active;
	struct timespec fs_last_seen;
	uint8_t fs_version;
	uint8_t fs_max_open_files;
	uint8_t fs_caps;
	struct isobusfs_buf_log tx_buf_log;
	enum isobusfs_cli_state state;

	struct isobusfs_cmn cmn;
};

/* isobusfs_cli_cm.c */
void isobusfs_cli_ccm_init(struct isobusfs_priv *priv);
int isobusfs_cli_ccm_send(struct isobusfs_priv *priv);
void isobusfs_cli_fs_detect_timeout(struct isobusfs_priv *priv);
int isobusfs_cli_rx_cg_cm(struct isobusfs_priv *priv, struct isobusfs_msg *msg);
int isobusfs_cli_property_req(struct isobusfs_priv *priv);
int isobusfs_cli_volume_status_req(struct isobusfs_priv *priv,
				   uint8_t volume_mode,
				   uint16_t path_name_length,
				   const char *volume_name);

/* isobusfs_cli_dh.c */
int isobusfs_cli_ccd_req(struct isobusfs_priv *priv, const char *name,
			 size_t name_len);
int isobusfs_cli_get_current_dir_req(struct isobusfs_priv *priv);
int isobusfs_cli_rx_cg_dh(struct isobusfs_priv *priv,
			  struct isobusfs_msg *msg);

/* isobusfs_cli_fa.c */
int isobusfs_cli_rx_cg_fa(struct isobusfs_priv *priv,
			  struct isobusfs_msg *msg);
int isobusfs_cli_fa_of_req(struct isobusfs_priv *priv, const char *name,
			   size_t name_len, uint8_t flags);
int isobusfs_cli_fa_cf_req(struct isobusfs_priv *priv, uint8_t handle);

/* isobusfs_cli_selftests.c */
void isobusfs_cli_run_self_tests(struct isobusfs_priv *priv);

#endif /* ISOBUSFS_CLI_H */
