// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2020 Pengutronix, Oleksij Rempel <o.rempel@pengutronix.de>

#ifndef _ISOBUSFS_H_
#define _ISOBUSFS_H_

#define ISOBUS_PGN_CLIENT			0x0ab00 /* 43766 */
#define ISOBUS_PGN_FS				0x0aa00 /* 43520 */

#define ISOBUSFS_DEFAULT_PRIO			7
#define ISOBUSFS_MAX_OPENED_FILES		255
#define ISOBUSFS_MAX_SHORT_FILENAME_LENGH	12 /* 12 chars */
#define ISOBUSFS_MAX_LONG_FILENAME_LENGH	31 /* 31 chars */
#define ISOBUSFS_MAX_DATA_LENGH			65530 /* Bytes */
#define ISOBUSFS_MAX_TRANSFER_LENGH		6 + ISOBUSFS_MAX_DATA_LENGH
#define ISOBUSFS_MIN_TRANSFER_LENGH		8

/* Command groups (CG) */
#define ISOBUSFS_CG_CONNECTION_MANAGMENT	0
#define ISOBUSFS_CG_DIRECTORY_HANDLING		1
#define ISOBUSFS_CG_FILE_ACCESS			2
#define ISOBUSFS_CG_FILE_HANDLING		3
#define ISOBUSFS_CG_VOLUME_HANDLING		4

/* Connection Management functions: */
/* send by server: */
#define ISOBUSFS_CM_F_FS_STATUS			0
/* Get File Server Properties Response */
#define ISOBUSFS_CM_GET_FS_PROPERTIES_RES	1

/* send by client: */
/* Client Connection Maintenance */
#define ISOBUSFS_CM_F_CC_MAINTENANCE		0
/* Get File Server Properties */
#define ISOBUSFS_CM_GET_FS_PROPERTIES		1

/* send by client: */
#define ISOBUSFS_CM_GET_FS_PROPERTIES		1

/* File Server Status */
#define ISOBUSFS_FS_SATUS_BUSY_WRITING		BIT(1)
#define ISOBUSFS_FS_SATUS_BUSY_READING		BIT(0)

/* Directory Handling functions: */
/* send by server: */
#define ISOBUSFS_DH_F_GET_CURRENT_DIR_RES	0
#define ISOBUSFS_DH_F_CHANGE_CURRENT_DIR_RES	1

/* send by client: */
#define ISOBUSFS_DH_F_GET_CURRENT_DIR_REQ	0
#define ISOBUSFS_DH_F_CHANGE_CURRENT_DIR_REQ	1

/* File Access functions: */
/* send by server: */
#define ISOBUSFS_FA_F_OPEN_FILE_RES		0
#define ISOBUSFS_FA_F_SEEK_FILE_RES		1
#define ISOBUSFS_FA_F_READ_FILE_RES		2
#define ISOBUSFS_FA_F_WRITE_FILE_RES		3
#define ISOBUSFS_FA_F_CLOSE_FILE_RES		4

/* send by client: */
#define ISOBUSFS_FA_F_OPEN_FILE_REQ		0
#define ISOBUSFS_FA_F_SEEK_FILE_REQ		1
#define ISOBUSFS_FA_F_READ_FILE_REQ		2
#define ISOBUSFS_FA_F_WRITE_FILE_REQ		3
#define ISOBUSFS_FA_F_CLOSE_FILE_REQ		4

/* File Handling functions: */
/* send by server: */
#define ISOBUSFS_FH_F_MOVE_FILE_RES		0
#define ISOBUSFS_FH_F_DELETE_FILE_RES		1
#define ISOBUSFS_FH_F_GET_FILE_ATTR_RES		2
#define ISOBUSFS_FH_F_SET_FILE_ATTR_RES		3
#define ISOBUSFS_FH_F_GET_FILE_DATETIME_RES	4

/* send by client: */
#define ISOBUSFS_FH_F_MOVE_FILE_REQ		0
#define ISOBUSFS_FH_F_DELETE_FILE_REQ		1
#define ISOBUSFS_FH_F_GET_FILE_ATTR_REQ		2
#define ISOBUSFS_FH_F_SET_FILE_ATTR_REQ		3
#define ISOBUSFS_FH_F_GET_FILE_DATETIME_REQ	4

/* Volume Access functions: */
/* Preparing or repairing the volume for files and directory structures.
 * These commands should be limited to initial setup, intended to be used by
 * service tool clients only.
 */
/* send by server: */
/* Initialize Volume: Prepare the volume to accept files and directories. All
 * data will be lost upon completion of this command.
 */
#define ISOBUSFS_VA_F_INITIALIZE_VOLUME_RES	0

/* send by client: */
#define ISOBUSFS_VA_F_INITIALIZE_VOLUME_REQ	0

#include "libj1939.h"

enum isobusfs_error {
	/* Success */
	ISOBUSFS_ERR_SUCCESS = 0,
	/* Access Denied */
	ISOBUSFS_ERR_ACCESS_DENIED = 1,
	/* Invalid Access */
	ISOBUSFS_ERR_INVALID_ACCESS = 2,
	/* Too many files open */
	ISOBUSFS_ERR_TOO_MANY_FILES_OPEN = 3,
	/* File or path not found */
	ISOBUSFS_ERR_FILE_ORPATH_NOT_FOUND = 4,
	/* Invalid handle */
	ISOBUSFS_ERR_INVALID_HANDLE = 5,
	/* Invalid given source name */
	ISOBUSFS_ERR_INVALID_SRC_NAME = 6,
	/* Invalid given destination name */
	ISOBUSFS_ERR_INVALID_DST_NAME = 7,
	/* Volume out of free space */
	ISOBUSFS_ERR_NO_SPACE = 8,
	/* Failure during a write operation */
	ISOBUSFS_ERR_ON_WRITE = 9,
	/* Volume is possibly not initialized */
	ISOBUSFS_ERR_VOLUME_NOT_INITIALIZED = 10,
	/* Failure during a read operation */
	ISOBUSFS_ERR_ON_READ = 11,
	/* Function not supported */
	ISOBUSFS_ERR_FUNC_NOT_SUPPORTED = 12,
	/* Invalid request length */
	ISOBUSFS_ERR_INVALID_REQUESTED_LENGHT = 42,
	/* Out of memory */
	ISOBUSFS_ERR_OUT_OF_MEM = 43,
	/* Any other error */
	ISOBUSFS_ERR_OTHER = 44,
	/* End of file reached, will only be reported when file pointer is at
	 * end of file
	 -*/
	ISOBUSFS_ERR_END_OF_FILE = 45,
};

struct isobusfs_stats {
	int err;
	uint32_t tskey;
	uint32_t send;
};

struct isobusfs_priv {
	int sock;
	int infile;
	int outfile;
	size_t max_transfer;
	unsigned long repeat;
	unsigned long round;
	int prio;

	bool valid_peername;
	bool todo_recv;
	bool todo_filesize;
	bool todo_connect;

	unsigned long polltimeout;

	struct sockaddr_can sockname;
	struct sockaddr_can peername;

	struct sock_extended_err *serr;
	struct scm_timestamping *tss;
	struct isobusfs_stats stats;
};

struct isobusfs_msg {
	uint8_t buf[ISOBUSFS_MAX_TRANSFER_LENGH];
	size_t buf_size;
	ssize_t recv_size;
	struct sockaddr_can peername;
	socklen_t peer_addr_len;
};

void isobusfs_init_sockaddr_can(struct sockaddr_can *sac, uint32_t pgn);
int isobusfs_ser_rx_buf(struct isobusfs_priv *priv, struct isobusfs_msg *msg);
int isobusfs_cl_rx_buf(struct isobusfs_priv *priv, struct isobusfs_msg *msg);
int isobusfs_cl_property_req(struct isobusfs_priv *priv);

/*
 * min()/max()/clamp() macros that also do
 * strict type-checking.. See the
 * "unnecessary" pointer comparison.
 */
#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#endif /* !_ISOBUSFS_H_ */
