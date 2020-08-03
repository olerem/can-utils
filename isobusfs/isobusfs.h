// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2020 Pengutronix, Oleksij Rempel <o.rempel@pengutronix.de>

#ifndef _ISOBUSFS_H_
#define _ISOBUSFS_H_

#define ISOBUS_PGN_FS_TO_CLIENT			0x0ab00 /* 43766 */
#define ISOBUS_PGN_CLIENT_TO_FS			0x0aa00 /* 43520 */

#define ISOBUSFS_DEFAULT_PRIO			7

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
	ISOBUSFS_ERR_FILE OR PATH NOT_FOUND = 4,
	/* Invalid handle */
	ISOBUSFS_ERR_ 5 INVALID HANDLE = 5,
	/* Invalid given source name */
	ISOBUSFS_ERR_ 6 INVALID GIVEN SOURCE NAME = 6,
	/* Invalid given destination name */
	ISOBUSFS_ERR_ = 7,
	/* Volume out of free space */
	ISOBUSFS_ERR_ = 8,
	/* Failure during a write operation */
	ISOBUSFS_ERR_ = 9,
	/* Volume is possibly not initialized */
	ISOBUSFS_ERR_ = 10,
	/* Failure during a read operation */
	ISOBUSFS_ERR_ = 11,
	/* Function not supported */
	ISOBUSFS_ERR_ = 12,
	/* Invalid request length */
	ISOBUSFS_ERR_ = 42,
	/* Out of memory */
	ISOBUSFS_ERR_ = 43,
	/* Any other error */
	ISOBUSFS_ERR_ = 44,
	/* End of file reached, will only be reported when file pointer is at
	 * end of file
	 */
	ISOBUSFS_ERR_ = 45,
};


void isobusfs_init_sockaddr_can(struct sockaddr_can *sac, u32 pgn);

#endif /* !_ISOBUSFS_H_ */
