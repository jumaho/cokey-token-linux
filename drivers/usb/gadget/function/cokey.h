/*
 * CoKey token USB driver:
 * USB Gadget driver to use a Linux device with gadget capability as CoKey token.
 *
 * Copyright (c) 2015-2016, Fraunhofer AISEC.
 * Author: Julian Horsch <julian.horsch@aisec.fraunhofer.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

enum cokey_command_code {
	COKEY_CMD_SETKEY,
	COKEY_CMD_CTR_ENCRYPT,
	COKEY_CMD_CTR_DECRYPT,
	COKEY_CMD_ECB_ENCRYPT,
	COKEY_CMD_ECB_DECRYPT,
	COKEY_CMD_SETALG,
	COKEY_CMD_GETALG,
	COKEY_CMD_CONTAINER,
	COKEY_CMD_CONTAINER_RESP_CONTAINER,
};

enum cokey_status_code {
	COKEY_STATUS_OK,
	COKEY_STATUS_ERROR,
};

#define COKEY_COMMAND_LENGTH (3*4)
#define COKEY_STATUS_LENGTH (2*4)

struct cokey_command {
	enum cokey_command_code code;
	uint32_t length;
	uint32_t tag;
};

struct cokey_status {
	enum cokey_status_code code;
	uint32_t tag;
};

/* Currently unused */
//struct cokey_response {
//	enum cokey_status;
//	uint32_t length;
//	uint32_t tag;
//};
