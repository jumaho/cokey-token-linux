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

/*
 * TODOs:
 * - Move to current Linux kernel version - Support for skcipher Crypto API
 * - Safety check if key is set before allowing crypto operations
 * - Abstract access to SCC -> support other platforms
 * - Extend USB protocol with tags and status responses
 * - Test USB 3 support
 * - Find valid USB interface class/subclass/protocol
 */

/* #define VERBOSE_DEBUG */
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/err.h>

#include <linux/usb/composite.h>

#include <linux/crypto.h>

#include "cokey.h"

#include <linux/imx_scc2.h>

#define COKEY_ABLKCIPHER

#define COKEY_INTERFACE_SUBCLASS 0xab
#define COKEY_INTERFACE_PROTOCOL 0xcd

#define COKEY_BULK_BUFLEN		4096

/* TODO this is a random placeholder ID */
static const uint8_t SCC_UMID_default[16] = {
		0x42, 0xfa, 0, 0, 0x43, 0, 0, 0, 0x19, 0, 0, 0, 0x59, 0, 0, 0};

struct f_cokey {
	struct usb_function	function;

	struct usb_ep		*in_ep;
	struct usb_ep		*out_ep;
};

struct f_cokey_inst {
	struct usb_function_instance func_inst;
	unsigned bulk_buflen;

	void *scc_part_base;
	uint32_t scc_part_phys;
	int scc_part_no;
	uint8_t scc_UMID[16];

	uint32_t iv[4];

	struct workqueue_struct *wq;

	char cipher_str[32];
	char cipher_str_ctr[32];
	char cipher_str_ecb[32];

	// TODO check if key is set!

#ifdef COKEY_ABLKCIPHER
	struct crypto_ablkcipher *ablkcipher_ctr;
	struct crypto_ablkcipher *ablkcipher_ecb;
#else
	struct crypto_blkcipher *blkcipher_ctr;
	struct crypto_blkcipher *blkcipher_ecb;
#endif


	/*
	 * Read/write access to configfs attributes is handled by configfs.
	 *
	 * This is to protect the data from concurrent access by read/write
	 * and create symlink/remove symlink.
	 */
	struct mutex			lock;
	int				refcnt;
};

typedef struct {
	struct work_struct my_work;
	struct f_cokey *cokey;
	struct usb_request *req;
} cokey_work_t;

static inline struct f_cokey *func_to_cokey(struct usb_function *f)
{
	return container_of(f, struct f_cokey, function);
}

static unsigned buflen;

/*-------------------------------------------------------------------------*/

static struct usb_interface_descriptor cokey_intf = {
	.bLength =		sizeof cokey_intf,
	.bDescriptorType =	USB_DT_INTERFACE,

	.bNumEndpoints =	2,
	.bInterfaceClass =	USB_CLASS_VENDOR_SPEC,
	.bInterfaceSubClass = COKEY_INTERFACE_SUBCLASS,
	.bInterfaceProtocol = COKEY_INTERFACE_PROTOCOL,
	/* .iInterface = DYNAMIC */
};

/* full speed support: */
static struct usb_endpoint_descriptor cokey_fs_in_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,
	.bEndpointAddress =	USB_DIR_IN,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
};

static struct usb_endpoint_descriptor cokey_fs_out_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,
	.bEndpointAddress =	USB_DIR_OUT,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
};

static struct usb_descriptor_header *cokey_fs_descs[] = {
	(struct usb_descriptor_header *) &cokey_intf,
	(struct usb_descriptor_header *) &cokey_fs_in_desc,
	(struct usb_descriptor_header *) &cokey_fs_out_desc,
	NULL,
};

/* high speed support: */
static struct usb_endpoint_descriptor cokey_hs_in_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(512),
};

static struct usb_endpoint_descriptor cokey_hs_out_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(512),
};

static struct usb_descriptor_header *cokey_hs_descs[] = {
	(struct usb_descriptor_header *) &cokey_intf,
	(struct usb_descriptor_header *) &cokey_hs_in_desc,
	(struct usb_descriptor_header *) &cokey_hs_out_desc,
	NULL,
};

/* super speed support: */
static struct usb_endpoint_descriptor cokey_ss_in_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(1024),
};

static struct usb_endpoint_descriptor cokey_ss_out_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,
	.bmAttributes =		USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize =	cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor cokey_ss_bulk_comp_desc = {
	.bLength =		USB_DT_SS_EP_COMP_SIZE,
	.bDescriptorType =	USB_DT_SS_ENDPOINT_COMP,
	.bMaxBurst =		0,
	.bmAttributes =		0,
	.wBytesPerInterval =	0,
};

static struct usb_descriptor_header *cokey_ss_descs[] = {
	(struct usb_descriptor_header *) &cokey_intf,
	(struct usb_descriptor_header *) &cokey_ss_in_desc,
	(struct usb_descriptor_header *) &cokey_ss_bulk_comp_desc,
	(struct usb_descriptor_header *) &cokey_ss_out_desc,
	(struct usb_descriptor_header *) &cokey_ss_bulk_comp_desc,
	NULL,
};

/* function-specific strings: */
static struct usb_string cokey_string_defs[] = {
	[0].s = "CoKey: Cooperative Crypto over USB",
	{  }			/* end of list */
};

static struct usb_gadget_strings cokey_stringtab = {
	.language	= 0x0409,	/* en-us */
	.strings	= cokey_string_defs,
};

static struct usb_gadget_strings *cokey_strings[] = {
	&cokey_stringtab,
	NULL,
};

/*-------------------------------------------------------------------------*/

static int cokey_bind(struct usb_configuration *c, struct usb_function *f)
{
	struct usb_composite_dev *cdev = c->cdev;
	struct f_cokey *crypt = func_to_cokey(f);
	int			id;
	int ret;

	/* allocate interface ID(s) */
	id = usb_interface_id(c, f);
	if (id < 0)
		return id;
	cokey_intf.bInterfaceNumber = id;

	id = usb_string_id(cdev);
	if (id < 0)
		return id;
	cokey_string_defs[0].id = id;
	cokey_intf.iInterface = id;

	/* allocate endpoints */
	crypt->in_ep = usb_ep_autoconfig(cdev->gadget, &cokey_fs_in_desc);
	if (!crypt->in_ep) {
autoconf_fail:
		ERROR(cdev, "%s: can't autoconfigure on %s\n",
			f->name, cdev->gadget->name);
		return -ENODEV;
	}
	crypt->in_ep->driver_data = cdev;	/* claim */

	crypt->out_ep = usb_ep_autoconfig(cdev->gadget, &cokey_fs_out_desc);
	if (!crypt->out_ep)
		goto autoconf_fail;
	crypt->out_ep->driver_data = cdev;	/* claim */

	/* support high speed hardware */
	cokey_hs_in_desc.bEndpointAddress =
		cokey_fs_in_desc.bEndpointAddress;
	cokey_hs_out_desc.bEndpointAddress =
		cokey_fs_out_desc.bEndpointAddress;

	/* support super speed hardware */
	cokey_ss_in_desc.bEndpointAddress =
		cokey_fs_in_desc.bEndpointAddress;
	cokey_ss_out_desc.bEndpointAddress =
		cokey_fs_out_desc.bEndpointAddress;

	ret = usb_assign_descriptors(f, cokey_fs_descs, cokey_hs_descs,
			cokey_ss_descs);
	if (ret)
		return ret;

	DBG(cdev, "%s speed %s: IN/%s, OUT/%s\n",
	    (gadget_is_superspeed(c->cdev->gadget) ? "super" :
	     (gadget_is_dualspeed(c->cdev->gadget) ? "dual" : "full")),
			f->name, crypt->in_ep->name, crypt->out_ep->name);
	return 0;
}

static void cokey_free_func(struct usb_function *f)
{
	struct f_cokey_inst *inst;
	struct f_cokey *cokey;

	inst = container_of(f->fi, struct f_cokey_inst, func_inst);

	cokey = func_to_cokey(f);

	mutex_lock(&inst->lock);
	inst->refcnt--;
	mutex_unlock(&inst->lock);

	usb_free_all_descriptors(f);
	kfree(cokey);
}

void cokey_free_ep_req(struct usb_ep *ep, struct usb_request *req)
{
	kfree(req->buf);
	usb_ep_free_request(ep, req);
}

static inline struct usb_request *cokey_alloc_ep_req(struct usb_ep *ep, int len)
{
	struct usb_request      *req;

	req = usb_ep_alloc_request(ep, GFP_ATOMIC);
	if (req) {
		req->length = len ?: buflen;
		req->buf = kzalloc(req->length, GFP_ATOMIC);
		if (!req->buf) {
			usb_ep_free_request(ep, req);
			req = NULL;
		}
	}
	return req;
}

static void cokey_complete(struct usb_ep *ep, struct usb_request *req);

static int cokey_request_command(struct f_cokey *cokey) {
	struct usb_request *req;
	int result;
	struct usb_composite_dev *cdev = cokey->function.config->cdev;

	req = cokey_alloc_ep_req(cokey->out_ep, COKEY_COMMAND_LENGTH);
	if (!req)
		return -ENOMEM;

	req->complete = cokey_complete;
	result = usb_ep_queue(cokey->out_ep, req, GFP_ATOMIC);
	if (result) {
		ERROR(cdev, "%s queue req --> %d\n",
				cokey->out_ep->name, result);
	}
	return result;
}

static struct cokey_command *cokey_command_parse(void *buf)
{
	struct cokey_command *cmd = kzalloc(sizeof(struct cokey_command), GFP_KERNEL);

	cmd->code = le32_to_cpup(buf);
	cmd->length = le32_to_cpup(buf+4);
	cmd->tag = le32_to_cpup(buf+8);

	pr_debug("Received cokey command: code: %d, length: %d, tag: %08x\n",
			cmd->code, cmd->length, cmd->tag);

	return cmd;
}

static struct f_cokey_inst *f_cokey_to_f_cokey_inst(struct f_cokey *cokey)
{
	struct f_cokey_inst *inst;
	struct usb_function *func = &cokey->function;

	inst = container_of(func->fi, struct f_cokey_inst, func_inst);
	return inst;
}

static int cokey_cmd_setkey(struct f_cokey *cokey, struct
		cokey_command *cmd, void *cmd_data_in, __attribute__
		((unused)) void *cmd_data_out)
{
	struct f_cokey_inst *inst = f_cokey_to_f_cokey_inst(cokey);
	scc_return_t scc_ret;
	int ret = 0;

	pr_debug("SETKEY command\n");

	// TODO maybe cache flush black_data region, i.e. cmd_data_in -> doesn't seem to be necessary

	/* 1. Take SCC information from function instance and use it to derive key */

	// Lock access to SCC partition => two functions have to wait for each other
	mutex_lock(&inst->lock);

	//pr_debug("cmd_data_in vaddr: %p, virt_to_phys: %08x\n", cmd_data_in, virt_to_phys(cmd_data_in));
	//pr_debug("SCC partition content BEFORE setkey:\n");
	//print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_ADDRESS, 32, 1,
	//		inst->scc_part_base, cmd->length, false);

	/* Decrypt input key into SCC partition */
	scc_ret = scc_decrypt_region((uint32_t) inst->scc_part_base, 0, cmd->length,
			(uint8_t *) virt_to_phys(cmd_data_in), (uint32_t *)&inst->iv, SCC_CYPHER_MODE_CBC);
	if (scc_ret != SCC_RET_OK) {
		pr_err("scc_decrypt_region failed\n");
		ret = -1;
		goto out;
	}

	//pr_debug("SCC partition content AFTER setkey:\n");
	//print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_ADDRESS, 32, 1,
	//		inst->scc_part_base, cmd->length, false);

	/* 2. Set key for ciphers */
#ifdef COKEY_ABLKCIPHER
	if (crypto_ablkcipher_setkey(inst->ablkcipher_ctr, inst->scc_part_base, cmd->length)
		|| crypto_ablkcipher_setkey(inst->ablkcipher_ecb, inst->scc_part_base, cmd->length)) {
		pr_err("key could not be set\n");
		ret = -1;
		goto out;
	}
#else
	if (crypto_blkcipher_setkey(inst->blkcipher_ctr, inst->scc_part_base, cmd->length)
		|| crypto_blkcipher_setkey(inst->blkcipher_ecb, inst->scc_part_base, cmd->length)) {
		pr_err("key could not be set\n");
		ret = -1;
		goto out;
	}
#endif

	/* TODO USB Protocol Extension: Add status response here */

out:
	mutex_unlock(&inst->lock);
	return ret;
}

#ifdef COKEY_ABLKCIPHER
struct ablkcipher_result {
	struct completion completion;
	int err;
};

static void cokey_ablkcipher_cb(struct crypto_async_request *req, int error)
{
	struct ablkcipher_result *result = req->data;

	if (error == -EINPROGRESS)
		return;
	result->err = error;
	complete(&result->completion);
}
#endif

static int cokey_cmd_crypt(struct f_cokey *cokey, struct
		cokey_command *cmd, void *cmd_data_in, void *cmd_data_out)
{
	struct f_cokey_inst *inst = f_cokey_to_f_cokey_inst(cokey);
	struct usb_composite_dev *cdev = cokey->function.config->cdev;

	struct scatterlist sg_in, sg_out;
	void *iv = cmd_data_in;
	unsigned int ivsize;

	unsigned int length;
	int status = 0;

#ifdef COKEY_ABLKCIPHER
	struct crypto_ablkcipher *ablkcipher;
	struct ablkcipher_request *ablkcipher_req;
	struct ablkcipher_result ablkcipher_result;
#else
	struct crypto_blkcipher *blkcipher;
	struct blkcipher_desc desc;
#endif

	/* set the right transformation */
	switch (cmd->code) {
	case COKEY_CMD_CTR_ENCRYPT:
	case COKEY_CMD_CTR_DECRYPT:
#ifdef COKEY_ABLKCIPHER
		ablkcipher = inst->ablkcipher_ctr;
#else
		blkcipher = inst->blkcipher_ctr;
#endif
		break;
	case COKEY_CMD_ECB_ENCRYPT:
	case COKEY_CMD_ECB_DECRYPT:
#ifdef COKEY_ABLKCIPHER
		ablkcipher = inst->ablkcipher_ecb;
#else
		blkcipher = inst->blkcipher_ecb;
#endif
		break;
	default:
		ERROR(cdev, "unknown crypto command!\n");
		goto out;
	}

#ifdef COKEY_ABLKCIPHER
	ivsize = crypto_ablkcipher_ivsize(ablkcipher);
#else
	ivsize = crypto_blkcipher_ivsize(blkcipher);
#endif

	length = cmd->length - ivsize;

	/* initialize crypto data scatterlists */
	sg_init_one(&sg_in, cmd_data_in + ivsize, length);
	sg_out = sg_in;

	/* if data is not encrypted in-place */
	if (cmd_data_in != cmd_data_out) {
		/* copy IV to out data (if there is one */
		memcpy(cmd_data_out, cmd_data_in, ivsize);
		sg_init_one(&sg_out, cmd_data_out + ivsize, length);
	}

	//DBG(cdev, "IV with length %d: ", ivsize);
	//print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_ADDRESS, 32, 1,
	//		iv, ivsize, false);
	//DBG(cdev, "Data with length %d: ", length);
	//print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_ADDRESS, 32, 1,
	//		data, length, false);


#ifdef COKEY_ABLKCIPHER
	ablkcipher_req = ablkcipher_request_alloc(ablkcipher, GFP_KERNEL);
	if (IS_ERR(ablkcipher_req)) {
		pr_info("could not allocate request queue\n");
		status = PTR_ERR(ablkcipher_req);
		goto out;
	}
	ablkcipher_request_set_callback(ablkcipher_req, CRYPTO_TFM_REQ_MAY_BACKLOG,
					cokey_ablkcipher_cb,
					&ablkcipher_result);
	ablkcipher_request_set_crypt(ablkcipher_req, &sg_in, &sg_out, length, iv);
	init_completion(&ablkcipher_result.completion);

	switch (cmd->code) {
	case COKEY_CMD_CTR_DECRYPT:
	case COKEY_CMD_ECB_DECRYPT:
		/* decrypt data in place */
		status = crypto_ablkcipher_decrypt(ablkcipher_req);
		break;
	case COKEY_CMD_CTR_ENCRYPT:
	case COKEY_CMD_ECB_ENCRYPT:
		/* encrypt data in place */
		status = crypto_ablkcipher_encrypt(ablkcipher_req);
		break;
	default:
		ERROR(cdev, "cannot crypt, unknown command %d\n", cmd->code);
	}

	/* wait for crypto completion */
	switch (status) {
	case 0:
		break;
	case -EINPROGRESS:
	case -EBUSY:
		status = wait_for_completion_interruptible(
				&ablkcipher_result.completion);
		if (!status && !ablkcipher_result.err) {
			reinit_completion(&ablkcipher_result.completion);
			break;
		}
	default:
		ERROR(cdev, "ablkcipher encrypt returned with %d result %d\n",
				status, ablkcipher_result.err);
		break;
	}
	init_completion(&ablkcipher_result.completion);

#else
	desc.flags = 0;
	desc.tfm = blkcipher;
	/* Set the IV for the encryption operation; IV should reside in the first n bytes
	 * of the buffer received. We have two possibilities:
	 * 1. Store IV into desc.info and call crypto_blkcipher_encrypt_iv()
	 * 2. call crypto_blkcipher_set_iv() and then call crypto_blkcipher_encrypt() */
	desc.info = iv;

	switch (cmd_code) {
	case COKEY_CMD_CTR_DECRYPT:
	case COKEY_CMD_ECB_DECRYPT:
		/* decrypt data in place */
		status = crypto_blkcipher_decrypt_iv(&desc, &sg_out, &sg_in, length);
		break;
	case COKEY_CMD_CTR_ENCRYPT:
	case COKEY_CMD_ECB_ENCRYPT:
		/* encrypt data in place */
		status = crypto_blkcipher_encrypt_iv(&desc, &sg_out, &sg_in, length);
		break;
	default:
		ERROR(cdev, "cannot crypt, unknown command %d\n", cmd_code);
	}
#endif

	if (status < 0) {
		ERROR(cdev, "encryption/decryption failed with status %d\n", status);
		goto out;
	}

	/* return how much space in the out buffer we used */
	status = cmd->length;

	//DBG(cdev, "IV with length %d after crypto: ", ivsize);
	//print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_ADDRESS, 32, 1, iv, ivsize, false);
	//DBG(cdev, "Data with length %d after crypto: ", length);
	//print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_ADDRESS, 32, 1,
	//		data, length, false);

out:
#ifdef COKEY_ABLKCIPHER
	if (ablkcipher_req)
		ablkcipher_request_free(ablkcipher_req);
#endif
	return status;
}

static ssize_t cokey_handle_cmd(struct f_cokey *cokey, struct cokey_command *cmd, void *cmd_data_in, void *cmd_data_out)
{
	struct usb_composite_dev *cdev = cokey->function.config->cdev;

	ssize_t ret;

	switch (cmd->code) {
		case COKEY_CMD_SETKEY:
			DBG(cdev, "command set key received\n");
			ret = cokey_cmd_setkey(cokey, cmd, cmd_data_in,
					cmd_data_out);
			break;
		case COKEY_CMD_CTR_ENCRYPT:
		case COKEY_CMD_CTR_DECRYPT:
		case COKEY_CMD_ECB_ENCRYPT:
		case COKEY_CMD_ECB_DECRYPT:
			DBG(cdev, "command crypt received\n");
			ret = cokey_cmd_crypt(cokey, cmd, cmd_data_in,
					cmd_data_out);
			break;
		default:
			ret = -1;
			ERROR(cdev, "unknown command received!\n");
	}

	return ret;

	/* TODO USB Protocol Extension: Add status response here */
}

static void cokey_wq_function(struct work_struct *work)
{
	cokey_work_t *cokey_work = (cokey_work_t *)work;
	struct f_cokey *cokey = cokey_work->cokey;
	struct usb_composite_dev *cdev = cokey->function.config->cdev;
	struct usb_request *req = cokey_work->req;

	struct usb_request *response_req;
	void *response_buf = NULL;
	void *curr_response_buf;

	struct cokey_command *cmd = req->context;

	struct cokey_command *curr_cmd;
	void *curr_buf;

	int status = 0;

	if (cmd->code == COKEY_CMD_CONTAINER_RESP_CONTAINER) {
		response_buf = kmalloc(cmd->length, GFP_ATOMIC);
		if (!response_buf) {
			pr_err("Could not allocate mem\n");
			cokey_free_ep_req(cokey->out_ep, req);
			goto out;
		}

		/* iterate over commands embedded in cmd container */
		curr_response_buf = response_buf;
		curr_buf = req->buf;
		while (curr_buf+COKEY_COMMAND_LENGTH <= req->buf+req->length) {
			curr_cmd = cokey_command_parse(curr_buf);
			if (!curr_cmd) {
				pr_err("Command could not be parsed\n");
				status = -1;
				break;
			}
			curr_buf += COKEY_COMMAND_LENGTH;
			if (!(curr_buf+curr_cmd->length <= req->buf+req->length)) {
				pr_err("Command data incomplete\n");
				kfree(curr_cmd);
				status = -1;
				break;
			}
			status = cokey_handle_cmd(cokey, curr_cmd,
					curr_buf, curr_response_buf);
			if (status < 0) {
				ERROR(cdev, "could not handle command\n");
				kfree(curr_cmd);
				break;
			} else if (status == 0) {
				/* command did not generate a response */
			} else {
				/* command generated a response */
				curr_response_buf += status;
			}
			curr_buf += curr_cmd->length;
			kfree(curr_cmd);
		}
		cokey_free_ep_req(cokey->out_ep, req);

		if (status < 0 || response_buf == curr_response_buf) {
			/* we left the loop because of some error or there is
			 * nothing to be sent in response
			 * => do not send anything */
			kfree(response_buf);
			goto out;
		}

		/* loop went fine, prepare and send response */
		response_req = usb_ep_alloc_request(cokey->in_ep, GFP_ATOMIC);
		if (!response_req) {
			ERROR(cdev, "could not allocate usb request\n");
			kfree(response_buf);
			goto out;
		}
		response_req->length = curr_response_buf - response_buf;
		response_req->buf = response_buf;
		response_req->complete = cokey_complete;
		status = usb_ep_queue(cokey->in_ep, response_req, GFP_ATOMIC);
		if (status < 0) {
			ERROR(cdev, "could not enqueue request; status %d\n", status);
			cokey_free_ep_req(cokey->in_ep, response_req);
			kfree(response_buf);
			goto out;
		}
	}
	else if (cmd->code == COKEY_CMD_CONTAINER) {
		// iterate over commands embedded in cmd container
		curr_buf = req->buf;
		while (curr_buf+COKEY_COMMAND_LENGTH <= req->buf+req->length) {
			curr_cmd = cokey_command_parse(curr_buf);
			if (!curr_cmd) {
				pr_err("Command could not be parsed\n");
				break;
			}
			curr_buf += COKEY_COMMAND_LENGTH;
			if (!(curr_buf+curr_cmd->length <= req->buf+req->length)) {
				pr_err("Command data incomplete\n");
				kfree(curr_cmd);
				break;
			}
			/* initialize buffer for response */
			curr_response_buf = kmalloc(curr_cmd->length, GFP_ATOMIC);
			if (!curr_response_buf) {
				pr_err("Could not allocate mem\n");
				kfree(curr_cmd);
				break;
			}

			status = cokey_handle_cmd(cokey, curr_cmd,
					curr_buf, curr_response_buf);
			if (status < 0) {
				ERROR(cdev, "could not handle command\n");
				kfree(curr_cmd);
				kfree(curr_response_buf);
				break;
			} else if (status == 0) {
				/* command did not generate a response */
				kfree(curr_response_buf);

			} else {
				/* command generated a response */
				response_req = usb_ep_alloc_request(cokey->in_ep, GFP_ATOMIC);
				if (!response_req) {
					ERROR(cdev, "could not allocate usb request\n");
					kfree(curr_response_buf);
					kfree(curr_cmd);
					break;
				}
				response_req->length = status;
				response_req->buf = curr_response_buf;
				response_req->complete = cokey_complete;
				status = usb_ep_queue(cokey->in_ep, response_req, GFP_ATOMIC);
				if (status < 0) {
					ERROR(cdev, "could not enqueue request; status %d\n", status);
					cokey_free_ep_req(cokey->in_ep, response_req);
					kfree(curr_response_buf);
					kfree(curr_cmd);
					break;
				}
			}

			curr_buf += curr_cmd->length;
			kfree(curr_cmd);
		}
		cokey_free_ep_req(cokey->out_ep, req);
	} else {
		status = cokey_handle_cmd(cokey, cmd, req->buf, req->buf);
		if (status < 0) {
			ERROR(cdev, "could not handle command\n");
		}

		if (status > 0) {
			/* the command generated a response */
			/* Reuse request as IN request to send back encrypted/decrypted data to host */
			req->length = status;
			status = usb_ep_queue(cokey->in_ep, req, GFP_ATOMIC);
			if (status < 0) {
				ERROR(cdev, "could not enqueue request; status %d\n", status);
				cokey_free_ep_req(cokey->out_ep, req);
			}
		} else {
			/* no response from the command */
			/* we don't need the request anymore -> free it */
			cokey_free_ep_req(cokey->out_ep, req);
		}
	}

out:
	kfree(cokey_work);
	kfree(cmd);
}

static void cokey_handle_out(struct f_cokey *cokey, struct usb_request *req)
{
	struct cokey_command *cmd;
	struct usb_request *req_new;
	int result;
	cokey_work_t *work;
	struct f_cokey_inst *cokey_inst = f_cokey_to_f_cokey_inst(cokey);

	if (req->length != req->actual) {
		pr_err("Received less data than expected... Problem!\n");
		goto newcmd;
	}

	if (!req->context) {
		// No context -> COMMAND
		if (req->actual != COKEY_COMMAND_LENGTH) {
			pr_err("Received data length does not match command length... Problem!\n");
			goto newcmd;
		}
		// parse command
		cmd = cokey_command_parse(req->buf);
		if (!cmd) {
			pr_err("Command could not be parsed\n");
			goto newcmd;
		}
		// read required data from host
		req_new = cokey_alloc_ep_req(cokey->out_ep, cmd->length);
		if (!req_new) {
			pr_err("No mem for new request... PROBLEM!\n");
			goto newcmd;
		}
		req_new->context = cmd;
		req_new->complete = cokey_complete;
		result = usb_ep_queue(cokey->out_ep, req_new, GFP_ATOMIC);
		if (result) {
			pr_err("Error: %s queue req --> %d\n",
					cokey->out_ep->name, result);
		}
		goto cleanreq;
	} else {
		// Context already established -> DATA
		// Generate work item
		work = kmalloc(sizeof(cokey_work_t), GFP_KERNEL);
		if (!work) {
			pr_err("Could not allocate work struct\n");
			goto newcmd;
		}
		work->cokey = cokey;
		work->req = req;
		// enqueue work
		INIT_WORK((struct work_struct *)work, cokey_wq_function);
		queue_work(cokey_inst->wq, (struct work_struct *)work);

		/* immediately request new command; for this it must be made sure that
		 * the workqueue handles the requests and sends the responses in the
		 * order they were queued */
		cokey_request_command(cokey);
	}

	return;

newcmd:
	cokey_request_command(cokey);
cleanreq:
	cokey_free_ep_req(cokey->out_ep, req);
}

static void cokey_handle_in(struct f_cokey *cokey, struct usb_request *req)
{
	// Currently nothing to be done here except freeing the request
	cokey_free_ep_req(cokey->in_ep, req);
}

static void cokey_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct f_cokey *cokey= ep->driver_data;
	struct usb_composite_dev *cdev = cokey->function.config->cdev;
	int	status = req->status;

	switch (status) {

	case 0:				/* normal completion? */
		DBG(cdev, "%s cokey complete --> %d, %d/%d\n", ep->name,
				status, req->actual, req->length);
		if (ep == cokey->out_ep) {
			cokey_handle_out(cokey, req);
		} else /* in_ep */ {
			cokey_handle_in(cokey, req);
		}
		break;

	default:

	case -ECONNABORTED:		/* hardware forced ep reset */
	case -ECONNRESET:		/* request dequeued */
	case -ESHUTDOWN:		/* disconnect from host */
		ERROR(cdev, "%s cokey complete --> %d, %d/%d\n", ep->name,
				status, req->actual, req->length);
		cokey_free_ep_req(ep, req);
		return;
	}
}

static void cokey_disable_ep(struct usb_composite_dev *cdev, struct usb_ep *ep)
{
	int value;

	if (ep->driver_data) {
		value = usb_ep_disable(ep);
		if (value < 0)
			DBG(cdev, "disable %s --> %d\n",
					ep->name, value);
		ep->driver_data = NULL;
	}
}

static void disable_cokey(struct f_cokey *cokey)
{
	struct usb_composite_dev	*cdev;

	cdev = cokey->function.config->cdev;
	cokey_disable_ep(cdev, cokey->in_ep);
	cokey_disable_ep(cdev, cokey->out_ep);
	VDBG(cdev, "%s disabled\n", cokey->function.name);
}

static int enable_endpoint(struct usb_composite_dev *cdev, struct f_cokey *cokey,
		struct usb_ep *ep)
{
	int					result;

	/*
	 * one endpoint writes data back IN to the host while another endpoint
	 * just reads OUT packets
	 */
	result = config_ep_by_speed(cdev->gadget, &(cokey->function), ep);
	if (result)
		return result;
	result = usb_ep_enable(ep);
	if (result < 0)
		return result;
	ep->driver_data = cokey;

	return 0;
}

static int
enable_cokey(struct usb_composite_dev *cdev, struct f_cokey *cokey)
{
	int result = 0;

	result = enable_endpoint(cdev, cokey, cokey->in_ep);
	if (result)
		return result;

	result = enable_endpoint(cdev, cokey, cokey->out_ep);
	if (result)
		return result;

	/* Allocate and enqueue request to read first command */
	result = cokey_request_command(cokey);
	if (result)
		return result;

	DBG(cdev, "%s enabled\n", cokey->function.name);
	return result;
}

static int cokey_set_alt(struct usb_function *f,
		unsigned intf, unsigned alt)
{
	struct f_cokey *cokey = func_to_cokey(f);
	struct usb_composite_dev *cdev = f->config->cdev;

	/* we know alt is zero */
	if (cokey->in_ep->driver_data)
		disable_cokey(cokey);
	return enable_cokey(cdev, cokey);
}

static void cokey_disable(struct usb_function *f)
{
	struct f_cokey	*cokey = func_to_cokey(f);

	disable_cokey(cokey);
}

static struct usb_function *cokey_alloc(struct usb_function_instance *fi)
{
	struct f_cokey		*cokey;
	struct f_cokey_inst	*cokey_inst;

	cokey = kzalloc(sizeof *cokey, GFP_KERNEL);
	if (!cokey)
		return ERR_PTR(-ENOMEM);

	cokey_inst = container_of(fi, struct f_cokey_inst, func_inst);

	mutex_lock(&cokey_inst->lock);
	cokey_inst->refcnt++;
	mutex_unlock(&cokey_inst->lock);

	buflen = cokey_inst->bulk_buflen;

	cokey->function.name = "cokey";
	cokey->function.bind = cokey_bind;
	cokey->function.set_alt = cokey_set_alt;
	cokey->function.disable = cokey_disable;
	cokey->function.strings = cokey_strings;

	cokey->function.free_func = cokey_free_func;

	return &cokey->function;
}

/********************************
 * ConfigFS related code */

static inline struct f_cokey_inst *to_f_cokey_inst(struct config_item *item)
{
	return container_of(to_config_group(item), struct f_cokey_inst,
			    func_inst.group);
}

CONFIGFS_ATTR_STRUCT(f_cokey_inst);
CONFIGFS_ATTR_OPS(f_cokey_inst);

static void cokey_attr_release(struct config_item *item)
{
	struct f_cokey_inst *cokey_inst = to_f_cokey_inst(item);

	usb_put_function_instance(&cokey_inst->func_inst);
}

static struct configfs_item_operations cokey_item_ops = {
	.release		= cokey_attr_release,
	.show_attribute		= f_cokey_inst_attr_show,
	.store_attribute	= f_cokey_inst_attr_store,
};

static ssize_t f_cokey_inst_bulk_buflen_show(struct f_cokey_inst *inst, char *page)
{
	int result;

	mutex_lock(&inst->lock);
	result = sprintf(page, "%d", inst->bulk_buflen);
	mutex_unlock(&inst->lock);

	return result;
}

static ssize_t f_cokey_inst_bulk_buflen_store(struct f_cokey_inst *inst,
				    const char *page, size_t len)
{
	int ret;
	u32 num;

	mutex_lock(&inst->lock);
	if (inst->refcnt) {
		ret = -EBUSY;
		goto end;
	}

	ret = kstrtou32(page, 0, &num);
	if (ret)
		goto end;

	inst->bulk_buflen = num;
	ret = len;
end:
	mutex_unlock(&inst->lock);
	return ret;
}

static struct f_cokey_inst_attribute f_cokey_inst_bulk_buflen =
	__CONFIGFS_ATTR(buflen, S_IRUGO | S_IWUSR,
			f_cokey_inst_bulk_buflen_show,
			f_cokey_inst_bulk_buflen_store);

static struct configfs_attribute *cokey_attrs[] = {
	&f_cokey_inst_bulk_buflen.attr,
	NULL,
};

static struct config_item_type cokey_func_type = {
	.ct_item_ops    = &cokey_item_ops,
	.ct_attrs	= cokey_attrs,
	.ct_owner       = THIS_MODULE,
};

/*************************/
/* USB function instance */

static void cokey_free_instance(struct usb_function_instance *fi)
{
	struct f_cokey_inst *cokey_inst;

	cokey_inst = container_of(fi, struct f_cokey_inst, func_inst);

	scc_release_partition(cokey_inst->scc_part_base);

#ifdef COKEY_ABLKCIPHER
	crypto_free_ablkcipher(cokey_inst->ablkcipher_ctr);
	crypto_free_ablkcipher(cokey_inst->ablkcipher_ecb);
#else
	crypto_free_blkcipher(cokey_inst->blkcipher_ctr);
	crypto_free_blkcipher(cokey_inst->blkcipher_ecb);
#endif

	flush_workqueue(cokey_inst->wq);
	destroy_workqueue(cokey_inst->wq);

	kfree(cokey_inst);
}

static struct usb_function_instance *cokey_alloc_instance(void)
{
	struct f_cokey_inst *cokey_inst;

	uint32_t scc_part_permissions = SCM_PERM_TH_READ | SCM_PERM_TH_WRITE |
		SCM_PERM_HD_READ | SCM_PERM_HD_WRITE;

	cokey_inst = kzalloc(sizeof(*cokey_inst), GFP_KERNEL);
	if (!cokey_inst)
		return ERR_PTR(-ENOMEM);
	mutex_init(&cokey_inst->lock);
	cokey_inst->func_inst.free_func_inst = cokey_free_instance;
	cokey_inst->bulk_buflen = COKEY_BULK_BUFLEN;

	/* INITIALIZE CRYPTO */
	snprintf(cokey_inst->cipher_str, sizeof cokey_inst->cipher_str, "%s", "aes");
	snprintf(cokey_inst->cipher_str_ctr, sizeof cokey_inst->cipher_str_ctr, "%s(%s)", "ctr", cokey_inst->cipher_str);
	snprintf(cokey_inst->cipher_str_ecb, sizeof cokey_inst->cipher_str_ecb, "%s(%s)", "ecb", cokey_inst->cipher_str);

#ifdef COKEY_ABLKCIPHER
	cokey_inst->ablkcipher_ctr = crypto_alloc_ablkcipher(cokey_inst->cipher_str_ctr, 0, 0);
	cokey_inst->ablkcipher_ecb = crypto_alloc_ablkcipher(cokey_inst->cipher_str_ecb, 0, 0);
	if (IS_ERR(cokey_inst->ablkcipher_ctr) ||
			IS_ERR(cokey_inst->ablkcipher_ecb)) {
		pr_info("could not allocate ablkcipher handles\n");
		return ERR_PTR(-ENOMEM);;
	}

	pr_info("cokey: ablkciphers allocated, using driver %s and %s\n",
			crypto_tfm_alg_driver_name(crypto_ablkcipher_tfm(cokey_inst->ablkcipher_ctr)),
			crypto_tfm_alg_driver_name(crypto_ablkcipher_tfm(cokey_inst->ablkcipher_ecb)));

#else
	cokey_inst->blkcipher_ctr = crypto_alloc_blkcipher(cokey_inst->cipher_str_ctr, 0, 0);
	cokey_inst->blkcipher_ecb = crypto_alloc_blkcipher(cokey_inst->cipher_str_ecb, 0, 0);
	if (IS_ERR(cokey_inst->blkcipher_ctr) ||
			IS_ERR(cokey_inst->blkcipher_ecb)) {
		pr_info("could not allocate blkcipher handles\n");
		return ERR_PTR(-ENOMEM);;
	}

	pr_info("cokey: blkciphers allocated, using driver %s and %s\n",
			crypto_tfm_alg_driver_name(crypto_blkcipher_tfm(cokey_inst->blkcipher_ctr)),
			crypto_tfm_alg_driver_name(crypto_blkcipher_tfm(cokey_inst->blkcipher_ecb)));
#endif

	/* initialize workqueue */
	// TODO give name based on instance name
	/* WQ_HIGHPRI should make sure that we get most performance out of the WQ...
	   not sure if the WQ_MEM_RECLAIM flag is necessary... */
	cokey_inst->wq = alloc_ordered_workqueue("%s", WQ_MEM_RECLAIM | WQ_HIGHPRI, "cokey");

	/****************************
	 * Initialize SCC */

	/* IV for key derivation
	 * Currently we use CBC on the SCC for deriving key_combined from
	 * key_host and the SCC internal key.
	 * The IV here should be set to a fixed value to make sure that keys are
	 * derived in a deterministic way. Alternatively, ECB could be used.
	 * Furthermore, the IV might be used in the future to differentiate
	 * between USB function instances and let them derive different keys
	 * with the same SCC without much implementation effort */
	cokey_inst->iv[0] = 0x12345678;
	cokey_inst->iv[1] = 0x12345678;
	cokey_inst->iv[2] = 0x12345678;
	cokey_inst->iv[3] = 0x12345678;

	/* INITIALIZE SCC2 */
	memcpy(cokey_inst->scc_UMID, SCC_UMID_default, sizeof(cokey_inst->scc_UMID));

	if (scc_allocate_partition(0, &cokey_inst->scc_part_no,
				&cokey_inst->scc_part_base,
				&cokey_inst->scc_part_phys) != SCC_RET_OK)
		return ERR_PTR(-EIO);

	pr_info("cokey: Partition allocated at partition_base: %p"
			" partition status: %d\n", cokey_inst->scc_part_base,
			scc_partition_status(cokey_inst->scc_part_base));

	if (scc_engage_partition(cokey_inst->scc_part_base,
				cokey_inst->scc_UMID, scc_part_permissions) != SCC_RET_OK)
		return ERR_PTR(-EIO);

	pr_info("cokey: Partition engaged. Partition status: %d\n",
			scc_partition_status(cokey_inst->scc_part_base));

	config_group_init_type_name(&cokey_inst->func_inst.group, "",
				    &cokey_func_type);

	return  &cokey_inst->func_inst;
}
DECLARE_USB_FUNCTION_INIT(cokey, cokey_alloc_instance, cokey_alloc);
MODULE_LICENSE("GPL");
