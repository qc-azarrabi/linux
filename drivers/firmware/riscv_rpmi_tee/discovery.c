// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <linux/bits.h>
#include <linux/errno.h>
#include <linux/cleanup.h>
#include <linux/mailbox/riscv-rpmi-message.h>
#include <linux/slab.h>
#include <asm/byteorder.h>

#include "rpmi_tee_private.h"

/* Endpoint flags in PROBE_SYSTEM responses. */
#define RPMI_TEE_ENDPOINT_TEE		BIT(31)
#define RPMI_TEE_ENDPOINT_PHYSICAL	BIT(30)

/**
 * struct rpmi_tee_probe_system_req - PROBE_SYSTEM request
 * @start_index: First endpoint index to retrieve.
 */
struct rpmi_tee_probe_system_req {
	__le32 start_index;
} __packed;

/**
 * struct rpmi_tee_probe_system_resp - PROBE_SYSTEM response prefix
 * @status: RPMI completion status.
 * @remaining: Number of endpoints remaining after this response.
 * @returned: Number of endpoint records in this response.
 * @endpoints: Interleaved endpoint ID and flags pairs.
 */
struct rpmi_tee_probe_system_resp {
	__le32 status;
	__le32 remaining;
	__le32 returned;
	__le32 endpoints[];
} __packed;

/**
 * struct rpmi_tee_probe_self_resp - PROBE_SELF response
 * @status: RPMI completion status.
 * @endpoint_id: Calling physical endpoint ID.
 */
struct rpmi_tee_probe_self_resp {
	__le32 status;
	__le32 endpoint_id;
} __packed;

/* PROBE_ENDPOINT query for service UUIDs. */
#define RPMI_TEE_ENDPOINT_DATA_SERVICES	3

/**
 * struct rpmi_tee_probe_endpoint_req - PROBE_ENDPOINT request
 * @endpoint_id: Endpoint identifier from PROBE_SYSTEM.
 * @data_id: Endpoint data query identifier.
 * @start_index: Byte offset in the queried data.
 */
struct rpmi_tee_probe_endpoint_req {
	__le32 endpoint_id;
	__le32 data_id;
	__le32 start_index;
} __packed;

/**
 * struct rpmi_tee_probe_endpoint_resp - PROBE_ENDPOINT response prefix
 * @status: RPMI completion status.
 * @remaining: Number of query data bytes remaining after this response.
 * @returned: Number of query data bytes in this response.
 * @data: Queried endpoint data, excluding transport padding.
 */
struct rpmi_tee_probe_endpoint_resp {
	__le32 status;
	__le32 remaining;
	__le32 returned;
	u8 data[];
} __packed;

struct rpmi_tee_endpoint_info {
	u32 service_count;
	const u8 *services;
};

/* Return an owned probe response, or -ENOENT for vanished IDs. */
static int rpmi_tee_probe_info(struct rpmi_tee_transport *priv, u32 service,
			       const void *req, size_t req_len, void **data,
			       size_t *data_len)
{
	size_t resp_len = priv->mbox.max_msg_data_size;
	s32 status;
	int ret;

	void *resp __free(kfree) = kzalloc(resp_len, GFP_KERNEL);
	if (!resp)
		return -ENOMEM;

	ret = rpmi_tee_send_with_status(priv, service, req, req_len, resp,
					&resp_len, &status);
	if (ret)
		return ret;

	if (status == RPMI_ERR_INVALID_PARAM &&
	    service == RPMI_TEE_SRV_PROBE_ENDPOINT)
		return -ENOENT;

	ret = rpmi_to_linux_error(status);
	if (ret)
		return ret;

	*data_len = resp_len;
	*data = no_free_ptr(resp);

	return 0;
}

/* Copy the service UUID at a validated index in the endpoint response. */
static inline void
rpmi_tee_service_uuid_at(const struct rpmi_tee_endpoint_info *info,
			 u32 index, uuid_t *uuid)
{
	import_uuid(uuid, info->services + (size_t)index * UUID_SIZE);
}

static int rpmi_tee_add_endpoint(struct rpmi_tee_discovery *system, u32 ep_id,
				 const struct rpmi_tee_endpoint_info *info)
{
	struct rpmi_tee_discovered_endpoint *ep;
	u32 i;

	/* Skip endpoints already discovered. */
	list_for_each_entry(ep, &system->eps, node)
		if (ep->ep_id == ep_id)
			return 0;

	ep = kzalloc_flex(*ep, services, info->service_count, GFP_KERNEL);
	if (!ep)
		return -ENOMEM;

	ep->ep_id = ep_id;
	ep->service_count = info->service_count;
	for (i = 0; i < ep->service_count; i++)
		rpmi_tee_service_uuid_at(info, i, &ep->services[i]);
	list_add_tail(&ep->node, &system->eps);

	return 0;
}

/* Read one endpoint's services, skipping endpoints that have disappeared. */
static int rpmi_tee_discover_endpoint(struct rpmi_tee_transport *priv,
				      u32 ep_id,
				      struct rpmi_tee_discovery *system)
{
	struct rpmi_tee_probe_endpoint_req req = {
		.endpoint_id = cpu_to_le32(ep_id),
		.data_id = cpu_to_le32(RPMI_TEE_ENDPOINT_DATA_SERVICES),
	};
	struct rpmi_tee_endpoint_info info;
	u32 start = 0, total = 0;
	size_t len;
	int ret;

	u8 *services __free(kfree) = NULL;

	for (;;) {
		const struct rpmi_tee_probe_endpoint_resp *resp;
		u32 returned, remaining;

		void *endpoint_data __free(kfree) = NULL;

		req.start_index = cpu_to_le32(start);
		ret = rpmi_tee_probe_info(priv, RPMI_TEE_SRV_PROBE_ENDPOINT,
					  &req, sizeof(req), &endpoint_data,
					  &len);
		if (ret == -ENOENT)
			return 0;
		if (ret)
			return ret;

		resp = endpoint_data;
		if (len < sizeof(*resp))
			return -EPROTO;

		returned = le32_to_cpu(resp->returned);
		remaining = le32_to_cpu(resp->remaining);
		/* RETURNED excludes up to three transport padding bytes. */
		if (returned > len - sizeof(*resp) ||
		    len - sizeof(*resp) - returned >= sizeof(__le32) ||
		    (remaining && !returned))
			return -EPROTO;

		if (!start) {
			if (remaining > U32_MAX - returned)
				return -EPROTO;

			total = returned + remaining;
			if (total % UUID_SIZE)
				return -EPROTO;
			if (!total)
				break;

			services = kmalloc(total, GFP_KERNEL);
			if (!services)
				return -ENOMEM;
		}

		if (returned > total - start ||
		    remaining != total - start - returned)
			return -EPROTO;

		memcpy(services + start, resp->data, returned);
		start += returned;
		if (!remaining)
			break;
	}

	info.service_count = total / UUID_SIZE;
	info.services = services;
	return rpmi_tee_add_endpoint(system, ep_id, &info);
}

/* Free all discovered endpoints and their copied service UUIDs. */
void rpmi_tee_free_discovery(struct rpmi_tee_discovery *system)
{
	struct rpmi_tee_discovered_endpoint *ep, *next;

	list_for_each_entry_safe(ep, next, &system->eps, node) {
		list_del(&ep->node);
		kfree(ep);
	}
}

/**
 * rpmi_tee_discover_endpoints() - Discover physical TEE endpoints and services
 * @priv: RPMI TEE transport
 * @system: Returned list of endpoints and their service UUIDs
 *
 * Obtain caller identity with PROBE_SELF and paginate PROBE_SYSTEM results.
 * The caller releases the entries with rpmi_tee_free_discovery() on success.
 *
 * Return: 0 on success, or a negative error code.
 */
int rpmi_tee_discover_endpoints(struct rpmi_tee_transport *priv,
				struct rpmi_tee_discovery *system)
{
	struct rpmi_tee_probe_system_req req = {};
	struct rpmi_tee_probe_self_resp *self;
	u32 start = 0;
	size_t len;
	int ret;

	void *self_data __free(kfree) = NULL;

	INIT_LIST_HEAD(&system->eps);
	ret = rpmi_tee_probe_info(priv, RPMI_TEE_SRV_PROBE_SELF, NULL, 0,
				  &self_data, &len);
	if (ret)
		return ret;

	self = self_data;
	if (len != sizeof(*self))
		return -EPROTO;
	/* Record the caller endpoint ID for subsequent requests. */
	priv->self_id = le32_to_cpu(self->endpoint_id);

	for (;;) {
		const struct rpmi_tee_probe_system_resp *resp;
		u32 returned, remaining, i;

		void *system_data __free(kfree) = NULL;

		req.start_index = cpu_to_le32(start);
		ret = rpmi_tee_probe_info(priv, RPMI_TEE_SRV_PROBE_SYSTEM,
					  &req, sizeof(req), &system_data,
					  &len);
		if (ret)
			goto out_failed;

		resp = system_data;
		ret = -EPROTO;
		if (len < sizeof(*resp))
			goto out_failed;

		returned = le32_to_cpu(resp->returned);
		remaining = le32_to_cpu(resp->remaining);
		/* Check length, pagination progress and index overflow. */
		if (len != sizeof(*resp) + (u64)returned * 2 * sizeof(__le32) ||
		    (remaining && !returned) || returned > U32_MAX - start)
			goto out_failed;

		for (i = 0; i < returned; i++) {
			/* Entries are pairs of endpoint ID and flags. */
			u32 ep_id = le32_to_cpu(resp->endpoints[2 * i]);
			u32 flags = le32_to_cpu(resp->endpoints[2 * i + 1]);
			/* Only physical TEE endpoints are processed. */
			if (ep_id == priv->self_id ||
			    !(flags & RPMI_TEE_ENDPOINT_TEE) ||
			    !(flags & RPMI_TEE_ENDPOINT_PHYSICAL))
				continue;

			ret = rpmi_tee_discover_endpoint(priv, ep_id, system);
			if (ret)
				goto out_failed;
		}

		if (!remaining)
			return 0;

		start += returned;
	}

out_failed:
	rpmi_tee_free_discovery(system);

	return ret;
}
