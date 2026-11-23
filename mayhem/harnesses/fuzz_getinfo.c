/*
 * fuzz_getinfo: the string-facing public API of libfabric.
 *   fi_getinfo(node, service, flags, hints{prov_name, ep_type, addr_format, caps})
 *     -> src/fabric.c provider/hints filtering, src/common.c address handling,
 *        prov/util/src/util_attr.c attribute matching in every built-in provider
 *   fi_tostr() of every returned fi_info's attributes (src/fi_tostr.c)
 *   fi_av_insertsym/fi_av_insertsvc/fi_av_straddr on a udp AV
 *     -> prov/util/src/util_av.c ofi_ip_av_insertsym / node+service range expansion
 * Input: byte0 = selector bits, byte1 = counts, then '\n'-separated fields:
 *   node \n service \n prov_name \n
 * The fabric/domain of the udp provider are opened once (read-only afterwards); the AV is
 * opened and closed per input so no address state carries over.
 */
#include "fuzz_common.h"
#include <rdma/fi_domain.h>

static struct fid_fabric *fabric;
static struct fid_domain *domain;
static struct fi_info *udp_info;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	fuzz_env();
	udp_info = fuzz_getinfo("udp", FI_EP_DGRAM, FI_MSG);
	if (fi_fabric(udp_info->fabric_attr, &fabric, NULL) ||
	    fi_domain(fabric, udp_info, &domain, NULL))
		abort();
	return 0;
}

static char *next_field(const uint8_t **p, const uint8_t *end)
{
	const uint8_t *s = *p, *nl = s;
	while (nl < end && *nl != '\n')
		nl++;
	char *out = malloc((size_t)(nl - s) + 1);
	if (!out)
		abort();
	memcpy(out, s, (size_t)(nl - s));
	out[nl - s] = '\0';
	*p = nl < end ? nl + 1 : end;
	return out;
}

static const enum fi_ep_type ep_types[] = {FI_EP_UNSPEC, FI_EP_MSG, FI_EP_DGRAM, FI_EP_RDM};
static const uint32_t addr_formats[] = {FI_FORMAT_UNSPEC, FI_SOCKADDR, FI_SOCKADDR_IN,
					FI_SOCKADDR_IN6, FI_ADDR_STR};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 2)
		return 0;
	uint8_t sel = data[0], cnt = data[1];
	const uint8_t *p = data + 2, *end = data + size;
	char *node = next_field(&p, end);
	char *service = next_field(&p, end);
	char *prov = next_field(&p, end);

	struct fi_info *hints = fi_allocinfo(), *info = NULL;
	if (!hints)
		abort();
	if (*prov)
		hints->fabric_attr->prov_name = strdup(prov);
	hints->ep_attr->type = ep_types[sel & 3];
	hints->addr_format = addr_formats[((sel >> 2) & 7) % 5];
	if (sel & 0x20)
		hints->caps = FI_MSG | FI_TAGGED;
	if (sel & 0x40)
		hints->caps |= FI_RMA | FI_ATOMIC;
	uint64_t flags = FI_NUMERICHOST | ((sel & 0x80) ? FI_SOURCE : 0);
	int ret = fi_getinfo(FUZZ_FI_VERSION, *node ? node : NULL, *service ? service : NULL,
			     flags, hints, &info);
	if (!ret) {
		/* fi_tostr(info, FI_TYPE_INFO) is not used: it computes &info->nic->fid on a
		 * NULL nic (src/fi_tostr.c ofi_tostr_info), which UBSan flags on every input.
		 * Print the attribute structs it is made of instead. */
		for (struct fi_info *cur = info; cur; cur = cur->next) {
			fi_tostr(&cur->caps, FI_TYPE_CAPS);
			fi_tostr(&cur->mode, FI_TYPE_MODE);
			fi_tostr(&cur->addr_format, FI_TYPE_ADDR_FORMAT);
			fi_tostr(cur->tx_attr, FI_TYPE_TX_ATTR);
			fi_tostr(cur->rx_attr, FI_TYPE_RX_ATTR);
			fi_tostr(cur->ep_attr, FI_TYPE_EP_ATTR);
			fi_tostr(cur->domain_attr, FI_TYPE_DOMAIN_ATTR);
			fi_tostr(cur->fabric_attr, FI_TYPE_FABRIC_ATTR);
		}
		fi_freeinfo(info);
	}
	fi_freeinfo(hints);

	/* Symmetric AV insert on the udp provider. */
	struct fi_av_attr av_attr = {.type = FI_AV_TABLE, .count = 64};
	struct fid_av *av;
	if (fi_av_open(domain, &av_attr, &av, NULL))
		abort();
	size_t nodecnt = (cnt & 0x7) + 1, svccnt = ((cnt >> 3) & 0x7) + 1;
	fi_addr_t addrs[64];
	int n = 0;
	/* man/fi_av.3.md: fi_av_insertsvc/fi_av_insertsym take "the starting node address" (a
	 * hostname or network address); an empty field is an absent argument here, exactly as
	 * it is for fi_getinfo above, so the AV calls are made only when a node was given.
	 * (Known finding, not masked: an all-digit node such as "121" still reaches the
	 * node[-1] read in util_av.c ofi_av_insertsym; see mayhem/fuzz-getinfo/known-findings.) */
	if (!*node)
		;
	else if (cnt & 0x40)
		n = fi_av_insertsvc(av, node, service, addrs, 0, NULL);
	else
		n = fi_av_insertsym(av, node, nodecnt, service, svccnt, addrs, 0, NULL);
	for (int i = 0; i < n && i < 64; i++) {
		char buf[128];
		size_t len = sizeof(buf);
		fi_av_straddr(av, &addrs[i], buf, &len);
		uint8_t raw[128];
		len = sizeof(raw);
		fi_av_lookup(av, addrs[i], raw, &len);
	}
	if (n > 0)
		fi_av_remove(av, addrs, (size_t)(n < 64 ? n : 64), 0);
	fi_close(&av->fid);

	free(node);
	free(service);
	free(prov);
	return 0;
}
