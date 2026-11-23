/*
 * fuzz_msg_connect: the client side of a MSG endpoint connection (FUZZ_PROV: "tcp" ->
 * prov/tcp/src/xnet_cm.c connresp handling + xnet_progress.c; "sockets" ->
 * prov/sockets/src/sock_ep_msg.c). The harness fi_connect()s to a raw TCP listener; the
 * raw side accepts and answers with the fuzz input (connection response + cm data, then
 * data-path messages). Progress is manual, driven by bounded fi_eq_read/fi_cq_read loops.
 * Fabric/domain persist across inputs; eq, ep, cq, mr and the raw sockets are per input.
 */
#include "fuzz_common.h"
#include <stdbool.h>

#ifndef FUZZ_PROV
#define FUZZ_PROV "tcp"
#endif

static struct fi_info *base;
static struct fid_fabric *fabric;
static struct fid_domain *domain;
static uint8_t rxbuf[4][4096];
static uint8_t rmabuf[4096];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	fuzz_env();
	base = fuzz_getinfo(FUZZ_PROV, FI_EP_MSG, FI_MSG | FI_RMA | FI_RECV | FI_SEND |
						     FI_REMOTE_READ | FI_REMOTE_WRITE);
	if (fi_fabric(base->fabric_attr, &fabric, NULL) || fi_domain(fabric, base, &domain, NULL))
		abort();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct fi_eq_attr eq_attr = {.size = 16, .wait_obj = FI_WAIT_NONE};
	struct fi_cq_attr cq_attr = {.size = 64, .format = FI_CQ_FORMAT_TAGGED,
				     .wait_obj = FI_WAIT_NONE};
	struct fid_eq *eq;
	struct fid_ep *ep;
	struct fid_cq *cq;
	struct fid_mr *mr;

	/* raw listener on an ephemeral loopback port */
	int l = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	struct sockaddr_in sin = {.sin_family = AF_INET};
	socklen_t slen = sizeof(sin);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (l < 0 || bind(l, (struct sockaddr *)&sin, sizeof(sin)) || listen(l, 4) ||
	    getsockname(l, (struct sockaddr *)&sin, &slen))
		abort();

	/* endpoint info aimed at the listener: the base info with dest_addr replaced */
	struct fi_info *info = fi_dupinfo(base);
	if (!info)
		abort();
	free(info->src_addr);
	info->src_addr = NULL;
	info->src_addrlen = 0;
	free(info->dest_addr);
	info->dest_addr = malloc(sizeof(sin));
	if (!info->dest_addr)
		abort();
	memcpy(info->dest_addr, &sin, sizeof(sin));
	info->dest_addrlen = sizeof(sin);

	if (fi_eq_open(fabric, &eq_attr, &eq, NULL) || fi_cq_open(domain, &cq_attr, &cq, NULL) ||
	    fi_endpoint(domain, info, &ep, NULL) || fi_ep_bind(ep, &eq->fid, 0) ||
	    fi_ep_bind(ep, &cq->fid, FI_TRANSMIT | FI_RECV) || fi_enable(ep))
		abort();
	if (fi_mr_reg(domain, rmabuf, sizeof(rmabuf), FI_REMOTE_READ | FI_REMOTE_WRITE | FI_RECV,
		      0, 0, 0, &mr, NULL))
		abort();
	for (int b = 0; b < 4; b++)
		fi_recv(ep, rxbuf[b], sizeof(rxbuf[b]), fi_mr_desc(mr), 0, NULL);
	fi_connect(ep, &sin, NULL, 0);

	int s = -1;
	for (int i = 0; i < 64; i++) {
		if (s < 0) {
			s = accept(l, NULL, NULL);
			if (s >= 0) {
				size_t off = 0;
				while (off < size) {
					ssize_t n = send(s, data + off, size - off,
							 MSG_DONTWAIT | MSG_NOSIGNAL);
					if (n <= 0)
						break;
					off += (size_t)n;
				}
				shutdown(s, SHUT_WR);
			}
		}
		struct fi_eq_cm_entry entry;
		uint32_t event;
		ssize_t rd = fi_eq_read(eq, &event, &entry, sizeof(entry), 0);
		if (rd == -FI_EAVAIL) {
			struct fi_eq_err_entry err = {0};
			fi_eq_readerr(eq, &err, 0);
		}
		struct fi_cq_tagged_entry comp[8];
		ssize_t n = fi_cq_read(cq, comp, 8);
		if (n == -FI_EAVAIL) {
			struct fi_cq_err_entry err = {0};
			fi_cq_readerr(cq, &err, 0);
		}
	}

	if (s >= 0)
		close(s);
	close(l);
	fi_close(&ep->fid);
	fi_close(&mr->fid);
	fi_close(&cq->fid);
	fi_close(&eq->fid);
	fi_freeinfo(info);
	return 0;
}
