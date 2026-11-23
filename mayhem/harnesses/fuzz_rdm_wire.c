/*
 * fuzz_rdm_wire: an RDM endpoint of a socket-based provider (FUZZ_PROV, set at compile
 * time: "tcp" -> prov/tcp/src/xnet_rdm_cm.c + xnet_rdm.c + xnet_progress.c; "sockets" ->
 * prov/sockets/src/sock_conn.c + sock_progress.c) receiving a raw byte stream from a remote
 * peer. The endpoint listens on 127.0.0.1; a raw TCP socket connects and sends the fuzz
 * input (connection handshake + protocol messages). Receive buffers and an RMA-accessible
 * MR are posted; progress is driven by bounded fi_cq_read loops.
 * Fabric/domain persist across inputs; av, cq, ep, mr are opened and closed per input.
 */
#include "fuzz_common.h"

#ifndef FUZZ_PROV
#error "define FUZZ_PROV"
#endif

static struct fi_info *info;
static struct fid_fabric *fabric;
static struct fid_domain *domain;
static uint8_t rxbuf[4][4096];
static uint8_t rmabuf[4096];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	fuzz_env();
	info = fuzz_getinfo(FUZZ_PROV, FI_EP_RDM, FI_MSG | FI_TAGGED | FI_RMA | FI_RECV |
						     FI_SEND | FI_REMOTE_READ | FI_REMOTE_WRITE);
	if (fi_fabric(info->fabric_attr, &fabric, NULL) || fi_domain(fabric, info, &domain, NULL))
		abort();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct fi_av_attr av_attr = {.type = FI_AV_TABLE, .count = 16};
	struct fi_cq_attr cq_attr = {.size = 64, .format = FI_CQ_FORMAT_TAGGED,
				     .wait_obj = FI_WAIT_NONE};
	struct fid_av *av;
	struct fid_cq *cq;
	struct fid_ep *ep;
	struct fid_mr *mr;

	if (fi_av_open(domain, &av_attr, &av, NULL) || fi_cq_open(domain, &cq_attr, &cq, NULL) ||
	    fi_endpoint(domain, info, &ep, NULL) || fi_ep_bind(ep, &av->fid, 0) ||
	    fi_ep_bind(ep, &cq->fid, FI_TRANSMIT | FI_RECV) || fi_enable(ep))
		abort();
	if (fi_mr_reg(domain, rmabuf, sizeof(rmabuf), FI_REMOTE_READ | FI_REMOTE_WRITE | FI_RECV,
		      0, 0, 0, &mr, NULL))
		abort();
	for (int b = 0; b < 2; b++) {
		fi_recv(ep, rxbuf[b], sizeof(rxbuf[b]), fi_mr_desc(mr), FI_ADDR_UNSPEC, NULL);
		fi_trecv(ep, rxbuf[b + 2], sizeof(rxbuf[b + 2]), fi_mr_desc(mr), FI_ADDR_UNSPEC,
			 0, ~0ULL, NULL);
	}

	int s = fuzz_tcp_peer(fuzz_port(&ep->fid), data, size);

	for (int i = 0; i < 64; i++) {
		struct fi_cq_tagged_entry comp[8];
		ssize_t n = fi_cq_read(cq, comp, 8);
		if (n == -FI_EAVAIL) {
			struct fi_cq_err_entry err = {0};
			fi_cq_readerr(cq, &err, 0);
		}
	}

	if (s >= 0)
		close(s);
	fi_close(&ep->fid);
	fi_close(&mr->fid);
	fi_close(&cq->fid);
	fi_close(&av->fid);
	return 0;
}
