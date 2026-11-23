/*
 * fuzz_tcp_msg: the tcp (xnet) provider's MSG endpoint, server side, fed by a remote peer.
 * A passive endpoint listens on 127.0.0.1; a raw TCP socket connects and sends the fuzz
 * input as the peer's byte stream: first the connection request (ofi_ctrl_hdr + cm data,
 * prov/tcp/src/xnet_cm.c), then — once the harness fi_accept()s — data-path messages
 * (xnet_base_hdr + op headers, prov/tcp/src/xnet_progress.c, xnet_msg.c, xnet_rma.c).
 * Progress is manual and driven by bounded fi_eq_read/fi_cq_read loops.
 *
 * sockets (FUZZ_PROV="sockets") carries the data path on a SECOND connection: the accepting
 * endpoint listens on its own port (sock_conn_listen) and returns it in the ACCEPT reply
 * (sock_ep_cm_accept), and the peer then connects there and sends sock_msg_hdr messages
 * (sock_conn.c, sock_progress.c). So for sockets the input is split by the protocol's own
 * framing: the first SOCK_CONN_REQ_SZ + hdr.cm_data_sz bytes are the conn request on the CM
 * connection (sock_pep_req_handler reads exactly that), and the rest is the data stream, sent
 * on a raw connection to the accepted endpoint's port once fi_accept() has returned. The CM
 * thread and the conn listener thread run asynchronously, so each poll round yields the CPU.
 *
 * Fabric/domain persist across inputs; eq, pep, ep, cq, mr are opened and closed per input.
 */
#include <sched.h>
#include "fuzz_common.h"

/* FUZZ_PROV selects the provider at compile time: "tcp" (default) or "sockets"
 * (prov/sockets/src/sock_ep_msg.c sock_conn_req/response handling, sock_progress.c). */
#ifndef FUZZ_PROV
#define FUZZ_PROV "tcp"
#endif

#ifdef FUZZ_SOCKETS
/* sizeof(struct sock_conn_req), prov/sockets/include/sock.h: sock_conn_hdr (type, reserved[3],
 * port, cm_data_sz = 8) + union ofi_sock_ip (48, include/ofi_net.h) + uint64_t caps. */
#define SOCK_CONN_REQ_SZ (8 + 48 + 8)
#define POLL_ROUNDS 512
#else
#define POLL_ROUNDS 64
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
	info = fuzz_getinfo(FUZZ_PROV, FI_EP_MSG, FI_MSG | FI_RMA | FI_RECV | FI_SEND |
					      FI_REMOTE_READ | FI_REMOTE_WRITE);
	if (fi_fabric(info->fabric_attr, &fabric, NULL) || fi_domain(fabric, info, &domain, NULL))
		abort();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct fi_eq_attr eq_attr = {.size = 16, .wait_obj = FI_WAIT_NONE};
	struct fi_cq_attr cq_attr = {.size = 64, .format = FI_CQ_FORMAT_TAGGED,
				     .wait_obj = FI_WAIT_NONE};
	struct fid_eq *eq;
	struct fid_pep *pep;
	struct fid_ep *ep = NULL;
	struct fid_cq *cq = NULL;
	struct fid_mr *mr = NULL;

	if (fi_eq_open(fabric, &eq_attr, &eq, NULL) || fi_passive_ep(fabric, info, &pep, NULL) ||
	    fi_pep_bind(pep, &eq->fid, 0) || fi_listen(pep))
		abort();

#ifdef FUZZ_SOCKETS
	size_t cm_len = size;
	if (size >= 8)
		cm_len = SOCK_CONN_REQ_SZ + (((size_t)data[6] << 8) | data[7]); /* ntohs(cm_data_sz) */
	if (cm_len > size)
		cm_len = size;
	/* keep the CM connection open (no half-close): EOF there is a disconnect */
	int s = fuzz_tcp_send(fuzz_port(&pep->fid), data, cm_len, 0);
	int d = -1;
#else
	int s = fuzz_tcp_peer(fuzz_port(&pep->fid), data, size);
#endif

	for (int i = 0; i < POLL_ROUNDS; i++) {
		struct fi_eq_cm_entry entry;
		uint32_t event;
		ssize_t rd = fi_eq_read(eq, &event, &entry, sizeof(entry), 0);
		if (rd == -FI_EAVAIL) {
			struct fi_eq_err_entry err = {0};
			fi_eq_readerr(eq, &err, 0);
		} else if (rd > 0 && event == FI_CONNREQ && !ep) {
			if (fi_endpoint(domain, entry.info, &ep, NULL) ||
			    fi_cq_open(domain, &cq_attr, &cq, NULL) ||
			    fi_ep_bind(ep, &eq->fid, 0) ||
			    fi_ep_bind(ep, &cq->fid, FI_TRANSMIT | FI_RECV) || fi_enable(ep))
				abort();
			if (fi_mr_reg(domain, rmabuf, sizeof(rmabuf),
				      FI_REMOTE_READ | FI_REMOTE_WRITE | FI_RECV, 0, 0, 0, &mr, NULL))
				abort();
			for (int b = 0; b < 4; b++)
				fi_recv(ep, rxbuf[b], sizeof(rxbuf[b]), fi_mr_desc(mr), 0, NULL);
			int acc = fi_accept(ep, NULL, 0);
			fi_freeinfo(entry.info);
#ifdef FUZZ_SOCKETS
			if (!acc)
				d = fuzz_tcp_peer(fuzz_port(&ep->fid), data + cm_len, size - cm_len);
#else
			(void)acc;
#endif
		} else if (rd > 0 && event == FI_CONNREQ) {
			fi_freeinfo(entry.info);
		}
		if (cq) {
			struct fi_cq_tagged_entry comp[8];
			ssize_t n = fi_cq_read(cq, comp, 8);
			if (n == -FI_EAVAIL) {
				struct fi_cq_err_entry err = {0};
				fi_cq_readerr(cq, &err, 0);
			}
		}
#ifdef FUZZ_SOCKETS
		sched_yield();
#endif
	}

#ifdef FUZZ_SOCKETS
	if (d >= 0)
		close(d);
#endif
	if (s >= 0)
		close(s);
	if (ep)
		fi_close(&ep->fid);
	if (mr)
		fi_close(&mr->fid);
	if (cq)
		fi_close(&cq->fid);
	fi_close(&pep->fid);
	fi_close(&eq->fid);
	return 0;
}
