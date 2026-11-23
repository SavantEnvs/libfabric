/*
 * fuzz_rxd_udp: the ofi_rxd reliable-datagram protocol layered over the udp provider
 * ("udp;ofi_rxd"), fed by a remote peer's datagrams. prov/rxd/src/rxd_cq.c
 * rxd_handle_recv_comp (RTS/CTS/ACK/DATA/DATA_READ, msg/tagged/read/write/atomic op
 * headers), rxd_ep.c, rxd_atomic.c, rxd_rma.c.
 * Input: the 4-byte envelope tag "RXD2", then a sequence of [peer][len_lo len_hi][len bytes]
 * records; each record is sent as one
 * datagram to the endpoint from raw UDP socket number (peer % NPEERS), followed by
 * fi_cq_read progress. Several source sockets let one input build a peer table with more
 * than one remote (rxd_add_peer, per-peer windows/ordering).
 * The tag marks this envelope format. Inputs in the first integration's format (bare
 * [len][bytes] records) still sit in Mayhem's stored corpus; without the tag they are rejected
 * with -1 instead of being misread as datagrams. The tag gates only the harness envelope: every
 * tagged input reaches rxd unfiltered, including the known crashes (known-findings/).
 * Fabric/domain persist across inputs; av, cq, ep, mr are opened and closed per input, and
 * each input uses fresh raw sockets (new peer addresses).
 */
#include "fuzz_common.h"
#include <rdma/fi_atomic.h>

static struct fi_info *info;
static struct fid_fabric *fabric;
static struct fid_domain *domain;
static uint8_t rxbuf[4][4096];
static uint8_t rmabuf[4096];
#define NPEERS 2
static const uint8_t envelope_tag[4] = {'R', 'X', 'D', '2'};

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	fuzz_env();
	info = fuzz_getinfo("udp;ofi_rxd", FI_EP_RDM,
			    FI_MSG | FI_TAGGED | FI_RMA | FI_ATOMIC | FI_RECV | FI_SEND |
				    FI_REMOTE_READ | FI_REMOTE_WRITE);
	if (fi_fabric(info->fabric_attr, &fabric, NULL) || fi_domain(fabric, info, &domain, NULL))
		abort();
	return 0;
}

static void progress(struct fid_cq *cq, int rounds)
{
	for (int i = 0; i < rounds; i++) {
		struct fi_cq_tagged_entry comp[8];
		ssize_t n = fi_cq_read(cq, comp, 8);
		if (n == -FI_EAVAIL) {
			struct fi_cq_err_entry err = {0};
			fi_cq_readerr(cq, &err, 0);
		}
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < sizeof(envelope_tag) || memcmp(data, envelope_tag, sizeof(envelope_tag)))
		return -1;
	data += sizeof(envelope_tag);
	size -= sizeof(envelope_tag);
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

	struct sockaddr_in dst = {.sin_family = AF_INET, .sin_port = fuzz_port(&ep->fid)};
	dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	int s[NPEERS];
	for (int i = 0; i < NPEERS; i++) {
		s[i] = socket(AF_INET, SOCK_DGRAM, 0);
		if (s[i] < 0)
			abort();
	}
	size_t off = 0;
	while (off + 3 <= size) {
		int peer = data[off] % NPEERS;
		size_t len = (size_t)data[off + 1] | ((size_t)data[off + 2] << 8);
		off += 3;
		if (len > size - off)
			len = size - off;
		sendto(s[peer], data + off, len, MSG_DONTWAIT, (struct sockaddr *)&dst, sizeof(dst));
		off += len;
		progress(cq, 4);
	}
	progress(cq, 16);

	for (int i = 0; i < NPEERS; i++)
		close(s[i]);
	fi_close(&ep->fid);
	fi_close(&mr->fid);
	fi_close(&cq->fid);
	fi_close(&av->fid);
	return 0;
}
