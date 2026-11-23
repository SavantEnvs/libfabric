/* Shared helpers for the libfabric fuzz harnesses (mayhem/harnesses). */
#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_tagged.h>

#define FUZZ_FI_VERSION FI_VERSION(1, 21)

/* Library-global configuration, set once before the library initializes: quiet logging and
 * no hooks, so every iteration runs with the same process-global settings. */
static void fuzz_env(void)
{
	setenv("FI_LOG_LEVEL", "none", 1);
	unsetenv("FI_HOOK");
	unsetenv("FI_PROVIDER");
	/* rxm only polls its connection EQ after a wall-clock interval (default 10 ms); 0 makes
	 * connection progress depend on the fi_cq_read calls alone, not on host speed. */
	setenv("FI_OFI_RXM_CM_PROGRESS_INTERVAL", "0", 1);
}

/* Look up exactly one fi_info for provider `prov` on 127.0.0.1 (numeric, no DNS), port 0. */
static struct fi_info *fuzz_getinfo(const char *prov, enum fi_ep_type type, uint64_t caps)
{
	struct fi_info *hints = fi_allocinfo(), *info = NULL;
	if (!hints)
		abort();
	hints->fabric_attr->prov_name = strdup(prov);
	hints->ep_attr->type = type;
	hints->caps = caps;
	hints->addr_format = FI_SOCKADDR_IN;
	hints->domain_attr->data_progress = FI_PROGRESS_MANUAL;
	hints->domain_attr->control_progress = FI_PROGRESS_MANUAL;
	hints->domain_attr->mr_mode = FI_MR_LOCAL | FI_MR_VIRT_ADDR | FI_MR_ALLOCATED | FI_MR_PROV_KEY;
	hints->domain_attr->threading = FI_THREAD_DOMAIN;
	/* small queues: endpoints are opened per input, keep their buffer pools cheap */
	hints->tx_attr->size = 64;
	hints->rx_attr->size = 64;
	int ret = fi_getinfo(FUZZ_FI_VERSION, "127.0.0.1", "0", FI_SOURCE | FI_NUMERICHOST, hints, &info);
	fi_freeinfo(hints);
	if (ret || !info) {
		fprintf(stderr, "fuzz: fi_getinfo(%s) failed: %d (%s)\n", prov, ret, fi_strerror(-ret));
		abort();
	}
	return info;
}

/* Port of an endpoint, read through the public fi_getname(). */
static uint16_t fuzz_port(fid_t fid)
{
	struct sockaddr_in sin;
	size_t len = sizeof(sin);
	if (fi_getname(fid, &sin, &len) || sin.sin_family != AF_INET)
		abort();
	return sin.sin_port; /* network order */
}

/* Raw TCP peer: connect to 127.0.0.1:port and write `data`; then (half_close) shut down the
 * write side so the provider sees EOF after the bytes. */
static int fuzz_tcp_send(uint16_t port_be, const uint8_t *data, size_t size, int half_close)
{
	struct sockaddr_in sin = {.sin_family = AF_INET, .sin_port = port_be};
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	int s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		abort();
	int one = 1;
	setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	if (connect(s, (struct sockaddr *)&sin, sizeof(sin))) {
		close(s);
		return -1;
	}
	/* loopback buffers hold far more than max_len; send with MSG_DONTWAIT so a full
	 * buffer can never block the harness. */
	size_t off = 0;
	while (off < size) {
		ssize_t n = send(s, data + off, size - off, MSG_DONTWAIT | MSG_NOSIGNAL);
		if (n <= 0)
			break;
		off += (size_t)n;
	}
	if (half_close)
		shutdown(s, SHUT_WR);
	return s;
}

static int fuzz_tcp_peer(uint16_t port_be, const uint8_t *data, size_t size)
{
	return fuzz_tcp_send(port_be, data, size, 1);
}
#endif
