# sockets MSG connect: CM handle freed by the CM thread while the endpoint still uses it

`fi_connect` allocates a `sock_conn_req_handle` (`sock_ep_cm_connect`, `sock_ep_msg.c:487`). When the
peer's reply is bad or the peer resets the connection, the domain's CM thread frees that handle in
`sock_ep_cm_handle_rx` (`sock_ep_msg.c:1221`). The endpoint still points at it. The application's
later `fi_close(ep)` then uses it in `sock_ep_cm_wait_handle_finalized:1280` and
`sock_ep_cm_add_to_msg_list:375` (`dlist_insert_after`), and the CM thread uses it again in
`sock_ep_cm_pop_from_msg_list:800` (`dlist_remove`). These are the 3 use-after-free defects on this target.

This is a race inside upstream's CM teardown. It is not an artifact of the harness keeping
fabric/domain across inputs: the handle is allocated and freed within one input, and the crash
reproduces from a single input in a fresh process. In 3 tries per file, 17 of the run's 33 crashers
crashed at least once with `fuzz_sockets_connect-standalone <file>`. `connect-peer-reset` crashed 3 of 3.

Reproduce: `/mayhem/fuzz_sockets_connect-standalone mayhem/fuzz-sockets-connect/known-findings/sock-cm-handle-freed-by-cm-thread/connect-peer-reset`
(rerun a few times: it is a race).
