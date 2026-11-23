# ofi_rxd: the wire `peer` index is never validated (prov/rxd/src/rxd_cq.c)

Every rxd packet carries `base_hdr.peer`, a 32-bit index the receiver uses as
`rxd_peer(ep, peer)` = `ofi_idm_lookup(&ep->peers_idm, peer)`. The handlers dereference the result
without checking it for NULL. So any CTS, ACK or op packet that names a peer this endpoint never
created dereferences NULL:

- `cts-unknown-peer`: a CTS with no RTS before it. `rxd_verify_active`, `rxd_cq.c:210`.
- `ack-unknown-peer`: an RTS from 127.0.0.1:12345 (it becomes peer 1), then an ACK naming peer 0.
  `rxd_handle_ack`, `rxd_cq.c:1096`. A msg or tagged op naming peer 0 crashes the same way, in
  `rxd_handle_op` at `rxd_cq.c:1024`.

Any host that can send UDP to an rxd endpoint can crash the process with one datagram. Fix upstream:
in `rxd_handle_recv_comp`, drop any packet other than an RTS when `rxd_peer(ep, base_hdr.peer)` is NULL.

These files were seeds in the first integration. The seed replay in Mayhem's startup probe crashed on
them, so the run failed with 0 edges. They now live here. The shipped seeds name peer 1, the peer the
leading RTS creates, so they replay cleanly and reach the ACK, CTS and op handlers.

Mayhem had already stored these first seeds in the target's server-side corpus (`testsuite.tar`),
which every run replays, so moving them out of git did not help: later runs still failed in the
startup probe. The harness envelope now starts with the tag `RXD2` and gives each record a peer
selector byte (`RXD2` then `[peer][len_lo len_hi][bytes]`...). Inputs in the old format are rejected
with -1. The files here are in the new format and still crash.

Reproduce: `/mayhem/fuzz_rxd_udp-standalone mayhem/fuzz-rxd-udp/known-findings/rxd-unvalidated-peer-index/cts-unknown-peer`
