# fuzz-sockets-rdm: known upstream findings (prov/sockets/src/sock_progress.c)

Mayhem reports 22 defects on this target. They come from 3 root causes. Every one is reached by
bytes a remote peer sends on its data connection, and the standalone binary reproduces each:
`/mayhem/fuzz_sockets_rdm-standalone <file>`.

1. **`sock-wire-pe-entry-id/`: wire `pe_entry_id` trusted as a `pe_table` index (19 of the 22).**
   An ACK, READ/WRITE/ATOMIC completion or error response carries
   `sock_msg_response.pe_entry_id`. `sock_pe_handle_ack:584`, `_read_complete:642`,
   `_write_complete:676`, `_atomic_complete:700` and `_error:606` index `pe->pe_table[128]` with it.
   They check it only with `assert(... <= SOCK_PE_MAX_ENTRIES)`, which is compiled out and off by one.
   - Out of range: `ack-pe-entry-out-of-table` is an array-index OOB at `:584`.
   - In range but naming an idle entry (not a TX entry this endpoint posted): the entry's `comp` is NULL.
     `completion-idle-pe-entry` is a NULL deref in `sock_pe_report_send_cq_completion:238`. The same
     happens in `sock_pe_report_tx_rma_read_err:442` / `_write_err:456`.
   Mayhem lists each site twice, as CWE-20 and as the array-index or NULL deref.
   Fix: bounds-check the id and require `type == SOCK_PE_TX` with a pending op.
2. **`sock-wire-dest-iov-len/`: wire `dest_iov_len` trusted as the `rx_iov[8]` count (2).**
   `sock_pe_report_mr_completion:325` loops `i < msg_hdr.dest_iov_len` (a wire byte, 255 here) over
   `pe.rx.rx_iov[SOCK_EP_MAX_IOV_LIMIT]`, reached from `sock_pe_process_rx_atomic:1006`.
3. **`sock-wire-discard-len/`: wire length passed to `malloc` (1, OOM-class).**
   `sock_pe_discard_field:138` calls `sock_comm_discard(pe_entry, pe_entry->rem)`, and `sock_comm.c:215`
   does `malloc(len)` with the remaining length from `msg_len`. ASan reports
   `requested allocation size ... exceeds maximum supported size`.

The crash density does not hide coverage. In a 5-minute run the target reached 575 edges at
~2400 exec/s. Crashing inputs end early, but libFuzzer keeps the non-crashing ones, and these are
what grow the corpus.
