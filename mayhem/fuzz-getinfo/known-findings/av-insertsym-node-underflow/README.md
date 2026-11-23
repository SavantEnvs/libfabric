# fi_av_insertsym: read before the node string (util_av.c ofi_av_insertsym)

`prov/util/src/util_av.c` strips the numeric suffix of `node` with

    for (name_len = strlen(node); isdigit(node[name_len - 1]); )
        name_len--;

With no lower bound on `name_len`, a node made only of digits (`"121"`), or an empty node, reads
`node[-1]`: UBSan reports `pointer-overflow` at `util_av.c:802`, and ASan a heap-buffer-overflow read.
The function is reached through the public `fi_av_insertsym()` on a udp AV.

- `all-digit-node`: the node `121`. The harness still reaches this one (it is a finding, not filtered out).
- `empty-node`: the node `""`. The harness calls the AV functions only when a node was given
  (`man/fi_av.3.md`: the node is "the starting node address"). Without that, Mayhem's 5-run
  startup probe on an empty corpus hit this read on about half of all seeds, so every run failed.

Fix upstream: `while (name_len > 0 && isdigit((unsigned char)node[name_len - 1]))`.

Reproduce: `/mayhem/fuzz_getinfo-standalone mayhem/fuzz-getinfo/known-findings/av-insertsym-node-underflow/all-digit-node`
