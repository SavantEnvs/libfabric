# fuzz-rxd-udp

Harness: `mayhem/harnesses/fuzz_rxd_udp.c`. Input: the 4-byte tag `RXD2`, then
`[peer][len_lo len_hi][len bytes]` records; each record is one UDP datagram to the rxd endpoint.

**The `RXD2` tag is a harness-format version, not a library precondition.** rxd itself has no such
magic and accepts any datagram. The tag exists only so that inputs in the first integration's
envelope (bare `[len][bytes]` records), which Mayhem still holds in this target's stored
`testsuite.tar`, are rejected with `-1` instead of being misread as datagrams. It filters nothing
the library would see: every tagged input reaches rxd unchanged, including the known crashes in
`known-findings/`. The cost is that the fuzzer must keep the 4 bytes intact, which is cheap
(libFuzzer keeps them via the seeds).
