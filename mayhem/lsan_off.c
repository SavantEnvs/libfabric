/* Leak detection is not the bug class fuzzed here (ASan + UBSan are): turn LSan off at build time. */
int __lsan_is_turned_off(void) { return 1; }
