### Summary

z3 (Z3 version 4.13.1 - 64 bit) WCNF parser contains a buffer overflow vulnerability in the `opt_stream_buffer::parse_token` function. When parsing the "`wcnf`", the function fails to properly check the buffer boundaries, allowing read beyond the allocated memory leading to code execution or denial of service attack.

### Harness 

```C
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>

class opt_stream_buffer {
    const char* m_data;
    size_t m_size;
    size_t m_pos;

public:
    opt_stream_buffer(const char* data, size_t size) : m_data(data), m_size(size), m_pos(0) {}

    int ch() const { return (m_pos < m_size) ? m_data[m_pos] : EOF; }
    void next() { if (m_pos < m_size) m_pos++; }
    bool eof() const { return m_pos >= m_size; }

    bool parse_token(const char* token) {
        const char* t = token;
        while (ch() == *t) {
            next();
            ++t;
        }
        return 0 == *t;
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 4) return 0; 

    opt_stream_buffer buffer(reinterpret_cast<const char*>(data), size);

    buffer.parse_token("wcnf");

    return 0;
}
```

**Compile:** `clang++ -g -fsanitize=fuzzer,address -o z3_overflow_fuzzer z3_overflow_fuzzer.cpp`

### ASAN

```
==773017==ERROR: AddressSanitizer: global-buffer-overflow on address 0x00000056b145 at pc 0x000000550716 bp 0x7fffffffdbe0 sp 0x7fffffffdbd8
READ of size 1 at 0x00000056b145 thread T0
    #0 0x550715 in opt_stream_buffer::parse_token(char const*) /z3/build/z3_overflow_fuzzer.cpp:20:24
    #1 0x5504f7 in LLVMFuzzerTestOneInput /z3/build/z3_overflow_fuzzer.cpp:34:12
    #2 0x458771 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/z3/build/z3_overflow_fuzzer+0x458771)
    #3 0x457eb5 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool*) (/z3/build/z3_overflow_fuzzer+0x457eb5)
    #4 0x45a157 in fuzzer::Fuzzer::MutateAndTestOne() (/z3/build/z3_overflow_fuzzer+0x45a157)
    #5 0x45ae55 in fuzzer::Fuzzer::Loop(std::__Fuzzer::vector<fuzzer::SizedFile, fuzzer::fuzzer_allocator<fuzzer::SizedFile> >&) (/z3/build/z3_overflow_fuzzer+0x45ae55)
    #6 0x44980e in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/z3/build/z3_overflow_fuzzer+0x44980e)
    #7 0x472652 in main (/z3/build/z3_overflow_fuzzer+0x472652)
    #8 0x7ffff7a6a082 in __libc_start_main /build/glibc-LcI20x/glibc-2.31/csu/../csu/libc-start.c:308:16
    #9 0x41e5ad in _start (/z3/build/z3_overflow_fuzzer+0x41e5ad)

0x00000056b145 is located 0 bytes to the right of global variable '<string literal>' defined in 'z3_overflow_fuzzer.cpp:34:24' (0x56b140) of size 5
  '<string literal>' is ascii string 'wcnf'
SUMMARY: AddressSanitizer: global-buffer-overflow /z3/build/z3_overflow_fuzzer.cpp:20:24 in opt_stream_buffer::parse_token(char const*)
Shadow bytes around the buggy address:
  0x0000800a55d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000800a55e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000800a55f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000800a5600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000800a5610: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0000800a5620: 00 00 00 00 00 00 00 00[05]f9 f9 f9 f9 f9 f9 f9
  0x0000800a5630: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000800a5640: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000800a5650: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000800a5660: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000800a5670: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
  Shadow gap:              cc
==773017==ABORTING
```

**Fix:** https://github.com/Z3Prover/z3/commit/ed17de56d2433dbdfd11cca03f78ea8a47adb98e
