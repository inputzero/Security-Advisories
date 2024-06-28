## Summary
While fuzzing `opensips` I discovered a heap buffer overflow under `strlen` function during a READ operation, indicating an attempt to read beyond the allocated buffer leading to code execution or denial of service under `opnesips` tested against commit "64c0042".

## ASAN

```
==263085==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60c0000000b8 at pc 0x0000004454f9 bp 0x7fffffffc6d0 sp 0x7fffffffbe90
READ of size 121 at 0x60c0000000b8 thread T0
    #0 0x4454f8 in strlen (/opensips/opensips+0x4454f8)
    #1 0x657d51 in __flatten_opensips_cfg /opensips/cfg_pp.c:371:15
    #2 0x64df02 in flatten_opensips_cfg /opensips/cfg_pp.c:476:6
    #3 0x64c986 in parse_opensips_cfg /opensips/cfg_pp.c:88:6
    #4 0x802312 in main /opensips/main.c:707:13
    #5 0x7ffff7c2e082 in __libc_start_main /build/glibc-e2p3jK/glibc-2.31/csu/../csu/libc-start.c:308:16
    #6 0x4328cd in _start (/opensips/opensips+0x4328cd)

0x60c0000000b8 is located 0 bytes to the right of 120-byte region [0x60c000000040,0x60c0000000b8)
allocated by thread T0 here:
    #0 0x4ab00d in malloc (/opensips/opensips+0x4ab00d)
    #1 0x7ffff7c8d543 in getdelim /build/glibc-e2p3jK/glibc-2.31/libio/iogetdelim.c:62:27

SUMMARY: AddressSanitizer: heap-buffer-overflow (/opensips/opensips+0x4454f8) in strlen
Shadow bytes around the buggy address:
  0x0c187fff7fc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c187fff7fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c187fff7fe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c187fff7ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c187fff8000: fa fa fa fa fa fa fa fa 00 00 00 00 00 00 00 00
=>0x0c187fff8010: 00 00 00 00 00 00 00[fa]fa fa fa fa fa fa fa fa
  0x0c187fff8020: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c187fff8030: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c187fff8040: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c187fff8050: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c187fff8060: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==263085==ABORTING
```

## Proof-of-concept  

Configuration file

```
#
# OpenSIPS residential configuration script
#     by OpenSIPS Solutions <team@opensips-sodparaolutions.com>
#
# This script was generated via "make menuconfig", from
#   the "Residential" scenario.
# You can enable / disable more features / functional#
# OpenSIPS residential configuration script
#     by OpenSIPS Solutions <team@opensips-solutions.com>
#
# This script was generated via "make menuconfig", from
#   the "Residential" scenarioelf("$rd")) {
		append_hf("P-hine features / functionalities by
#   re-generating the scenario with d‡fferent options.#
#
# Please refer to the Core CookBook at:
#      https://opensips.org/Resources/DocsCookbooks
# for a exxxxxxxxxxxxxxxxxxxxplanation of possible statements, functions and parameters.
#<0x1a>
```

## Fix Commit

Commit refernece: [50b651c](https://github.com/OpenSIPS/opensips/commit/50b651c230eec5daaf52f8742a9c3dd92123f3d2)<br>
File reference: (cfg_pp.c)

```C
@@ -368,7 +368,7 @@ static int __flatten_opensips_cfg(FILE *cfg, const char *cfg_path,
				goto out_err;
			}

			line_len = strlen(line);
			line_len = 0;
			break;

		} else if (line_len == 0) {
```

The above commit checks when `getline()` returns -1, the `@lineptr` argument is never safe to read, nor is this recommended.  So when both `rc == -1` and EOF conditions
occur, it is safe to assume we read 0 bytes, without doing the `strlen()`.

