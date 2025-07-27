# LibArchive ACL Buffer Overflow Vulnerability

## Overview

A heap buffer overflow vulnerability was discovered in libarchive's Access Control List (ACL) handling code. This security issue occurs when the library processes ACL entries with invalid type parameters, leading to a buffer overflow that could potentially crash applications or cause memory corruption.

## Technical Details

### Vulnerability Summary
- **Severity**: Low
- **Type**: Heap buffer overflow
- **Affected Function**: `archive_acl_to_text_l()`
- **Component**: libarchive ACL processing (`archive_acl.c`) (267042e)

## ASAN

```
=================================================================
==5462==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x604000011133 at pc 0x000102652b0f bp 0x7ff7bdd779b0 sp 0x7ff7bdd77178
READ of size 6 at 0x604000011133 thread T0
    #0 0x000102652b0e in strlen+0x80e (libclang_rt.asan_osx_dynamic.dylib:x86_64h+0x19b0e)
    #1 0x000102198f69 in archive_acl_to_text_l archive_acl.c:983
    #2 0x0001021883d4 in LLVMFuzzerTestOneInput fuzz_archive.cc:146
    #3 0x0001021da49b in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) FuzzerLoop.cpp:619
    #4 0x0001021d9ac5 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) FuzzerLoop.cpp:516
    #5 0x0001021db715 in fuzzer::Fuzzer::MutateAndTestOne() FuzzerLoop.cpp:765
    #6 0x0001021dc185 in fuzzer::Fuzzer::Loop(std::__1::vector<fuzzer::SizedFile, std::__1::allocator<fuzzer::SizedFile>>&) FuzzerLoop.cpp:910
    #7 0x0001021caef5 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) FuzzerDriver.cpp:915
    #8 0x0001021f6d52 in main FuzzerMain.cpp:20
    #9 0x7ff801c5d52f in start+0xbef (dyld:x86_64+0xfffffffffffe652f)

0x604000011133 is located 0 bytes after 35-byte region [0x604000011110,0x604000011133)
allocated by thread T0 here:
    #0 0x00010271b4d2 in malloc+0x82 (libclang_rt.asan_osx_dynamic.dylib:x86_64h+0xe24d2)
    #1 0x000102197eaf in archive_acl_to_text_l archive_acl.c:929
    #2 0x0001021883d4 in LLVMFuzzerTestOneInput fuzz_archive.cc:146
    #3 0x0001021da49b in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) FuzzerLoop.cpp:619
    #4 0x0001021d9ac5 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) FuzzerLoop.cpp:516
    #5 0x0001021db715 in fuzzer::Fuzzer::MutateAndTestOne() FuzzerLoop.cpp:765
    #6 0x0001021dc185 in fuzzer::Fuzzer::Loop(std::__1::vector<fuzzer::SizedFile, std::__1::allocator<fuzzer::SizedFile>>&) FuzzerLoop.cpp:910
    #7 0x0001021caef5 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) FuzzerDriver.cpp:915
    #8 0x0001021f6d52 in main FuzzerMain.cpp:20
    #9 0x7ff801c5d52f in start+0xbef (dyld:x86_64+0xfffffffffffe652f)

SUMMARY: AddressSanitizer: heap-buffer-overflow archive_acl.c:983 in archive_acl_to_text_l
Shadow bytes around the buggy address:
  0x604000010e80: fa fa 00 00 00 00 00 fa fa fa 00 00 00 00 00 fa
  0x604000010f00: fa fa 00 00 00 00 00 fa fa fa fd fd fd fd fd fd
  0x604000010f80: fa fa fd fd fd fd fd fd fa fa 00 00 00 00 00 fa
  0x604000011000: fa fa 00 00 00 00 00 00 fa fa fd fd fd fd fd fd
  0x604000011080: fa fa fd fd fd fd fd fd fa fa fd fd fd fd fd fd
=>0x604000011100: fa fa 00 00 00 00[03]fa fa fa fa fa fa fa fa fa
  0x604000011180: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x604000011200: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x604000011280: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x604000011300: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x604000011380: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==5462==ABORTING
MS: 4 ShuffleBytes-CopyPart-ChangeBinInt-CrossOver-; base unit: d6f7f56e643724f007aaed2965bbba87dbf67361
0x2c,0xff,0x28,0xc9,0xff,0x2b,
,\377(\311\377+
artifact_prefix='./'; Test unit written to ./crash-6f6478a27ba21959355abafe52aefb83e389f559
Base64: LP8oyf8r
Abort trap: 6
bash-3.2$ 
bash-3.2$ hexdump ./crash-6f6478a27ba21959355abafe52aefb83e389f559
0000000 ff2c c928 2bff                         
0000006
bash-3.2$
```

### The Problem

The vulnerability stems from insufficient input validation in libarchive's ACL processing functions. When an invalid ACL type (such as `ARCHIVE_ENTRY_ACL_TYPE_NFS4`) is passed to ACL functions, the library fails to properly validate the input and continues processing, leading to a buffer overflow.

Here's what happens:

1. **Buffer Size Calculation**: The `archive_acl_text_len()` function calculates how much memory is needed for the ACL text representation
2. **Memory Allocation**: A buffer is allocated based on this calculation
3. **Text Generation**: The `append_entry()` function writes ACL information to the buffer
4. **Overflow**: Due to invalid type handling, more data is written than the buffer can hold

### Crash Details

The AddressSanitizer report shows:
- **Buffer Size**: 35 bytes allocated
- **Overflow**: Attempted to read 6 bytes past the buffer end
- **Trigger Input**: Just 6 bytes of data (`0x2c 0xff 0x28 0xc9 0xff 0x2b`)
- **Stack Trace**: Points to `strlen()` call within `append_entry()` function

### Root Cause Analysis

The issue occurs because the code lacks proper validation for ACL type parameters. The library accepts invalid type values like:
- `ARCHIVE_ENTRY_ACL_TYPE_NFS4` (which is not a valid individual type)
- Combined type flags that don't make sense together
- Unrecognized type values

When these invalid types are processed, the buffer size calculation doesn't account for the actual data that will be written, creating a size mismatch.

## Impact Assessment

### Severity: Low
This vulnerability has limited real-world impact because:

1. **API Misuse Required**: The bug only triggers when applications directly misuse libarchive's ACL API with invalid parameters
2. **Not Archive-Triggered**: Normal archive file parsing cannot trigger this vulnerability
3. **Controlled Input**: Only affects applications that programmatically create ACL entries with invalid types

### Potential Consequences
- Application crashes
- Memory corruption in rare cases
- Denial of service for applications using ACL functions incorrectly

## The Fix

The fix involves adding proper input validation at multiple points in the ACL processing code:

### 1. Early Validation in `acl_new_entry()`
```c
/* Reject an invalid type */
switch (type) {
    case ARCHIVE_ENTRY_ACL_TYPE_ACCESS:
    case ARCHIVE_ENTRY_ACL_TYPE_DEFAULT:
    case ARCHIVE_ENTRY_ACL_TYPE_ALLOW:
    case ARCHIVE_ENTRY_ACL_TYPE_DENY:
    case ARCHIVE_ENTRY_ACL_TYPE_AUDIT:
    case ARCHIVE_ENTRY_ACL_TYPE_ALARM:
        break;
    default:
        return (NULL);
}
```

### 2. Fix in `append_entry()` Functions
The fix adds default cases to handle unexpected type values safely:

```c
default:
    **p = '\0';
    break;
```

This ensures that if an invalid type somehow makes it through, the output string is properly terminated instead of causing undefined behavior.

**Reference** - https://github.com/libarchive/libarchive/pull/2704
