

```
# get current class label
# $rcx = SomeClass_o
# 0x0 = *SomeClass_c
/*
struct SomeClass_c {
    0x0 void* image
    0x8 void* gc_desc
    0x10 char const* name
}
*/
x/1bs *(*$rcx+0x10)


GroundItemLabel_o
Visuals located at +0x48

# examine it
x/s *(*{long*}(($rcx+0x48))+0x10)
# "GroundItemVisuals"

x/4gx (long)$visuals

set $visuals = {long}(($rcx+0x48))
set $unpacked_data = $visuals+0x18

x/s *(*{long*}$unpacked_data+0x10)
# "ItemDataUnpacked"

(gdb) x/s *(*{long}({long}($rcx+0x48)+0x18)+0x10)
0x62c8f7dd:     "ItemDataUnpacked"

rdi -- string
x/1wx $rdi+0x10 -- number of bytes in string
x/88bs $rdi+0x14 -- string total

```

