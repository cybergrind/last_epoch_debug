```
cmp    BYTE [rel $+0x32d6031], 0x0
```

```
For base: 0x73c8496c3000
1       breakpoint     keep y   0x00006ffff84920d0 
2       breakpoint     keep y   0x000073c8496c3001 
3       breakpoint     keep y   0x000073c8496c302b 
4       breakpoint     keep y   0x000073c8496c302d 
5       breakpoint     keep y   0x000073c8496c3049 
6       breakpoint     keep y   0x000073c8496c306c 
```


Registers at first breakpoint:
```
rax            0x62b4d701          1656018689
rbx            0x0                 0
rcx            0x134961870         5177219184
rdx            0x2e85f6cc0         12488502464
rsi            0x1344bef00         5172358912
rdi            0x2e8b8b550         12494353744
rbp            0x134257840         0x134257840
rsp            0x10ef28            0x10ef28
r8             0x10f028            1110056
r9             0x10f030            1110064
r10            0x6ffff72f0000      123145154396160
r11            0x6ffffffaf800      123145301981184
r12            0x10f020            1110048
r13            0x10f120            1110304
r14            0x10f030            1110064
r15            0x10f028            1110056
rip            0x6ffff84720d0      0x6ffff84720d0
eflags         0x206               [ PF IF ]
cs             0x33                51
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x2b                43
```


Registers before start saving:
```
rax            0x1                 1
rbx            0x0                 0
rcx            0xfe00              65024
rdx            0x6ffffb7aade0      123145226464736
rsi            0x134961870         5177219184
rdi            0x2e8b8b550         12494353744
rbp            0x2e85f6cc0         0x2e85f6cc0
rsp            0x10eec8            0x10eec8
r8             0xe                 14
r9             0x6ffff75d07c4      123145157412804
r10            0x6ffff72f0000      123145154396160
r11            0x6ffffffaf800      123145301981184
r12            0x10f028            1110056
r13            0x10f030            1110064
r14            0x10f030            1110064
r15            0x6ffffbf17488      123145234248840
rip            0x6ffff847216f      0x6ffff847216f
eflags         0x10246             [ PF ZF IF RF ]
cs             0x33                51
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x2b                43
```

Registers before call:

```

```

Registers dumped by `le_lib_echo`:
```

```

Registers after call:

```

```

Registers before start doing instructions moved to trampoline:

```

```

Registers after jump back:

```
```