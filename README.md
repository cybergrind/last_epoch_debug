```bash
export GAME_PID=$(pgrep 'Last Epoch.exe')
uv run proton_tools/__init__.py $GAME_PID

$WINELOADER '/home/kpi/games/SteamLibrary/steamapps/common/Proton - Experimental/files/lib64/wine/x86_64-windows/winedbg.exe' --command "info proc"

$WINELOADER '/home/kpi/games/SteamLibrary/steamapps/common/Proton - Experimental/files/lib64/wine/x86_64-windows/winedbg.exe' --gdb 0x128


# create novpn namespace
sudo -EH scripts/novpn_namespace.sh

# run steam in it
sudo -EH ip netns exec novpn sudo -EHu kpi /usr/bin/steam 
```


Change layout to:
```text
# all major variables are here
.envrc
Makefile
/infra
  il2cpp_dumper.envrc
  wine_custom.envrc

# add external to all ignores (.gitignore, pyrightconfig.json, .vscode)
/external 
  # clone from https://github.com/Perfare/Il2CppDumper.git
  /Il2CppDumper
  # download from https://github.com/Perfare/Il2CppDumper/releases/download/v6.7.46/Il2CppDumper-net6-win-v6.7.46.zip
  ​/Il2CppDumper-net6-v6.7.46
    .envrc -> /infra/il2cpp_dumper.envrc

  /wine_custom
    .envrc -> /infra/wine_custom.envrc
	
​/scripts
  # add as command to pyproject.toml
  # should prepare external structure (download, unzip, link directories, etc.)
  prepare.py
  run_cs.sh
  run_in_proton.py
  # change paths: sums must be in external
  dump.sh

# add /tools to PYTHONPATH
​/tools
  /proton_tools
  /le_tools

​/notes
  /examples
    script.py
  # context for agents and chats
  context.md
  todo.md
```


il2cpp.h edits:

```c
typedef uint64_t uintptr_t;
typedef int64_t intptr_t;

struct System_ParameterizedStrings_FormatParam_Fields {
    // replace _int32 with something else_
	// int32_t _int32;
    int32_t changed_int32;
	struct System_String_o* _string;
};

```


Steam detection strace:


```
30443 15:56:02.130773 socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, NETLINK_KOBJECT_UEVENT) = 7
30443 15:56:02.130877 setsockopt(7, SOL_SOCKET, SO_PASSCRED, [1], 4) = 0

[pid 29340] 15:53:29.319340 recvfrom(7, NULL, 0, MSG_PEEK|MSG_TRUNC, NULL, NULL) = 307
[pid 29340] 15:53:29.329180 recvmsg(7, {msg_name={sa_family=AF_NETLINK, nl_pid=531, nl_groups=0x000002}, msg_namelen=128 => 12, msg_iov=[{iov_base=[{prefix="libudev", magic=htonl(0xfeedcafe), header_size=40, properties_off=40, properties_len=267, filter_subsystem_hash=htonl(0xc2caf397), filter_devtype_hash=htonl(0), filter_tag_bloom_hi=htonl(0x2082808), filter_tag_bloom_lo=htonl(0x50100b)}, "\x55\x44\x45\x56\x5f\x44\x41\x54\x41\x42\x41\x53\x45\x5f\x56\x45\x52\x53\x49\x4f\x4e\x3d\x31\x00\x41\x43\x54\x49\x4f\x4e\x3d\x61"...], iov_len=307}], msg_iovlen=1, msg_control=[{cmsg_len=28, cmsg_level=SOL_SOCKET, cmsg_type=SCM_CREDENTIALS, cmsg_data={pid=29447, uid=0, gid=0}}], msg_controllen=32, msg_flags=0}, 0) = 307
[pid 29340] 15:53:29.329416 openat(AT_FDCWD, "/dev/hidraw7", O_RDONLY|O_NOCTTY|O_NONBLOCK|O_CLOEXEC) = 8
```