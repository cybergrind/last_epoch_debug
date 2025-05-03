```bash
export GAME_PID=$(pgrep 'Last Epoch.exe')
uv run proton_tools/__init__.py $GAME_PID

$WINELOADER '/home/kpi/games/SteamLibrary/steamapps/common/Proton - Experimental/files/lib64/wine/x86_64-windows/winedbg.exe' --command "info proc"

$WINELOADER '/home/kpi/games/SteamLibrary/steamapps/common/Proton - Experimental/files/lib64/wine/x86_64-windows/winedbg.exe' --gdb 0x128
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
