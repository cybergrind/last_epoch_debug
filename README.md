```bash
export GAME_PID=$(pgrep 'Last Epoch.exe')
uv run proton_tools/__init__.py $GAME_PID

$WINELOADER '/home/kpi/games/SteamLibrary/steamapps/common/Proton - Experimental/files/lib64/wine/x86_64-windows/winedbg.exe' --command "info proc"

$WINELOADER '/home/kpi/games/SteamLibrary/steamapps/common/Proton - Experimental/files/lib64/wine/x86_64-windows/winedbg.exe' --gdb 0x128
```

