
# run:
# $WINELOADER '/home/kpi/games/SteamLibrary/steamapps/common/Proton - Experimental/files/lib/wine/x86_64-windows/winedbg.exe' --command "info proc" | ag Last
# returns:
# 00000168 125      \_ 'Last Epoch.exe'
# then need to call:
# $WINELOADER '/home/kpi/games/SteamLibrary/steamapps/common/Proton - Experimental/files/lib/wine/x86_64-windows/winedbg.exe' --gdx 0x168

WDBG="/home/kpi/games/SteamLibrary/steamapps/common/Proton - Experimental/files/lib/wine/x86_64-windows/winedbg.exe"
INFO=$("$WINELOADER" "$WDBG" --command "info proc" | ag Last)
if [ -z "$INFO" ]; then
    echo "No process found"
    exit 1
fi
PID=$(echo "$INFO" | awk '{print $1}')
echo "PID: $PID"
HEX_PID="0x$PID"

"$WINELOADER" "$WDBG" --gdb "$HEX_PID"
