#!/usr/bin/env bash

STEAM_ID=1794680

export STEAM_COMPAT_DATA_PATH=/home/kpi/games/SteamLibrary/steamapps/compatdata/1794680
export STEAM_COMPAT_CLIENT_INSTALL_PATH=/home/kpi/.local/share/Steam

python3 /home/kpi/.local/share/Steam/compatibilitytools.d/GE-Proton9-16/proton run /home/kpi/games/SteamLibrary/steamapps/compatdata/${STEAM_ID}/pfx/drive_c/Program\ Files/Cheat\ Engine\ 7.4/cheatengine-x86_64.exe 
