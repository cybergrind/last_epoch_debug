#!/usr/bin/env bash
cd $PROJECT_ROOT

export EXTERNAL="${PROJECT_ROOT}/external"

cd "${EXTERNAL}"
cd 'Il2CppDumper-net6-v6.7.46'
direnv allow
eval $(direnv export bash)

# WINEPREFIX must be set
if [[ -z $WINEPREFIX ]]; then
    echo "WINEPREFIX is not set. Please set it to your Wine prefix."
    exit 1
fi

[[ ! -d $WINEPREFIX ]] && winetricks dotnet6

GAME_ASSEMBLY="${GAME_FOLDER}/GameAssembly.dll"
GLOBAL_METADATA="${METADATA}/global-metadata.dat"

[[ ! -f $GAME_ASSEMBLY ]] && echo "GameAssembly.dll not found at ${GAME_ASSEMBLY}" && exit 1
[[ ! -f $GLOBAL_METADATA ]] && echo "global-metadata.dat not found at ${GLOBAL_METADATA}" && exit 1


mkdir -p output
wine Il2CppDumper.exe "${GAME_ASSEMBLY}" "${GLOBAL_METADATA}" output
