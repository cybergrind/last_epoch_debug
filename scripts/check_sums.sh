#!/usr/bin/env bash

SUMS=${PROJECT_ROOT}/notes/sums
TMP_SUMS=/tmp/sums
GAME_ASSEMBLY="${GAME_FOLDER}/GameAssembly.dll"
GLOBAL_METADATA="${METADATA}/global-metadata.dat"

[[ ! -f $GAME_ASSEMBLY ]] && echo "GameAssembly.dll not found at ${GAME_ASSEMBLY}" && exit 1
[[ ! -f $GLOBAL_METADATA ]] && echo "global-metadata.dat not found at ${GLOBAL_METADATA}" && exit 1

md5sum "$GAME_ASSEMBLY" "$GLOBAL_METADATA" > "$TMP_SUMS"
# remove prefix $GAME_FOLDER
sed -i "s|$GAME_FOLDER/||g" "$TMP_SUMS"

diff -s "$SUMS" "$TMP_SUMS"
