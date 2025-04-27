#!/usr/bin/env bash

md5sum ${GAME_FOLDER}/GameAssembly.dll Metadata/global-metadata.dat > /tmp/sums && diff sums /tmp/sums
