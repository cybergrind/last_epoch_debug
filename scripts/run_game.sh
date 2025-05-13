#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
# parent directory
ROOT_DIR=$(realpath "$SCRIPT_DIR/..")
LOG_DIR=/tmp/le_lib.log

export HOOKS_CONFIG_PATH=$ROOT_DIR/bin_tools/le_lib/examples/ls_hook_example/le_hook.yaml
export LD_PRELOAD=$ROOT_DIR/bin_tools/le_lib/target/debug/lible_lib.so

echo "Running game with LD_PRELOAD set to $LD_PRELOAD" > $LOG_DIR
echo "Running game with HOOKS_CONFIG_PATH set to $HOOKS_CONFIG_PATH" >> $LOG_DIR
echo "Command: " ${@} >> $LOG_DIR

# run the game with LD_PRELOAD set to the lible_lib.so library
exec "${@}" 2>&1 | tee -a $LOG_DIR
