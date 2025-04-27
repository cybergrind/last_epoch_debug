This is a rust library that would be called from game code modified by loading it with `LD_PRELOAD`.
It is used for games that runs on linux with proton or wine.

Rust code style:

* IMPORTANT: use new module style (do not use `mod.rs` file in the nested directory, just create file in the root of the module)
* use `#[unsafe(no_mangle)]` where required

There are following functions:

* `le_lib_init` - initializes the library:
  * allocates memory for global variables
  * sets up hook that will be called after dll is loaded in memory
* `le_lib_echo` - dumps all registers when called from C code
* `le_lib_load_hook` - loads the hook into the game
* `le_lib_unload_hook` - unloads the hook from the game


Hooks are defined in yaml file with following structure:
```yaml
hooks:
  - name: hook_name
    target_address: 0x6ffff84e20d0
    # whe check memory content before modifying it
    memory_content: '@SUVATAUAWH\x83\xec(\x80=1`-\x03\x00M\x8b\xe9M\x8b\xe0H\x8b\xeaH\x8b'
    hook_function: le_lib_echo
    # file to be loaded in maps before we're trying to load the hook
    # if it is not defined, we will wait for the address to be loaded
    wait_for_file: '/home/kpi/games/SteamLibrary/steamapps/common/Last Epoch/GameAssembly.dll'
```

TODO:
* add module for hooks functions `hook_tools.rs` with following functions:
  - `le_lib_load_hook` - loads the hook into the game
  - `le_lib_unload_hook` - unloads the hook from the game
* `le_lib_load_hook` details:
  - read yaml file with hooks
  - for each hook:
    - check if hook is already loaded
    - if not, load it and log
    - get address for target function
    - compile two small assembly functions:
      - first will:
        - save registers information
        - call hook_function
        - restore registers
        - long jump to target function after the second function call
      - second will:
        - long jump to first function address
      - use following function to compile: `nasm -o /tmp/<somefile> -f elf64 -l -g -w+all`


### Testing

```bash
cargo build

LD_PRELOAD=$(pwd)/target/debug/lible_lib.so $WINELOADER cmd /c exit


# test are only single threaded for now
cargo test -- --test-threads=1

# game start params
HOOKS_CONFIG_PATH=/home/kpi/devel/github/last_epoch_debug/bin_tools/le_lib/examples/ls_hook_example/le_hook.yaml LD_PRELOAD=/home/kpi/devel/github/last_epoch_debug/bin_tools/le_lib/target/debug/lible_lib.so %command%
```