This is a rust library that would be called from game code modified by loading it with `LD_PRELOAD`.
It is used for games that runs on linux with proton or wine.

Other environmental variables:

* `HOOKS_CONFIG_PATH` - path to custom file, default: `/tmp/hooks.yaml`


## Rust code style:

* IMPORTANT: use new module style (do not use `mod.rs` file in the nested directory, just create file in the root of the module)
* use `#[unsafe(no_mangle)]` where required

There are following functions:

* `le_lib_init` - initializes the library:
  * allocates memory for global variables
  * sets up hook that will be called after dll is loaded in memory
* `le_lib_echo` - dumps all registers when called from C code
* `le_lib_load_hook` - loads the hook into the game
* `le_lib_unload_hook` - unloads the hook from the game

## Hooks

There are 2 types of hooks for now:
1. Simple overwrite of the memory (when you need to change condition or disable something)
2. Hook with jumper, trampoline and hook function

Configs:

```yaml
hooks:
  - name: hook_name                      # Unique name for the hook
    target_address: '0x12345678'         # Memory address to hook (as hex string)
    memory_content: '\x90\x90\x90'       # Expected memory content at target address (helps validate correct location)
    hook_functions:                      # List of functions to call when hook is triggered
      - le_lib_echo                      # Example: dump register state
      - le_lib_custom_function           # Custom function to execute
    target_process: 'ProcessName.exe'    # Target process name
    base_file: 'DllName.dll'             # Base DLL file name
    align_size: 14                       # Size of instructions to overwrite
    overwritten_instructions: |          # Original assembly that will be overwritten (for reference)
      push    rbx
      push    rbp
      sub     rsp, 0x28

  # Memory overwrite mode (no hook function, just patch memory)
  - name: memory_patch_example
    target_address: '0x12345678'
    memory_content: '\xe8\x41\x71\xf3\xff'   # Original bytes
    hook_functions: []                        # Empty for direct memory patch
    memory_overwrite: '\x90\x90\x90\x90\x90'  # New bytes to write (NOP example)
    target_process: 'ProcessName.exe'
    base_file: 'DllName.dll'
    align_size: 5                            # Size of the memory patch
    overwritten_instructions: ''             # Can be empty for simple patches
```

## TODO:
* implement HookManager
  * stores all hooks
  * should use yaml file to converge existing applied hooks 

## High Level Architecture

The library is organized into a hierarchy of components that work together to provide game hooking functionality:

### Core Components

1. **Process Integration & Initialization**
   - **Library Initialization (`lib_init.rs`)**
     - Entry point via `le_lib_init()` function
     - Constructor for LD_PRELOAD loading
     - Hook registry via global hashmaps
   - **Wine Process Hooks (`wine_hooks.rs`)**
     - Intercepts mmap syscalls for dynamic module loading
     - Monitors loaded DLLs and modules
     - Triggers hook application when target modules load

2. **Memory Management**
   - **Memory Access Layer (`wine_memory.rs`)**
     - Safe memory operations for Wine/Proton environment
     - Multiple memory access methods (process_vm_writev, ptrace, mprotect)
     - Memory protection handling
   - **Memory Mapping (`system_tools/maps.rs`)**
     - Process memory map scanning and tracking
     - Thread-safe memory map management

3. **Hook Implementation Stack**
   - **Hook Management (`low_level_tools/hook_tools.rs`)**
     - Loading/unloading hooks from configuration
     - Hook verification and validation
     - Hook storage and tracking
   - **Code Injection (`low_level_tools/injector.rs`)**
     - Memory allocation with execution permissions
     - Memory read/write operations
     - Hook injection and restoration
   - **Assembly Generation (`low_level_tools/templates.rs`)**
     - Trampoline code templates
     - Hook function templates
     - Dynamic code generation

4. **Compilation Subsystem**
   - **Compilation Manager (`low_level_tools/compiler/`)**
     - Local compilation via system NASM
     - Remote compilation via compiler server
     - Compilation result handling

5. **Hook Functionality**
   - **Debugging Hooks (`hooks/echo.rs`)**
     - Register state dumping
     - Execution tracing
   - **Game-Specific Hooks (`hooks/pickup.rs`)**
     - Game functionality modification
     - Custom game behavior

### Data Flow

1. Library is loaded via LD_PRELOAD
2. Constructor calls `le_lib_init()` to initialize the library
3. System monitors loaded modules via memory map scanning
4. When target module is loaded, hooks are applied:
   - Target memory is verified
   - Assembly is compiled (trampoline + hook code)
   - Memory is modified to redirect execution
5. Hook functions are executed when game code reaches hooked locations
6. Hooks can be dynamically loaded/unloaded at runtime

### Hooking Process

1. **Hook Configuration**: YAML files define hook targets and functions
2. **Hook Loading**: `le_lib_load_hook()` processes configuration
3. **Memory Verification**: Checks target memory matches expected content
4. **Assembly Generation**:
   - Trampoline code saves registers
   - Calls hook function(s)
   - Restores registers
   - Executes original instructions
   - Returns to original execution flow
5. **Code Injection**: Replaces target code with jump to trampoline

### Threading & Synchronization

- Thread-safe data structures using Mutex and RwLock
- Periodic background scanning for module loading
- One-time initialization with Once
- Thread-safe memory map access

### Compilation Process

1. Assembly templates are rendered with specific parameters
2. Templates compiled using either:
   - Local NASM compiler
   - Remote compiler server
3. Compiled code is injected into memory

## Already implemented:
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