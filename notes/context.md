
# Context

We're working on reverse engineering a game "Last Epoch".


## Code analysis

Important: Use tool `high_level_il` to analyze the code. You also can use tools like `disassembly` and `pseudo_c` for more low-level analysis, but `high_level_il` is the most useful for understanding the code.

When renaming variables or functions, please add `ai/` prefix.


## Small modifications

If we need just to make a small modification, we can directly modify memory with hook like
Note: we can use only the same amount of bytes. We can use `nop` instruction to skip some code.


```yaml
  - name: aerial_assault_disable_block_movement_2
    target_address: '0xefab06'
    memory_content: '\x75\x0f'
    hook_functions: []
    memory_overwrite: '\xeb\x0f'
    target_process: 'Last Epoch.exe'
    base_file: 'GameAssembly.dll'
    align_size: 2
    overwritten_instructions: ''
```



## Python coding

* Use single quotes
* Use `pathlib` for path manipulations when possible.
* Use modern Python features, such as f-strings, type hints, and the `with` statement for file handling.
* When writing new script, use `notes/examples/script.py` as a reference.
