
# Context

We're working on reverse engineering a game "Last Epoch".

## Code analysis

Important: Use tool `high_level_il` to analyze the code. You also can use tools like `disassembly` and `pseudo_c` for more low-level analysis, but `high_level_il` is the most useful for understanding the code.

When renaming variables or functions, please add `ai/` prefix.



## Python coding

* Use single quotes
* Use `pathlib` for path manipulations when possible.
* Use modern Python features, such as f-strings, type hints, and the `with` statement for file handling.
* When writing new script, use `notes/examples/script.py` as a reference.
