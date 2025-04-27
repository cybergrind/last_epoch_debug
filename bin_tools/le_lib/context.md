
This is a rust library that would be called from code.

TODO:
* Add logging to file: /tmp/le_lib.log
* Add simple function `le_lib_echo` that will dump all registers when called
* Add example C code that will be compiled and injected into the game. It should save all registers and call `le_lib_echo()`