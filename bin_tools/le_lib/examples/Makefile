CC = gcc
CFLAGS = -Wall -Wextra -g
CARGO = cargo

RUST_LIB_DIR = ../target/debug
RUST_LIB = lible_lib.so
EXAMPLE_NAME = register_dump

all: rust_lib $(EXAMPLE_NAME)

rust_lib:
	cd .. && $(CARGO) build

$(EXAMPLE_NAME): $(EXAMPLE_NAME).c
	$(CC) $(CFLAGS) -o $@ $< -L$(RUST_LIB_DIR) -lle_lib -Wl,-rpath,$(RUST_LIB_DIR)

test: all
	LD_LIBRARY_PATH=$(RUST_LIB_DIR) ./$(EXAMPLE_NAME)

clean:
	rm -f $(EXAMPLE_NAME)
	cd .. && $(CARGO) clean

.PHONY: all rust_lib test clean