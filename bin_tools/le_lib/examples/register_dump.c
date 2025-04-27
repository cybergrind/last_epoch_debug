#include <stdio.h>
#include <stdint.h>

// Define the Registers structure (kept for reference)
typedef struct {
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t rbp;
    uint64_t rsp;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rip;
    uint64_t rflags;
} Registers;

// Declaration of the function from our Rust library (now with no parameters)
extern void le_lib_echo(void);

// This function will be injected into the game
__attribute__((naked)) void injected_function(void) {
    // Save all registers to stack and call le_lib_echo
    asm volatile (
        // Prologue - save stack pointer
        "push %rbp\n"
        "mov %rsp, %rbp\n"
        
        // Preserve registers that might be clobbered by the function call
        "push %rax\n"
        "push %rcx\n"
        "push %rdx\n"
        "push %rsi\n"
        "push %rdi\n"
        "push %r8\n"
        "push %r9\n"
        "push %r10\n"
        "push %r11\n"
        
        // Call our library function directly - no parameters needed
        "call le_lib_echo\n"
        
        // Restore preserved registers
        "pop %r11\n"
        "pop %r10\n"
        "pop %r9\n"
        "pop %r8\n"
        "pop %rdi\n"
        "pop %rsi\n"
        "pop %rdx\n"
        "pop %rcx\n"
        "pop %rax\n"
        
        // Epilogue - restore stack pointer and return
        "mov %rbp, %rsp\n"
        "pop %rbp\n"
        "ret\n"
    );
}

// Example standalone function to demonstrate usage
int main() {
    printf("This is an example program demonstrating le_lib_echo\n");
    printf("In a real scenario, the injected_function would be called from within the game\n");
    
    // Call our library function directly (for testing)
    printf("Calling le_lib_echo...\n");
    le_lib_echo();
    printf("Check /tmp/le_lib.log for register dump\n");
    
    return 0;
}