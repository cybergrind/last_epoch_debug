/*```
    // Create the trampoline assembly
    let trampoline_asm = format!(
        r#"BITS 64
    ; restore previous rax state
    pop rax

    ; Save all registers and flags in the correct order for x86-64 ABI compliance
    ; Save flags first to preserve them before any operations
    pushfq

    ; Save all general purpose registers
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    ; create new stack frame
    push rbp
    mov rbp, rsp

    ; Call the hook function
    mov rax, 0x{:X}
    call rax

    ; restore the original stack frame
    mov rsp, rbp
    pop rbp

    ; Restore all registers in reverse order
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax

    ; Restore flags last
    popfq

    ; Execute overwritten instructions
    {}

    ; Jump back to the original function (after our jumper)
    push rax
    mov rax, 0x{:X}
    ; skip following instructions bytes
    ; push rax  ; l byte
    ; mov rax, 0xDEADBEEF  ; 10 bytes
    ; jmp rax  ; 2 bytes
    ; pop rax <- need to jump here
    add rax, 0xD
    jmp rax
"#,
        hook_function_address, hook.overwritten_instructions, target_address
    );
```*/

fn render_prologue() -> String {
    return format!(
        r#"
        BITS 64
        ; restore previous rax state
        pop rax
        "#,
    );
}

fn render_hook(hook_function_address: u64) -> String {
    format!(
        r#"

    ; Save all registers and flags in the correct order for x86-64 ABI compliance
    ; Save flags first to preserve them before any operations
    pushfq

    ; Save all general purpose registers
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    ; create new stack frame
    push rbp
    mov rbp, rsp
    ; Call the hook function
    mov rax, 0x{:X}
    call rax
    ; restore the original stack frame
    mov rsp, rbp
    pop rbp
    ; Restore all registers in reverse order
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax

    ; Restore flags last
    popfq
    "#,
        hook_function_address
    )
}

fn render_epilogue(overwritten_instructions: &str, src_address: u64) -> String {
    format!(
        r#"
    ; Execute overwritten instructions
    {}
    ; Jump back to the original function (after our jumper)
    push rax
    mov rax, 0x{:X}
    ; skip following instructions bytes
    ; push rax  ; l byte
    ; mov rax, 0xDEADBEEF  ; 10 bytes
    ; jmp rax  ; 2 bytes
    ; pop rax <- need to jump here
    add rax, 0xD
    jmp rax
"#,
        overwritten_instructions, src_address
    )
}

pub fn render_trampoline(
    hook_function_addresses: Vec<u64>,
    overwritten_instructions: &str,
    target_address: u64,
) -> String {
    let prologue = render_prologue();
    let hooks = hook_function_addresses
        .iter()
        .map(|&addr| render_hook(addr))
        .collect::<Vec<_>>()
        .join("\n");
    let epilogue = render_epilogue(overwritten_instructions, target_address);
    return vec![prologue, hooks, epilogue].join("\n");
}

pub fn render_jumper(addr: Option<u64>) -> String {
    format!(
        r#"BITS 64
    ; Jump to our trampoline
    push rax
    mov rax, 0x{:X}
    jmp rax
    pop rax
    "#,
        addr.unwrap_or(0xDEADBEEF)
    )
}
