use std::collections::HashMap;

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
use tera::{self, Result as TeraResult, Value};
use tera::{Context, Tera};

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
    ; Save stack pointer to the stack
    push rsp

    ; Save flags to preserve them before any operations
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

    ; save xmm registers
    lea rsp, [rsp-16*8]
    vmovdqu [rsp+16*0],xmm0
    vmovdqu [rsp+16*1],xmm1
    vmovdqu [rsp+16*2],xmm2
    vmovdqu [rsp+16*3],xmm3
    vmovdqu [rsp+16*4],xmm4
    vmovdqu [rsp+16*5],xmm5
    vmovdqu [rsp+16*6],xmm6
    vmovdqu [rsp+16*7],xmm7


    ; pass the stack pointer to the linux hook function
    mov rdi, rsp

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
    ; restore xmm registers
    vmovdqu xmm7,[rsp+16*7]
    vmovdqu xmm6,[rsp+16*6]
    vmovdqu xmm5,[rsp+16*5]
    vmovdqu xmm4,[rsp+16*4]
    vmovdqu xmm3,[rsp+16*3]
    vmovdqu xmm2,[rsp+16*2]
    vmovdqu xmm1,[rsp+16*1]
    vmovdqu xmm0,[rsp+16*0]
    lea rsp, [rsp+16*8]
    ; Restore regular registers in reverse order
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

    ; Restore flags
    popfq
    ; Restore the stack pointer
    pop rsp
    "#,
        hook_function_address
    )
}

fn lambda_relative(
    base_address: u64,
) -> impl Fn(&Value, &HashMap<String, Value>) -> TeraResult<Value> {
    move |value: &Value, _| {
        // parse hex value
        let parsed_address =
            u64::from_str_radix(value.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16)
                .unwrap();
        let address = parsed_address + base_address;
        Ok(Value::from(format!("0x{:X}", address)))
    }
}

fn prepare_overwritten_instructions(overwritten_instructions: &str) -> String {
    // we need to replace all occurences of template:
    // {# 0xSOMEVALUE #} with {{ '0xSOMEVALUE' | relative }}
    let updated_instructions = overwritten_instructions
        .replace("{# 0x", "{{ '0x")
        .replace(" #}", "' | relative }}");
    updated_instructions
}

fn render_epilogue(overwritten_instructions: &str, src_address: u64, base_address: u64) -> String {
    // overwritten_instructions is a tera template
    // it can require base address for relative operations
    // {{base_address + 0xDEADBEEF}}

    let mut tera = Tera::default();
    tera.register_filter("relative", lambda_relative(base_address));

    let mut ctx = Context::new();
    ctx.insert("base_address", &base_address);
    ctx.insert("src_address", &src_address);

    let rendered_instructions = tera
        .render_str(
            &prepare_overwritten_instructions(overwritten_instructions),
            &ctx,
        )
        .unwrap();

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
        rendered_instructions, src_address
    )
}

pub fn render_trampoline(
    hook_function_addresses: Vec<u64>,
    overwritten_instructions: &str,
    target_address: u64,
    base_address: u64,
) -> String {
    let prologue = render_prologue();
    let hooks = hook_function_addresses
        .iter()
        .map(|&addr| render_hook(addr))
        .collect::<Vec<_>>()
        .join("\n");
    let epilogue = render_epilogue(overwritten_instructions, target_address, base_address);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prepare_overwritten_instructions() {
        let overwritten_instructions = r#"
        mov rax, {# 0x200 #}
        mov rbx, {# 0x300 #}
        "#;

        let result = prepare_overwritten_instructions(overwritten_instructions);
        assert!(result.contains("mov rax, {{ '0x200' | relative }}"));
        assert!(result.contains("mov rbx, {{ '0x300' | relative }}"));
    }

    #[test]
    fn test_render_trampoline() {
        let hook_function_addresses = vec![0x12345678, 0x87654321];
        let overwritten_instructions = "mov rax, {# 0x200 #}";
        let target_address = 0x9ABCDEF0;
        let base_address = 0x10000000;

        let result = render_trampoline(
            hook_function_addresses,
            overwritten_instructions,
            target_address,
            base_address,
        );
        println!("{}", result);

        assert!(result.contains("BITS 64"));
        assert!(result.contains("mov rax, 0x87654321"));
        assert!(result.contains("mov rax, 0x10000200"));
    }
}
