#ifndef HOOK_H
#define HOOK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Register struct - must match assembly layout exactly!
 * This is what wechat_hook_core receives as its argument.
 */
struct hook_regs {
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
    uint64_t rflags;
};

/*
 * C hook function - called from assembly with pointer to saved registers.
 * You can read register values: regs->rdi, regs->rax, etc.
 * You can also MODIFY them: regs->rax = 0x1337; 
 * Modified values will be restored when returning to WeChat!
 */
void wechat_hook_core(struct hook_regs *regs);

/*
 * Assembly entry point - contains the NOP sleds.
 * DO NOT CALL DIRECTLY - this is the target of the WeChat hook jump.
 */
void wechat_hook(void);

#ifdef __cplusplus
}
#endif

#endif /* HOOK_H */