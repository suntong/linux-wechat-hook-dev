#include <iostream>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>

#include "hook.h"
#include "target/targetopt.h"
#include "log/log.h"

#define WECHAT_OFFSET 0x9b0a7a
#define NOP_PATTERN_SIZE 16

/*
 * Validate pointer is in user space range
 */
static inline bool is_valid_user_ptr(uint64_t addr)
{
    return (addr >= 0x10000 && addr < 0x7fffffffffff);
}

/*
 * Hook core function - receives pointer to saved registers
 * This is called from assembly: wechat_hook_core(&regs)
 */
extern "C" void wechat_hook_core(struct hook_regs *regs)
{
    /*
     * Access register values - these are the EXACT values
     * that were in the CPU registers when WeChat hit the hook point
     */

    if (is_valid_user_ptr(regs->rdi)) {
        LOGGER_INFO << " rdi  " << LogFormat::addr << regs->rdi
                    << "  " << (char *)regs->rdi;
    }

    /*
     * You can examine other registers too:
     */
    #if 0
    if (is_valid_user_ptr(regs->rsi)) {
        LOGGER_INFO << " rsi  " << LogFormat::addr << regs->rsi 
                    << "  " << (char *)regs->rsi;
    }
    if (is_valid_user_ptr(regs->rdx)) {
        LOGGER_INFO << " rdx  " << LogFormat::addr << regs->rdx;
    }
    if (is_valid_user_ptr(regs->rcx)) {
        LOGGER_INFO << " rcx  " << LogFormat::addr << regs->rcx;
    }
    if (is_valid_user_ptr(regs->r8)) {
        LOGGER_INFO << " r8   " << LogFormat::addr << regs->r8;
    }
    if (is_valid_user_ptr(regs->r9)) {
        LOGGER_INFO << " r9   " << LogFormat::addr << regs->r9;
    }
    #endif

    /*
     * You can also MODIFY registers!
     * Changes here will be restored to actual CPU registers
     * when returning to WeChat.
     * 
     * Example: Change return value
     *   regs->rax = 0;
     * 
     * Example: Modify first argument
     *   regs->rdi = (uint64_t)my_fake_string;
     */
}

/*
 * Library initialization - called when libX.so is loaded
 */
void __attribute__((constructor)) wechat_hook_init(void)
{
    printf("==============================================\n");
    printf("libX.so loaded - Installing WeChat hook\n");
    printf("==============================================\n");

    lmc::Logger::setLevel(LogLevel::all);

    TargetMaps target(getpid());
    Elf64_Addr wechat_baseaddr = 0;
    Elf64_Addr libx_baseaddr = 0;
    Elf64_Addr first_nop_cmd_addr = 0;
    Elf64_Addr second_nop_cmd_addr = 0;

    if (!target.readTargetAllMaps()) {
        LOGGER_ERROR << "Failed to read target maps";
        return;
    }

    /* Find base addresses */
    auto &maps = target.getMapInfo();
    for (auto &m : maps) {
        if (m.first.find("wechat") != std::string::npos && wechat_baseaddr == 0) {
            wechat_baseaddr = m.second;
            LOGGER_INFO << m.first << " :: " << LogFormat::addr << m.second;
        }
        if (m.first.find("libX.so") != std::string::npos && libx_baseaddr == 0) {
            libx_baseaddr = m.second;
            LOGGER_INFO << m.first << " :: " << LogFormat::addr << m.second;
        }
    }

    if (!wechat_baseaddr || !libx_baseaddr) {
        LOGGER_ERROR << "Failed to find base addresses";
        return;
    }

    /* Search for NOP sleds in our library */
    unsigned char nop_pattern[NOP_PATTERN_SIZE];
    memset(nop_pattern, 0x90, sizeof(nop_pattern));

    unsigned char *search_ptr = (unsigned char *)libx_baseaddr;
    for (int i = 0; i < 0x1000000; i++) {
        if (memcmp(&search_ptr[i], nop_pattern, sizeof(nop_pattern)) == 0) {
            if (first_nop_cmd_addr) {
                second_nop_cmd_addr = (Elf64_Addr)&search_ptr[i];
                LOGGER_INFO << "second NOP sled @ " << LogFormat::addr << second_nop_cmd_addr;
                break;
            } else {
                first_nop_cmd_addr = (Elf64_Addr)&search_ptr[i];
                LOGGER_INFO << "first NOP sled @ " << LogFormat::addr << first_nop_cmd_addr;
                i += NOP_PATTERN_SIZE;  /* Skip past this sled */
            }
        }
    }

    if (!first_nop_cmd_addr || !second_nop_cmd_addr) {
        LOGGER_ERROR << "Failed to find NOP sleds in libX.so";
        return;
    }

    /* Make memory writable for patching */
    size_t page_size = sysconf(_SC_PAGESIZE);
    Elf64_Addr wechat_page = wechat_baseaddr & ~(page_size - 1);
    Elf64_Addr libx_page = libx_baseaddr & ~(page_size - 1);

    if (mprotect((void *)wechat_page, 0x1000000, PROT_WRITE | PROT_READ | PROT_EXEC) < 0) {
        LOGGER_ERROR << "mprotect failed for WeChat region";
        return;
    }

    if (mprotect((void *)libx_page, 0x100000, PROT_WRITE | PROT_READ | PROT_EXEC) < 0) {
        LOGGER_ERROR << "mprotect failed for libX region";
        return;
    }

    /*
     * =================================================================
     * PATCH 1: Exit trampoline (second_nop_cmd_addr)
     * 
     * Layout (24 bytes total):
     *   [0-11]  Original 12 bytes from WeChat @ 0x9b0a7a
     *   [12-21] movabs rax, return_addr
     *   [22-23] jmp rax
     * =================================================================
     */
    unsigned char *exit_patch = (unsigned char *)second_nop_cmd_addr;
    
    /* Copy original 12 bytes that we're about to overwrite */
    memcpy(exit_patch, (unsigned char *)wechat_baseaddr + WECHAT_OFFSET, 12);
    
    /* movabs rax, imm64 (return address = hook point + 12) */
    Elf64_Addr return_addr = wechat_baseaddr + WECHAT_OFFSET + 12;
    exit_patch[12] = 0x48;  /* REX.W */
    exit_patch[13] = 0xB8;  /* MOV RAX, imm64 */
    memcpy(&exit_patch[14], &return_addr, 8);
    
    /* jmp rax */
    exit_patch[22] = 0xFF;
    exit_patch[23] = 0xE0;

    /*
     * =================================================================
     * PATCH 2: WeChat hook point (wechat_baseaddr + WECHAT_OFFSET)
     * 
     * Layout (12 bytes total):
     *   [0-9]   movabs rax, first_nop_cmd_addr
     *   [10-11] jmp rax
     * =================================================================
     */
    unsigned char *hook_patch = (unsigned char *)wechat_baseaddr + WECHAT_OFFSET;
    
    /* movabs rax, imm64 (our hook entry point) */
    hook_patch[0] = 0x48;   /* REX.W */
    hook_patch[1] = 0xB8;   /* MOV RAX, imm64 */
    memcpy(&hook_patch[2], &first_nop_cmd_addr, 8);
    
    /* jmp rax */
    hook_patch[10] = 0xFF;
    hook_patch[11] = 0xE0;

    /* Restore memory protection */
    mprotect((void *)wechat_page, 0x1000000, PROT_READ | PROT_EXEC);
    mprotect((void *)libx_page, 0x100000, PROT_READ | PROT_EXEC);

    LOGGER_INFO << "==============================================";
    LOGGER_INFO << "Hook installed successfully!";
    LOGGER_INFO << "  Hook point: " << LogFormat::addr << (wechat_baseaddr + WECHAT_OFFSET);
    LOGGER_INFO << "  Entry sled: " << LogFormat::addr << first_nop_cmd_addr;
    LOGGER_INFO << "  Exit sled:  " << LogFormat::addr << second_nop_cmd_addr;
    LOGGER_INFO << "==============================================";
}
