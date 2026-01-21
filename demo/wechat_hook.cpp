#include <iostream>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <cctype>

#include <sys/user.h>
#include <sys/mman.h>
#include <sys/uio.h>

#include "target/targetopt.h"
#include "log/log.h"

//=============================================================================
// HOOK CONFIGURATION
//=============================================================================
// movabs rax, imm64 (10 bytes) + jmp rax (2 bytes) = 12 bytes
#define JMP_STUB_SIZE 12

// Hook offset into WeChat binary - target instruction address (relative to base)
// Target location analysis:
//   71df9f: 41 8b 06                mov (%r14),%eax         ; 3 bytes
//   71dfa2: c7 44 24 30 06 00 00 00 movl $0x6,0x30(%rsp)    ; 8 bytes
//   71dfaa: 89 44 24 20             mov %eax,0x20(%rsp)     ; 4 bytes
// Total: 15 bytes of instructions to relocate
#define WECHAT_OFFSET 0x71df9f

// Size of original instructions to relocate to trampoline
// Must be >= 12 (hook size) and end on instruction boundary
// Hook injection requires: 10 bytes (movabs) + 2 bytes (jmp) = 12 bytes
// Instruction boundaries: 3, 11 (3+8), 15 (3+8+4),
// Therefore we must relocate 15 bytes to preserve complete instructions
#define WECHAT_HOOK_BYTES 15

//=============================================================================
// HOOK INITIALIZATION - Called when library is loaded via LD_PRELOAD
//=============================================================================
void __attribute__((constructor)) wechat_hook_init(void) {
  /*

  Init Actions:

    Find the base address of the wechat binary and libX.so
    Find 2nd NOP sleds (32 consecutive 0x90 bytes) in libX.so to use as trampoline
    Hook the instruction at WECHAT_OFFSET (0x9b0a7a) by:
        Relocating the instructions to the second NOP sled (trampoline)
        Replacing the original instructions with a jump to the first NOP sled
        The first NOP sled fall-throuh to the hook function
        After the trampoline code, it then jumps back to wechat to continue its normal operations

  Execution Flow Diagram:

   WeChat code at 0x71df9f
         |
         v (patched to jump)
    first_nop_cmd_addr (16 NOPs)
         |
         v
    push r14, push r15 (save original values)
    mov rbp->r14, mov rdi->r15 (for hook analysis)
         |
         v
    wechat_hook_run() -> wechat_hook_core()
         |
         v
    pop r15, pop r14 (restore original values)
         |
         v
    second_nop_cmd_addr (TRAMPOLINE):
      - Execute: mov (%r14),%eax      (uses correct r14!)
      - Execute: movl $0x6,0x30(%rsp)
      - Execute: mov %eax,0x20(%rsp)
      - Jump back to 0x71df9f + 15 = 0x71dfae
         |
         v
    Continue WeChat execution at 0x71dfae

   */

  printf("Dynamic library loaded: Running initialization.\n");
  lmc::Logger::setLevel(LogLevel::all);

  // Read process memory maps to find base addresses
  TargetMaps target(getpid());
  Elf64_Addr wechat_baseaddr = 0;      // Base address of WeChat executable
  Elf64_Addr libx_baseaddr = 0;         // Base address of our hook library (libX.so)
  Elf64_Addr first_nop_cmd_addr = 0;    // Entry point NOP sled (hook entry)
  Elf64_Addr second_nop_cmd_addr = 0;   // Trampoline NOP sled (displaced code + return)

  if (target.readTargetAllMaps())
  {
    auto &maps = target.getMapInfo();
    //---------------------------------------------------------------------
    // Step 1: Find base addresses of WeChat and our hook library
    //---------------------------------------------------------------------
    for (auto &m : maps)
    {
      if (m.first.find("wechat") != std::string::npos)
      {
        wechat_baseaddr = m.second;
        LOGGER_INFO << m.first << " :: " << LogFormat::addr << m.second;
      }

      if (m.first.find("libX.so") != std::string::npos)
      {
        libx_baseaddr = m.second;
        LOGGER_INFO << m.first << " :: " << LogFormat::addr << m.second;
      }
    }

    //---------------------------------------------------------------------
    // Step 2: Search for two 16-byte NOP sleds in our hook library
    // - First NOP sled: Hook entry point (wechat_hook function start)
    // - Second NOP sled: Trampoline (holds displaced instructions + jump back)
    //---------------------------------------------------------------------
    unsigned char buffer[16] = {0x90};
    memset(buffer, 0x90, sizeof(buffer));

    unsigned char *nop_cmd_byte = (unsigned char *)libx_baseaddr;
    for (int i = 0; i < 0x1000000; i++)
    {
      // Check for 16 consecutive NOP bytes
      if (!memcmp(&nop_cmd_byte[i], buffer, sizeof(buffer)))
      {
        if (first_nop_cmd_addr)
        {
          // Found second NOP sled - this will be our trampoline
          second_nop_cmd_addr = (Elf64_Addr)&nop_cmd_byte[i];
          LOGGER_INFO << "second search successful   " << LogFormat::addr << second_nop_cmd_addr;
          break;
        } else {
          // Found first NOP sled - this is where WeChat will jump to
          first_nop_cmd_addr = (Elf64_Addr)&nop_cmd_byte[i];
          LOGGER_INFO << "first search successful   " << LogFormat::addr << first_nop_cmd_addr;
          i += 16;  // Skip past this sled to find the next one
          continue;
        }
      }
    }

    //---------------------------------------------------------------------
    // Step 3: Make memory regions writable for patching
    //---------------------------------------------------------------------
    if (mprotect((void *)(wechat_baseaddr), 0x1000000, PROT_WRITE | PROT_READ | PROT_EXEC) < 0)
    {
      LOGGER_INFO << "mprotect wechat (RWX) failed";
    }

    if (mprotect((void *)(libx_baseaddr), 0x10000, PROT_WRITE | PROT_READ | PROT_EXEC) < 0)
    {
      LOGGER_INFO << "mprotect libx (RWX) failed";
    }

    //---------------------------------------------------------------------
    // Step 4: Build the TRAMPOLINE at second_nop_cmd_addr
    // Layout:
    //   [0-14]  : Displaced original instructions (15 bytes)
    //   [15-24] : movabs $return_addr, %rax (10 bytes)
    //   [25-26] : jmp *%rax (2 bytes)
    //---------------------------------------------------------------------

    // Copy 15 bytes of original instructions to trampoline
    memcpy((unsigned char *)second_nop_cmd_addr,
           (unsigned char *)wechat_baseaddr + WECHAT_OFFSET,
           WECHAT_HOOK_BYTES);

    // Build: movabs $return_address, %rax
    // Machine code: 48 b8 <8-byte immediate>
    // Return address is right after the relocated instructions in WeChat
    unsigned char movabs_wechat_buffer[10];
    memset(movabs_wechat_buffer, 0, sizeof(movabs_wechat_buffer));
    Elf64_Addr wechat_hook_point_addr = (Elf64_Addr)wechat_baseaddr + WECHAT_OFFSET + WECHAT_HOOK_BYTES;
    movabs_wechat_buffer[0] = 0x48;  // REX.W prefix
    movabs_wechat_buffer[1] = 0xb8;  // MOV imm64 to RAX
    memcpy(&movabs_wechat_buffer[2], &wechat_hook_point_addr, 8);
    memcpy((unsigned char *)second_nop_cmd_addr + WECHAT_HOOK_BYTES, movabs_wechat_buffer, 10);

    // Build: jmp *%rax
    // Machine code: ff e0
    unsigned char jmp_wechat_buffer[2];
    jmp_wechat_buffer[0] = 0xff;
    jmp_wechat_buffer[1] = 0xe0;
    memcpy((unsigned char *)second_nop_cmd_addr + WECHAT_HOOK_BYTES + 10, jmp_wechat_buffer, 2);

    //---------------------------------------------------------------------
    // Step 5: Patch the HOOK POINT in WeChat
    // Replace original instructions with jump to our hook entry
    //
    //   movabs rax, first_nop_cmd_addr
    //   jmp    rax
    //   [optional NOP padding for the remainder of WECHAT_HOOK_BYTES]

    // This completely replaces the first WECHAT_HOOK_BYTES bytes at
    // WECHAT_OFFSET. Any extra bytes beyond the 12-byte jump stub are
    // filled with NOP so we never execute a partially decoded instruction.
    //---------------------------------------------------------------------

    // Build: movabs $first_nop_cmd_addr, %rax
    unsigned char movabs_buffer[10];
    memset(movabs_buffer, 0, sizeof(movabs_buffer));
    movabs_buffer[0] = 0x48;  // REX.W prefix
    movabs_buffer[1] = 0xb8;  // MOV imm64 to RAX
    memcpy(&movabs_buffer[2], &first_nop_cmd_addr, 8);
    memcpy((unsigned char *)wechat_baseaddr + WECHAT_OFFSET, movabs_buffer, 10);

    // Build: jmp *%rax
    unsigned char jmp_buffer[2];
    jmp_buffer[0] = 0xff;
    jmp_buffer[1] = 0xe0;
    memcpy((unsigned char *)wechat_baseaddr + WECHAT_OFFSET + 10, jmp_buffer, 2);

    // Pad any remaining bytes (if WECHAT_HOOK_BYTES > 12) with NOPs so that
    // the whole overwritten region is clean and we don't leave remnants of
    // a partially executed instruction.
    if (WECHAT_HOOK_BYTES > JMP_STUB_SIZE) {
      memset((unsigned char *)wechat_baseaddr + WECHAT_OFFSET
             + JMP_STUB_SIZE,
             0x90,  // NOP
             WECHAT_HOOK_BYTES - JMP_STUB_SIZE);
    }

    //---------------------------------------------------------------------
    // Step 6: Restore original memory protections
    //---------------------------------------------------------------------
    if (mprotect((void *)(wechat_baseaddr), 0x1000000, PROT_READ | PROT_EXEC) < 0)
    {
      LOGGER_INFO << "mprotect wechat (RX) failed";
    }

    if (mprotect((void *)(libx_baseaddr), 0x10000, PROT_READ | PROT_EXEC) < 0)
    {
      LOGGER_INFO << "mprotect libx (RX) failed";
    }
  }
}


/*
 * Validate pointer is in user space range
 */
static inline bool is_valid_user_ptr(uint64_t addr) {
  return (addr >= 0x10000 && addr < 0x7fffffffffff);
}

/*
 * Try to safely read memory. Returns true if readable.
 */
static inline bool safe_memread(const void *addr, void *buf, size_t len) {
    // Use process_vm_readv so the kernel validates accessibility and copies for us.
    // This avoids SIGSEGV from direct user-space dereferences.
    struct iovec local_iov;
    struct iovec remote_iov;

    local_iov.iov_base = buf;
    local_iov.iov_len  = len;

    remote_iov.iov_base = const_cast<void *>(addr);
    remote_iov.iov_len  = len;

    ssize_t n = process_vm_readv(getpid(), &local_iov, 1, &remote_iov, 1, 0);
    return (n == (ssize_t)len);
}

template <typename T>
static inline bool safe_read_value(uint64_t addr, T *out) {
  return safe_memread((const void *)addr, out, sizeof(T));
}

/*
 * Dump a register value and, if it looks like a user pointer,
 * the first 16 bytes at that address in hex.
 */
static inline void dump_reg_and_mem(const char *name, uint64_t val) {
  LOGGER_INFO << "  " << name << "  " << LogFormat::addr << val;

  // Sanity check
  if (!is_valid_user_ptr(val)) {
    return;
  }
  unsigned char buf[16];
  if (!safe_memread((const void *)val, buf, sizeof(buf))) {
    LOGGER_INFO << "    [ <inaccessible> ]";
    return;
  }

  // NOTE: Use 'buf' here (NOT direct pointer dereference), otherwise we may SIGSEGV.
  char hex_buf[50]; // Max: 16 * 3 = 48 plus a null terminator
  int pos = 0;
  for (int i = 0; i < 16; i++) {
    pos += snprintf(&hex_buf[pos], sizeof(hex_buf) - pos, "%02x ", buf[i]);
  }
  LOGGER_INFO << "    [ " << hex_buf << "]";

  // Additional probing: if it looks like a string, print it
  // NOTE: Do not directly dereference 'val' as a char*; read safely instead.
  if (buf[0] != 0 && isprint((unsigned char)buf[0])) {
    char str_buf[256];
    if (safe_memread((const void *)val, str_buf, sizeof(str_buf) - 1)) {
      str_buf[sizeof(str_buf) - 1] = '\0';
      LOGGER_INFO << "    (as string: \"" << str_buf << "\")";
    }
  }
}

/*
 * Dump a presumed message struct pointed to by base_addr.
 * Based on inferred offsets from asm analysis.
 */
static inline void dump_message_struct(uint64_t base_addr) {
  if (!is_valid_user_ptr(base_addr)) {
    return;
  }

  LOGGER_INFO << "   --- Message Struct at " << LogFormat::addr << base_addr << " ---";

  // Content string (0x58: ptr, 0x60: len?, 0x68: null-term)
  uint64_t content_ptr = 0;
  if (safe_read_value<uint64_t>(base_addr + 0x58, &content_ptr)) {
    dump_reg_and_mem("Content (0x58)", content_ptr);
  } else {
    LOGGER_INFO << "  Content <inaccessible>";
    return;
  }

  // Sender string (0x78: ptr, 0x80: len?, 0x88: null-term)
  uint64_t sender_ptr = 0;
  if (safe_read_value<uint64_t>(base_addr + 0x78, &sender_ptr)) {
    dump_reg_and_mem("Sender (0x78)", sender_ptr);
  }

  // Chat/ID string (0x98: ptr, 0xa0: len?, 0xa8: null-term)
  uint64_t chat_ptr = 0;
  if (safe_read_value<uint64_t>(base_addr + 0x98, &chat_ptr)) {
    dump_reg_and_mem("Chat/ID (0x98)", chat_ptr);
  }

  // Type (0xb8: int32)
  uint32_t type = 0;
  if (safe_read_value<uint32_t>(base_addr + 0xb8, &type)) {
    LOGGER_INFO << "  Type (0xb8): " << type;
  }

  // Attachments array/vector (0xc0: xmm/zeroed, but assume ptr + size)
  uint64_t attach_ptr = 0;
  if (safe_read_value<uint64_t>(base_addr + 0xc0, &attach_ptr)) {
    dump_reg_and_mem("Attachments (0xc0)", attach_ptr);
  }

  // Metadata ptr (0xd0)
  uint64_t meta_ptr = 0;
  if (safe_read_value<uint64_t>(base_addr + 0xd0, &meta_ptr)) {
    dump_reg_and_mem("Metadata (0xd0)", meta_ptr);
  }

  // Extended ptr (0xd8)
  uint64_t ext_ptr = 0;
  if (safe_read_value<uint64_t>(base_addr + 0xd8, &ext_ptr)) {
    dump_reg_and_mem("Extended (0xd8)", ext_ptr);
  }

  // Timestamp/Secondary ID (0xe0: int32)
  uint32_t timestamp = 0;
  if (safe_read_value<uint32_t>(base_addr + 0xe0, &timestamp)) {
    LOGGER_INFO << "  Timestamp/ID (0xe0): " << timestamp;
  }

  // Status flag (0xe4: byte)
  uint8_t status = 0;
  if (safe_read_value<uint8_t>(base_addr + 0xe4, &status)) {
    LOGGER_INFO << "  Status (0xe4): " << (int)status;
  }

  // Reply/Chain ptr (0xe8)
  uint64_t reply_ptr = 0;
  if (safe_read_value<uint64_t>(base_addr + 0xe8, &reply_ptr)) {
    dump_reg_and_mem("Reply/Chain (0xe8)", reply_ptr);
  }
}

/*
 * Dump the current stack frame [rsp .. rbp) as hex.
 * This approximates "all wechat local variables" at the hook point.
 */
static inline void dump_stack_frame(struct user_regs_struct *regs) {
  // dumping [regs->rsp .. regs->rbp) to give the whole wechat stack frame
  uint64_t rsp = regs->rsp;
  uint64_t rbp = regs->rbp;

  // Basic sanity
  if (!is_valid_user_ptr(rsp) || !is_valid_user_ptr(rbp) || rbp <= rsp) {
    return;
  }

  uint64_t frame_size = rbp - rsp;
  uint64_t slots = frame_size / 8;

  LOGGER_INFO << "   --- Stack Frame (WeChat locals) ---";
  LOGGER_INFO << "   rsp=" << LogFormat::addr << rsp
              << " rbp=" << LogFormat::addr << rbp
              << " size=" << frame_size
              << " bytes (" << slots << " qwords)";

  // Don't spam too much: cap visible dump (e.g. 0x400 bytes)
  size_t max_bytes = (frame_size > 0x400) ? 0x400 : (size_t)frame_size;

  for (size_t off = 0; off < max_bytes; off += 16) {
    uint64_t addr = rsp + off;
    if (!is_valid_user_ptr(addr)) {
      break;
    }

    // NOTE: do not directly dereference (unsigned char*)addr; read safely instead.
    unsigned char line[16];
    size_t want = (max_bytes - off >= 16) ? 16 : (max_bytes - off);
    if (!safe_memread((const void *)addr, line, want)) {
      LOGGER_INFO << "     [rsp+" << LogFormat::addr << off << "] <inaccessible>";
      break;
    }

    char hex_buf[16 * 3 + 1];
    int pos = 0;
    for (size_t i = 0; i < want; ++i) {
      pos += snprintf(&hex_buf[pos], sizeof(hex_buf) - pos, "%02x ", line[i]);
    }
    hex_buf[pos] = 0;

    // Show offset from rsp so you can correlate slots
    LOGGER_INFO << "     [rsp+" << LogFormat::addr << off << "] " << hex_buf;
  }
}


//=============================================================================
// HOOK CORE - Processes captured register state
//=============================================================================
static void wechat_hook_core(struct user_regs_struct *regs)
{
  // if (regs->r8 > 0x5016f3e7d290 && regs->r8 < 0x7fffffffffff)
  // {
  //     LOGGER_INFO << " r8  " << LogFormat::addr << regs->r8 << "  " << (char *)regs->r8;
  // }
  // if (regs->r9 > 0x5016f3e7d290 && regs->r9 < 0x7fffffffffff)
  // {
  //     LOGGER_INFO << " r9  " << LogFormat::addr << regs->r9 << "  " << (char *)regs->r9;
  // }
  // if (regs->r10 > 0x5016f3e7d290 && regs->r10 < 0x7fffffffffff)
  // {
  //     LOGGER_INFO << " r10  " << LogFormat::addr << regs->r10 << "  " << (char *)regs->r10;
  // }
  // if (regs->r11 > 0x5016f3e7d290 && regs->r11 < 0x7fffffffffff)
  // {
  //     LOGGER_INFO << " r11  " << LogFormat::addr << regs->r11 << "  " << (char *)regs->r11;
  // }
  // if (regs->r12 > 0x5016f3e7d290 && regs->r12 < 0x7fffffffffff)
  // {
  //     LOGGER_INFO << " r12  " << LogFormat::addr << regs->r12 << "  " << (char *)regs->r12;
  // }
  // if (regs->r13 > 0x5016f3e7d290 && regs->r13 < 0x7fffffffffff)
  // {
  //     LOGGER_INFO << " r13  " << LogFormat::addr << regs->r13 << "  " << (char *)regs->r13;
  // }
  // if (regs->rsi > 0x5016f3e7d290 && regs->rsi < 0x7fffffffffff)
  // {
  //     LOGGER_INFO << " rsi  " << LogFormat::addr << regs->rsi << "  " << (char *)regs->rsi;
  // }
  LOGGER_INFO << "Hook core reached.";
  if (1) { // (regs->rdi > 0x5016f3e7d290 && regs->rdi < 0x7fffffffffff) {
    // if ( *((char *)regs->rdi) == '\0' ) return;

    // LOGGER_INFO << (char *)regs->rdi;

    // dump saved registers' values and optionally pointed data
    dump_reg_and_mem("rbx", regs->rbx);
    dump_reg_and_mem("rcx", regs->rcx);
    dump_reg_and_mem("rdx", regs->rdx);
    dump_reg_and_mem("rsi", regs->rsi);
    dump_reg_and_mem("rdi", regs->rdi);
    dump_reg_and_mem("r8",  regs->r8);
    dump_reg_and_mem("r9",  regs->r9);
    dump_reg_and_mem("r10", regs->r10);
    dump_reg_and_mem("r11", regs->r11);
    dump_reg_and_mem("r12", regs->r12);
    dump_reg_and_mem("r13", regs->r13);
    dump_reg_and_mem("r15", regs->r15);

    dump_reg_and_mem("rbp", regs->rbp);
    dump_reg_and_mem("r14 (org rbp)", regs->r14);
    dump_reg_and_mem("rsp", regs->rsp);

    // dump the entire wechat stack frame (locals, saved regs, etc.)
    dump_stack_frame(regs); // OK, but almost all are heap pointers

    // Dump inferred message struct (using r14 as base pointer)
    dump_message_struct(regs->r14);

    // Also try rsp as alternative struct base (if applicable)
    dump_message_struct(regs->rsp);

  }
  // if (regs->rsp > 0x5016f3e7d290 && regs->rsp < 0x7fffffffffff)
  // {
  //     LOGGER_INFO << " rsp  " << LogFormat::addr << regs->rsp << "  " << (char *)regs->rsp;
  // }
  // if (regs->rbp > 0x5016f3e7d290 && regs->rbp < 0x7fffffffffff)
  // {
  //     LOGGER_INFO << " rbp  " << LogFormat::addr << regs->rbp << "  " << (char *)regs->rbp;
  // }
}

//=============================================================================
// HOOK RUN - Captures and restores register state around hook core
//=============================================================================
static void wechat_hook_run()
{
  struct user_regs_struct regs = {0};

  // Capture current register state
  // Note: r14/r15 slots receive values saved there by wechat_hook()
  //       which are rbp and rdi respectively (for hook analysis)
  asm volatile (
    "mov %%rbx, %0\n"
    "mov %%rcx, %1\n"
    "mov %%rdx, %2\n"
    "mov %%rsi, %3\n"
    "mov %%r15, %4\n"   // r15 contains rdi (saved in wechat_hook)
    "mov %%r14, %5\n"   // r14 contains rbp (saved in wechat_hook)
    "mov %%rsp, %6\n"
    "mov %%r8, %7\n"
    "mov %%r9, %8\n"
    "mov %%r10, %9\n"
    "mov %%r11, %10\n"
    "mov %%r12, %11\n"
    "mov %%r13, %12\n"
    "mov %%r14, %13\n"
    "mov %%r15, %14\n"
    : "=m"(regs.rbx), "=m"(regs.rcx), "=m"(regs.rdx),
      "=m"(regs.rsi), "=m"(regs.rdi), "=m"(regs.rbp), "=m"(regs.rsp),
      "=m"(regs.r8), "=m"(regs.r9), "=m"(regs.r10), "=m"(regs.r11),
      "=m"(regs.r12), "=m"(regs.r13), "=m"(regs.r14), "=m"(regs.r15)
    :
    : "memory"
    );

  // Call the hook core with captured registers
  wechat_hook_core(&regs);

  // Restore register state (except r14/r15 which are handled by wechat_hook)
  asm volatile (
    "mov %0, %%rbx\n"
    "mov %1, %%rcx\n"
    "mov %2, %%rdx\n"
    "mov %3, %%rsi\n"
    "mov %4, %%rdi\n"
    "mov %5, %%r8\n"
    "mov %6, %%r9\n"
    "mov %7, %%r10\n"
    "mov %8, %%r11\n"
    "mov %9, %%r12\n"
    "mov %10, %%r13\n"
    "mov %11, %%r14\n"
    "mov %12, %%r15\n"
    :
    : "m"(regs.rbx), "m"(regs.rcx), "m"(regs.rdx),
      "m"(regs.rsi), "m"(regs.rdi), "m"(regs.r8),
      "m"(regs.r9), "m"(regs.r10), "m"(regs.r11),
      "m"(regs.r12), "m"(regs.r13), "m"(regs.r14), "m"(regs.r15)
    : "memory", "cc",
      "rax","rbx","rcx","rdx","rsi","rdi",
      "r8","r9","r10","r11","r12","r13","r14","r15"
    );
}

//=============================================================================
// HOOK FUNCTION - Contains NOP sleds that get patched at runtime
//=============================================================================
void wechat_hook()
{
  // first_nop_cmd_addr
  //-------------------------------------------------------------------------
  // FIRST NOP SLED (16 bytes) - Hook entry point
  // WeChat's patched code jumps here (to first_nop_cmd_addr)
  //-------------------------------------------------------------------------
  asm("nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      //---------------------------------------------------------------------
      // CRITICAL: Save r14 and r15 before modifying them!
      // At hook point 0x71df9f:
      //   - r14 contains original rdx (saved at 71df8b: mov %rdx,%r14)
      //   - r15 contains original rsi (saved at 71df8e: mov %rsi,%r15)
      // The displaced instruction "mov (%r14),%eax" needs r14 intact!
      //---------------------------------------------------------------------
      "push %r14;\n"
      "push %r15;\n"
      // Prepare values for hook_core analysis
      // rbp -> r14 (will be read as regs.rbp in hook_core)
      // rdi -> r15 (will be read as regs.rdi in hook_core)
      "mov %rbp,%r14;\n"
      "mov %rdi,%r15;\n"
      "pushfq;\n"        // save flags from cmp %r12,%rdi
      "sub $8, %rsp;\n"  // keep stack 16-byte aligned for call (if desired)
    );

  // Execute hook logic
  wechat_hook_run();

  asm("add $8, %rsp;\n"  // undo alignment adjustment (if used)
      "popfq;\n"         // restore flags before executing relocated je/call/cmpb
      //-------------------------------------------------------------------------
      // Restore r14/r15 to their original values before trampoline executes
      // This is essential because the displaced instruction "mov (%r14),%eax"
      // must read from the correct memory location
      //-------------------------------------------------------------------------
      "pop %r15;\n"
      "pop %r14;\n"

      // second_nop_cmd_addr
      //---------------------------------------------------------------------
      // SECOND NOP SLED (30 bytes) - Trampoline location
      // At runtime, this gets patched with:
      //   [0-14]  : Original instructions (15 bytes)
      //   [15-24] : movabs $return_addr, %rax
      //   [25-26] : jmp *%rax
      //---------------------------------------------------------------------
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
      "nop;\n"
    );
}

