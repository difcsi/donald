#ifndef DONALD_H_
#define DONALD_H_

#include <elf.h>
#include <unistd.h>
#include <stdint.h>

// stolen from glibc's link.h
#ifdef __x86_64__
#ifndef __ELF_NATIVE_CLASS
#define __ELF_NATIVE_CLASS 64
#endif
#define DONALD_ELFCLASS ELFCLASS64
#define DONALD_ELFMACHINE EM_X86_64
#elif defined(__i386__)
#define __ELF_NATIVE_CLASS 32
#define DONALD_ELFCLASS ELFCLASS32
#define DONALD_ELFMACHINE EM_386
#else
#error "Unrecognised architecture."
#endif

#ifndef ElfW
#define ElfW(type)      _ElfW (Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e,w,t)    _ElfW_1 (e, w, _##t)
#define _ElfW_1(e,w,t)  e##w##t
#endif

/* object-local  */
#define HIDDEN __attribute__((visibility("hidden")))

#define PAGE_ADJUST(n) (((uintptr_t)(n)) % page_size)
#define ROUND_UP_TO(mult, v) \
    ((mult) * (((v) + ((mult)-1)) / (mult)))

#ifndef DONALD_NAME
#define DONALD_NAME "donald"
#endif

extern int _begin; // defined by linker script; if used, we need it, so non-weak
extern char **environ HIDDEN;
extern ElfW(Dyn) *p_dyn HIDDEN;
extern ElfW(auxv_t) *p_auxv HIDDEN;
extern unsigned long page_size HIDDEN;
extern void *sp_on_entry HIDDEN;
extern ElfW(Dyn) _DYNAMIC[];

int main(int argc, char **argv) HIDDEN;
int load_one_phdr(unsigned long base_addr, int fd, unsigned long vaddr, unsigned long offset,
	unsigned long memsz, unsigned long filesz, _Bool read, _Bool write, _Bool exec) HIDDEN;
void enter(void *entry_point) __attribute__((noreturn)) HIDDEN;
uintptr_t __get_from_tls_reg_offset(unsigned off);

#endif
