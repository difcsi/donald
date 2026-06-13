.globl _start
.text
.align 16
_start:
#if defined(__x86_64__)
     mov %rsp, %rdi      # "sp_on_entry [to _start]" is the argument to start_donald
     push %rsp           # Linux ABI gives us 16-byte-aligned %rsp, but C psABI needs 8 modulo 16
     jmp start_donald
#elif defined(__i386__)
     push %esp           # first (stack) arg: the cdecl arg lands at [ebp+8] of start_donald
                         # only if a return-address slot sits at [ebp+4], so use call (which
                         # pushes one) rather than jmp -- otherwise start_donald reads argc.
     call start_donald   # start_donald does not return (it jumps to the loaded program)
#else
#error "Unrecognised architecture."
#endif
