#include "donald.h"
#ifdef DONALD_DEBUG
#include <stdio.h>
#endif

void __attribute__((noreturn)) enter(void *entry_point)
{
#ifdef DONALD_DEBUG
	fprintf(stderr, "donald: jumping to entry point %p\n", (void*) entry_point);
	fflush(stderr);
#endif
	__asm__("jmpq *%0\n" : : "r"(entry_point));
	__builtin_unreachable();
}
