#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <err.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include "donald.h"

#define die(s, ...) do { fprintf(stderr, "donald: " s , ##__VA_ARGS__); return -1; } while(0)
// #define die(s, ...) do { fwrite("donald: " s , sizeof "donald: " s, 1, stderr); return -1; } while(0)

int main(int argc, char **argv)
{
	// we need an argument
	if (argc < 2) { die("no program specified\n"); }
	
	/* Were we invoked directly (e.g. `donald ./prog`), or as another
	 * program's .interp? When the kernel loads us as an interpreter it sets
	 * AT_BASE in the auxv to our load address; when we are run directly there
	 * is no interpreter, so the kernel leaves AT_BASE as 0. Reading the auxv
	 * we were already handed avoids stat()ing /proc/self/exe and argv[0] on
	 * every launch. */
	uintptr_t at_base = 0;
	for (ElfW(auxv_t) *aux = p_auxv; aux->a_type != AT_NULL; ++aux)
	{
		if (aux->a_type == AT_BASE) { at_base = aux->a_un.a_val; break; }
	}
	int argv_program_ind = (at_base != 0) ? 0 : 1;

	if (argc <= argv_program_ind) { die("no program specified\n"); }

	/* We have a program to run. Let's read it. */
	int exe_fd = open(argv[argv_program_ind], O_RDONLY);
	if (exe_fd == -1) { die("could not open %s\n", argv[argv_program_ind]); }
	// read just the ELF header -- no need to map the whole file
	ElfW(Ehdr) ehdr;
	ssize_t nread = pread(exe_fd, &ehdr, sizeof ehdr, 0);
	if (nread != sizeof ehdr) { die("could not read ELF header from %s\n", argv[argv_program_ind]); }

	ElfW(Ehdr) *p_hdr = &ehdr;
	// check it's a file we can grok
	if (p_hdr->e_ident[EI_MAG0] != 0x7f
			|| p_hdr->e_ident[EI_MAG1] != 'E'
			|| p_hdr->e_ident[EI_MAG2] != 'L'
			|| p_hdr->e_ident[EI_MAG3] != 'F'
			|| p_hdr->e_ident[EI_CLASS] != ELFCLASS64
			|| p_hdr->e_ident[EI_DATA] != ELFDATA2LSB
			|| p_hdr->e_ident[EI_VERSION] != EV_CURRENT
			|| (p_hdr->e_ident[EI_OSABI] != ELFOSABI_SYSV && p_hdr->e_ident[EI_OSABI] != ELFOSABI_GNU)
			// || phdr->e_ident[EI_ABIVERSION] != /* what? */
			|| p_hdr->e_type != ET_EXEC
			|| p_hdr->e_machine != EM_X86_64
			)
	{
		die("unsupported file: %s\n", argv[argv_program_ind]);
	}
	
	// read the program header table -- it's all we need to load the file
	if (p_hdr->e_phnum == 0) { die("file %s has no program headers\n", argv[argv_program_ind]); }
	size_t phdrs_size = (size_t) p_hdr->e_phnum * p_hdr->e_phentsize;
	ElfW(Phdr) *p_phdr = malloc(phdrs_size);
	if (!p_phdr) { die("could not allocate program header table for %s\n", argv[argv_program_ind]); }
	nread = pread(exe_fd, p_phdr, phdrs_size, p_hdr->e_phoff);
	if (nread != (ssize_t) phdrs_size)
	{ free(p_phdr); die("could not read program header table from %s\n", argv[argv_program_ind]); }
	uintptr_t base_addr = 0;
	for (unsigned i = 0; i < p_hdr->e_phnum; ++i)
	{
		if (p_phdr[i].p_type == PT_LOAD)
		{	
			_Bool read = (p_phdr[i].p_flags & PF_R);
			_Bool write = (p_phdr[i].p_flags & PF_W);
			_Bool exec = (p_phdr[i].p_flags & PF_X);

			int ret = load_one_phdr(base_addr, exe_fd, p_phdr[i].p_vaddr,
				p_phdr[i].p_offset, p_phdr[i].p_memsz, p_phdr[i].p_filesz, read, write, exec);
			switch (ret)
			{
				case 2: die("file %s has bad PT_LOAD filesz/memsz (phdr index %d)\n", 
						argv[argv_program_ind], i);
				case 1: die("could not create mapping for PT_LOAD phdr index %d\n", i);
				default:
					break;
			}
		}
	}
	
	// do relocations!

	// grab the entry point
	unsigned long entry_point = p_hdr->e_entry;

	// now we're finished with the file
	free(p_phdr);
	close(exe_fd);
	
	// jump to the entry point
	enter((void*) entry_point);
}
