#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/intr-stubs.h"
#include <list.h>
#include <stdint.h>
#include <ctype.h>


static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Create a new thread to execute FILE_NAME. */

  char tmp[100] = "";
  char command[100] = "";
  char *ptr;
  char *next_ptr;

  strlcpy(tmp, file_name, strlen(file_name)+1);
  ptr = strtok_r(tmp, " ", &next_ptr);
  strlcpy(command, ptr, strlen(ptr)+1);

  if(filesys_open(command) == NULL)
	return -1;


  tid = thread_create (command, PRI_DEFAULT, start_process, fn_copy);

  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  //printf("%s=====================\n", file_name);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success) 
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */


  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  struct list_elem* e;
  struct list_elem* k;
  struct thread* t = NULL;
  struct thread* m = NULL;
  int exit_status;
  	
  int ttid;

//  while(1){
	//print_wait_list();
	t = thread_current();

	int cur_idx = search_wait_list(t->tid);


	//if(there_is_no_child_thread(t->tid) == false){
	while(1){
		thread_yield();
		if(there_is_no_child_thread(t->tid)==true && there_is_no_zombie() == true)
			break;
	}
//	}

	if(there_is_no_child_thread(t->tid) == true && create_idx > 2){
		//printf("%d\n",create_idx);
		for(int j = 1; j < create_idx; j++){
			if(wait_list[j].flag == 0 && wait_list[j].parent_tid == t->tid){
				ttid = wait_list[j].tid;

				exit_status = wait_list[j].exitStatus;
				//what??
				wait_list[j].flag = -100;
				wait_list_remove(j);
				//break;

			}
			else if(wait_list[j].flag == -1){
				//printf("sssssssssssssssssssssssssssssssssssss\n");
				return -1;
			}
			else if(wait_list[j].flag == -100){
				//printf("ttttttttttttttttttttttttttttttt\n");
				continue;
			}
		}

		//printf("%d %d\n",ttid,exit_status);
		//print_wait_list();
		return exit_status;
	}

	else if(there_is_no_remain() == true){
		//printf("haha\n");
		//exit_status = wait_list[0].exitStatus;
		return -1;
	}

	/*
	else{	
		while(1){
			thread_yield();
			if(there_is_no_child_thread(t->tid)==true)
				break;
		}
		
	}*/

 // }



  return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  struct list_elem* e;
  struct thread* t = NULL;

 // printf("exit : %d", cur->tid);


  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  int s_idx = search_wait_list(cur->tid);
  //printf("num : %d\n",s_idx);

  pd = cur->pagedir;
  if (pd != NULL && wait_list[s_idx].flag == -100) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */

	wait_list[s_idx].exitStatus = cur->exit_status;
  //printf("exit : %d\n", (int)thread_tid());
	if(there_is_no_child_thread(cur->tid) == false)
      	  	wait_list[s_idx].flag = -1;
 	else
        	wait_list[s_idx].flag = 0;

      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

void eraseBlank(char str[]);
void changeBlank(char str[]);

//문자열에 있는 다양한 공백들을 모두 ' '으로 바꿔주는 함수
void changeBlank(char str[]){
        for(int i = 0; i < strlen(str); i++){
                if(isspace(str[i]) != 0)
                         str[i] = ' ';
        }
}

//문자열 앞 뒤 공백을 지워주는 함수
void eraseBlank(char str[]){
         int startC = 0, endC = 0;

         //앞 공백을 제외한 문자열의 첫 글자의 위치를 알려주는 startC를 구하는 과정
         for(int i = 0;;i++){
                   if(isspace(str[i]) == 0){
                           startC = i;
                            break;
                   }
         }

         //뒷 공백을 제외한 문자열의 마지막 글자의 위치를 알려주는 endC를 구하는 과정
         for(int i = strlen(str)-1;;i--){
                   if(isspace(str[i]) == 0){
                                   endC = i;
                                   break;
                           }
         }

         //공백을 정제하는 과정
         for(int i = 0; i < endC - startC + 1; i++){
                  str[i] = str[i+startC];
         }

        for(int i = endC-startC+1; i < 50; i++)
                 str[i] = '\0';

}




bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  char table[25][50];
  char tmp[100] = "";
  char *ptr;
  char *next_ptr;
  off_t file_ofs;
  bool success = false;
  int arg_num = 1;
  int i;
  bool isWord = false;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  //changeBlank(file_name); 
  eraseBlank(file_name);

  strlcpy(tmp, file_name, strlen(file_name)+1);

  for(int i = 0; i < strlen(tmp); i++){
	if(tmp[i] != ' ' && isWord == false){
		arg_num++;
		isWord = true;
	}

	if(tmp[i] == ' ' && isWord == true){
		isWord = false;
	}
  }

  arg_num--;
  //printf("qqqqqqqqqqqqqqqqq %d\n",arg_num);
  
  //table에 첫번째 argument 복사
  ptr = strtok_r(tmp, " ", &next_ptr);
  strlcpy(table[0], ptr, strlen(ptr)+1);
  eraseBlank(table[0]);  

  //table에 두번째 이후 arg parsing
  for(int j = 1; j < arg_num; j++){
	ptr = strtok_r(NULL, " ", &next_ptr);
	strlcpy(table[j], ptr, strlen(ptr)+1);
	eraseBlank(table[j]);
	table[j][strlen(table[j])] = '\0';
	//printf("%s\n",table[j]);
  }
  table[0][strlen(table[0])] = '\0';

  strlcpy(file_name, table[0], strlen(table[0])+1);

  /* Open executable file. */
  file = filesys_open(table[0]);

  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;

  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {

              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }

              if (!load_segment (file, file_page, (void *) mem_page,read_bytes, zero_bytes, writable))
                goto done;

            }
          else
            goto done;
         break;
        }
    }


  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;


  char **esp_table;

  esp_table = (char **)malloc(sizeof(char *) * arg_num);

  int total_len = 0;
  int idx = arg_num;


  while(1){
	idx--;

	if(idx < 0)
		break;

	int tmp_len = strlen(table[idx])+1;
	total_len += tmp_len;
	*esp -= tmp_len;
	memcpy(*esp, table[idx], tmp_len);
	//strlcpy(*esp, table[idx], tmp_len+1);

	esp_table[idx] = *esp;

  }
  
  //hex_dump(*esp, *esp, 100, 1);

  if((PHYS_BASE - *esp) % 4 != 0){
	*esp -= sizeof(uint32_t **) - ((PHYS_BASE - *esp) % 4);
  }

  *esp -= sizeof(uint32_t **);
  **(uint32_t **)esp = 0;
  
  for(i = arg_num-1; 0 <= i; i--){
	*esp -= sizeof(uint32_t **);
	*(uint32_t **)*esp = esp_table[i];
  }	


  *esp -= sizeof(uint32_t **);
  *(uint32_t **)*esp = *esp + 4;

  *esp -= sizeof(uint32_t **);
  *(uint32_t **)*esp = arg_num;

  *esp -= sizeof(uint32_t **);
  *(uint32_t **)*esp = 0;

  //hex_dump(*esp, *esp, 100, 1);

  //hex_dump(esp,esp,1000,1);

  //hex_dump(*esp, *esp, 400, 1);


  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  //hex_dump(esp,esp,100,1);

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
