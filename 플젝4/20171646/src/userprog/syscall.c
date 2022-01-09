#include "userprog/syscall.h"
#include "threads/vaddr.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "lib/kernel/list.h"
#include "userprog/process.h"
#ifdef VM
#include "vm/page.h"
#include "vm/frame.h"
#endif

static void syscall_handler (struct intr_frame *);
struct lock sys_lock;


static void fail_invalid_access(void) {
  if (lock_held_by_current_thread(&sys_lock))
    lock_release (&sys_lock);

  exit (-1);
  NOT_REACHED();
}


static int32_t
get_user (const uint8_t *uaddr) {
  if (! ((void*)uaddr < PHYS_BASE)) {
    return -1;
  }

  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a" (result) : "m" (*uaddr));
  return result;
}


static void
check_user (const uint8_t *uaddr) {

	if(get_user(uaddr) == -1)
		fail_invalid_access();

}

static int
memread_user (void *src, void *dst, size_t bytes)
{
  int32_t value;
  size_t i;
  for(i=0; i<bytes; i++) {
    value = get_user(src + i);
    if(value == -1) {
	exit(-1);
  }

    *(char*)(dst + i) = value & 0xff;
  }
  return (int)bytes;
}


int fibonacci(int n){
	if(n == 0)
                 return 0;
         else if(n == 1)
                 return 1;
         else if(n == 2)
                 return 1;
         else
                 return fibonacci(n-1) + fibonacci(n-2);

}

int max_of_four_int(int a, int b, int c, int d){
	int arr[4];
         int max = 0;

         arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;


         for(int i = 0; i < 4; i++){
                 if(max < arr[i])
                         max = arr[i];

         }

        return max;

}


pid_t exec(const char* command){
	check_user((const uint8_t*)command);

	lock_acquire(&sys_lock);
	pid_t pid = process_execute(command);
	lock_release(&sys_lock);
	return pid;
}


int wait (pid_t process_id){
	int res = process_wait(process_id);
	return res;
}

void exit(int status){
	printf("%s: exit(%d)\n", thread_name(), status);
	thread_current() -> exit_status = status;
	int s_idx = search_wait_list(thread_current()->tid);
	wait_list[s_idx].exitStatus = status;

	for(int i = 3; i < 128; i++){
		if(thread_current()->file_des[i] != NULL)
			close(i);
	}

	thread_exit();
}

void halt(void){
	shutdown_power_off();
}

void
syscall_init (void) 
{
	lock_init(&sys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

//project 2
bool create(const char *file, unsigned initial_size){
	if(file==NULL || !is_user_vaddr(file))
		exit(-1);

	return filesys_create(file, initial_size);
}

bool remove(const char *file){
	if(file == NULL || !is_user_vaddr(file))
		exit(-1);

	return filesys_remove(file);
}

int open(const char *file){
	int i;

	struct file_desc* fd = palloc_get_page(0);


	if(!fd)
		return -1;
	check_user((const uint8_t*)file);


	if(!is_user_vaddr(file) || file == NULL){
		lock_release(&sys_lock);
		exit(-1);
	}

	struct file* fp = filesys_open(file);

	if(!fp){
		palloc_free_page(fd);
		lock_release(&sys_lock);
		exit(-1);
	}

	if(fp == NULL)
		return -1;
	else{
		for(i = 3; i < 128; i++){
			if(thread_current()->file_des[i] == NULL){

				if(strcmp(thread_current()->name, file) == 0)
					file_deny_write(fp);
				else
					file_allow_write(fp);

				thread_current()->file_des[i] = fp;
				return i;
			}

		}

	}

	return -1;
}

int filesize(int fd){
	if(thread_current()->file_des[fd] == NULL)
		exit(-1);

	return file_length(thread_current()->file_des[fd]);
}

int write(int fd, const void *buffer, unsigned n){
		
	if(!(0x08048000 < buffer && buffer < 0xc0000000)){
		lock_release(&sys_lock);
		exit(-1);
	}


	int res = -1;


	check_user((const uint8_t*)buffer);
	check_user((const uint8_t*)buffer+n-1);

	if(!is_user_vaddr(buffer) || !is_user_vaddr(buffer + n - 1)){
		lock_release(&sys_lock);
		exit(-1);
	}

        if(fd == 1){
                putbuf(buffer, n);
		return n;
        }
        else if(fd > 2 && fd < 128){
		if(thread_current()->file_des[fd] == NULL){
			lock_release(&sys_lock);
			exit(-1);
		}
		/*
		if(buffer < 0x8084000){
                        lock_release(&sys_lock);
                        exit(-1);
                }*/


		if(thread_current()->file_des[fd]->deny_write)
			file_deny_write(thread_current()->file_des[fd]);
		else
			file_allow_write(thread_current()->file_des[fd]);

		res = file_write(thread_current()->file_des[fd], buffer, n);
		return res;
	}
	else
        	return -1;
}

int read(int fd, void *buffer, unsigned n){
        int i;
	int ret=-1;

	if(!is_user_vaddr(buffer)){
		lock_release(&sys_lock);
		exit(-1);
	}

	check_user((const uint8_t*)buffer);
	check_user((const uint8_t*)buffer + n - 1);


	if(fd == 0){

		for(i = 0; i < n; i++){

			if(input_getc() == '\0')
				break;
		}
		return i;
	}
	else if(fd > 2 && fd < 128){
		if(thread_current()->file_des[fd] == NULL){
			lock_release(&sys_lock);
			exit(-1);
		}

		if(buffer < 0x8084000){
			lock_release(&sys_lock);
			exit(-1);
		}


		ret = file_read(thread_current()->file_des[fd], buffer, n);
		return ret;
	}
	else
		return -1;

}

void seek(int fd, unsigned position){

	if(thread_current()->file_des[fd] == NULL)
		exit(-1);

	lock_acquire(&sys_lock);
	file_seek(thread_current()->file_des[fd], position);
	lock_release(&sys_lock);
}

unsigned tell(int fd){
	if(thread_current()->file_des[fd] == NULL)
                exit(-1);

	
	return file_tell(thread_current()->file_des[fd]);
}

void close(int fd){
	struct file* fp;

	if(thread_current()->file_des[fd] == NULL)
                exit(-1);

	fp = thread_current()->file_des[fd];
	thread_current()->file_des[fd] = NULL;

	return file_close(fp);

}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  struct thread *t = thread_current();
  t->current_esp = f->esp;


  int sys_num = *(uint32_t *)(f->esp);

  //printf("sys num : %d\n",sys_num);
  //printf("tid : %d\n", t->tid);
  //printf("syscall stack : %p\n", f->esp);

  if(!is_user_vaddr(f->esp))
	exit(-1);

  memread_user(f->esp, &sys_num, sizeof(sys_num));


  if(sys_num < 0){
	printf("not valid system call number\n");
	exit(-1);
  }

  else{

  	if(sys_num == (int)SYS_HALT){
		halt();
 	 }

	  else if(sys_num == (int)SYS_EXIT){

		if(!is_user_vaddr(f->esp + 4)){
			exit(-1);
		}
		exit(*(uint32_t *)(f->esp + 4));
  	}

 	 else if(sys_num == (int)SYS_EXEC){
		if(!is_user_vaddr(f->esp + 4))
			exit(-1);
		f->eax = exec((const char *)*(uint32_t *)(f->esp + 4));
  	}

	  else if(sys_num == (int)SYS_WAIT){
		if(!is_user_vaddr(f->esp + 4))
			exit(-1);
	
		f->eax = wait((pid_t)*(uint32_t *)(f->esp + 4));	
 	 }  

	  else if(sys_num == (int)SYS_CREATE){
		if(!is_user_vaddr(f->esp + 16) || !is_user_vaddr(f->esp+20))
			exit(-1);
		f->eax = create((const char *)*(uint32_t *)(f->esp + 16), (unsigned)*(uint32_t *)(f->esp + 20));
  	 }

	  else if(sys_num == (int)SYS_REMOVE){
		if(!is_user_vaddr(f->esp+4))
			exit(-1);

		f->eax = remove((const char*)*(uint32_t *)(f->esp+4));
  	}

 	 else if(sys_num == (int)SYS_OPEN){
		if(!is_user_vaddr(f->esp+4))
			exit(-1);

		const char* filename;
		int return_code;

		memread_user(f->esp+4, &filename, sizeof(filename));

		lock_acquire(&sys_lock);

		return_code = open(filename);
		//f->eax = open((const char*)*(uint32_t *)(f->esp+4));
		f->eax = return_code;
		lock_release(&sys_lock);
 	 }

	  else if(sys_num == (int)SYS_FILESIZE){
		if(!is_user_vaddr(f->esp+4))
			exit(-1);
		f->eax = filesize((int)*(uint32_t *)(f->esp+4));
 	 }

	  else if(sys_num == (int)SYS_READ){
		//printf("read\n");
		if(!is_user_vaddr(f->esp + 20) || !is_user_vaddr(f->esp + 24) || !is_user_vaddr(f->esp+28))
			exit(-1);
	
		int fd, return_code;
		void *buffer;
		unsigned size;


		memread_user(f->esp + 4, &fd, sizeof(fd));
     		memread_user(f->esp + 8, &buffer, sizeof(buffer));
  		memread_user(f->esp + 12, &size, sizeof(size));

		lock_acquire(&sys_lock);

		return_code = read(fd, buffer, size);
		f->eax = (uint32_t) return_code;
		lock_release(&sys_lock);


 	 }


	  else if(sys_num == (int)SYS_WRITE){
		//printf("write\n");

		if(!is_user_vaddr(f->esp + 20) || !is_user_vaddr(f->esp + 24) || !is_user_vaddr(f->esp+28))
			exit(-1);

		int fd, return_code;
		const void *buffer;
		unsigned size;

		//printf("before\n");
		memread_user(f->esp+4, &fd, sizeof(fd));
		memread_user(f->esp+8, &buffer, sizeof(buffer));
		memread_user(f->esp+12, &size, sizeof(size));
		//printf("after\n");


		lock_acquire(&sys_lock);

		//printf("sema??\n");

		return_code = write(fd, buffer, size);
		f->eax = (uint32_t) return_code;
		//f->eax = write((int)*(uint32_t *)(f->esp + 20), (char *)*(uint32_t *)(f->esp + 24), (unsigned)*((uint32_t *)(f->esp + 28)));

		lock_release(&sys_lock);
 	 }

 	 else if(sys_num == (int)SYS_SEEK){
		if(!is_user_vaddr(f->esp+16) || !is_user_vaddr(f->esp+20))
			exit(-1);

		int fd;
		unsigned position;

		memread_user(f->esp + 4, &fd, sizeof(fd));
		memread_user(f->esp+8, &position, sizeof(position));

		seek(fd, position);

		//seek((int)*(uint32_t *)(f->esp + 16), (unsigned)*(uint32_t *)(f->esp+20));
 	 }

 	 else if(sys_num == (int)SYS_TELL){
		if(!is_user_vaddr(f->esp+4))
			exit(-1);

		f->eax = tell((int)*(uint32_t *)(f->esp + 4));
 	 }

 	 else if(sys_num == (int)SYS_CLOSE){

		if(!is_user_vaddr(f->esp+4))
			exit(-1);
		close((int)*(uint32_t *)(f->esp+4));
 	 }

	  else if(sys_num == (int)SYS_FIBO){
		if(!is_user_vaddr(f->esp + 32))
			exit(-1);

		f->eax = fibonacci((int)*(uint32_t *)(f->esp + 32));
 	 }
 	 else if(sys_num == (int)SYS_MAX){
		if(!is_user_vaddr(f->esp + 32) || !is_user_vaddr(f->esp + 36) || !is_user_vaddr(f->esp + 44))
			exit(-1);
		f->eax = max_of_four_int((int)*(uint32_t *)(f->esp + 32), (int)*(uint32_t *)(f->esp + 36), (int)*(uint32_t *)(f->esp + 40), (int)*(uint32_t *)(f->esp + 44));
 	 }

  }
}
