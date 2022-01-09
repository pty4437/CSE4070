#include "userprog/syscall.h"
#include "threads/vaddr.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);
struct semaphore wro;


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
	return process_execute(command);
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
  sema_init(&wro, 1);
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

	if(!is_user_vaddr(file) || file == NULL){
		sema_up(&wro);
		exit(-1);
	}

	struct file* fp = filesys_open(file);

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
		
	int res = -1;

	if(!is_user_vaddr(buffer)){
		sema_up(&wro);
		exit(-1);
	}


        if(fd == 1){
                putbuf(buffer, n);
		return n;
        }
        else if(fd > 2){
		if(thread_current()->file_des[fd] == NULL){
			sema_up(&wro);
			exit(-1);
		}

		if(thread_current()->file_des[fd]->deny_write)
			file_deny_write(thread_current()->file_des[fd]);
		else
			file_allow_write(thread_current()->file_des[fd]);

		return file_write(thread_current()->file_des[fd], buffer, n);
	}
	else
        	return -1;
}

int read(int fd, void *buffer, unsigned n){
	
        int i;
	int ret=-1;

	if(!is_user_vaddr(buffer)){
		sema_up(&wro);
		exit(-1);
	}


	if(fd == 0){
		for(i = 0; i < n; i++){
			if(input_getc() == '\0')
				break;
		}
		return i;
	}
	else if(fd > 2){
		if(thread_current()->file_des[fd] == NULL){
			sema_up(&wro);
			exit(-1);
		}

		return file_read(thread_current()->file_des[fd], buffer, n);
	}
	else
		return -1;

}

void seek(int fd, unsigned position){

	if(thread_current()->file_des[fd] == NULL)
		exit(-1);

	file_seek(thread_current()->file_des[fd], position);
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


  int sys_num = *(uint32_t *)(f->esp);

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

		sema_down(&wro);
		f->eax = open((const char*)*(uint32_t *)(f->esp+4));
		sema_up(&wro);
 	 }

	  else if(sys_num == (int)SYS_FILESIZE){
		if(!is_user_vaddr(f->esp+4))
			exit(-1);
		f->eax = filesize((int)*(uint32_t *)(f->esp+4));
 	 }

	  else if(sys_num == (int)SYS_READ){
		if(!is_user_vaddr(f->esp + 20) || !is_user_vaddr(f->esp + 24) || !is_user_vaddr(f->esp+28))
			exit(-1);
		sema_down(&wro);

		f->eax = read((int)*(uint32_t *)(f->esp+20), (void *)*(uint32_t *)(f->esp + 24), (unsigned)*((uint32_t *)(f->esp + 28)));
		sema_up(&wro);
 	 }


	  else if(sys_num == (int)SYS_WRITE){
		if(!is_user_vaddr(f->esp + 20) || !is_user_vaddr(f->esp + 24) || !is_user_vaddr(f->esp+28))
			exit(-1);


		sema_down(&wro);

		f->eax = write((int)*(uint32_t *)(f->esp + 20), (char *)*(uint32_t *)(f->esp + 24), (unsigned)*((uint32_t *)(f->esp + 28)));

		sema_up(&wro);
 	 }

 	 else if(sys_num == (int)SYS_SEEK){
		if(!is_user_vaddr(f->esp+16) || !is_user_vaddr(f->esp+20))
			exit(-1);

		seek((int)*(uint32_t *)(f->esp + 16), (unsigned)*(uint32_t *)(f->esp+20));
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
