#include "userprog/syscall.h"
#include "threads/vaddr.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

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

int write(int fd, const void *buffer, size_t n){
	//printf("%d\n",n);
	if(fd == 1){
		putbuf(buffer, n);
		//printf("%s",(char *)buffer);
		return true;
	}
	else
		return false;
}	

void halt(void){
	shutdown_power_off();
}

int read(int fd, void *buffer, size_t n){
	int res;

	if(fd == 0){
		res = input_getc();
		return res;
	}
	else
		return -1;
	//return res;
}

pid_t exec(const char* command){
	return process_execute(command);
}


int wait (pid_t process_id){
	int res = process_wait(process_id);

	//if(res > -100)
	return res;
}

void exit(int status){

	printf("%s: exit(%d)\n", thread_name(), status);
	thread_current() -> exit_status = status;
	int s_idx = search_wait_list(thread_current()->tid);
	//thread_current()->parent->child_exit_status = status;
	wait_list[s_idx].exitStatus = status;

	
	thread_exit();
	
}


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("system call!\n");
  struct thread *t = thread_current();

 // hex_dump(f->esp, f->esp, 100, 1);
  //hex_dump(f->esp-100, f->esp-100, 100, 1);

  int sys_num = *(uint32_t *)(f->esp);

  if(sys_num < 0){
	printf("not valid system call number\n");
	exit(-1);
  }

  else{

  	if(sys_num == (int)SYS_HALT){
		//printf("SYS_HALT\n");
		//shutdown_power_off();
		halt();
 	 }

	  else if(sys_num == (int)SYS_EXIT){

		if(!is_user_vaddr(f->esp + 4))
			exit(-1);
		//wait_list[s_idx].exitStatus = cur->exit_status;
		exit(*(uint32_t *)(f->esp + 4));
  	}

 	 else if(sys_num == (int)SYS_EXEC){
		//printf("SYS_EXEC\n");
		if(!is_user_vaddr(f->esp + 4))
			exit(-1);
		f->eax = exec((const char *)*(uint32_t *)(f->esp + 4));
  	}

	  else if(sys_num == (int)SYS_WAIT){
		//printf("SYS_WAIT\n");
		if(!is_user_vaddr(f->esp + 4))
			exit(-1);
	
		//hex_dump(f->esp, f->esp, 300, 1);
	
		f->eax = wait((pid_t)*(uint32_t *)(f->esp + 4));	
 	 }  

	  else if(sys_num == (int)SYS_CREATE){
		//printf("SYS_CREATE\n");
  	 }

	  else if(sys_num == (int)SYS_REMOVE){
		//printf("SYS_REMOVE\n");
  	}

 	 else if(sys_num == (int)SYS_OPEN){
		//printf("SYS_OPEN\n");
 	 }

	  else if(sys_num == (int)SYS_FILESIZE){
		//printf("SYS_FILESIZE\n");
 	 }

	  else if(sys_num == (int)SYS_READ){
		//printf("SYS_READ\n");
		//f->eax = i
		if(!is_user_vaddr(f->esp + 20) || !is_user_vaddr(f->esp + 24) || !is_user_vaddr(f->esp+28))
			exit(-1);
		f->eax = read((int)*(uint32_t *)(f->esp+20), (void *)*(uint32_t *)(f->esp + 24), (unsigned)*((uint32_t *)(f->esp + 28)));
 	 }

	  else if(sys_num == (int)SYS_WRITE){
		//f-> eax = write(1, (void *)*(uint32_t *)(f->esp + 24), (unsigned)*((uint32_t *)(f->esp + 28)));
		if(!is_user_vaddr(f->esp + 24) || !is_user_vaddr(f->esp+28))
			exit(-1);

		//print("%d\n",(int)*((uint32_t*)(f->esp + 28)));


		f->eax = write((int)*(uint32_t *)(f->esp + 20), (char *)*(uint32_t *)(f->esp + 24), (unsigned)*((uint32_t *)(f->esp + 28)));

		//putbuf((void *)*(uint32_t *)(f->esp + 24), (unsigned)*((uint32_t *)(f->esp + 28)));
 	 }

 	 else if(sys_num == (int)SYS_SEEK){
		//printf("SYS_SEEK\n");
 	 }

 	 else if(sys_num == (int)SYS_TELL){
		//printf("SYS_TELL\n");
 	 }

 	 else if(sys_num == (int)SYS_CLOSE){
		//printf("SYS_CLOSE\n");
 	 }

	  else if(sys_num == (int)SYS_FIBO){
		//hex_dump(f->esp, f->esp, 300, 1);
		if(!is_user_vaddr(f->esp + 32))
			exit(-1);

		f->eax = fibonacci((int)*(uint32_t *)(f->esp + 32));
 	 }
 	 else if(sys_num == (int)SYS_MAX){
		//hex_dump(f->esp, f->esp, 300, 1);
		if(!is_user_vaddr(f->esp + 32) || !is_user_vaddr(f->esp + 36) || !is_user_vaddr(f->esp + 44))
			exit(-1);
		f->eax = max_of_four_int((int)*(uint32_t *)(f->esp + 32), (int)*(uint32_t *)(f->esp + 36), (int)*(uint32_t *)(f->esp + 40), (int)*(uint32_t *)(f->esp + 44));
 	 }


  }
  //thread_exit ();
}
