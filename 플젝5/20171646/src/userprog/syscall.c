#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"
#ifdef VM
#include "vm/page.h"
#include "vm/frame.h"
#endif

static void syscall_handler (struct intr_frame *);
struct lock sys_lock;
enum file_dir{FD_FILE = 1, FD_DIRECTORY = 2};

static void invalid_access(void) {
  if (lock_held_by_current_thread(&sys_lock))
    lock_release (&sys_lock);

  exit (-1);
  NOT_REACHED();
}


static struct file_desc*
find_file_desc(struct thread *t, int fd, enum file_dir flag)
{

  if (fd < 3) 
    return NULL;

  if(list_empty(&t->file_descriptors) == true)
	return NULL;

  else if (list_empty(&t->file_descriptors) == false) {
    for(struct list_elem *e = list_begin(&t->file_descriptors); e != list_end(&t->file_descriptors); e = list_next(e)){
      struct file_desc *desc = list_entry(e, struct file_desc, elem);
      if(desc->id == fd) {
        if (desc->dir != NULL && (flag & FD_DIRECTORY) )
          return desc;
        else if (desc->dir == NULL && (flag & FD_FILE) )
          return desc;
      }
    }
  }

  return NULL;
}

static int32_t is_user (const uint8_t *uaddr) {
  if (((void*)uaddr < PHYS_BASE) == false)
    return -1;

  int res;
  asm ("movl $1f, %0; movzbl %1, %0; 1:": "=&a" (res) : "m" (*uaddr));
  return res;
}

static void check_user (const uint8_t *uaddr) {
	if(is_user(uaddr) == -1)
		invalid_access();
}

static int
memread_user (void *src, void *dst, size_t bytes)
{
  int32_t value;
  for(unsigned int i=0; i<bytes; i++) {
    value = is_user(src + i);

    if(value == -1)
	exit(-1);

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
	//printf("exit tid : %d\n", thread_current()->tid);
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

	lock_acquire(&sys_lock);
	bool return_code = filesys_create(file, initial_size, false);
	lock_release(&sys_lock);

	return return_code;
}

bool remove(const char *file){
	if(file == NULL || !is_user_vaddr(file))
		exit(-1);

	lock_acquire(&sys_lock);
	bool return_code = filesys_remove(file);
	lock_release(&sys_lock);

	return return_code;
}

int open(const char *file){
	int i;
	struct thread* cur = thread_current();
	struct file_desc* fd = palloc_get_page(0);


	if(!fd)
		return -1;
	check_user((const uint8_t*)file);

	if(!is_user_vaddr(file) || file == NULL){
		palloc_free_page(fd);
		lock_release(&sys_lock);
		exit(-1);
	}

	struct file* fp = filesys_open(file);

	if(!fp){
		palloc_free_page(fd);
		return -1;
	}

	fd->file = fp;

	struct inode *inode = file_get_inode(fd->file);
  	if(inode != NULL && inode_is_directory(inode)) {
    		fd->dir = dir_open( inode_reopen(inode) );
  	}
  	else fd->dir = NULL;

	if(fp == NULL)
		return -1;
	else{
		for(i = 3; i < 128; i++){
			if(thread_current()->file_des[i] == NULL){

				if(strcmp(thread_current()->name, file) == 0)
					file_deny_write(fp);
				else
					file_allow_write(fp);

				fd->id = i;
				cur->file_des[i] = fp;
				list_push_back(&cur->file_descriptors, &(fd->elem));

				return i;
			}

		}

	}

	return -1;
}

int filesize(int fd){
	if(thread_current()->file_des[fd] == NULL)
		exit(-1);

	lock_acquire(&sys_lock);
	struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE);
	if(file_d == NULL){
		lock_release(&sys_lock);
		return -1;
	}
	int ret = file_length(file_d->file);
	lock_release(&sys_lock);
	return ret;

}

int write(int fd, const void *buffer, unsigned n){
		
	if(!(0x08048000 < buffer && buffer < 0xc0000000)){
		lock_release(&sys_lock);
		exit(-1);
	}
	
	int res = -1;


	check_user((const uint8_t*)buffer);
	check_user((const uint8_t*)buffer+n-1);

        if(fd == 1){
                putbuf(buffer, n);
		return n;
        }
        else if(fd > 2 && fd < 128){
		if(thread_current()->file_des[fd] == NULL){
			lock_release(&sys_lock);
			exit(-1);
		}


		struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE);
		if(file_d && file_d->file){
			return file_write(file_d->file, buffer, n);
		}
		else{
			return -1;
		}
	}
	else{
        	return -1;
	}
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

		struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE);
		if(file_d && file_d->file)
			return file_read(file_d->file, buffer, n);
		else
			return -1;
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
	struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE | FD_DIRECTORY);
	

	if(thread_current()->file_des[fd] == NULL)
                exit(-1);

	lock_acquire(&sys_lock);

	if(file_d && file_d->file){
	fp = thread_current()->file_des[fd];
	thread_current()->file_des[fd] = NULL;
	file_close(fp);
	if(file_d->dir) dir_close(file_d->dir);
	list_remove(&(file_d->elem));
	palloc_free_page(file_d);

	}


	lock_release(&sys_lock);

}


bool mkdir(const char *filename)
{
  check_user((const uint8_t*) filename);

  lock_acquire (&sys_lock);
  bool res = filesys_create(filename, 0, true);
  lock_release (&sys_lock);

  return res;
}

bool chdir(const char *filename)
{
  check_user((const uint8_t*) filename);

  lock_acquire (&sys_lock);
  bool res = filesys_chdir(filename);
  lock_release (&sys_lock);

  return res;
}


bool readdir(int fd, char *name)
{
  struct file_desc* file_d;
  bool res = false;

  lock_acquire (&sys_lock);
  file_d = find_file_desc(thread_current(), fd, FD_DIRECTORY);
  if (file_d == NULL){
	lock_release(&sys_lock);
	return false;
  }

  struct inode *inode;
  inode = file_get_inode(file_d->file);
  if(inode == NULL || inode_is_directory(inode) == false) {
	lock_release(&sys_lock);
	return false;
  }


  res = dir_readdir (file_d->dir, name);

  lock_release(&sys_lock);
  return res;

}

bool isdir(int fd)
{
  lock_acquire (&sys_lock);

  struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE | FD_DIRECTORY);
  bool res = inode_is_directory(file_get_inode(file_d->file));

  lock_release (&sys_lock);
  return res;
}

int inumber(int fd)
{
  lock_acquire (&sys_lock);

  struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE | FD_DIRECTORY);
  int res = (int)inode_get_inumber(file_get_inode(file_d->file));

  lock_release (&sys_lock);
  return res;
}
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  struct thread *t = thread_current();
  t->current_esp = f->esp;


  int sys_num = *(uint32_t *)(f->esp);

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
		f->eax = return_code;
		lock_release(&sys_lock);
 	 }

	  else if(sys_num == (int)SYS_FILESIZE){
		if(!is_user_vaddr(f->esp+4))
			exit(-1);
		f->eax = filesize((int)*(uint32_t *)(f->esp+4));
 	 }

	  else if(sys_num == (int)SYS_READ){
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
		if(!is_user_vaddr(f->esp + 20) || !is_user_vaddr(f->esp + 24) || !is_user_vaddr(f->esp+28))
			exit(-1);

		int fd, return_code;
		const void *buffer;
		unsigned size;

		memread_user(f->esp+4, &fd, sizeof(fd));
		memread_user(f->esp+8, &buffer, sizeof(buffer));
		memread_user(f->esp+12, &size, sizeof(size));

		lock_acquire(&sys_lock);

		return_code = write(fd, buffer, size);
		f->eax = (uint32_t) return_code;

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
	else if(sys_num == (int)SYS_CHDIR){
		const char* filename;
  	        int return_code;

   	        memread_user(f->esp + 4, &filename, sizeof(filename));

 	        return_code = chdir(filename);
 	        f->eax = return_code;
	}
	else if(sys_num == (int)SYS_MKDIR){
		const char* filename;
     	        int return_code;
 
      		memread_user(f->esp + 4, &filename, sizeof(filename));

      		return_code = mkdir(filename);
      		f->eax = return_code;

	}
	else if(sys_num == (int)SYS_READDIR){
		int fd;
     		char *name;
      		int return_code;

      		memread_user(f->esp + 4, &fd, sizeof(fd));
      		memread_user(f->esp + 8, &name, sizeof(name));


      		return_code = readdir(fd, name);
      		f->eax = return_code;
	}
	else if(sys_num == (int)SYS_ISDIR){
		int fd;
      		int return_code;

      		memread_user(f->esp + 4, &fd, sizeof(fd));
      		return_code = isdir(fd);
      		f->eax = return_code;
	}
	else if(sys_num == (int)SYS_INUMBER){
		int fd;
      		int return_code;

      		memread_user(f->esp + 4, &fd, sizeof(fd));
      		return_code = inumber(fd);
      		f->eax = return_code;
	}

  }
}
