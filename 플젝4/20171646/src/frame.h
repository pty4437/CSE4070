#ifndef __FRAME_H__
#define __FRAME_H__

#include <hash.h>
#include "lib/kernel/hash.h"

#include "threads/synch.h"
//#include "threads/thread.h"
#include "threads/palloc.h"

typedef struct frame_table_entry{
	void *kpage;  //hash테이블에 대응되는 kernel page 주소
	
	struct hash_elem helem;
	struct list_elem lelem;

	void *upage;
	struct thread *t;

	bool pinned;

}FTE;

