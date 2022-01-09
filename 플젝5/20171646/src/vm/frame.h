#ifndef __FRAME_H__
#define __FRAME_H__

#include <hash.h>
#include "lib/kernel/hash.h"
#include "threads/synch.h"
#include "threads/palloc.h"

typedef struct frame_table_entry
{
   struct hash_elem helem;
   struct list_elem lelem;

   void *kernel_page;
   void *user_page;

   struct thread *t;
   bool pinned;
}ft_entry;

static struct lock frame_lock;
static struct hash frame_map;
static struct list frame_list;
static struct list_elem *clock_ptr;
static unsigned frame_hash_func(const struct hash_elem *elem, void *aus);
static bool frame_less_func(const struct hash_elem *, const struct hash_elem *, void *aux);
static ft_entry* pick_frame_to_evict(uint32_t* pagedir);


void frame_init(void); //초기화
void* frame_allocate(enum palloc_flags flags, void *user_page); //가상 주소에 대응되는 frame page를 하나 생성, mapping후 kernel address 리턴.
void frame_do_free(void *, bool);
struct frame_table_entry* clock_frame_next(void);

#endif
