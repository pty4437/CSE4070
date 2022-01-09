#include <hash.h>
#include <list.h>
#include <stdio.h>
#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"
#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

//entry->kpage를 key로 하는 해시 function
static unsigned frame_hash_func(const struct hash_elem* elem, void* aus UNUSED) {
	ft_entry* entry = hash_entry(elem, ft_entry, helem);
	return hash_bytes(&entry->kernel_page, sizeof entry->kernel_page);
}

static bool frame_less_func(const struct hash_elem* a, const struct hash_elem* b, void* aux UNUSED) {
	ft_entry* a_entry = hash_entry(a, ft_entry, helem);
	ft_entry* b_entry = hash_entry(b, ft_entry, helem);
	return a_entry->kernel_page < b_entry->kernel_page;
}

void frame_init(){
	clock_ptr = NULL;
	hash_init(&frame_map, frame_hash_func, frame_less_func, NULL);
	list_init(&frame_list);
	lock_init(&frame_lock);
}

//upage에 해당하는 frame page를 하나 생성해서 page mapping 수행, kernel address리턴
void* frame_allocate(enum palloc_flags flags, void *upage){
	lock_acquire(&frame_lock);
	
	bool is_dirty;
	void *frame_page = palloc_get_page(PAL_USER | flags);
	
	if(frame_page == NULL){
		ft_entry *f_evicted = pick_frame_to_evict(thread_current()->pagedir);
		is_dirty = false;

		pagedir_clear_page(f_evicted->t->pagedir, f_evicted->user_page);
	
		if(pagedir_is_dirty(f_evicted->t->pagedir, f_evicted->user_page) == true)
			is_dirty = true;
		if(pagedir_is_dirty(f_evicted->t->pagedir, f_evicted->kernel_page) == true)
			is_dirty = true;

		pt_entry *pte = page_table_lookup(f_evicted->t->page_table, f_evicted->user_page);

		pte->swap_idx = swap_out(f_evicted->kernel_page);
		pte->status = SWAP_PAGE;
		pte->kernel_page = NULL;

		if(is_dirty == true);
			pte->dirty_bit = true;

		frame_do_free(f_evicted->kernel_page, true); //쫓아낸건 free

		frame_page = palloc_get_page (PAL_USER | flags);
	}

	ft_entry *frame = malloc(sizeof(ft_entry));
  	if(frame == NULL) {
    		lock_release (&frame_lock);
    		return NULL;
  	}

	else{
		frame->user_page = upage;
		frame->kernel_page = frame_page;
		frame->t = thread_current();
		frame->pinned = true;

		hash_insert(&frame_map, &frame->helem);
		list_push_back(&frame_list, &frame->lelem);

		lock_release(&frame_lock);
		return frame_page;
	}
}

//frame이나 page에서 엔트리를 삭제하는 실질적인 동작
void frame_do_free(void *kpage, bool free_page){
	//kpage에 해당하는 해시테이블 elem를 찾음
	ft_entry f_tmp;
	f_tmp.kernel_page = kpage;
	struct hash_elem *h = hash_find(&frame_map, &(f_tmp.helem));

	ft_entry *f = hash_entry(h, ft_entry, helem);

	hash_delete(&frame_map, &f->helem);
	list_remove(&f->lelem);

	if(free_page) palloc_free_page(kpage);
	free(f);
}

//LRU, clock 알고리즘을 통해 evict를 한다.
struct frame_table_entry* pick_frame_to_evict(uint32_t *pagedir){
	size_t n = hash_size(&frame_map);

	for(int i = 0; i <= 2 * n; ++i){
		ft_entry *e = clock_frame_next();
	
		//pinned면 스왑하면 안되지!
		if(e->pinned) 
			continue;

		//clock알고리즘은 access되지 않은 페이지를 스왑 대상으로 선택한다
		//보고 있는 페이지가 access된거라면 access bit을 false로 바꾸고 그냥 넘어감
		else if(pagedir_is_accessed(pagedir, e->user_page)){
			pagedir_set_accessed(pagedir, e->user_page, false);
			continue;
		}


		return e;
	}

}

//frame list의 요소를 순서대로 반환해줌
struct frame_table_entry* clock_frame_next(void){
	if(clock_ptr == NULL || clock_ptr == list_end(&frame_list))
		clock_ptr = list_begin(&frame_list);
	else
		clock_ptr = list_next(clock_ptr);

	ft_entry *e = list_entry(clock_ptr, ft_entry, lelem);
	return e;
}





