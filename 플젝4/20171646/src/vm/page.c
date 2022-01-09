#include <hash.h>
#include <string.h>
#include "lib/kernel/hash.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "filesys/file.h"

static unsigned page_table_entry_hash_func(const struct hash_elem* elem, void* aux UNUSED)
{
    pt_entry* entry = hash_entry(elem, pt_entry, elem);
    return hash_int((int)entry->user_page);
}
static bool page_table_entry_less_func(const struct hash_elem* a, const struct hash_elem* b, void* aux UNUSED)
{
    pt_entry* a_entry = hash_entry(a, pt_entry, elem);
    pt_entry* b_entry = hash_entry(b, pt_entry, elem);
    return a_entry->user_page < b_entry->user_page;
}
static void page_table_entry_destroy_func(struct hash_elem* elem, void* aux UNUSED)
{
    pt_entry* entry = hash_entry(elem, pt_entry, elem);

    if (entry->kernel_page != NULL)
        frame_do_free(entry->kernel_page, false);

    else if (entry->status == SWAP_PAGE)
        swap_free(entry->swap_idx);

    free(entry);
}

page_table* page_table_create (void)
{
  page_table *pt = (page_table*) malloc(sizeof(page_table));

  hash_init (&pt->page_map, page_table_entry_hash_func, page_table_entry_less_func, NULL);
  return pt;
}

pt_entry* page_table_lookup (page_table *pt, void *page_addr)
{
  pt_entry tmp_pte;
  struct hash_elem *elem;
  tmp_pte.user_page = page_addr;

  elem = hash_find (&pt->page_map, &tmp_pte.elem);
  if(elem == NULL) 
	return NULL;
  else
  	return hash_entry(elem, pt_entry, elem);
}

bool load_page(page_table *pt, uint32_t *dir, void *userpage)
{
  pt_entry *pte = page_table_lookup(pt, userpage);
  void *fpage = frame_allocate(PAL_USER, userpage);
  bool writable = true;  

  if(pte->status == FRAME_PAGE)
    return true;
  else if(pte->status == SWAP_PAGE){
	if(pte == NULL || fpage == NULL)
		return false;
	swap_in(pte->swap_idx, fpage);
  }
  else if(pte->status == FILE_PAGE){
	if(pte == NULL || fpage == NULL)
		return false;
	else if(load_page_from_filesys(pte, fpage) == false){
		frame_do_free(fpage, true);
		return false;
  	}
  }
  else if(pte->status == ZERO_PAGE){
	if(pte == NULL || fpage == NULL)
		return false;
	else{
		memset(fpage, 0, PGSIZE);
	}
  }
  

  if(!pagedir_set_page (dir, userpage, fpage, writable)) {
    frame_do_free(fpage, true);
    return false;
  }

  pte->kernel_page = fpage;
  pte->status = FRAME_PAGE;

  pagedir_set_dirty (dir, fpage, false);

  return true;
}

static bool load_page_from_filesys(pt_entry* pte, void* kerpage)
{
    file_seek(pte->file, pte->file_ofs);

    int n_read = file_read(pte->file, kerpage, pte->read_b);
    if (n_read != (int)pte->read_b)
        return false;

    memset(kerpage + n_read, 0, pte->zero_b);
    return true;
}

bool page_table_install(page_table* pt, void* userpage, void* kerpage, uint32_t swap_index, struct file* file, off_t offset, uint32_t rb, uint32_t zb, bool writable, enum page_status status) {
    pt_entry* pte;
    struct hash_elem* prev_elem;
    pte = (pt_entry*)malloc(sizeof(pt_entry));

    if (status == FRAME_PAGE) {
        pte->status = FRAME_PAGE;
        pte->swap_idx = -1;
        pte->dirty_bit = false;
        pte->user_page = userpage;
        pte->kernel_page = kerpage;

        prev_elem = hash_insert(&pt->page_map, &pte->elem);
        if (prev_elem == NULL)
            return true;
        else
            free(pte);

    }
    else if (status == ZERO_PAGE) {
        pte->status = ZERO_PAGE;
        pte->dirty_bit = false;
        pte->user_page = userpage;
        pte->kernel_page = NULL;

        prev_elem = hash_insert(&pt->page_map, &pte->elem);
        if (prev_elem == NULL)
            return true;
    }
    else if (status == FILE_PAGE) {
        pte->read_b = rb;
        pte->zero_b = zb;
        pte->file = file;
        pte->dirty_bit = false;
        pte->writable = writable;
        pte->file_ofs = offset;
        pte->status = FILE_PAGE;
        pte->user_page = userpage;
        pte->kernel_page = NULL;

        prev_elem = hash_insert(&pt->page_map, &pte->elem);
        if (prev_elem == NULL)
            return true;
    }

    return false;
}


void page_table_destroy(page_table* pt)
{
    hash_destroy(&pt->page_map, page_table_entry_destroy_func);
    free(pt);
}
