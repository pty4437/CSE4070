#ifndef __PAGE_H__
#define __PAGE_H__

#include "vm/swap.h"
#include <hash.h>
#include "filesys/off_t.h"

enum page_status{
  ZERO_PAGE,
  FRAME_PAGE,
  SWAP_PAGE,
  FILE_PAGE
};

typedef struct PAGE_TABLE
{
    struct hash page_map;
}page_table;

typedef struct page_table_entry
{
    struct hash_elem elem;
    enum page_status status;
    bool dirty_bit;
    uint32_t swap_idx;
    struct file *file;
    off_t file_ofs;
    uint32_t read_b, zero_b;
    
    void *user_page;              
    void *kernel_page;

    bool writable;
}pt_entry;


static unsigned page_table_entry_hash_func(const struct hash_elem *elem, void *aux);
static bool page_table_entry_less_func(const struct hash_elem *, const struct hash_elem *, void *aux);
static void page_table_entry_destroy_func(struct hash_elem *elem, void *aux);
static bool load_page_from_filesys(pt_entry *, void *);

page_table* page_table_create (void);
void page_table_destroy (page_table *);

bool page_table_install(page_table* pt, void*, void*, uint32_t, struct file*, off_t, uint32_t, uint32_t, bool, enum page_status);

pt_entry* page_table_lookup (page_table*, void *);
bool load_page(page_table*, uint32_t*, void*);

#endif
