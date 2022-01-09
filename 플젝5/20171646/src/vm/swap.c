#include <bitmap.h>
#include "threads/vaddr.h"
#include "devices/block.h"
#include "vm/swap.h"

void swap_init ()
{
  swap_block = block_get_role(BLOCK_SWAP);
  swap_size = block_size(swap_block) / SECTORS_PER_PAGE;
  swap_available = bitmap_create(swap_size);
  bitmap_set_all(swap_available, true);
}

void swap_free(uint32_t swap_index)
{
    bitmap_set(swap_available, swap_index, true);
}


void swap_in(uint32_t swap_index, void* page)
{
    for (int i = 0; i < SECTORS_PER_PAGE; ++i) {
        block_read(swap_block,
            swap_index * SECTORS_PER_PAGE + i,
            page + (BLOCK_SECTOR_SIZE * i)
        );
    }

    bitmap_set(swap_available, swap_index, true);
}

uint32_t swap_out (void *page)
{
  size_t swap_index = bitmap_scan (swap_available, 0, 1, true);

  for (int i = 0; i < SECTORS_PER_PAGE; ++i) {
    block_write(swap_block,
        swap_index * SECTORS_PER_PAGE + i,
        page + (BLOCK_SECTOR_SIZE * i)
        );
  }

  bitmap_set(swap_available, swap_index, false);
  return swap_index;
}


