#ifndef __SWAP_H__
#define __SWAP_H__

#include "devices/block.h"
#include "threads/vaddr.h"

static struct block *swap_block;
static struct bitmap *swap_available;
static const size_t SECTORS_PER_PAGE = PGSIZE / BLOCK_SECTOR_SIZE;
static size_t swap_size;

void swap_init(void);
uint32_t swap_out(void *page);
void swap_in(uint32_t swap_index, void *page);
void swap_free(uint32_t swap_index);

#endif
