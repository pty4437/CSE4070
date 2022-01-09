#ifndef __CACHE_H__
#define __CACHE_H__

#include "devices/block.h"
#include <stdbool.h>


#define NUM_CACHE 64


typedef struct BUFFER_CACHE_ENTRY{
	bool valid_bit;
	bool reference_bit;
	bool dirty_bit;
	block_sector_t disk_sector;
	uint8_t buffer[BLOCK_SECTOR_SIZE];
} bc_entry;

void buffer_cache_init(void);
//void buffer_cache_close(void);
void buffer_cache_flush_entry(bc_entry* entry);
void buffer_cache_flush_all(void);
bc_entry* buffer_cache_lookup(block_sector_t sector);
bc_entry** buffer_cache_select_victim(void);
void buffer_cache_read(block_sector_t sector, void *target);
void buffer_cache_write(block_sector_t sector, const void *source);



#endif
