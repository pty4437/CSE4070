#include <debug.h>
#include <string.h>
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/synch.h"

#define NUM_CACHE 64

static struct lock buffer_cache_lock;


static bc_entry cache[NUM_CACHE];


void buffer_cache_init(void){
	for(unsigned int i = 0; i < NUM_CACHE; ++i){
		cache[i].valid_bit = false;
		cache[i].dirty_bit = false;
		cache[i].reference_bit = false;
	}

	lock_init(&buffer_cache_lock);
}

void buffer_cache_flush_entry(bc_entry *entry){
        if(entry->dirty_bit && entry != NULL){
                block_write(fs_device, entry->disk_sector, entry->buffer);
                entry->dirty_bit = false;
        }
}


void buffer_cache_flush_all(void){
        lock_acquire(&buffer_cache_lock);

        for(unsigned int i = 0; i < NUM_CACHE; ++i){
                if(cache[i].valid_bit == true)
                        buffer_cache_flush_entry(&(cache[i]));
        }

        lock_release(&buffer_cache_lock);

}

bc_entry* buffer_cache_lookup(block_sector_t sector){

	for(unsigned int i = 0; i < NUM_CACHE; ++i){
		if(cache[i].valid_bit && cache[i].disk_sector == sector){
				return &(cache[i]);
		}
	}


	return NULL;
}

bc_entry** buffer_cache_select_victim(void){
	unsigned int clock = 0;
	for(clock = 0;;clock++){
		if(cache[clock].reference_bit)
			cache[clock].reference_bit = false;
		else
			break;
		if(!cache[clock].valid_bit)
			return &(cache[clock]);
		if(clock == NUM_CACHE)
			clock = 0;
	}

	if(cache[clock].dirty_bit)
		buffer_cache_flush_entry(&(cache[clock]));

	cache[clock].valid_bit = false;
	return &(cache[clock]);
}

void buffer_cache_read(block_sector_t sector, void *target){
	lock_acquire(&buffer_cache_lock);

	bc_entry *temp = buffer_cache_lookup(sector);

	if(temp != NULL){
		temp->reference_bit = true;
		memcpy(target, temp->buffer, BLOCK_SECTOR_SIZE);
	}

	else{
		temp = buffer_cache_select_victim();
		temp->reference_bit = true;
		temp->valid_bit = true;
		temp->disk_sector = sector;
		temp->dirty_bit = false;
		block_read(fs_device, sector, temp->buffer);
	
		memcpy(target, temp->buffer, BLOCK_SECTOR_SIZE);
	}

	lock_release(&buffer_cache_lock);

}

void buffer_cache_write(block_sector_t sector, const void *str){
	lock_acquire(&buffer_cache_lock);

	bc_entry *temp = buffer_cache_lookup(sector);


	if(temp != NULL){
		temp->reference_bit = true;
		temp->dirty_bit = true;

		memcpy(temp->buffer, str, BLOCK_SECTOR_SIZE);
	}
	else{
		temp = buffer_cache_select_victim();
		temp->valid_bit = true;
		temp->disk_sector = sector;
		temp->dirty_bit = true;
		temp->reference_bit = true;

		block_read(fs_device, sector, temp->buffer);
		memcpy(temp->buffer, str, BLOCK_SECTOR_SIZE);
	}

	lock_release(&buffer_cache_lock);
}






















