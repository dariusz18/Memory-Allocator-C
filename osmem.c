// SPDX-License-Identifier: BSD-3-Clause
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../utils/block_meta.h"
#include "../utils/osmem.h"
#include "../utils/printf.h"

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20
#define MMAP_THRESHOLD (128 * 1024)
#define ALIGNMENT 8
#define ALIGN(size) ((((size) + ALIGNMENT - 1) / ALIGNMENT) * ALIGNMENT)

struct block_meta *start;
int status = STATUS_FREE;

void initializare(struct block_meta *block, size_t size, int status, struct block_meta *prev, struct block_meta *next)
{
    block->size = size;
    block->status = status;
    block->prev = prev;
    block->next = next;
}

void coalitie(void)
{
    struct block_meta *curent = start;

    while (curent != NULL) {
        if (curent->status == STATUS_FREE) {
            while (curent->next != NULL && curent->next->status == STATUS_FREE) {
                curent->size += curent->next->size + sizeof(struct block_meta);
                curent->next = curent->next->next;
                if (curent->next != NULL)
                    curent->next->prev = curent;
            }

            while (curent->prev != NULL && curent->prev->status == STATUS_FREE) {
                curent->prev->size += curent->size + sizeof(struct block_meta);
                curent->prev->next = curent->next;
                if (curent->next != NULL)
                    curent->next->prev = curent->prev;
                curent = curent->prev;
            }
        }
        curent = curent->next;
    }
}

void divide(struct block_meta *block, size_t size)
{
    if (block->size >= ALIGN(size) + sizeof(struct block_meta) + ALIGN(1)) {
        struct block_meta *new_block = (struct block_meta *)((char *)block + ALIGN(size) + sizeof(struct block_meta));

        initializare(new_block, block->size - ALIGN(size) - sizeof(struct block_meta), STATUS_FREE, block, block->next);
        block->next = new_block;
        block->size = ALIGN(size);
        block->status = STATUS_ALLOC;
    } else {
        block->status = STATUS_ALLOC;
    }
}

void *heap(size_t size)
{
    void *memory = sbrk(size);
    if (memory == NULL)
        return NULL;

    start = (struct block_meta *)memory;
    initializare(start, size - sizeof(struct block_meta), STATUS_ALLOC, NULL, NULL);

    return (char *)start + sizeof(struct block_meta);
}

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc */
    if (size <= 0)
        return NULL;

    size_t size_block = ALIGN(size) + sizeof(struct block_meta);
    void *memory;
    struct block_meta *block = start;
    struct block_meta *last = NULL;
	size_t treshold = MMAP_THRESHOLD;

    if (size_block > treshold) {
        memory = mmap(NULL, size_block, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (memory == NULL)
            return NULL;

        block = (struct block_meta *)memory;
        initializare(block, ALIGN(size), STATUS_MAPPED, NULL, NULL);
        return (char *)block + sizeof(struct block_meta);
    }

    if (status == STATUS_FREE) {
        memory = heap(MMAP_THRESHOLD);
        status = STATUS_ALLOC;
        return memory;
    }

    while (block != NULL) {
        if (block->status == STATUS_FREE && block->size >= size) {
            divide(block, size);
            return (char *)block + sizeof(struct block_meta);
        }
        last = block;
        block = block->next;
    }

    memory = sbrk(size_block);
    if (memory == NULL)
        return NULL;

    block = (struct block_meta *)memory;
    initializare(block, ALIGN(size), STATUS_ALLOC, last, NULL);
    if (last != NULL)
        last->next = block;

    return (char *)block + sizeof(struct block_meta);
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */
    if (ptr == NULL)
        return;

    struct block_meta *block = (struct block_meta *)((char *)ptr - sizeof(struct block_meta));

    if (block->status == STATUS_MAPPED) {
        munmap(block, block->size + sizeof(struct block_meta));
    } else if (block->status == STATUS_ALLOC) {
        block->status = STATUS_FREE;
        coalitie();
    }
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
    if (nmemb == 0 || size == 0)
        return NULL;

    size_t total = nmemb * size;
    void *memory = os_malloc(total);
    if (memory == NULL)
        return NULL;

    unsigned char *ptr = (unsigned char *)memory;
    for (size_t i = 0; i < total; i++) {
        ptr[i] = 0;
    }
    return memory;
}


void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
    if (ptr == NULL)
        return os_malloc(size);

    if (size <= 0) {
        os_free(ptr);
        return NULL;
    }

    struct block_meta *block = (struct block_meta *)((char *)ptr - sizeof(struct block_meta));
	
    if (block->size >= size) {
        divide(block, size);
        return ptr;
    }

    void *new = os_malloc(size);
    if (new == NULL)
        return NULL;

    memcpy(new, ptr, block->size);
    os_free(ptr);
    return new;
}
