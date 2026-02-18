# Memory Allocator — os_malloc / os_free / os_calloc / os_realloc in C

A custom **heap memory allocator** implemented in C, mimicking the behavior of `malloc`, `free`, `calloc`, and `realloc` using raw `sbrk()` and `mmap()` system calls. Developed as an Operating Systems course assignment.

## Overview

The allocator manages a **singly-structured free list** of heap blocks, each prefixed with a `block_meta` header. Small allocations go through `sbrk()` (heap), while large ones use `mmap()`. Freed heap blocks are coalesced with their neighbors to reduce fragmentation.

## Key Design Decisions

- **Threshold-based strategy**: allocations ≥ 128 KB use `mmap()`; smaller ones use `sbrk()`
- **Heap pre-allocation**: on the first `sbrk` call, 128 KB is reserved upfront to minimize future system calls
- **Block splitting (`divide()`)**: when a free block is larger than needed, it is split into an allocated block and a smaller free remainder — only if the remainder is large enough to hold at least 1 aligned byte plus a `block_meta` header
- **Coalescing (`coalitie()`)**: after every `free`, adjacent free blocks are merged in both directions to reconstruct larger contiguous regions
- **8-byte alignment**: all allocation sizes are rounded up via `ALIGN(size) = ((size + 7) / 8) * 8`

## Functions

### `os_malloc(size)`
- Returns `NULL` for `size <= 0`
- If `size + sizeof(block_meta) >= 128 KB` → allocates with `mmap`, marked `STATUS_MAPPED`
- On first heap call → pre-allocates 128 KB with `sbrk`, marked `STATUS_ALLOC`
- Otherwise → walks the free list looking for a fitting free block; splits if possible
- If no suitable block exists → extends the heap with `sbrk`

### `os_free(ptr)`
- Recovers the `block_meta` header from `ptr - sizeof(block_meta)`
- `STATUS_MAPPED` blocks → released with `munmap`
- `STATUS_ALLOC` blocks → marked `STATUS_FREE`, then `coalitie()` is called

### `os_calloc(nmemb, size)`
- Calls `os_malloc(nmemb * size)` and zeroes the memory byte by byte

### `os_realloc(ptr, size)`
- `ptr == NULL` → delegates to `os_malloc(size)`
- `size <= 0` → calls `os_free(ptr)`, returns `NULL`
- If current block is already large enough → tries to split in-place
- Otherwise → allocates a new block, copies data with `memcpy`, frees the old block

## Block Metadata

Each allocated region is preceded by a `block_meta` struct (defined in `utils/block_meta.h`):

```c
struct block_meta {
    size_t size;        // usable size (excluding header)
    int status;         // STATUS_FREE, STATUS_ALLOC, or STATUS_MAPPED
    struct block_meta *prev;
    struct block_meta *next;
};
```

## Building

```bash
make
```

## Project Structure

```
.
├── osmem.c                  # Allocator implementation
├── utils/
│   ├── block_meta.h         # block_meta struct and status constants
│   ├── osmem.h              # Function declarations
│   └── printf.h             # Debug printf utility
└── Makefile
```
