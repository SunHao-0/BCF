// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <string.h>
#include <stdatomic.h>

#include <linux/slab.h>
#include <malloc.h>
#include <linux/gfp.h>

#ifdef BCF_MEM_PROFILE
atomic_long kmalloc_bytes_allocated;
atomic_long kmalloc_max_bytes_allocated;

static void update_max_memory(void)
{
	long current = atomic_load(&kmalloc_bytes_allocated);
	long max = atomic_load(&kmalloc_max_bytes_allocated);
	while (current > max &&
	       !atomic_compare_exchange_weak(&kmalloc_max_bytes_allocated, &max,
					     current)) {
	}
}
#endif

struct kmem_cache {
	const char *name;
	unsigned int size;
	unsigned int align;
	unsigned int flags;
	void (*ctor)(void *);
};

struct list_lru {
	// Simple placeholder for list_lru structure
	int dummy;
};

void *kmalloc(size_t size, gfp_t gfp)
{
	void *ret;

	if (!(gfp & __GFP_DIRECT_RECLAIM))
		return NULL;

	ret = malloc(size);
#ifdef BCF_MEM_PROFILE
	if (ret) {
		atomic_fetch_add(&kmalloc_bytes_allocated,
				 malloc_usable_size(ret));
		update_max_memory();
	}
#endif
	if (gfp & __GFP_ZERO)
		memset(ret, 0, size);
	return ret;
}

void *krealloc(void *p, size_t new_size, gfp_t gfp)
{
	void *ret;
#ifdef BCF_MEM_PROFILE
	size_t old_size = 0;

	if (p)
		old_size = malloc_usable_size(p);
#endif

	ret = realloc(p, new_size);
#ifdef BCF_MEM_PROFILE
	if (ret) {
		if (p)
			atomic_fetch_sub(&kmalloc_bytes_allocated, old_size);
		atomic_fetch_add(&kmalloc_bytes_allocated,
				 malloc_usable_size(ret));
		update_max_memory();
	}
#endif

	if (ret && (gfp & __GFP_ZERO))
		memset(ret, 0, new_size);
	return ret;
}

void kfree(void *p)
{
	if (!p)
		return;
#ifdef BCF_MEM_PROFILE
	atomic_fetch_sub(&kmalloc_bytes_allocated, malloc_usable_size(p));
#endif
	free(p);
}

void *kmalloc_array(size_t n, size_t size, gfp_t gfp)
{
	void *ret;

	if (!(gfp & __GFP_DIRECT_RECLAIM))
		return NULL;

	ret = calloc(n, size);
#ifdef BCF_MEM_PROFILE
	if (ret) {
		atomic_fetch_add(&kmalloc_bytes_allocated,
				 malloc_usable_size(ret));
		update_max_memory();
	}
#endif
	if (gfp & __GFP_ZERO)
		memset(ret, 0, n * size);
	return ret;
}

void *kmem_cache_alloc_lru(struct kmem_cache *cachep, struct list_lru *lru,
			   int flags)
{
	void *ret;

	if (!cachep)
		return NULL;

	ret = malloc(cachep->size);
	if (!ret)
		return NULL;
#ifdef BCF_MEM_PROFILE
	atomic_fetch_add(&kmalloc_bytes_allocated, malloc_usable_size(ret));
	update_max_memory();
#endif

	// Call constructor if provided
	if (cachep->ctor)
		cachep->ctor(ret);

	return ret;
}

void kmem_cache_free(struct kmem_cache *cachep, void *objp)
{
	if (!objp || !cachep)
		return;

#ifdef BCF_MEM_PROFILE
	atomic_fetch_sub(&kmalloc_bytes_allocated, malloc_usable_size(objp));
#endif
	free(objp);
}

struct kmem_cache *kmem_cache_create(const char *name, unsigned int size,
				     unsigned int align, unsigned int flags,
				     void (*ctor)(void *))
{
	struct kmem_cache *cachep;

	cachep = malloc(sizeof(struct kmem_cache));
	if (!cachep)
		return NULL;

#ifdef BCF_MEM_PROFILE
	atomic_fetch_add(&kmalloc_bytes_allocated, malloc_usable_size(cachep));
	update_max_memory();
#endif
	cachep->name = name;
	cachep->size = size;
	cachep->align = align;
	cachep->flags = flags;
	cachep->ctor = ctor;
	return cachep;
}

void kmem_cache_free_bulk(struct kmem_cache *cachep, size_t size, void **list)
{
	size_t i;

	if (!cachep || !list)
		return;

	for (i = 0; i < size; i++) {
		if (list[i]) {
			kmem_cache_free(cachep, list[i]);
			list[i] = NULL;
		}
	}
}

int kmem_cache_alloc_bulk(struct kmem_cache *cachep, gfp_t gfp, size_t size,
			  void **list)
{
	size_t i;
	int allocated = 0;

	if (!cachep || !list || !(gfp & __GFP_DIRECT_RECLAIM))
		return 0;

	for (i = 0; i < size; i++) {
		list[i] = kmem_cache_alloc_lru(cachep, NULL, gfp);
		if (list[i])
			allocated++;
		else
			break; // Stop on first failure
	}

	return allocated;
}
