// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <string.h>
#include <stdatomic.h>

#include <linux/slab.h>
#include <malloc.h>
#include <linux/gfp.h>

atomic_int kmalloc_nr_allocated;
int kmalloc_verbose;

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
	atomic_fetch_add(&kmalloc_nr_allocated, 1);
	if (kmalloc_verbose)
		printf("Allocating %p from malloc\n", ret);
	if (gfp & __GFP_ZERO)
		memset(ret, 0, size);
	return ret;
}

void kfree(void *p)
{
	if (!p)
		return;
	atomic_fetch_sub(&kmalloc_nr_allocated, 1);
	if (kmalloc_verbose)
		printf("Freeing %p to malloc\n", p);
	free(p);
}

void *kmalloc_array(size_t n, size_t size, gfp_t gfp)
{
	void *ret;

	if (!(gfp & __GFP_DIRECT_RECLAIM))
		return NULL;

	ret = calloc(n, size);
	atomic_fetch_add(&kmalloc_nr_allocated, 1);
	if (kmalloc_verbose)
		printf("Allocating %p from calloc\n", ret);
	if (gfp & __GFP_ZERO)
		memset(ret, 0, n * size);
	return ret;
}

void *kmem_cache_alloc_lru(struct kmem_cache *cachep, struct list_lru *lru, int flags)
{
	void *ret;

	if (!cachep)
		return NULL;

	ret = malloc(cachep->size);
	if (!ret)
		return NULL;

	atomic_fetch_add(&kmalloc_nr_allocated, 1);
	if (kmalloc_verbose)
		printf("Allocating %p from kmem_cache %s\n", ret, cachep->name);

	// Call constructor if provided
	if (cachep->ctor)
		cachep->ctor(ret);

	return ret;
}

void kmem_cache_free(struct kmem_cache *cachep, void *objp)
{
	if (!objp || !cachep)
		return;

	atomic_fetch_sub(&kmalloc_nr_allocated, 1);
	if (kmalloc_verbose)
		printf("Freeing %p to kmem_cache %s\n", objp, cachep->name);

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

	cachep->name = name;
	cachep->size = size;
	cachep->align = align;
	cachep->flags = flags;
	cachep->ctor = ctor;

	if (kmalloc_verbose)
		printf("Created kmem_cache %s with size %u\n", name, size);

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