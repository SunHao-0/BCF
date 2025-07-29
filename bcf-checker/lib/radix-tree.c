// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2001 Momchil Velikov
 * Portions Copyright (C) 2001 Christoph Hellwig
 * Copyright (C) 2005 SGI, Christoph Lameter
 * Copyright (C) 2006 Nick Piggin
 * Copyright (C) 2012 Konstantin Khlebnikov
 * Copyright (C) 2016 Intel, Matthew Wilcox
 * Copyright (C) 2016 Intel, Ross Zwisler
 */

#include <linux/xarray.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/init.h>

#include "radix-tree.h"

#define radix_tree_root		xarray
#define radix_tree_node		xa_node
/*
 * Radix tree node cache.
 */
struct kmem_cache *radix_tree_node_cachep;

static void radix_tree_node_ctor(void *arg)
{
	struct radix_tree_node *node = arg;

	memset(node, 0, sizeof(*node));
	INIT_LIST_HEAD(&node->private_list);
}

void radix_tree_node_rcu_free(struct rcu_head *head)
{
	struct radix_tree_node *node =
			container_of(head, struct radix_tree_node, rcu_head);

	/*
	 * Must only free zeroed nodes into the slab.  We can be left with
	 * non-NULL entries by radix_tree_free_nodes, so clear the entries
	 * and tags here.
	 */
	memset(node->slots, 0, sizeof(node->slots));
	memset(node->tags, 0, sizeof(node->tags));
	INIT_LIST_HEAD(&node->private_list);

	kmem_cache_free(radix_tree_node_cachep, node);
}

static void __init radix_tree_init(void)
{
	radix_tree_node_cachep = kmem_cache_create("radix_tree_node",
			sizeof(struct radix_tree_node), 0,
			SLAB_PANIC | SLAB_RECLAIM_ACCOUNT,
			radix_tree_node_ctor);
}
