#include <stdlib.h>

#include <fluent-bit/flb_heap.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>

struct flb_heap* flb_heap_create(int capacity, int (*cmp)(void*, void*), void (*value_free)(void*)){
	int i;

	struct flb_heap *heap = NULL;

	heap = flb_calloc(1, sizeof(struct flb_heap));
	if (heap == NULL) {
		flb_errno();
		return NULL;
	}

	heap->capacity = capacity;
	heap->count = 0;
	heap->heap = flb_calloc(capacity, sizeof(struct flb_heap_item *));
	if (heap->heap == NULL) {
		flb_heap_destroy(heap);
		flb_errno();
		return NULL;
	}

	for (i = 0; i < heap->capacity; ++i) {
		heap->heap[i] = NULL;
	}

	heap->cmp = cmp;
	heap->value_free = value_free;

	return heap;
}

void flb_heap_destroy(struct flb_heap *heap) {
	int i;

	if (heap == NULL) {
		return;
	}

	if (heap->heap != NULL) {
		for (i = 0; i < heap->count; ++i) {
			flb_heap_item_destroy(heap, heap->heap[i]);
		}

		flb_free(heap->heap);
		heap->heap = NULL;
	}

	flb_free(heap);
}

struct flb_heap_item *flb_heap_item_create() {
	struct flb_heap_item *item = NULL;

	item = flb_calloc(1, sizeof(struct flb_heap_item));
	if (item == NULL) {
		flb_errno();
		return NULL;
	}

	return item;
}

void flb_heap_item_destroy(struct flb_heap *heap, struct flb_heap_item *item) {
	if (heap == NULL || item == NULL) {
		return;
	}

	if (heap->value_free != NULL) {
		heap->value_free(item->value);
	} else {
		flb_free(item->value);
	}

	flb_free(item);
}

void* flb_heap_get(struct flb_heap *heap) {
	if (heap->count > 0 && heap->heap != NULL) {
		return heap->heap[0]->value;
	}

	return NULL;
}

static void flb_heap_adjust_up(struct flb_heap *heap, int index) {
	int parent;
	void *tmp;

	while (index > 0) {
		parent = (index - 1) / 2;

		if (heap->cmp(heap->heap[parent]->value, heap->heap[index]->value) < 0) {
			break;
		}

		tmp = heap->heap[parent];
		heap->heap[parent] = heap->heap[index];
		heap->heap[index] = tmp;

		heap->heap[parent]->position = parent;
		heap->heap[index]->position = index;

		index = parent;
	}
}

static void flb_heap_adjust_down(struct flb_heap *heap, int index) {
	int son;
	void *tmp;

	son = index * 2 + 1;
	while (son < heap->count) {
		if (son + 1 < heap->count) {
			if (heap->cmp(heap->heap[son]->value, heap->heap[son + 1]->value) > 0) {
				son = son + 1;
			}
		}

		if (heap->cmp(heap->heap[index]->value, heap->heap[son]->value) < 0) {
			break;
		}

		tmp = heap->heap[son];
		heap->heap[son] = heap->heap[index];
		heap->heap[index] = tmp;

		heap->heap[son]->position = son;
		heap->heap[index]->position = index;

		index = son;
		son = index * 2 + 1;
	}
}

static void flb_heap_adjust(struct flb_heap *heap, int index) {
	int parent;
	int son;

	if (heap->count <= 1 && heap->heap == NULL) {
		return;
	}

	if (heap->cmp == NULL) {
		return;
	}

	// first critical
	if (index * 2 + 1 >= heap->count) {
		flb_heap_adjust_up(heap, index);
		return;
	} else if (index == 0) {
		flb_heap_adjust_down(heap, index);
		return;
	}

	// parent;
	parent = (index - 1) / 2;
	if (heap->cmp(heap->heap[parent]->value, heap->heap[index]->value) > 0) {
		flb_heap_adjust_up(heap, index);
		return;
	}

	// son
	son = index * 2 + 1;
	if (son + 1 < heap->count) {
		if (heap->cmp(heap->heap[son]->value, heap->heap[son + 1]->value) > 0) {
			son = son + 1;
		}
	}

	if (heap->cmp(heap->heap[index]->value, heap->heap[son]->value) > 0) {
		flb_heap_adjust_down(heap, index);
		return;
	}
}

struct flb_heap_item* flb_heap_add(struct flb_heap *heap, void *value) {
	int i;

	struct flb_heap_item **heap_item = NULL;
	struct flb_heap_item *heap_item_ptr = NULL;

	if (heap->count >= heap->capacity) {
		heap_item = heap->heap;
		heap->heap = flb_realloc(heap->heap, sizeof(struct flb_heap_item) * heap->capacity * 2);
		if (heap->heap == NULL) {
			heap->heap = heap_item;
			return NULL;
		}
		for (i = heap->capacity; i < heap->capacity * 2; ++i) {
			heap->heap[i] = NULL;
		}
		heap->capacity = heap->capacity * 2;
	}

	// add
	heap_item_ptr = flb_heap_item_create();
	if (heap_item_ptr == NULL) {
		return NULL;
	}
	heap->heap[heap->count] = heap_item_ptr;
	heap->heap[heap->count]->value = value;
	heap->heap[heap->count]->position = heap->count;
	heap->count++;
	flb_heap_adjust(heap, heap->count - 1);

	return heap_item_ptr;
}

void flb_heap_delete(struct flb_heap *heap) {
	if (heap->count == 0) {
		return;
	}

	struct flb_heap_item *heap_item_ptr = NULL;
	heap_item_ptr = heap->heap[0];

	heap->count--;
	heap->heap[0] = heap->heap[heap->count];
	heap->heap[heap->count] = NULL;

	flb_heap_item_destroy(heap, heap_item_ptr);

	flb_heap_adjust(heap, 0);
}

void flb_heap_update(struct flb_heap *heap, struct flb_heap_item *data) {
	if (data == NULL) {
		return;
	}

    flb_heap_adjust(heap, data->position);
}

static void flb_heap_node_print(struct flb_heap_item *heap_node, void (*print)(void *)) {
	if (heap_node == NULL) {
		return;
	}

	if (print == NULL) {
		return;
	}

	print(heap_node->value);
}

void flb_heap_print(struct flb_heap *heap, void (*print)(void *)) {
	int root = 0;
	int left = 0;
	int right = 0;

	struct flb_heap_item *heap_root = NULL;
	struct flb_heap_item *heap_left = NULL;
	struct flb_heap_item *heap_right = NULL;

	for (root = 0; root < heap->count; ++root) {
		heap_root = heap->heap[root];

		left = root * 2 + 1;
		right = root * 2 + 2;

		printf("root: %d(", heap_root->position);
		flb_heap_node_print(heap_root, print);
		printf(")");

		if (left < heap->count) {
			heap_left = heap->heap[left];

			printf("     left: %d(", heap_left->position);
			flb_heap_node_print(heap_left, print);
			printf(")");
		}
		if (right < heap->count) {
			heap_right = heap->heap[right];

			printf("     right: %d(", heap_right->position);
			flb_heap_node_print(heap_right, print);
			printf(")");
		}

		printf("\n");
	}
}
