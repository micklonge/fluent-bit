#ifndef FLB_HEAP_H
#define FLB_HEAP_H

struct flb_heap_item {
	int position;
	void *value;
};

struct flb_heap {
	struct flb_heap_item **heap;
	int count;
	int capacity;

	int (*cmp)(void*, void*);     // -1 up, 1 down, 0 keep
	void (*value_free)(void*);
};

struct flb_heap* flb_heap_create(int capacity, int (*cmp)(void*, void*), void (*value_free)(void*));
void flb_heap_destroy(struct flb_heap *heap);

struct flb_heap_item *flb_heap_item_create();
void flb_heap_item_destroy(struct flb_heap *heap, struct flb_heap_item *item);

void* flb_heap_get(struct flb_heap *heap);  // get the min/max value
struct flb_heap_item* flb_heap_add(struct flb_heap *heap, void *value);
void flb_heap_delete(struct flb_heap *heap);  // delete the min/max value
void flb_heap_update(struct flb_heap *heap, struct flb_heap_item *value);  // delete the min/max value

void flb_heap_print(struct flb_heap *heap, void (*print)(void *));

#endif
