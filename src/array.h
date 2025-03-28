#ifndef ARRAY_H
#define ARRAY_H

#include <stddef.h>
#include <stdbool.h>

typedef struct Array
{
    void* base;
    size_t length, capacity;
    size_t element_size;
} array_t;

typedef bool (*array_find_func)(void* element, void* key_element);

void array_create(array_t* array, size_t capacity, size_t element_size);
void array_destroy(array_t* array);

void array_resize(array_t* array, size_t capacity);

void array_push(array_t* array, void* element);
bool array_pop(array_t* array, void* element);

void* array_at(array_t* array, size_t index);
void* array_index(array_t* array, size_t index);

void array_delete(array_t* array, size_t index);
void array_clear(array_t* array);

void* array_find_first(array_t* array, array_find_func func, void* key);

#endif