#include "array.h"

#include <stdlib.h>
#include <string.h>

void array_create(array_t* array, size_t capacity, size_t element_size)
{
    array->base = malloc(capacity * element_size);
    array->capacity = capacity;
    array->element_size = element_size;
    array->length = 0;
}
void array_destroy(array_t* array)
{
    free(array->base);
    array->capacity = 0;
    array->length = 0;
    array->element_size = 0;
}

void array_push(array_t* array, void* element)
{
    if (array->length >= array->capacity)
    {
        array->capacity *= 2;
        array->base = realloc(array->base, array->capacity * array->element_size);
    }
    void* p = (unsigned char*)array->base + array->element_size * array->length;
    memcpy(p, element, array->element_size);
    array->length++;
}
bool array_pop(array_t* array, void* element)
{
    if (array->length == 0) return false;
    array->length--;
    void* p = (unsigned char*)array->base + array->element_size * array->length;
    memcpy(element, p, array->element_size);
    return true;
}

void* array_at(array_t* array, size_t index)
{
    if (index >= array->length) return NULL;
    void* p = (unsigned char*)array->base + array->element_size * index;
    return p;
}

void* array_index(array_t* array, size_t index)
{
    return (unsigned char*)array->base + array->element_size * index;
}

size_t array_ptr_index(array_t* array, void* element)
{
    size_t ptr_diff = (size_t) element - (size_t)array->base;
    return ptr_diff / array->element_size;
}

void array_delete(array_t* array, size_t index)
{
    if (index >= array->length) return;
    void* pBase = (unsigned char*)array->base + array->element_size * index;
    void* pStartFrom = (unsigned char*)pBase + array->element_size;
    size_t remainingBytes = (array->length - index) * array->element_size;
    array->length--;
    memmove(pBase, pStartFrom, remainingBytes);
}

void array_clear(array_t* array)
{
    array->length = 0;
}

void array_resize(array_t* array, size_t capacity)
{
    array->capacity = capacity;
    array->base = realloc(array->base, array->capacity * array->element_size);
}

// Returns NULL if not found otherwise a pointer
void* array_find_first(array_t* array, array_find_func func, void* key)
{
    char* p = array->base;
    for (size_t i = 0; i < array->length; i++)
    {
        if (func(p, key)) return p;
        p += array->element_size;
    }
    return NULL;
}