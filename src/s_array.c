#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "s_array.h"

struct s_array_t*
s_array_init( struct s_array_t* array, int32_t init_size, int32_t elem_size )
{
    if ( ! array )
        array = ( struct s_array_t*) malloc( sizeof( *array ) );
    array->elts = calloc( init_size, elem_size );
    array->max_size = init_size;
    array->elem_size = elem_size;
    array->size = 0;
    return array;
}

void*
s_array_ensure_n( struct s_array_t* array, int n )
{
    if ( n == 0 )
        return NULL;
    uint32_t need_size = array->size + n;
    if ( need_size > array->max_size )
    {
        uint32_t new_max_size = array->max_size * 2;
        if ( new_max_size <= need_size )
            new_max_size += need_size;
        void* new = realloc( array->elts, new_max_size * array->elem_size );
        if ( new == NULL )
            return NULL;
        array->elts = new;
        array->max_size = new_max_size;
    }
    return array->elts;
}

void*
s_array_get( struct s_array_t* array, uint32_t ix )
{
    assert( ix <= array->size );
    return (char*) array->elts + array->elem_size * ix;
}

void*
s_array_add_n( struct s_array_t* array, void* elem, int n )
{
    if ( n == 0 )
        return NULL;
    if ( s_array_ensure_n( array, n ) == NULL )
        return NULL;
    void* add = s_array_get( array, array->size );
    if ( elem )
        memcpy( add, elem, n * array->elem_size );
    array->size += n;
    return add;
}

void*
s_array_add( struct s_array_t* array, void* elem )
{
    return s_array_add_n( array, elem, 1 );
}

void
s_array_free( struct s_array_t* array, void (*clear_func)(void*) )
{
    uint32_t i;
    if( ! array->elts )
        return;
    for( i = 0; i < array->size; i++ ) {
        if ( clear_func )
            clear_func( s_array_get( array, i ) );
    }
    free( array->elts );
    array->elts = NULL;
    array->size = 0;
}
