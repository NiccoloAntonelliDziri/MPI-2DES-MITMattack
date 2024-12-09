#ifndef SORTING_C
#define SORTING_C

#include "utils.h"

void display(u64 k, u64 v, int taille);

int proc(entry);

// swap function to swap two values
void swap(u64 k1, u64 k2, u64 v1, u64 v2);

// Partition method which selects a pivot
// and places each element which is less than the pivot value
// to its left and the elements greater to its right.
// tab[]: array to be partitionned
// lower: lower index
// upper: upper index
int partition(entry tab[], int lower, int upper);

void quickSort(entry tab[], int lower, int upper);

#endif
