#ifndef SORTING_C
#define SORTING_C

#include "utils.h"

void display(clefvaleur tab[], int taille);

int proc(clefvaleur);

// swap function to swap two values
void swap(clefvaleur *first, clefvaleur*second);

// Partition method which selects a pivot
// and places each element which is less than the pivot value
// to its left and the elements greater to its right.
// tab[]: array to be partitionned
// lower: lower index
// upper: upper index
int partition(clefvaleur tab[], int lower, int upper);

// void quickSort(clefvaleur tab[], int lower, int upper);


void quickSort(clefvaleur arr[], int first_index, int last_index);

#endif
