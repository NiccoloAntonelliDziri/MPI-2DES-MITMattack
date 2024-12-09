#include "sorting.h"

#include <stdio.h>

void display(entry tab[], int taille){
    for (int i = 0; i < taille; i++) {
        printf("%d ", proc(tab[i]));
    }
    printf("\n");
}

int proc(entry e){
    return e.k % world_size;
}

void swap(entry *first, entry*second){
    entry temp = *first;
    *first = *second;
    *second = temp;
}

int partition(entry tab[], int lower, int upper) {
    int i = lower;
    int pivot = proc(tab[lower]);
    
    for (int j = lower + 1; j < upper; j++) {
        if (proc(tab[j]) < pivot) {
            i++;
        } 
        if (j > i) {
            swap(&tab[i], &tab[j]);
        }
    }
    if (i > lower) {
        swap(&tab[i], &tab[lower]);
    }
    return i;
}

void quickSort(entry tab[], int lower, int upper){
    if (upper - 1 > lower) {
        int partitionIndex = partition(tab, lower, upper);

        quickSort(tab, lower, partitionIndex);
        quickSort(tab, partitionIndex + 1, upper);
    }
}
