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
    *second = *first;
}

int partition(entry tab[], int lower, int upper) {
    int i = lower - 1;
    int pivot = proc(tab[upper]);
    
    for (int j = 0; j < upper; j++) {
        if (proc(tab[j]) <= pivot) {
            i++;
            swap(&tab[i], &tab[j]);
        }
    }

    swap(&tab[i + 1], &tab[upper]);
    return i + 1;
}

void quickSort(entry tab[], int lower, int upper){
    if (upper > lower) {
        int partitionIndex = partition(tab, lower, upper);

        quickSort(tab, lower, partitionIndex - 1);
        quickSort(tab, partitionIndex + 1, upper);
    }
}
