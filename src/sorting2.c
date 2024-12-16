#include "sorting.h"

#include <stdio.h>

void display(clefvaleur tab[], int taille){
    for (int i = 0; i < taille; i++) {
        printf("%d ", proc(tab[i]));
    }
    printf("\n");
}

int proc(clefvaleur e){
    return e.k % world_size;
}


void quick_sort2(clefvaleur arr[], int first_index, int last_index) {
  // declaring index variables
  int pivotIndex, index_a, index_b;
  clefvaleur temp;

  if (first_index < last_index) {
    // assigning first element index as pivot element
    pivotIndex = first_index;
    index_a = first_index;
    index_b = last_index;

    // Sorting in Ascending order with quick sort
    while (index_a < index_b) {
      while (proc(arr[index_a]) <= proc(arr[pivotIndex]) && index_a < last_index) {
        index_a++;
      }
      while (proc(arr[index_b]) > proc(arr[pivotIndex])) {
        index_b--;
      }

      if (index_a < index_b) {
        // Swapping operation
        temp = arr[index_a];
        arr[index_a] = arr[index_b];
        arr[index_b] = temp;
      }
    }

    // At the end of first iteration, swap pivot element with index_b element
    temp = arr[pivotIndex];
    arr[pivotIndex] = arr[index_b];
    arr[index_b] = temp;

    // Recursive call for quick sort, with partitioning
    quick_sort(arr, first_index, index_b - 1);
    quick_sort(arr, index_b + 1, last_index);
  }
}