#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "utils.h"

#include "sorting.h"

int world_size;
int world_rank;
int root;

int main(){

    world_size=4;
    // int world_rank=4;
    clefvaleur *tab = (clefvaleur*) malloc(sizeof(clefvaleur) * 10);

    int indice =0;
    srand(time(NULL));
    for (u64 x = 0; x < 8192; x++) {
        // u64 x=rand() %100;
        u64 z=rand()%100;
        tab[indice].k = z;
        tab[indice].v = x;
        //  printf("tab[%d].k=%llu\n",indice,z);
        printf("tab[%d].k=%llu\n",indice,tab[indice].k%world_size);
        // printf("tab[%d].v=%llu\n",indice,tab[indice].v);
        indice++;
    }



    quickSort(tab, 0, 8192);

    for (int i=0;i<8192;i++){
        printf("tab[%d].k=%llu\n",i,tab[i].k%world_size);
    }
    return 0;
}