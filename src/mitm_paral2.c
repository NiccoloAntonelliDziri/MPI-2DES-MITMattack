#include "mpi.h"
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <assert.h>
#include <getopt.h>
#include <err.h>
#include <assert.h>

#include "utils.h"

#include "sorting.h"

/***************************** global variables ******************************/

u64 n = 0;         /* block size (in bits) */
u64 mask;          /* this is 2**n - 1 */

u64 dict_size;     /* number of slots in the hash table */
struct entry *A;   /* the hash table */

/* (P, C) : two plaintext-ciphertext pairs */
u32 P[2][2] = {{0, 0}, {0xffffffff, 0xffffffff}};
u32 C[2][2];

int world_size;
int world_rank;
int root;

/************************ tools and utility functions *************************/

double wtime()
{
	struct timeval ts;
	gettimeofday(&ts, NULL);
	return (double)ts.tv_sec + ts.tv_usec / 1E6;
}

// murmur64 hash functions, tailorized for 64-bit ints / Cf. Daniel Lemire
u64 murmur64(u64 x)
{
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdull;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ull;
    x ^= x >> 33;
    return x;
}

/* represent n in 4 bytes */
void human_format(u64 n, char *target)
{
    if (n < 1000) {
        sprintf(target, "%" PRId64, n);
        return;
    }
    if (n < 1000000) {
        sprintf(target, "%.1fK", n / 1e3);
        return;
    }
    if (n < 1000000000) {
        sprintf(target, "%.1fM", n / 1e6);
        return;
    }
    if (n < 1000000000000ll) {
        sprintf(target, "%.1fG", n / 1e9);
        return;
    }
    if (n < 1000000000000000ll) {
        sprintf(target, "%.1fT", n / 1e12);
        return;
    }
}

/******************************** SPECK block cipher **************************/

#define ROTL32(x,r) (((x)<<(r)) | (x>>(32-(r))))
#define ROTR32(x,r) (((x)>>(r)) | ((x)<<(32-(r))))

#define ER32(x,y,k) (x=ROTR32(x,8), x+=y, x^=k, y=ROTL32(y,3), y^=x)
#define DR32(x,y,k) (y^=x, y=ROTR32(y,3), x^=k, x-=y, x=ROTL32(x,8))

void Speck64128KeySchedule(const u32 K[],u32 rk[])
{
    u32 i,D=K[3],C=K[2],B=K[1],A=K[0];
    for(i=0;i<27;){
        rk[i]=A; ER32(B,A,i++);
        rk[i]=A; ER32(C,A,i++);
        rk[i]=A; ER32(D,A,i++);
    }
}

void Speck64128Encrypt(const u32 Pt[], u32 Ct[], const u32 rk[])
{
    u32 i;
    Ct[0]=Pt[0]; Ct[1]=Pt[1];
    for(i=0;i<27;)
        ER32(Ct[1],Ct[0],rk[i++]);
}

void Speck64128Decrypt(u32 Pt[], const u32 Ct[], u32 const rk[])
{
    int i;
    Pt[0]=Ct[0]; Pt[1]=Ct[1];
    for(i=26;i>=0;)
        DR32(Pt[1],Pt[0],rk[i--]);
}

/******************************** dictionary ********************************/

/*
 * "classic" hash table for 64-bit key-value pairs, with linear probing.  
 * It operates under the assumption that the keys are somewhat random 64-bit integers.
 * The keys are only stored modulo 2**32 - 5 (a prime number), and this can lead 
 * to some false positives.
 */
static const u32 EMPTY = 0xffffffff;
static const u64 PRIME = 0xfffffffb;

/* allocate a hash table with `size` slots (12*size bytes) */
void dict_setup(u64 size)
{
    dict_size = size;
	// dict_size = size / world_size + 1;
    // dict_size = int(1.25*(size / world_size)) + 1;

	char hdsize[8];
	human_format(dict_size * sizeof(*A), hdsize);
	printf("Dictionary size: %sB\n", hdsize);

	A = malloc(sizeof(*A) * dict_size);
	if (A == NULL)
		err(1, "impossible to allocate the dictionnary");
	for (u64 i = 0; i < dict_size; i++)
		A[i].k = EMPTY;
}

/* Insert the binding key |----> value in the dictionnary */
void dict_insert(u64 key, u64 value)
{
    u64 h = murmur64(key) % dict_size;
    for (;;) {
        if (A[h].k == EMPTY)
            break;
        h += 1;
        if (h == dict_size)
            h = 0;
    }
    assert(A[h].k == EMPTY);
    A[h].k = key % PRIME;
    A[h].v = value;
}

/* Query the dictionnary with this `key`.  Write values (potentially) 
 *  matching the key in `values` and return their number. The `values`
 *  array must be preallocated of size (at least) `maxval`.
 *  The function returns -1 if there are more than `maxval` results.
 */
int dict_probe(u64 key, int maxval, u64 values[])
{
    u32 k = key % PRIME;
    u64 h = murmur64(key) % dict_size;
    int nval = 0;
    for (;;) {
        if (A[h].k == EMPTY)
            return nval;
        if (A[h].k == k) {
        	if (nval == maxval)
        		return -1;
            values[nval] = A[h].v;
            nval += 1;
        }
        h += 1;
        if (h == dict_size)
            h = 0;
   	}
}

/***************************** MITM problem ***********************************/

/* f : {0, 1}^n --> {0, 1}^n.  Speck64-128 encryption of P[0], using k */
u64 f(u64 k)
{
    assert((k & mask) == k);
    u32 K[4] = {k & 0xffffffff, k >> 32, 0, 0};
    u32 rk[27];
    Speck64128KeySchedule(K, rk);
    u32 Ct[2];
    Speck64128Encrypt(P[0], Ct, rk);
    return ((u64) Ct[0] ^ ((u64) Ct[1] << 32)) & mask;
}

/* g : {0, 1}^n --> {0, 1}^n.  speck64-128 decryption of C[0], using k */
u64 g(u64 k)
{
    assert((k & mask) == k);
    u32 K[4] = {k & 0xffffffff, k >> 32, 0, 0};
    u32 rk[27];
    Speck64128KeySchedule(K, rk);
    u32 Pt[2];
    Speck64128Decrypt(Pt, C[0], rk);
    return ((u64) Pt[0] ^ ((u64) Pt[1] << 32)) & mask;
}

bool is_good_pair(u64 k1, u64 k2)
{
    u32 Ka[4] = {k1 & 0xffffffff, k1 >> 32, 0, 0};
    u32 Kb[4] = {k2 & 0xffffffff, k2 >> 32, 0, 0};
    u32 rka[27];
    u32 rkb[27];
    Speck64128KeySchedule(Ka, rka);
    Speck64128KeySchedule(Kb, rkb);
    u32 mid[2];
    u32 Ct[2];
    Speck64128Encrypt(P[1], mid, rka);
    Speck64128Encrypt(mid, Ct, rkb);
    return (Ct[0] == C[1][0]) && (Ct[1] == C[1][1]);
}

/******************************************************************************/
int compar (const void * p1, const void * p2){
    clefvaleur* clefvaleurp1=(clefvaleur*)(p1);
    clefvaleur* clefvaleurp2=(clefvaleur*)(p2);
    return(((clefvaleurp1->k)%world_size)-((clefvaleurp2->k)%world_size));
}

/* search the "golden collision" */
int golden_claw_search(int maxres, u64 k1[], u64 k2[])
{
    double start = wtime();
    u64 N = 1ull << n;

    u64 petit_N = N / world_size;
    u64 reste = N % world_size;
    
    if(world_rank < reste) petit_N++;

    int begin = world_rank * petit_N;
    int end = (world_rank + 1) * petit_N;
    if (world_rank >= reste) {
        begin += reste;
        end += reste;
    }

    // printf("Petit_N = %llu, process = %d\n", petit_N, world_rank);
    // printf("reste=%llu\n",reste);

    // Alloue un tableau à trier
    clefvaleur *tab = (clefvaleur*) malloc(sizeof(clefvaleur) * petit_N);
    int indice = 0;
    

    // Calcul première boucle
    for (u64 x = begin; x < end; x++) {
        u64 z = f(x);
        tab[indice].k = z;
        tab[indice].v = x;
        indice++;
    }
    // printf("Process: %d, begin = %d, end = %d\n", world_rank, begin, end);
    // printf("indicefinal=%d\n",indice);
    // printf("delta=%llu\n",end-begin);


    // range le tableau selon le numéro de proccus auquel il faut l'aligner
    // for (int i = 0; i < petit_N; i++) {
    //     printf("process: %d, tab[%d].k=%llu, tab[%d].v=%llu\n", world_rank, i, tab[i].k,i,tab[i].v);
    // }
    // quickSort(tab, 0, petit_N);
    qsort(tab,petit_N,sizeof(clefvaleur),compar);
    
    // for (int i = 0; i < petit_N; i++) {
    //     printf("process: %d, tab[%d].k=%llu, tab[%d].v=%llu\n", world_rank, i, tab[i].k%world_size,i,tab[i].v);
    // }
    

    // Création du tableau de tailles à envoyer
    int tailles[world_size];
    int taille_recue[world_size];
    for (int i=0;i<world_size;i++){
        tailles[i]=0;
        taille_recue[i]=0;
    }
    
    int compteur = 1;
    for (int i = 1; i < petit_N; i++) {
        if (proc(tab[i - 1]) != proc(tab[i])) {
            tailles[proc(tab[i - 1])] = compteur;
            compteur = 0;
        }
        compteur++;
    }
    tailles[proc(tab[petit_N - 1])] = compteur;
    // for (int i=0;i<world_size;i++){
    //     printf("taille[%d]=%d\n",i,tailles[i]);
    // }

    // Taille recue depuis chaque processus
    MPI_Alltoall(tailles, 1, MPI_INT , taille_recue, 1, MPI_INT, MPI_COMM_WORLD);
    

    // Creation d'un datatype pour le struct clefvaleur
    const int nitems = 2;
    int blocklenght[2] = {1,1};
    MPI_Datatype types[2] = { MPI_UINT64_T, MPI_UINT64_T};
    MPI_Datatype MPI_CLEFVALEUR_TYPE;
    MPI_Aint offsets[2];
    offsets[0] = offsetof(clefvaleur, k);
    offsets[1] = offsetof(clefvaleur, v);
    MPI_Type_create_struct(nitems, blocklenght, offsets, types, &MPI_CLEFVALEUR_TYPE);
    MPI_Type_commit(&MPI_CLEFVALEUR_TYPE);

    // Calcul de la taille totale du tableau avec les tailles recues et du displs


    // C'est le cumsum des tailles pour les strides
    // pareil pour l'autre displs
    int sum = 0;
    int sum_recu = 0;
    int displs[world_size];
    int displs_recue[world_size];

    for (int i = 0; i < world_size; i++) {
        displs[i] = sum;
        displs_recue[i] = sum_recu;
        sum += tailles[i];
        sum_recu += taille_recue[i];
    }
  
    // if (world_rank==root){
    // for (int i = 0; i < world_size; i++) {
    //         printf("process = %d, displs[%d]=%d\n",world_rank, i,displs[i]);
    //         printf("process = %d, displs_recue[%d]=%d\n",world_rank, i,displs_recue[i]);
    //         printf("process = %d, taille_recue[%d]=%d\n",world_rank, i,taille_recue[i]);
    //         printf("process = %d, taille[%d]=%d\n",world_rank, i,tailles[i]);
    //     }
    // }
   

    // Envoi des struct clefvaleur, avec toutes les clefs valeurs au bon endroit
    clefvaleur tab_recu[sum_recu];
    MPI_Alltoallv(tab, tailles, displs, MPI_CLEFVALEUR_TYPE, tab_recu, taille_recue, displs_recue, MPI_CLEFVALEUR_TYPE, MPI_COMM_WORLD);


    // Insertion de toutes les valeurs dans le dictionnaire au bon endroit
    // printf("wr=%d,sum_recu=%d\n",world_rank,sum_recu);
    dict_setup(sum_recu);
    //sum remplacée par sum_recu ça fait une boucle infinie
    for (int i = 0; i < sum_recu; i++) {
        // printf("wr=%d, %d cle:%llu  val:%llu\n",world_rank,i,tab_recu[i].k, tab_recu[i].v);
        
        dict_insert(tab_recu[i].k, tab_recu[i].v);
    }
    free(tab);

    double mid = wtime();
    printf("Fill: %.1fs\n", mid - start);
    
    int nres = 0;
    u64 ncandidates = 0;
    u64 x[256];
    // Faire un système Maitre esclave où le maitre fait la boucle for du prog séquentiel et calcule le g(z). Au début il en calcul des tableaux (autant qu'il y'a de processus) d'une 
    // taille conséquente pour que chaque process ait suffisamment de travail avant d'en redemander au maitre et que le maitre ait le temps de calculer suffisamment de valeurs de g(z)
    //Attention gérer le cas où le maître s'envoie à lui même des "g(z)" (càd proc(g(z))==root), il devra faire des calculs en même tps qu'il répartie le travail
    //Soit on modifie le début en ne mettant pas de dictionnaire pour le root
    //Soit le root calcule par intermittence ses propres paires (et en même temps répartie le travail)

    //\\ATTENTION//\\ATTENTION//\\ATTENTION la manière dont on définie triger_work est arbitraire, il faudra faire des tests pour voir comment le définir de manière opti
    // u64 triger_work=(u64)(N/(world_size*world_size));
    //\\ATTENTION//\\ATTENTION//\\ATTENTION HARD CODE
    u64 triger_work=5;
    printf("triger_work=%llu\n",triger_work);
    // u64 triger_work=(u64)(N/(world_size));
    // u64 triger_work=N;

    tab = (clefvaleur*) malloc(sizeof(clefvaleur) * petit_N);
    indice = 0;
    

    // Calcul première boucle
    for (u64 z = begin; z < end; z++) {
        u64 y = g(z);
        tab[indice].k = y;
        tab[indice].v = z;
        indice++;
    }
    // for (int i = 0; i < petit_N; i++) {
    //     printf("process: %d, tab[%d].k=%llu, tab[%d].v=%llu\n", world_rank, i, tab[i].k,i,tab[i].v);
    // }


    qsort(tab,petit_N,sizeof(clefvaleur),compar);
    //    for (int i = 0; i < petit_N; i++) {
    //     printf("process: %d, tab[%d].k=%llu, tab[%d].v=%llu\n", world_rank, i, tab[i].k%world_size,i,tab[i].v);
    // }
    

    for (int i=0;i<world_size;i++){
        tailles[i]=0;
        taille_recue[i]=0;
    }
    
    compteur = 1;
    for (int i = 1; i < petit_N; i++) {
        if (proc(tab[i - 1]) != proc(tab[i])) {
            tailles[proc(tab[i - 1])] = compteur;
            compteur = 0;
        }
        compteur++;
    }
    tailles[proc(tab[petit_N - 1])] = compteur;


    MPI_Alltoall(tailles, 1, MPI_INT , taille_recue, 1, MPI_INT, MPI_COMM_WORLD);
    sum = 0;
    sum_recu = 0;

    for (int i = 0; i < world_size; i++) {
        displs[i] = sum;
        displs_recue[i] = sum_recu;
        sum += tailles[i];
        sum_recu += taille_recue[i];
    }

    MPI_Alltoallv(tab, tailles, displs, MPI_CLEFVALEUR_TYPE, tab_recu, taille_recue, displs_recue, MPI_CLEFVALEUR_TYPE, MPI_COMM_WORLD);
    // printf("wr=%d,sum_recu=%d\n",world_rank,sum_recu);
    //   for (int i = 0; i < sum_recu; i++) {
    //     printf("wr=%d, %d cle:%llu  val:%llu\n",world_rank,i,tab_recu[i].k, tab_recu[i].v);
    //   }

     printf("%d TESTTESTTESTTESTTEST\n",world_rank);
      for (int i = 0; i < sum_recu; i++) {
        u64 y = tab_recu[i].k;
        int nx = dict_probe(y, 256, x);
        assert(nx >= 0);
        ncandidates += nx;
        for (int i = 0; i < nx; i++)
            if (is_good_pair(x[i], tab_recu[i].v)) {
            	if (nres == maxres)
            		return -1;
            	k1[nres] = x[i];
            	k2[nres] = tab_recu[i].v;
            	printf("SOLUTION FOUND!\n");
            	nres += 1;
            }

    }
    free(tab);






    // if (world_rank==root){
    //     clefvaleur ** tabSend = (clefvaleur**) malloc(sizeof(clefvaleur*) * world_size);
    //     for (int i=0;i<world_size;i++){
    //         //\\ATTENTION//\\ATTENTION//\\ATTENTION la valeur 5000 est arbitrairement fixée mais elle pourrait être trop faible
    //         //Changer 5000 avec int(1.25*(size / world_size)) + 1;
    //         //Tester avec 0.80*triger_work 
    //         tabSend[i]=(clefvaleur*) malloc(sizeof(clefvaleur) * triger_work);
    //         tabSend[i][0].k=1;
    //     }

    //     for (u64 z = 0; z < triger_work; z++) {
    //     u64 y = g(z);
    //     int process_assoc=(int)(y%world_size);
    //     tabSend[process_assoc][tabSend[process_assoc][0].k].k=y;
    //     tabSend[process_assoc][tabSend[process_assoc][0].k].v=z;
    //     tabSend[process_assoc][0].k+=1;
    //     }
    //     // for (int i=0;i<world_size;i++){
    //     //     for (int j=0;j<30;j++){
    //     //         printf("tab[%d][%d]=%llu\n",i,j,tabSend[i][j].k);
    //     //     }
            
    //     // }

    //     for (int i=0;i<world_size;i++){
    //         if (i!=root){
    //             MPI_Send(&tabSend[i][0].k,1,MPI_UINT64_T,i,41,MPI_COMM_WORLD);
    //             MPI_Send(tabSend[i],tabSend[i][0].k,MPI_CLEFVALEUR_TYPE,i,42,MPI_COMM_WORLD);
    //             tabSend[i][0].k=0;
    //         }else{

    //         }

    //     }
    //     for (int k=1;k<tabSend[root][0].k;k++){
    //         // printf("proc %d tab2[%d]=%llu\n",world_rank,k,tabSend[root][k].k);
    //         u64 y = tabSend[root][k].k;
    //         u64 z=tabSend[root][k].v;
    //         int nx = dict_probe(y, 256, x);
    //         assert(nx >= 0);
    //         ncandidates += nx;
    //         for (int i = 0; i < nx; i++)
    //             if (is_good_pair(x[i], z)) {
    //                 if (nres == maxres)
    //                     return -1;
    //                 k1[nres] = x[i];
    //                 k2[nres] = z;
    //                 printf("SOLUTION FOUND!\n");
    //                 nres += 1;
    //             }
            

    //     }
    

    // }else{
    //     // printf("proc num %d\n",world_rank);
    //     MPI_Status status;
    //     u64 tab2_size;
    //     MPI_Recv(&tab2_size,1,MPI_UINT64_T,root,MPI_ANY_TAG,MPI_COMM_WORLD,&status);
    //     clefvaleur* tab_recu2=( clefvaleur* )(malloc(sizeof(clefvaleur)*tab2_size));
    //     MPI_Recv(tab_recu2,tab2_size,MPI_CLEFVALEUR_TYPE,root,MPI_ANY_TAG,MPI_COMM_WORLD,&status);
    //     // printf("TESTTESTTESTTESTTEST\n");
        
    //     for (int k=1;k<tab2_size;k++){
    //         // printf("proc %d tab2[%d]=%llu\n",world_rank,k,tab_recu2[k].k);
    //         u64 y = tab_recu2[k].k;
    //         u64 z=tab_recu2[k].v;
    //         int nx = dict_probe(y, 256, x);
    //         assert(nx >= 0);
    //         ncandidates += nx;
    //         for (int i = 0; i < nx; i++)
    //             if (is_good_pair(x[i], z)) {
    //                 if (nres == maxres)
    //                     return -1;
    //                 k1[nres] = x[i];
    //                 k2[nres] = z;
    //                 printf("SOLUTION FOUND!\n");
    //                 nres += 1;
    //             }
            


    //     }
        // while(1){}
    //}
    // printf("wr=%d, TESTSTETSTSTSTE\n",world_rank);
    // while(1){}

    // for (u64 z = 0; z < N; z++) {
    //     u64 y = g(z);
    //     int nx = dict_probe(y, 256, x);
    //     assert(nx >= 0);
    //     ncandidates += nx;
    //     for (int i = 0; i < nx; i++)
    //         if (is_good_pair(x[i], z)) {
    //         	if (nres == maxres)
    //         		return -1;
    //         	k1[nres] = x[i];
    //         	k2[nres] = z;
    //         	printf("SOLUTION FOUND!\n");
    //         	nres += 1;
    //         }
    // }
    printf("Probe: %.1fs. %" PRId64 " candidate pairs tested\n", wtime() - mid, ncandidates);
    return nres;
}

/************************** command-line options ****************************/

void usage(char **argv)
{
        printf("%s [OPTIONS]\n\n", argv[0]);
        printf("Options:\n");
        printf("--n N                       block size [default 24]\n");
        printf("--C0 N                      1st ciphertext (in hex)\n");
        printf("--C1 N                      2nd ciphertext (in hex)\n");
        printf("\n");
        printf("All arguments are required\n");
        exit(0);
}

void process_command_line_options(int argc, char ** argv)
{
        struct option longopts[4] = {
                {"n", required_argument, NULL, 'n'},
                {"C0", required_argument, NULL, '0'},
                {"C1", required_argument, NULL, '1'},
                {NULL, 0, NULL, 0}
        };
        char ch;
        int set = 0;
        while ((ch = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
                switch (ch) {
                case 'n':
                        n = atoi(optarg);
                        mask = (1ull << n) - 1;
                        break;
                case '0':
                        set |= 1;
                        u64 c0 = strtoull(optarg, NULL, 16);
                        C[0][0] = c0 & 0xffffffff;
                        C[0][1] = c0 >> 32;
                        break;
                case '1':
                        set |= 2;
                        u64 c1 = strtoull(optarg, NULL, 16);
                        C[1][0] = c1 & 0xffffffff;
                        C[1][1] = c1 >> 32;
                        break;
                default:
                        errx(1, "Unknown option\n");
                }
        }
        if (n == 0 || set != 3) {
        	usage(argv);
        	exit(1);
        }
}

/******************************************************************************/

int main(int argc, char **argv)
{
    root=0;
    MPI_Init(&argc, &argv);

    MPI_Comm_size(MPI_COMM_WORLD, &world_size);
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);

    // voir si il est pas judicieux de mettre le MPI_init après pour éviter que chacun des coeurs fasse le calcul
    //ATTENTION si on demande qu'au process root de faire la ligne suivante, ça bug car les autres process n'auront pas accès à f et g
	process_command_line_options(argc, argv);

    if (world_rank == root) {
        printf("Running with n=%d, C0=(%08x, %08x) and C1=(%08x, %08x)\n", 
            (int) n, C[0][0], C[0][1], C[1][0], C[1][1]);
    }

    // printf("n: %lu; n_process:%lu\n", n, n_process);
	// dict_setup(1.125 * (1ull << n));

	/* search */
	u64 k1[16], k2[16];
	int nkey = golden_claw_search(16, k1, k2);
	assert(nkey > 0);

	/* validation */
	for (int i = 0; i < nkey; i++) {
    	assert(f(k1[i]) == g(k2[i]));
    	assert(is_good_pair(k1[i], k2[i]));		
	    printf("Solution found: (%" PRIx64 ", %" PRIx64 ") [checked OK]\n", k1[i], k2[i]);
	}
    MPI_Finalize();
}
