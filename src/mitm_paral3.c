#include "mpi.h"
#include <assert.h>
#include <err.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "utils.h"

/***************************** global variables ******************************/

u64 n = 0; /* block size (in bits) */
u64 mask;  /* this is 2**n - 1 */

u64 dict_size;   /* number of slots in the hash table */
struct entry *A; /* the hash table */

/* (P, C) : two plaintext-ciphertext pairs */
u32 P[2][2] = {{0, 0}, {0xffffffff, 0xffffffff}};
u32 C[2][2];

int world_size;
int world_rank;
int root;

char *output_file_path = "output.csv";
FILE *output_file;
FILE *results_file;

/************************ tools and utility functions *************************/

double wtime() {
    struct timeval ts;
    gettimeofday(&ts, NULL);
    return (double)ts.tv_sec + ts.tv_usec / 1E6;
}

// murmur64 hash functions, tailorized for 64-bit ints / Cf. Daniel Lemire
u64 murmur64(u64 x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdull;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ull;
    x ^= x >> 33;
    return x;
}

/* represent n in 4 bytes */
void human_format(u64 n, char *target) {
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

#define ROTL32(x, r) (((x) << (r)) | (x >> (32 - (r))))
#define ROTR32(x, r) (((x) >> (r)) | ((x) << (32 - (r))))

#define ER32(x, y, k)                                                          \
    (x = ROTR32(x, 8), x += y, x ^= k, y = ROTL32(y, 3), y ^= x)
#define DR32(x, y, k)                                                          \
    (y ^= x, y = ROTR32(y, 3), x ^= k, x -= y, x = ROTL32(x, 8))

void Speck64128KeySchedule(const u32 K[], u32 rk[]) {
    u32 i, D = K[3], C = K[2], B = K[1], A = K[0];
    for (i = 0; i < 27;) {
        rk[i] = A;
        ER32(B, A, i++);
        rk[i] = A;
        ER32(C, A, i++);
        rk[i] = A;
        ER32(D, A, i++);
    }
}

void Speck64128Encrypt(const u32 Pt[], u32 Ct[], const u32 rk[]) {
    u32 i;
    Ct[0] = Pt[0];
    Ct[1] = Pt[1];
    for (i = 0; i < 27;)
        ER32(Ct[1], Ct[0], rk[i++]);
}

void Speck64128Decrypt(u32 Pt[], const u32 Ct[], u32 const rk[]) {
    int i;
    Pt[0] = Ct[0];
    Pt[1] = Ct[1];
    for (i = 26; i >= 0;)
        DR32(Pt[1], Pt[0], rk[i--]);
}

/******************************** dictionary ********************************/

/*
 * "classic" hash table for 64-bit key-value pairs, with linear probing.
 * It operates under the assumption that the keys are somewhat random 64-bit
 * integers. The keys are only stored modulo 2**32 - 5 (a prime number), and
 * this can lead to some false positives.
 */
static const u32 EMPTY = 0xffffffff;
static const u64 PRIME = 0xfffffffb;

/* allocate a hash table with `size` slots (12*size bytes) */
void dict_setup(u64 size) {
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
void dict_insert(u64 key, u64 value) {
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
int dict_probe(u64 key, int maxval, u64 values[]) {
    // printf("bonjour\n");
    // dict_size=size;
    // printf("proc%d dict_size=%llu\n",world_rank,dict_size);
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
u64 f(u64 k) {
    assert((k & mask) == k);
    u32 K[4] = {k & 0xffffffff, k >> 32, 0, 0};
    u32 rk[27];
    Speck64128KeySchedule(K, rk);
    u32 Ct[2];
    Speck64128Encrypt(P[0], Ct, rk);
    return ((u64)Ct[0] ^ ((u64)Ct[1] << 32)) & mask;
}

/* g : {0, 1}^n --> {0, 1}^n.  speck64-128 decryption of C[0], using k */
u64 g(u64 k) {
    assert((k & mask) == k);
    u32 K[4] = {k & 0xffffffff, k >> 32, 0, 0};
    u32 rk[27];
    Speck64128KeySchedule(K, rk);
    u32 Pt[2];
    Speck64128Decrypt(Pt, C[0], rk);
    return ((u64)Pt[0] ^ ((u64)Pt[1] << 32)) & mask;
}

bool is_good_pair(u64 k1, u64 k2) {
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
int compar(const void *p1, const void *p2) {
    clefvaleur *clefvaleurp1 = (clefvaleur *)(p1);
    clefvaleur *clefvaleurp2 = (clefvaleur *)(p2);
    return (((clefvaleurp1->k) % world_size) -
            ((clefvaleurp2->k) % world_size));
}

int proc(clefvaleur c) { return c.k % world_size; }

/* search the "golden collision" */
int golden_claw_search(int maxres, u64 k1[], u64 k2[]) {
    // Creation d'un datatype pour le struct clefvaleur
    const int nitems = 2;
    int blocklenght[2] = {1, 1};
    MPI_Datatype types[2] = {MPI_UINT64_T, MPI_UINT64_T};
    MPI_Datatype MPI_CLEFVALEUR_TYPE;
    MPI_Aint offsets[2];
    offsets[0] = offsetof(clefvaleur, k);
    offsets[1] = offsetof(clefvaleur, v);
    MPI_Type_create_struct(nitems, blocklenght, offsets, types,
                           &MPI_CLEFVALEUR_TYPE);
    MPI_Type_commit(&MPI_CLEFVALEUR_TYPE);

    double time_start = wtime();

    u64 N = 1ull << n;

    u64 petit_N = N / world_size;
    u64 reste = N % world_size;

    if (world_rank < reste)
        petit_N++;

    int begin = world_rank * petit_N;
    int end = (world_rank + 1) * petit_N;
    if (world_rank >= reste) {
        begin += reste;
        end += reste;
    }
    // Alloue un tableau à trier
    clefvaleur *tab = (clefvaleur *)malloc(sizeof(clefvaleur) * petit_N);
    int indice = 0;

    // Calcul première boucle
    for (u64 x = begin; x < end; x++) {
        u64 z = f(x);
        tab[indice].k = z;
        tab[indice].v = x;
        indice++;
    }
    double time_before_qsort1 = wtime();

    qsort(tab, petit_N, sizeof(clefvaleur), compar);

    double time_after_qsort1 = wtime();

    // Création du tableau de tailles à envoyer
    int tailles[world_size];
    int taille_recue[world_size];
    for (int i = 0; i < world_size; i++) {
        tailles[i] = 0;
        taille_recue[i] = 0;
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

    // Taille recue depuis chaque processus
    MPI_Alltoall(tailles, 1, MPI_INT, taille_recue, 1, MPI_INT, MPI_COMM_WORLD);

    // Calcul de la taille totale du tableau avec les tailles recues et du
    // displs
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

    // Envoi des struct clefvaleur, avec toutes les clefs valeurs au bon endroit
    // clefvaleur tab_recu[sum_recu];
    clefvaleur *tab_recu = (clefvaleur *)malloc(sizeof(clefvaleur) * sum_recu);
    MPI_Alltoallv(tab, tailles, displs, MPI_CLEFVALEUR_TYPE, tab_recu,
                  taille_recue, displs_recue, MPI_CLEFVALEUR_TYPE,
                  MPI_COMM_WORLD);
    free(tab);

    // Insertion de toutes les valeurs dans le dictionnaire au bon endroit
    dict_setup(sum_recu + 1);

    // sum remplacée par sum_recu ça fait une boucle infinie
    for (int i = 0; i < sum_recu; i++) {
        dict_insert(tab_recu[i].k, tab_recu[i].v);
    }
    // free(tab);
    free(tab_recu);

    // parellisation de la deuxième boucle
    double time_mid = wtime();

    // Chaque processus calcule les valeurs de z pour les x qui lui sont
    // attribués Chaque processus envoie ensuite la valeur au processus qui a le
    // bon dictionnaire pour tester si il y a une collision
    // Utilisation de MPI_Send, MPI_Irecv, MPI_Test pour savoir si on a reçu

    // Fonctionnement du programme:
    // Chaque processus calcule les valeurs de z pour les x qui lui sont
    // Boucle sur les z
    // Envoi des z au processus qui a le bon dictionnaires
    // Test des collisions

    int nres = 0;
    u64 ncandidates = 0;
    u64 x[256];

    // Block size
    int size_block = 256;
    int nblock = petit_N / size_block;
    int reste_block = petit_N % size_block;

    // Buffers for sending and receiving
    clefvaleur *send_buffer =
        (clefvaleur *)malloc(sizeof(clefvaleur) * size_block);
    clefvaleur *receive_buffer = NULL;

    // Arrays for sizes and displacements
    int taille_send[world_size];
    int taille_recu[world_size];
    int displs_send[world_size];
    int displs_recu[world_size];

    // Initialize sizes and displacements
    for (int i = 0; i < world_size; i++) {
        taille_send[i] = 0;
        taille_recu[i] = 0;
        displs_send[i] = 0;
        displs_recu[i] = 0;
    }

    // Arrays for MPI requests
    MPI_Request *send_requests =
        (MPI_Request *)malloc(world_size * sizeof(MPI_Request));
    MPI_Request *recv_requests =
        (MPI_Request *)malloc(world_size * sizeof(MPI_Request));

    // Initialize requests
    for (int i = 0; i < world_size; i++) {
        send_requests[i] = MPI_REQUEST_NULL;
        recv_requests[i] = MPI_REQUEST_NULL;
    }

    // Process each block
    for (int i = 0; i < nblock; i++) {
        // Fill send buffer with y = g(z) and z values
        for (int j = 0; j < size_block; j++) {
            u64 z = i * size_block + j;
            u64 y = g(z);
            send_buffer[j].k = y;
            send_buffer[j].v = z;
            taille_send[y % world_size]++;
        }

        // Sort send buffer by target process
        qsort(send_buffer, size_block, sizeof(clefvaleur), compar);

        // Exchange sizes with all processes
        MPI_Alltoall(taille_send, 1, MPI_INT, taille_recu, 1, MPI_INT,
                     MPI_COMM_WORLD);

        // Calculate displacements for sending and receiving
        for (int j = 1; j < world_size; j++) {
            displs_send[j] = displs_send[j - 1] + taille_send[j - 1];
            displs_recu[j] = displs_recu[j - 1] + taille_recu[j - 1];
        }

        // Allocate receive buffer based on the total number of elements to
        // receive
        int total_recv =
            displs_recu[world_size - 1] + taille_recu[world_size - 1];
        receive_buffer = (clefvaleur *)realloc(receive_buffer,
                                               sizeof(clefvaleur) * total_recv);

        // Post non-blocking receives
        for (int j = 0; j < world_size; j++) {
            if (taille_recu[j] > 0) {
                MPI_Irecv(&receive_buffer[displs_recu[j]], taille_recu[j],
                          MPI_CLEFVALEUR_TYPE, j, 0, MPI_COMM_WORLD,
                          &recv_requests[j]);
            }
        }

        // Post non-blocking sends
        for (int j = 0; j < world_size; j++) {
            if (taille_send[j] > 0) {
                MPI_Isend(&send_buffer[displs_send[j]], taille_send[j],
                          MPI_CLEFVALEUR_TYPE, j, 0, MPI_COMM_WORLD,
                          &send_requests[j]);
            }
        }

        // Probe dictionary and check for collisions while waiting for
        // communication
        int completed_recv = 0;
        int index = 0;
        while (index < world_size) {
            int flag;
            MPI_Testany(world_size, recv_requests, &completed_recv, &flag,
                        MPI_STATUS_IGNORE);
            if (flag) {
                index++;
                // Process received data
                for (int j = 0; j < taille_recu[completed_recv]; j++) {
                    u64 y = receive_buffer[displs_recu[completed_recv] + j].k;
                    u64 z = receive_buffer[displs_recu[completed_recv] + j].v;
                    int nx = dict_probe(y, 256, x);
                    assert(nx >= 0);
                    ncandidates += nx;
                    for (int k = 0; k < nx; k++) {
                        if (is_good_pair(x[k], z)) {
                            if (nres == maxres) {
                                free(send_buffer);
                                free(receive_buffer);
                                free(send_requests);
                                free(recv_requests);
                                return -1;
                            }
                            k1[nres] = x[k];
                            k2[nres] = z;
                            printf("SOLUTION FOUND!\n");
                            nres++;
                        }
                    }
                }
            }
        }

        // Wait for all sends to complete
        MPI_Waitall(world_size, send_requests, MPI_STATUSES_IGNORE);

        // Reset sizes for the next block
        for (int j = 0; j < world_size; j++) {
            taille_send[j] = 0;
            taille_recu[j] = 0;
        }
    }

    // Process the remaining block (if any)
    if (reste_block > 0) {
        // Fill send buffer with y = g(z) and z values
        for (int j = 0; j < reste_block; j++) {
            u64 z = nblock * size_block + j;
            u64 y = g(z);
            send_buffer[j].k = y;
            send_buffer[j].v = z;
            taille_send[y % world_size]++;
        }

        // Sort send buffer by target process
        qsort(send_buffer, reste_block, sizeof(clefvaleur), compar);

        // Exchange sizes with all processes
        MPI_Alltoall(taille_send, 1, MPI_INT, taille_recu, 1, MPI_INT,
                     MPI_COMM_WORLD);

        // Calculate displacements for sending and receiving
        for (int j = 1; j < world_size; j++) {
            displs_send[j] = displs_send[j - 1] + taille_send[j - 1];
            displs_recu[j] = displs_recu[j - 1] + taille_recu[j - 1];
        }

        // Allocate receive buffer based on the total number of elements to
        // receive
        int total_recv =
            displs_recu[world_size - 1] + taille_recu[world_size - 1];
        receive_buffer = (clefvaleur *)realloc(receive_buffer,
                                               sizeof(clefvaleur) * total_recv);

        // Post non-blocking receives
        for (int j = 0; j < world_size; j++) {
            if (taille_recu[j] > 0) {
                MPI_Irecv(&receive_buffer[displs_recu[j]], taille_recu[j],
                          MPI_CLEFVALEUR_TYPE, j, 0, MPI_COMM_WORLD,
                          &recv_requests[j]);
            }
        }

        // Post non-blocking sends
        for (int j = 0; j < world_size; j++) {
            if (taille_send[j] > 0) {
                MPI_Isend(&send_buffer[displs_send[j]], taille_send[j],
                          MPI_CLEFVALEUR_TYPE, j, 0, MPI_COMM_WORLD,
                          &send_requests[j]);
            }
        }

        // Probe dictionary and check for collisions while waiting for
        // communication
        int completed_recv = 0;
        while (completed_recv < world_size) {
            int flag;
            MPI_Testany(world_size, recv_requests, &completed_recv, &flag,
                        MPI_STATUS_IGNORE);
            if (flag) {
                // Process received data
                for (int j = 0; j < taille_recu[completed_recv]; j++) {
                    u64 y = receive_buffer[displs_recu[completed_recv] + j].k;
                    u64 z = receive_buffer[displs_recu[completed_recv] + j].v;
                    int nx = dict_probe(y, 256, x);
                    assert(nx >= 0);
                    ncandidates += nx;
                    for (int k = 0; k < nx; k++) {
                        if (is_good_pair(x[k], z)) {
                            if (nres == maxres) {
                                free(send_buffer);
                                free(receive_buffer);
                                free(send_requests);
                                free(recv_requests);
                                return -1;
                            }
                            k1[nres] = x[k];
                            k2[nres] = z;
                            nres++;
                        }
                    }
                }
            }
        }

        // Wait for all sends to complete
        MPI_Waitall(world_size, send_requests, MPI_STATUSES_IGNORE);
    }

    double time_end = wtime();

    if (world_rank == root) {
        char hdsize[8];
        human_format(dict_size * sizeof(*A), hdsize);
        fprintf(results_file, "%d, %lu, %s, %.4f, %.4f, %.4f, %.4f, %.4f\n",
                world_size, n, hdsize, time_before_qsort1 - time_start,
                time_after_qsort1 - time_before_qsort1,
                time_mid - time_after_qsort1, time_end - time_mid,
                time_end - time_start);
    }

    // Free buffers
    free(send_buffer);
    free(receive_buffer);
    free(send_requests);
    free(recv_requests);

    return nres;
}

/************************** command-line options ****************************/

void usage(char **argv) {
    printf("%s [OPTIONS]\n\n", argv[0]);
    printf("Options:\n");
    printf("--n N                       block size [default 24]\n");
    printf("--C0 N                      1st ciphertext (in hex)\n");
    printf("--C1 N                      2nd ciphertext (in hex)\n");
    printf("\n");
    printf("All arguments are required\n");
    exit(0);
}

void process_command_line_options(int argc, char **argv) {
    struct option longopts[5] = {{"n", required_argument, NULL, 'n'},
                                 {"C0", required_argument, NULL, '0'},
                                 {"C1", required_argument, NULL, '1'},
                                 {"o", required_argument, NULL, 'o'},
                                 {NULL, 0, NULL, 0}};

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
        case 'o':
            output_file_path = optarg;
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

int main(int argc, char **argv) {
    root = 0;
    MPI_Init(&argc, &argv);

    MPI_Comm_size(MPI_COMM_WORLD, &world_size);
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);

    // voir si il est pas judicieux de mettre le MPI_init après pour éviter que
    // chacun des coeurs fasse le calcul
    // ATTENTION si on demande qu'au process root de faire la ligne suivante, ça
    // bug car les autres process n'auront pas accès à f et g
    process_command_line_options(argc, argv);
    if (world_rank == root) {
        output_file = fopen(output_file_path, "a");
        if (output_file == NULL) {
            printf("Error opening file!\n");
            exit(1);
        }
    }

    // Creation d'un datatype pour le struct clefvaleur
    const int nitems = 2;
    int blocklenght[2] = {1, 1};
    MPI_Datatype types[2] = {MPI_UINT64_T, MPI_UINT64_T};
    MPI_Datatype MPI_CLEFVALEUR_TYPE;
    MPI_Aint offsets[2];
    offsets[0] = offsetof(clefvaleur, k);
    offsets[1] = offsetof(clefvaleur, v);
    MPI_Type_create_struct(nitems, blocklenght, offsets, types,
                           &MPI_CLEFVALEUR_TYPE);
    MPI_Type_commit(&MPI_CLEFVALEUR_TYPE);

    if (world_rank == root) {
        printf("Running with n=%d, C0=(%08x, %08x) and C1=(%08x, %08x)\n",
               (int)n, C[0][0], C[0][1], C[1][0], C[1][1]);

        results_file = fopen("results_file.txt", "a");
        if (results_file == NULL) {
            printf("Error opening file!\n");
            exit(1);
        }
        time_t t = time(NULL);
        struct tm tm = *localtime(&t);
        fprintf(results_file, "\n%d-%02d-%02d %02d:%02d:%02d\n",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
                tm.tm_min, tm.tm_sec);

        fprintf(results_file,
                "Running with n=%d, C0=(%08x, %08x) and C1=(%08x, %08x)\n",
                (int)n, C[0][0], C[0][1], C[1][0], C[1][1]);
        fprintf(results_file, "Results:\n");
    }

    // printf("n: %lu; n_process:%lu\n", n, n_process);
    // dict_setup(1.125 * (1ull << n));

    /* search */
    u64 k1[16], k2[16];
    int nkey = golden_claw_search(16, k1, k2);
    // printf("process: %d, nkey: %d\n", world_rank, nkey);

    // Récupération de toutes les collisions trouvées dans le processus root
    int nkey_recu[world_size];
    MPI_Gather(&nkey, 1, MPI_INT, nkey_recu, 1, MPI_INT, root, MPI_COMM_WORLD);

    int nkeys_total = 0;
    int displs[world_size];
    for (int i = 0; i < world_size; i++) {
        displs[i] = nkeys_total;
        nkeys_total += nkey_recu[i];
    }

    u64 *k1_total;
    u64 *k2_total;
    if (world_rank == root) {
        k1_total = (u64 *)malloc(nkeys_total * sizeof(u64));
        k2_total = (u64 *)malloc(nkeys_total * sizeof(u64));
    }

    MPI_Gatherv(k1, nkey, MPI_UINT64_T, k1_total, nkey_recu, displs,
                MPI_UINT64_T, root, MPI_COMM_WORLD);
    MPI_Gatherv(k2, nkey, MPI_UINT64_T, k2_total, nkey_recu, displs,
                MPI_UINT64_T, root, MPI_COMM_WORLD);

    if (world_rank == root) {
        assert(nkeys_total > 0);

        /* validation */
        for (int i = 0; i < nkeys_total; i++) {
            assert(f(k1_total[i]) == g(k2_total[i]));
            assert(is_good_pair(k1_total[i], k2_total[i]));
            printf("Solution found: (%" PRIx64 ", %" PRIx64 ") [checked OK]\n",
                   k1_total[i], k2_total[i]);
            fprintf(results_file,
                    "Solution found: (%" PRIx64 ", %" PRIx64 ")\n", k1_total[i],
                    k2_total[i]);
        }

        free(k1_total);
        free(k2_total);
    }
    MPI_Finalize();
}
