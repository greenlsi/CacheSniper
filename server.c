#include "Table.h"
#include <stdio.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>

#define OPTSTR "t:o:d:a:s:h"
#define USAGE_FMT "[-d detectionaddress][-a targetaddress] [-t wait time] [-o outputfile] [-s ip address][-h]"

#define THRESHOLD 20000 / 2
#define PACKET_SIZE 24
#define FILE_NAME_SIZE 80
#define PREFETCHED_LINES 8

#define lfence() __asm__ volatile("lfence;");

FILE *fd;

struct sockaddr_in server;
struct sockaddr_in client;
socklen_t clientlen;
int s, r;
int target_pos;
int detection_pos;
int wait_time;
int counter_app;
long int *target_address;
long int *detection_address;
char *quixote;
char file_name[FILE_NAME_SIZE];
char in[2 * PACKET_SIZE];
char out[PACKET_SIZE];

void usage(char *progname, int opt)
{
  fprintf(stderr, USAGE_FMT);
  exit(EXIT_FAILURE);
}

/*Get the value of rdtsc*/
unsigned long int timestamp(void)
{
  unsigned long int result;
  unsigned int bottom;
  unsigned int top;
  asm volatile("rdtsc"
               : "=a"(bottom), "=d"(top));
  result = top;
  result = (result << 32) & 0xFFFFFFFF00000000UL;
  return (result | bottom);
}

/*Get the value of a memory location*/
long int mem_access(long int *v)
{
  long int rv = 0;
  asm volatile(
      "movq (%1), %0"
      : "+r"(rv)
      : "r"(v)
      :);
  return rv;
}

/*Measure read time*/
int access_timed(long int *pos_data)
{
  volatile unsigned int time;
  asm __volatile__(
      //" mfence \n"
      //" lfence \n"
      " rdtsc \n"
      " lfence \n"
      " movl %%eax, %%esi \n"
      " movl (%1), %%eax \n"
      " lfence \n"
      " rdtsc \n"
      " subl %%esi, %%eax \n"
      : "=a"(time)
      : "c"(pos_data)
      : "%esi", "%edx");
  return time;
}

//Target function
void handle(char out[PACKET_SIZE], char in[PACKET_SIZE * 2])
{
  unsigned long int t1 = timestamp();
  unsigned long int t2, t3;
  mem_access(detection_address);
  int i;
  int res = 0;
  lfence();
  int cont = 0;
  /*while (cont < wait_time)
  {
    asm __volatile__(
      "xor %%rbx, %%rbx \n"
      : 
      : 
      :);
    cont++;
  }*/
  /*while (cont < wait_time)
  {
    cont++;
  }*/
  t3 = timestamp() + wait_time;
  while (timestamp() < t3)
  {
  }
  lfence();
  //Prefetch
  for (i = 0; i < PREFETCHED_LINES; ++i)
  {
    mem_access(target_address + (16 * i));
  }
  //Access
  t2 = timestamp();
  int op = rand() % PREFETCHED_LINES;
  //t2 = timestamp();
  res = access_timed(target_address + (16 * op));
  t3 = timestamp();
  lfence();
  fprintf(fd, "%lu %lu %lu %lu %i %i\n", t1, t2, t3, t2 - t1, op, res);
  fflush(fd);
  for (i = 0; i < PACKET_SIZE - sizeof(uint64_t); ++i)
    out[i] = in[i]; //Authenticate on the attacker side
  uint64_t value = (uint64_t) * ((unsigned long int *)(in + PACKET_SIZE - sizeof(uint64_t)));
  *(unsigned long int *)(out + PACKET_SIZE - sizeof(uint64_t)) = (uint64_t)timestamp();
}

int main(int argc, char **argv)
{
  int opt;
  while ((opt = getopt(argc, argv, OPTSTR)) != EOF)
    switch (opt)
    {
    case 's':
      if (!inet_aton(optarg, &server.sin_addr))
      {
        printf("Wrong IP \n");
        return -1;
      }
      server.sin_family = AF_INET;
      server.sin_port = htons(10000);
      s = socket(AF_INET, SOCK_DGRAM, 0);

      if (s == -1)
        return 2;

      if (bind(s, (struct sockaddr *)&server, sizeof server) == -1)
        return 3;
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
      wait_time = atoi(optarg);
      break;
    case 'o':
      fd = fopen(optarg, "w");
      if (fd == NULL)
        fprintf(stderr, "Unable to open file\n");
      break;
    case 'h':
    default:
      usage(basename(argv[0]), opt);
      break;
    }

  while (1)
  {
    clientlen = sizeof client;
    r = recvfrom(s, in, sizeof in, 0, (struct sockaddr *)&client, &clientlen);
    //printf("Received \n");
    if (r < PACKET_SIZE)
      continue;
    handle(out, in);
    sendto(s, out, PACKET_SIZE, 0, (struct sockaddr *)&client, clientlen);
  }

  fclose(fd);
  return 0;
}
