#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <time.h>

#define KEY_SIZE 16
#define PACKET_SIZE 24
#define NUM_SAMPLES 20000
#define THRESHOLD 20000

FILE *fp;

long int *posicion_lectura;
char packet[2048];
int s;
int size = KEY_SIZE;
char response[PACKET_SIZE];
struct timespec tim = {0, 500000L};

unsigned long int timestamp(void)
{
  unsigned long int result;
  unsigned int bottom;
  unsigned int top;
  asm volatile(".byte 15;.byte 49"
               : "=a"(bottom), "=d"(top));
  result = top;
  result = (result << 32) & 0xFFFFFFFF00000000UL;
  return (result | bottom);
}

void studyinput(void)
{
  int j;
  struct pollfd p;
  unsigned long int inter = 0;

  for (j = 0; j < size; ++j)
    packet[j] = random();
  uint64_t ale = (uint64_t)(rand() % THRESHOLD);
  *(unsigned long int *)(packet + PACKET_SIZE - sizeof(uint64_t)) = ale;
  send(s, packet, PACKET_SIZE, 0);
}

int main(int argc, char **argv)
{
  char data_in[20];
  char data_out[PACKET_SIZE];
  int num_samples = NUM_SAMPLES;

  fp = fopen("data_received.txt", "w+");

  struct sockaddr_in server;
  long long inputs = 0;
  if (!argv[1])
    return 100;
  if (!inet_aton(argv[1], &server.sin_addr))
    return 100;
  server.sin_family = AF_INET;
  server.sin_port = htons(10000);

  if (argv[2])
    num_samples = atoi(argv[2]);

  while ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    sleep(1);
  while (connect(s, (struct sockaddr *)&server, sizeof server) == -1)
    sleep(1);

  int kkk;
  for (kkk = 0; kkk < num_samples; ++kkk)
  {
    tim.tv_nsec = 500000 + (rand() % 50000);
    nanosleep(&tim, NULL);
    studyinput();
  }
  fclose(fp);
}
