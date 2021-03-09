# CacheSniper

This is a proof of concept of the work done for "Aim, Wait, Shoot: How the CacheSniper Technique Improves Unprivileged Cache Attacks" 

This code was designed for Intel processors with TSX enabled and Linux Systems. In case your processor has TSX disabled, enable it under your own risk.

`Warning: this is a proof-of-concept, only useful for trying out the techniques described in CacheSniper and easing its utilization for research. Use it under your own risk.`

## Requirements

It requires Hugepages and assumes they are mounted on `/mnt/hugetlbfs/`. This value can be modified by changing the value of FILE_NAME.
The mount point must be created previously:

`$ sudo mkdir /mnt/hugetlbfs`.

Once reserved, hugepages can be mounted:

`$ sudo mount -t hugetlbfs none /mnt/hugetlbfs`

Note that this may require to use `sudo` for the examples or to change the permissions of the `/mnt/hugetlbfs/` folder.

To enable a fixed amount of huge pages, after a reboot the number of huge pages must be set:

`$ echo 100 > /proc/sys/vm/nr_hugepages`

To check that 100 huge pages are indeed available:

`$ cat /proc/meminfo | grep HugePages`

Check if your cpu supports TSX

`cat /proc/cpuinfo | grep rtm`

It is possible to check if the processor has any mitication enabled against TAA by running:

`/sys/devices/system/cpu/vulnerabilities/tsx_async_abort`

## Compiling and running

In order to use all the features of this code, it may be necessary to install make and gcc. 
For example in a machine with Ubuntu it is possible to install them:

`$ apt-get install make gcc python3-pip` (May require sudo)

## Configuration

#### Architecture details

In order for the example to work properly, these values must be manually changed in the `cache_details.h` file:

```
/*Cache and memory architecture details*/
#define CACHE_SIZE 6 //MB
#define CPU_CORES 4
#define CACHE_SET_SIZE 12 //Ways
#define CACHE_SLICES 8
#define SETS_PER_SLICE 1024
#define BITS_SET 10 //log2(SETS_PER_SLICE)
#define BITS_LINE 6 //64 bytes per cache line 

#define BITS_HUGEPAGE 21
#define BITS_NORMALPAGE 12
```

In order to know the concrete values of a server:

`$ cat /proc/cpuinfo`

The values for the different constants are stored in the following variables:

```
CACHE_SIZE -> $ cat /proc/cpuinfo | grep "cache size" | head -n 1
CPU_CORES  -> $ cat /proc/cpuinfo | grep "cpu cores" | head -n 1
CACHE_SET_SIZE -> $ cpuid | grep -A 9 "cache 3" | grep "ways" | head -n 1
CACHE_SLICES -> Usually Intel 6th generation and above have slices of 1024 sets and Intel 4th and 5th 2048, 
therefore this value is equal to number of total sets divided by the size of the slices, where the number of sets
is obtained $ cpuid | grep -A 14 "cache 3" | grep sets | head -n 1 
SETS_PER_SLICE -> Usually Intel 6th generation and above, 1024 and Intel 4th and 5th 2048
BITS_SET -> log2(SETS_PER_SLICE), that is, 10 or 11
BITS_LINE 6 //64 bytes per cache line, same value in all the systems tested, check with cat /proc/cpuinfo | grep "clflush size" | head -n 1

BITS_HUGEPAGE -> log2(HUGEPAGESIZE), which can be checked using grep Hugepagesize /proc/meminfo. It is 21 for systems whose hugepagesize is 2MB
BITS_NORMALPAGE -> log2(PAGESIZE), which can be checked using getconf PAGESIZE. It is 12 for 4KB pages
```

#### Options and calibration

Different options can be configured in various source files, `example_code.c' and 'example_code_sync.c`

```
#define TIME_LIMIT 150         /*Time for main memory access, must be calibrated*/
#define TIME_PRIME 650         /*Time for Prime, must be calibrated not entirely neccessary*/
#define NUM_CANDIDATES 3 * CACHE_SET_SIZE *CACHE_SLICES
#define RES_MEM (1UL * 1024 * 1024) * 4 * CACHE_SIZE
```
Note that the timings are machine dependand and as a consquence, must be calibrated. We do include a function for calibration 
that is executed at the very beginning, but it may require to increase the number of loops until the frequency is stable 
(the number of iterations is currently fixed)

Other configuration in `cache_utils.h`

```
#define SLICE_HASH_AVAILABLE 1
```
Defines whether it is possible to use the physical addresses (1) or not (0) in that machine. Default is Not

## Installation

Only a `make` is required to build the static binary.

`Warning:` It builds a shared library `libTable.so` . Since it is not in an standard location of the system, it will not
be found, one easy way to make it available it is:
export LD_LIBRARY_PATH=.

## How to use

In this scenario we consider three different agents, the server (server), the attacker (attack_tsk) and any the client that sends requests (send_request)
Each of them needs to be launched on a different terminal.

### server

It executes the sample fake vulnerable application, it will prefetch and then use data. In order to execute it:

```
./server -d detectionaddress -a targetaddress -t wait time -o outputfile -s ip address
```

#### Options

* detectionaddress
  * Expects an int value in the range of the Table.h, will be used for detection
* targetaddress
  * Expects an int value in the range of the Table.h, will be used for the eviction (after the prefetch)
* wait time
  * Time elapsed between the access to detectionaddress and the prefech of targetaddress
* outputfile
  * To store information about the actual execution of the function
* ip address
  * ip address of the server, localhost should work

Example:

```
./server -d 25 -a 25 -t 200 -o out.txt -s 127.0.0.1
```
Note that using invalid parameters may results in a segmentation fault
**NOTE** Current version of the code requires the detection and target addresses to be the same

### attack_tsk

This functions monitors the cache set where the detection and target addresses are located, 
when an execution is detected, it triggers the posterior eviction. To execute it:

```
./attack_tsk  -d detectionaddress -a targetaddress -t wait time-o outputfile [-p for access based eviction or -f for flush based eviction] -s ip address
```

#### Options

* detectionaddress
  * Expects an int value in the range of the Table.h, will be used for detection
* targetaddress
  * Expects an int value in the range of the Table.h, will be used for the eviction (after the prefetch)
* wait time
  * Time elapsed between the access to detectionaddress and the prefech of targetaddress this has to be chosen
   depending on the time used for the server.
* outputfile
  * To store the information about the evictions and future utilization (the attacker's information)
* ip address
  * ip address of the server, localhost should work
* attack tested (-p or -f)
  * p stands for the one access eviction, f for the flush based eviction

**NOTE** The addresses here must be the same than the ones in the server or map to the same cache line, 
otherwise they do not map to the same cache set. Sometimes it works better if it is not exactly the same
address but the consecutive one 

Examples (one for each posibility):

```
./attack_tsk -d 26 -a 26 -t 220 -o out.txt -s 127.0.0.1 -f 
./attack_tsk -d 26 -a 26 -t 220 -o out.txt -s 127.0.0.1 -p 

```

### send_request
This application send requests to the server that trigger the execution of the vulnerable function.
It sends a fixed number of requests defined on the code, modify at will.

```
./send_request 127.0.0.1
```

## Tested systems

This code has been successfully tested on:

* Intel(R) Core(TM) i5-7600K CPU @ 3.80GHz
	* Cores (4x1)
	* L3: 6MB
	* Associativity: 12
	* Cache sets: 8192
	* Slices: 8
* Intel(R) Core(TM) i7-6700K CPU @ 4.00GHz
	* Cores (4x2)
	* L3: 8MB
	* Associativity: 16
	* Cache sets: 8192
	* Slices: 8
