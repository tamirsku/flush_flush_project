#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sched.h>
#include "../cacheutils.h"

size_t array[5*1024];
size_t hit_histogram[80];
size_t miss_histogram[80];

// Creates 80 "Buckets" that represents time it took to flush the memory. The Content is the time it took to flush the data.

size_t cachehit(void* addr)
{ // Simulate Cache hit by preforming memory access, flushing the cache memory of the address and measure time.
  maccess(addr);
  size_t time = rdtsc();
  flush(addr);
  size_t delta = rdtsc() - time;
  return delta;
}

size_t cachemiss(void* addr)
{ // Simulate Cache miss by preforming memory access, flushing the cache memory of the address and measure time.
  flush(addr);
  size_t time = rdtsc();
  flush(addr);
  size_t delta = rdtsc() - time;
  return delta;
}

int main(int argc, char** argv)
{
  memset(array,-1,5*1024*sizeof(size_t));
  sched_yield();
  // Create Histogram For Cache Hits (Long Flush time)
  for (int i = 0; i < 4*1024*1024; ++i)
  {
    size_t d = cachehit(array+2*1024);
    hit_histogram[MIN(79,d/5)]++;
    sched_yield(); 
  }

  // Create Histogram For Cache Misses (Short Flush time)
  for (int i = 0; i < 4*1024*1024; ++i)
  {
    size_t d = cachemiss(array+2*1024);
    miss_histogram[MIN(79,d/5)]++;
    sched_yield(); 
  }

  printf("Offset\tMiss\tHit\n");
  for (int i = 0; i < 80; ++i)
  {
    printf("%3d: %10zu %10zu\n",i*5,hit_histogram[i],miss_histogram[i]);
  }
}
