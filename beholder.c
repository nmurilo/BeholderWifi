/*  
 * This code is very based on nice wireless-tools package. 
 * Big thanks to Jean to shared it with us. 

 * This file is part of beholder
 *
 * beholder is free software; you can redistribute it and/or modify
 * it under the terms of the AMS License. 
 *
 * beholder is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
 *
 * Copyright (c) Nelson Murilo <nelson@pangeia.com.br>, AMS Foundation and 
 * others.  
 * All rights reserved
*/
#include "iwlib.h"		/* Header */
#include <sys/time.h>
#include <syslog.h>
#include <stdarg.h>
#include <regex.h>
#include <time.h> 

#define max(a,b) (((a) > (b)) ? (a) : (b))
#define min(a,b) (((a) > (b)) ? (b) : (a))

#define MAXBUF 128
#define VERSION "0.8.9"
#define KARMA_TRAP_LEN 7
#define REGEX_MAX MAXBUF
#define AD_HOC_MODE 1
#define szofkarma sizeof(karma_addr)


struct result_scan 
{
   __u16  len;
   __u8   we_version;
   char *buffer; 
};

struct wireless_scan * iw_process_scanning_token( struct iw_event *, struct wireless_scan *);
struct result_scan *scanning_info( int, char *);
int add_in_table(int, struct wireless_scan *); 
int group_ssid(struct wireless_scan *); 
int check_karma(int, char *, wireless_scan *);
int check_new_ap(int,wireless_scan *);
int check_disappear(int, int, char *);
int check_regex(char *, char *);
int smart_check(int, char *);

void freebeer(wireless_scan *);
int print_out(int slog, const char *format, ...);
char *karma_trap(int, const char *); 
char netregex[REGEX_MAX];
regex_t *preg;

/* Global variables */ 
struct wireless_scan *ap_table_init, *wscan_init;
unsigned char karma_addr[14]; 

main(int argc, char *argv[])
{
   int skfd = 0; 
   char *dev; 
   wireless_scan *ap_table, *ap_temp;
   wireless_scan *wscan;
   struct iw_event iwe;
   struct stream_descr stream;
   // int we_version = iw_get_kernel_we_version(); 
   char buffer[MAXBUF], bufaux[MAXBUF], freqbuf[MAXBUF], karmatrap[MAXBUF];
   char netnames[MAXBUF];
   struct result_scan *rc; 
   int ret, len, debug, slog, newap, add, regex, mon, jam, clever;
   int level;

   ret = len = debug = slog = newap = add = clever = regex = mon = jam = 0;

   karmatrap[0] = ' ';
   karma_addr[0] = 0; 

   argv++; argc--;
   while (argc && *argv[0] == '-') // poor man getopts()
   {
      if (!(memcmp(argv[0], "-dd", 3)))
         debug = 2;
      else if (!(memcmp(argv[0], "-d", 2)))
         debug = 1; 
      else if (!(memcmp(argv[0], "-s", 2)))
         slog = 1;
      else if (!(memcmp(argv[0], "-c", 2)))
         clever = 1;
      else if (!(memcmp(argv[0], "-a", 2)))
         add = 1;
      else if (!(memcmp(argv[0], "-m", 2)))
      {
         memset(netnames, '\0', REGEX_MAX);
         memcpy(netnames, argv[1], min(REGEX_MAX, strlen(argv[1])));

         mon = 1;
         if (argc)
         {
            argv++; 
            argc--; 
         }
      }
      else if (!(memcmp(argv[0], "-r", 2)))
      {
         memset(netregex, '\0', REGEX_MAX);
         memcpy(netregex, argv[1], min(REGEX_MAX, strlen(argv[1])));
         regex = 1;
         if (argc)
         {
            argv++; 
            argc--; 
         }
      }
      argv++; 
      argc--; 
   }
   if (argc != 1)
   {
      printf("Usage: beholder [-a] [-s] [-c] [-d[d]] [-r pattern] [-m pattern ] <device>\n");
      printf("Version %s\n", VERSION);
      exit(1); 
   } 
   dev = argv[0];

   /* Create a channel to the NET kernel. */
   if((skfd = iw_sockets_open()) < 0)
   {
      perror("socket");
      return -1;
   }

   ap_table = ap_table_init = NULL;

   /* Scanning for visible APs */
   rc = scanning_info(skfd, dev); 
   /* Load AP table */

   if(rc->len > 0)
   {
      struct stream_descr stream;
      iw_init_event_stream(&stream, rc->buffer, rc->len);
      do
      {
         /* Extract an event */
         ret = iw_extract_event_stream(&stream, &iwe, rc->we_version);
         if(ret > 0)
            ap_table = iw_process_scanning_token(&iwe, ap_table);
      }while(ret >0);
      printf("Beholder version %s\n", VERSION);

      ap_table = ap_table_init;

      while (ap_table)
      {
         if (ap_table->b.freq < KILO)
            snprintf(freqbuf, MAXBUF, "% 3g Ch", ap_table->b.freq);
         else 
            snprintf(freqbuf, MAXBUF, "%g",(ap_table->b.freq/1000000));
            // snprintf(freqbuf, MAXBUF, "%g",(iw_freq_to_channel(ap_table->b.freq, range);

         level = ap_table->stats.qual.level;
         if (level && level != 256)
            level -= 0x100;
         else
            level = 0;
         print_out(slog, "%s:%-24s[%s]:%s:%ddBm\n",
             iw_operation_mode[ap_table->b.mode], 
             ap_table->b.has_essid ? ap_table->b.essid : "<hidden>", 
             iw_pr_ether(buffer, ap_table->ap_addr.sa_data), freqbuf, 
             level);

         ap_table->df = 0; /* set off disappear flag */
         ap_table = ap_table->next;
      }
      free(rc->buffer);
   }
   else
   {
      printf("%-8.16s  No scan results, is device up?\n", dev);
      exit (-1);
   }

   /* infinite loop to identify changes */ 
   while (1)
   {
      wscan = wscan_init = NULL;

      rc = scanning_info(skfd, dev);

      iw_init_event_stream(&stream, rc->buffer, rc->len);
      do
      {
         /* Extract an event */
         ret = iw_extract_event_stream(&stream, &iwe, rc->we_version);
         if(ret > 0)
            wscan = iw_process_scanning_token(&iwe, wscan);

      }while (ret > 0);

      karma_trap(skfd, dev);  // Set random interface essid

      ap_temp = ap_table_init;
      while (ap_temp) 
      {
         if (!wscan_init)
         {
            jam++;
            if (debug) 
               print_out(slog, "Possible jammer: jam count = %d\n", jam);
            if (jam == 3) 
            {
               print_out(slog, "ALERT: Danger, Will Robinson! Jamming device detected\n"); 
               break;
            }
         }
         jam = 0; 
         wscan = wscan_init;
         
         while (wscan)
         {
            if (check_karma(slog, karmatrap, wscan))
            {
               wscan = wscan->next;
               continue;
            } 
            if (regex && check_regex(netregex, wscan->b.essid)) 
            {
               if (!(group_essid(wscan)))
               {
                  print_out(slog, "ALERT: %s[%s] matches a pattern\n", 
                    wscan->b.essid, 
                    iw_pr_ether(buffer, wscan->ap_addr.sa_data));

                 //  wscan = wscan->next;
                 //  continue;
               }
            }
            if ((newap = check_new_ap(slog,wscan)) && add)
            { 
               if (debug)
                  print_out(slog, "NewAp = %d\n", newap);
               add_in_table(slog, wscan);
               if (clever) 
                  smart_check(slog, wscan->b.essid);
            }
            
            if (!(ap_temp->b.has_essid))  /* Hidden */
            {
               if (!(memcmp(&ap_temp->ap_addr.sa_data, &wscan->ap_addr.sa_data, szofkarma)))
               {
                  if (wscan->b.has_essid)
                  {
                     print_out(slog, "Warning: Essid of [%s] was reveled\n", 
                      iw_pr_ether(buffer, wscan->ap_addr.sa_data));
                     /* update init_table */
                     ap_temp->b.has_essid = 1; 
                     len = strlen(wscan->b.essid);
                     memcpy(ap_temp->b.essid, wscan->b.essid, len);
                     ap_temp->b.essid[len]='\0'; 
                  }
               }
            }
            else
            {
               if (!(memcmp(&ap_temp->ap_addr.sa_data, &wscan->ap_addr.sa_data, szofkarma)))
                  if (!wscan->b.has_essid)
                     print_out(slog, "Warning: Essid of %s was hidden\n", ap_temp->b.essid);
           }
           if (ap_temp->b.has_essid)
           {
               len = max(strlen(ap_temp->b.essid), strlen(wscan->b.essid));
               if (!(memcmp(ap_temp->b.essid, wscan->b.essid, len)))
               {
                  if (memcmp(&ap_temp->ap_addr.sa_data, &wscan->ap_addr.sa_data, szofkarma))
                  {
                     if (!(group_essid(wscan)))
                     {
                        iw_pr_ether(bufaux, wscan->ap_addr.sa_data);
                        if (ap_temp->b.mode == AD_HOC_MODE && wscan->b.mode != AD_HOC_MODE)
                        {
                           print_out(slog, "Warning: AP [%s] using the same ESSID (%s)\n",bufaux, ap_temp->b.essid);
                           /* add to table */ 
                           add_in_table(slog, wscan);
                        }
                        else
                        {
                           if (wscan->b.mode == AD_HOC_MODE)
                           {
                              print_out(slog, "Warning: mode AD-HOC[%s] using the same ESSID (%s)\n",bufaux, wscan->b.essid);
                              /* add to table */ 
                              add_in_table(slog, wscan);

                           }
                           else
                           {
                              if (memcmp(wscan->ap_addr.sa_data, karma_addr, szofkarma))
                              {
                                 iw_pr_ether(buffer, ap_temp->ap_addr.sa_data);
                                 print_out(slog, "Warning: MAC of %s was changed, from [%s] to [%s]\n", ap_temp->b.essid, buffer, bufaux);
                              }
                           }
                        }
                     }
                  } 
                  else /* same essid and same mac */
                  {
                     /* Check signal level */
                     iw_pr_ether(buffer, ap_temp->ap_addr.sa_data);

                     level = ap_temp->stats.qual.level; 
                     if (level && wscan->stats.qual.level < (level-50))
                     {
                        print_out(slog, "Warning: Huge level variation %24s[%s] %d/%d\n",
                        ap_temp->b.has_essid ? ap_temp->b.essid : "<hidden>",
                        buffer, level - 0x100, wscan->stats.qual.level - 0x100);
                     }
                     if (ap_temp->b.mode != wscan->b.mode) 
                        print_out(slog, "Warning: Mode of %s was changed\n", ap_temp->b.essid); 
                     if (ap_temp->b.freq != wscan->b.freq)
                     {
                        char fb[MAXBUF];
                        if (ap_temp->b.freq < KILO)
                           snprintf(freqbuf, MAXBUF, "%3g", ap_temp->b.freq);
                        else
                           snprintf(freqbuf, MAXBUF, "%g",(ap_temp->b.freq/1000000));
                        if (wscan->b.freq < KILO)
                           snprintf(fb, MAXBUF, "%3g", wscan->b.freq);
                        else
                           snprintf(fb, MAXBUF, "%g",(wscan->b.freq/1000000));
                        
                        print_out(slog, "Warning: Channel of %s has changed from %s to %s\n", ap_temp->b.essid, freqbuf, fb); 
                        /* update init_table */
                        ap_temp->b.freq = wscan->b.freq; 
                     }
                     if (wscan->b.key_flags != ap_temp->b.key_flags)
                     {
                        print_out(slog, "Warning: Encryption proto has changed from [%d] to [%d]\n", wscan->b.key_flags, ap_temp->b.key_flags);
                        
                        /* Update key_flags value */
                        ap_temp->b.key_flags = wscan->b.key_flags; 
                     }
                  }
               }
               else
               {
                  if (memcmp(ap_temp->ap_addr.sa_data, karma_addr, szofkarma)
                      && 
                     (!(memcmp(&ap_temp->ap_addr.sa_data, &wscan->ap_addr.sa_data, szofkarma))))
                  {
                     print_out(slog, "Warning: ESSID of [%s] was changed from %s to %s\n", 
                      iw_pr_ether(buffer, ap_temp->ap_addr.sa_data), ap_temp->b.essid, wscan->b.essid);
                     /* update init_table */ 
                     memcpy(ap_temp->b.essid, wscan->b.essid, len);
                  }
                  
               }
            }
            if (debug == 2)
            {
               iw_pr_ether(buffer, ap_temp->ap_addr.sa_data);
               iw_pr_ether(bufaux, wscan->ap_addr.sa_data);
               print_out(slog, "[%s]%-24s [%s]%-24s checked\n", 
                  buffer,
                  ap_temp->b.has_essid ? ap_temp->b.essid : "<hidden>",
                  bufaux,
                  wscan->b.has_essid ? wscan->b.essid : "<hidden>");
            }
            wscan = wscan->next;
         }
         ap_temp = ap_temp->next;
      }
      if (mon)
         check_disappear(slog, debug, netnames);
      memcpy(karmatrap, karma_trap(skfd, dev), KARMA_TRAP_LEN); 
      freebeer(wscan_init);
      free(rc->buffer);
   }
   /* Close the socket. */
   iw_sockets_close(skfd);

   return 0;
}

/*------------------------------------------------------------------*/
/*
 * Perform a scanning on one device
 */
struct result_scan *scanning_info(int skfd, char *ifname)
{
   struct iwreq		wrq;
   unsigned char *	buffer = NULL;		/* Results */
   int			buflen = IW_SCAN_MAX_DATA; /* Min for compat WE<17 */
   struct iw_range	range;
   int			has_range;
   struct timeval	tv;				/* Select timeout */
   int			timeout = 15000000;		/* 15s */
   // int			timeout = 30000000;		/* 30s */
   static struct result_scan rc;
    
   /* Get range stuff */
   has_range = (iw_get_range_info(skfd, ifname, &range) >= 0);
     
   /* Check if the interface could support scanning. */
   if((!has_range) || (range.we_version_compiled < 14))
   {
      fprintf(stderr, "%-8.16s  Interface doesn't support scanning.\n\n",
	      ifname);
      exit (-1); 
   }

   /* Init timeout value -> 250ms*/
   tv.tv_sec = 0;
   tv.tv_usec = 250000;

   /*
   * Here we should look at the command line args and set the IW_SCAN_ flags
   * properly
   */
   wrq.u.data.pointer = NULL;		/* Later */
   wrq.u.data.flags = 0;
   wrq.u.data.length = 0;
    
   /* Initiate Scanning */
   if(iw_set_ext(skfd, ifname, SIOCSIWSCAN, &wrq) < 0)
   {
      if(errno != EPERM && errno != EBUSY)
      {
         fprintf(stderr, "%-8.16s  Interface doesn't support scanning : %d-%s\n\n",
		  ifname, errno, strerror(errno));
         exit (-1);
      }
      /* If we don't have the permission to initiate the scan, we may
       * still have permission to read left-over results.
       * But, don't wait !!! */
      tv.tv_usec = 0;
   }
   timeout -= tv.tv_usec;
   
   /* Forever */
   while(1)
   {
      fd_set		rfds;		/* File descriptors for select */
      int		last_fd;	/* Last fd */
      int		ret;
             
      /* Guess what ? We must re-generate rfds each time */
      FD_ZERO(&rfds);
      last_fd = -1;

      /* In here, add the rtnetlink fd in the list */

      /* Wait until something happens */
      ret = select(last_fd + 1, &rfds, NULL, NULL, &tv);

      /* Check if there was an error */
      if(ret < 0)
      {
         if(errno == EAGAIN || errno == EINTR)
	    continue;
	 fprintf(stderr, "Unhandled signal - exiting...\n");
	 return(NULL);
      }

      /* Check if there was a timeout */
      if(ret == 0)
      {
         unsigned char *	newbuf;
       
	 realloc:
	 /* (Re)allocate the buffer - realloc(NULL, len) == malloc(len) */
	 newbuf = realloc(buffer, buflen);
	 if(newbuf == NULL)
         {
            if(buffer)
               free(buffer);
	    fprintf(stderr, "%s: Allocation failed\n", __FUNCTION__);
	    return(NULL);
	 }
	 buffer = newbuf;

	 /* Try to read the results */
	 wrq.u.data.pointer = buffer;
	 wrq.u.data.flags = 0;
         wrq.u.data.length = buflen;
         if(iw_get_ext(skfd, ifname, SIOCGIWSCAN, &wrq) < 0)
         {
	    /* Check if buffer was too small (WE-17 only) */
	    if((errno == E2BIG) && (range.we_version_compiled > 16))
            {
               /* Some driver may return very large scan results, either
               * because there are many cells, or because they have many
               * large elements in cells (like IWEVCUSTOM). Most will
               * only need the regular sized buffer. We now use a dynamic
               * allocation of the buffer to satisfy everybody. Of course,
               * as we don't know in advance the size of the array, we try
               * various increasing sizes. Jean II */

               /* Check if the driver gave us any hints. */
               if(wrq.u.data.length > buflen)
                  buflen = wrq.u.data.length;
               else
                  buflen *= 2;

               /* Try again */
               goto realloc;
            }

	    /* Check if results not available yet */
	    if(errno == EAGAIN)
            {
               /* Restart timer for only 100ms*/
               tv.tv_sec = 0;
               tv.tv_usec = 100000;
               //tv.tv_usec = 200000;
               timeout -= tv.tv_usec;
               if(timeout > 0)
                  continue;	/* Try again later */
            }

	    /* Bad error */
	    free(buffer);
	    fprintf(stderr, "%-8.16s  Failed to read scan data : [%d] %s\n\n",
	      ifname, errno, strerror(errno));
	    return(NULL);
	 }
	 else
	    /* We have the results, go to process them */
	    break;
      }

      /* In here, check if event and event type
       * if scan event, read results. All errors bad & no reset timeout */
   }
   rc.len = wrq.u.data.length;
   rc.we_version = range.we_version_compiled;
   rc.buffer = buffer;
   return (&rc);  
}

int add_in_table(int slog, wireless_scan *ap)
{
   wireless_scan *ap_temp = NULL;
   char buffer[MAXBUF], freqbuf[MAXBUF];
   struct iw_range range;
   int level;
   
   ap_temp = ap_table_init;
   while (ap_temp->next)
      ap_temp = ap_temp->next;
 
   if(!(ap_temp->next = calloc(1, sizeof(struct wireless_scan))))
   {
      perror("calloc");
      exit (-1);
   }
    
   ap_temp = ap_temp->next;
   memcpy(ap_temp, ap, (sizeof(wireless_scan))); 
   level = ap->stats.qual.level;
   if (level && level != 256)
      level -= 0x100;
   else 
      level = 0;
   if (ap->b.freq < KILO)
      snprintf(freqbuf, MAXBUF, "% 3g Ch", ap->b.freq);
   else 
      snprintf(freqbuf, MAXBUF, "%g",(ap->b.freq/1000000));
   print_out(slog, "%s:%s\t[%s]:%s:%ddBm Added.\n", 
        iw_operation_mode[ap->b.mode], 
        ap->b.has_essid ? ap->b.essid : "<hidden>", 
        iw_pr_ether(buffer, ap->ap_addr.sa_data),
        freqbuf, level);
    ap_temp->df = 0;
   ap_temp->next = NULL;
#if 0
      ap_temp = ap_table_init;
      printf("--- Internal Table --\n");
      while (ap_temp)
      {
         if (ap_temp->b.freq < KILO)
            snprintf(freqbuf, MAXBUF, "% 3g Ch", ap_temp->b.freq);
         else
            snprintf(freqbuf, MAXBUF, "%g",(ap_temp->b.freq/1000000));
         print_out(slog, "%s:%-24s[%s] %s\n",
          iw_operation_mode[ap_temp->b.mode],
          ap_temp->b.has_essid ? ap_temp->b.essid : "<hidden>",
          iw_pr_ether(buffer, ap_temp->ap_addr.sa_data),
          freqbuf);
         ap_temp = ap_temp->next;
      }
      printf("--- End internal table --\n");
#endif
   return 1;
}

void  freebeer(struct wireless_scan *ap)
{
   struct wireless_scan *wp; 
   while (ap)
   {
      wp = ap->next; 
      free(ap);
      ap = wp;
   } 
}

int print_out(int slog, const char *format, ...)
{
   va_list ap;
   static va_list ap_temp = NULL;
   static int count = 0;
   char str[128];
   struct tm *ptr;
   time_t tm; 

   va_start(ap, format);
   if (slog)
      vsyslog(LOG_ALERT, format, ap);
   else 
   {
      tm = time(NULL);
      ptr = localtime(&tm);
      strftime(str, 120, "%F:%H.%M.%S", ptr);
      fprintf(stderr,"%s:", str);
      vfprintf(stderr, format, ap);
   }
}

int group_essid(wireless_scan *ap)
{
   int len = 0;
   wireless_scan *ap_temp = NULL;
   ap_temp = ap_table_init; 
   while (ap_temp)
   {
      len = max(strlen(ap_temp->b.essid), strlen(ap->b.essid));
      if (!(memcmp(ap_temp->b.essid, ap->b.essid, len)))  
      {
         if (!(memcmp(&ap_temp->ap_addr.sa_data, &ap->ap_addr.sa_data, szofkarma)))
            return 1; /* Found */
      }
      ap_temp = ap_temp->next;
   }
   return 0;
}

int check_new_ap(int slog, wireless_scan *ap)
{
   int len = 0;
   wireless_scan *ap_temp = NULL;
   char buffer[MAXBUF], bufaux[MAXBUF];

   ap_temp = ap_table_init; 
/*
   if (ap->b.mode == AD_HOC_MODE) 
      return 0;
*/
   while (ap_temp)
   {
      if (karma_addr && !memcmp(&karma_addr, &ap->ap_addr.sa_data, szofkarma))
         return 0;

      if (ap->b.has_essid)
      {
         len = max(strlen(ap_temp->b.essid), strlen(ap->b.essid));
         if (!(memcmp(ap_temp->b.essid, ap->b.essid, len)))  
         {
            if (ap->b.mode != ap_temp->b.mode)
               return 0;
            if (!(memcmp(&ap_temp->ap_addr.sa_data, &ap->ap_addr.sa_data, szofkarma)))
               return 0; /* Found */
         }
      }
      else 
      {
         if (!(memcmp(&ap_temp->ap_addr.sa_data, &ap->ap_addr.sa_data, szofkarma)))
            return 0; /* Found */

      }
      iw_pr_ether(buffer, ap->ap_addr.sa_data);
      iw_pr_ether(bufaux, ap_temp->ap_addr.sa_data);
      ap_temp = ap_temp->next;
   }
   print_out(slog, "Warning: New essid found %s[%s]\n", 
             ap->b.has_essid ? ap->b.essid : "<hidden>", 
             buffer);
   return 1;
}

char *karma_trap(int skfd, const char *dev)
{
   struct iwreq wrq;
   // double freq; 
   char essid[KARMA_TRAP_LEN] = "XXXXXX"; 
   static char *p; 

   p = essid; 
   wrq.u.data.pointer = (caddr_t) NULL;
   wrq.u.data.flags = 0;
   wrq.u.data.length = 0;

   // Create a random ESSID
   mktemp(essid);

   wrq.u.essid.pointer = (caddr_t) essid; 
   wrq.u.essid.length = strlen(essid) + 1;
   wrq.u.data.flags |= IW_ENCODE_OPEN;

   // Set random ESSID 
   if(iw_set_ext(skfd, dev, SIOCSIWESSID, &wrq) < 0)
   {
       fprintf(stderr, "SIOCSIWESSID: %s\n", strerror(errno));
       return 0;
   }
   sleep (1);
   // Get random ESSID 
   if(iw_get_ext(skfd, dev, SIOCSIWESSID, &wrq) < 0)
   {
       fprintf(stderr, "SIOCSIWESSID: %s\n", strerror(errno));
   }

   sleep (1);
   wrq.u.data.pointer = NULL;           
   wrq.u.data.flags = 0;
   wrq.u.data.length = 0;
   if(iw_set_ext(skfd, dev, SIOCSIWESSID, &wrq) < 0)
   {
       fprintf(stderr, "SIOCSIWESSID: %s\n", strerror(errno));
       return 0;
   }
   iw_null_ether(&(wrq.u.ap_addr));
   sleep (1);
   if(iw_set_ext(skfd, dev, SIOCSIWSCAN, &wrq) < 0 && (errno != EPERM && errno != EBUSY))
   {
       fprintf(stderr, "SIOCSIWSCAN: %s\n", strerror(errno));
       return 0;
   }

// printf("p = %s\n", p);
   return p;
}

int check_karma(int slog, char *kt, wireless_scan *wscan)
{
   static char last_kt[KARMA_TRAP_LEN+1] =  " "; 
   char buffer [MAXBUF]; 
 
   if (!wscan->b.has_essid || *kt == ' ')
      return 0;
 
//   printf("kt = %s wscan->b.essid = %s\n", kt, wscan->b.essid);
   if (!memcmp(wscan->b.essid, last_kt, KARMA_TRAP_LEN) || 
      !memcmp(kt, last_kt, KARMA_TRAP_LEN))
      return 1;

   if (!memcmp(kt, wscan->b.essid, KARMA_TRAP_LEN))
// || !memcmp(wscan->b.essid, "karma", 5)) 
   {
      print_out(slog, "Warning: Karma is in the house (%s-%s) [%s]\n\r", kt, last_kt,
iw_pr_ether(buffer, wscan->ap_addr.sa_data));
      memcpy(last_kt, kt, KARMA_TRAP_LEN);
      memcpy(&karma_addr,  &wscan->ap_addr.sa_data, sizeof(sockaddr));
      sleep(20); // Under karma style attack we must be calm
      return 1;
   }
   return 0;
}

int check_regex(char *netregex, char *essid_name)
{
   regex_t preg;

   if (!regcomp(&preg, netregex, REG_EXTENDED|REG_ICASE|REG_NOSUB)) 
      if (!(regexec(&preg, essid_name, (size_t) 0, NULL, 0)))
         return 1; 
   return 0;
}

int check_disappear(int slog, int debug, char *netnames)
{
   wireless_scan *ap_temp = ap_table_init; 
   wireless_scan *ap = NULL;
   char buffer[MAXBUF];

   if (!wscan_init) 
      return 0;

   while(ap_temp)
   { 
      ap = wscan_init;
      while (ap)
      {
         int len = max(strlen(ap_temp->b.essid), strlen(ap->b.essid));
         if (debug)
         {
            print_out(slog, "init_table %s[%s] df=%d ", 
             ap_temp->b.has_essid ? ap_temp->b.essid : "<hidden>", 
             iw_pr_ether(buffer, ap_temp->ap_addr.sa_data), ap_temp->df);
            print_out(slog, " - scanned table %s[%s] len:%d\n", 
             ap->b.has_essid ? ap->b.essid : "<hidden>", 
             iw_pr_ether(buffer, ap->ap_addr.sa_data), len);
         } 
         if (!memcmp(ap->b.essid, ap_temp->b.essid, len) && 
             !memcmp(&ap_temp->ap_addr.sa_data, &ap->ap_addr.sa_data, szofkarma) &&
             ap_temp->b.freq == ap->b.freq)
         {
             if (ap_temp->df > 2)
             {
                print_out(slog, "Relax: essid %s on ap [%s] is back\n", 
                 ap_temp->b.has_essid ? ap_temp->b.essid : "<hidden>", 
                 iw_pr_ether(buffer, ap_temp->ap_addr.sa_data));
             }
             ap_temp->df = 0;
             break; /* Found */
         }
         ap = ap->next;
      }
      if (!ap) /* End of list */
      {
         if (check_regex(netnames, ap_temp->b.essid))
         {
            if (ap_temp->df < 5)
               ap_temp->df++;
            if (ap_temp->df == 3)
            {
               print_out(slog, "ALERT: essid disappeared %s[%s]\n", 
                ap_temp->b.has_essid ? ap_temp->b.essid : "<hidden>", 
                iw_pr_ether(buffer, ap_temp->ap_addr.sa_data));
            }
         }
      }
      ap_temp = ap_temp->next;
   } 
}

int smart_check(int slog, char * essid)
{
   int l1, l2, count = 0;
   wireless_scan *ap_temp = ap_table_init; 
   char buffer[MAXBUF], bufaux[MAXBUF];

   l1 = strlen(essid);
 
   // ap_temp = ap_table_init; 
   while (ap_temp)
   {
      count = 0;
      l2 = strlen(ap_temp->b.essid);

      if (l1 < 0 || l2 < 0) 
         return 0;

      if (l1 == l2)
      { 
         while (l2--)
         {
            if (ap_temp->b.essid[l2] != essid[l2])
               count++;
         }
         if (count && count < l1) 
         {
            print_out(slog, "ALERT: %s[%s] is similar to %s\n", 
                    ap_temp->b.essid, 
                    iw_pr_ether(buffer, ap_temp->ap_addr.sa_data),
                    essid);
            return 1; // Not equal 
         }
      }
      ap_temp = ap_temp->next;
   }
   return 0;
}

