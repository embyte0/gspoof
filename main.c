/*
 * This file is part of Gspoof-3 (a console/gtk+ tcp/ip packet forger)
 *
 * $Name: main.c $
 * $Version: 3.2 $
 * $Date: 2003/12/22 16:30:03 $
 * $Author: Embyte <embyte@madlab.it> $
 * $Copyright: Copyright (C) 2002-2003 by embyte $
 * $License: This software is under GPL version 2 of license $
 *
 */

#include <stdlib.h>
#include <sys/utsname.h>
#include "config.h"
#include "common.h"
#include "console.h"

#ifdef HAVE_GTK
# include "gtk.h"
#endif

int main (int argc, char *argv[])
{
   struct utsname buf;
   int opt;
   u_short GTK=0,
     CONSOLE=0;

   if (getuid() || getgid())
     {
	fprintf (stderr, "You must be r00t\n");
	return -1;
     }

   while ((opt=getopt(argc, argv, ":gGcCvVh?"))!=-1)
     {
	switch(opt)
	  {
	   case 'c':
	   case 'C':
	     CONSOLE=1;
	     break;
	   case 'g':
	   case 'G':
	     GTK=1;
	     break;
	   case 'v':
	   case 'V':
	     printf ("\nGspoof 3 - Version %s", VERSION);
	     if (uname(&buf)!=-1)
	       printf (", running on %s %s (%s)", buf.sysname, buf.release, buf.machine);
	     printf ("\n\n");
	     return 0;
	   case 'h':
	   case '?':
	     printf ("\nGspoof 3 -< Console/GTK+ TCP/IP Packet forger >- v. %s\n\n", VERSION);
	     printf ("Use:\n");
	     printf ("\t-c (-C)  Run in console mode\n");
	     printf ("\t-g (-G)  Run with GTK+ interface (*)\n");
	     printf ("\t-h (-?)  Print this help\n");
	     printf ("\t-v (-v)  Print some informations\n\n");
	     printf ("IMPORTANT:\n");
	     printf ("Default is: Console mode if GTK+ support isn't present\n");
	     printf ("            Graphics mode if GTK+ support is available\n\n");
	     printf ("(*) Only if compiled with GTK+ support\n\n");
	     return 0;
	  }
     }

#ifdef HAVE_GTK
   if (CONSOLE)
     return run_console();
   else
     run_gtk (argc, argv);
#else
   if (GTK)
     printf ("\nWarning: GTK+ support not present. GTK+ > 2.x required. Install and recompile\n");

   return run_console();
#endif

   return 0;
}

