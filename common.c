/*
 * This file is part of Gspoof-3 (a console/gtk+ tcp/ip packet forger)
 * 
 * $Name: common.c $
 * $Version: 3.2 $
 * $Date: 2003/12/22 16:30:03 $
 * $Author: Embyte <embyte@madlab.it> $
 * $Copyright: Copyright (C) 2002-2003 by embyte $
 * $License: This software is under GPL version 2 of license $
 *
 */

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include "common.h"

char * dn (char * s)
{
   if (s[strlen(s)-1]=='\n')
     s[strlen(s)-1]='\0';
   return s;
}

u_char * ltostr(u_long a)
{
   u_char *s;
   u_short k=0;
   u_long b=a;

   do
     {
	b/=10;
	k++;
     }
   while (b);

   s=calloc(k+1, sizeof (u_char));
   s+=k;

   for (;;)
     {
	*s=(a%10)+'0';
	a/=10;
	if (!a) break;
	s--;
     }
   
   return s;
}

/* Yeah, I don't like libnet_hex_aton(), myconvert work better */
u_char * emb_hex_aton(u_char *in)
{
   u_short i, a=0;
   u_char *out;
   u_short retvalue;

   out = malloc(6*sizeof(u_char));
   
   for (i=0; i<6; i++)
     {
	if (in[a+1]!=':')
	  {
	     if (in[a+2]!=':' && i!=5) /* check possibles errors */
	       return NULL;
	     else
	       {
		  if((retvalue=emb_ctoi(in[a]))==16)
		    return NULL;
		  retvalue*=16;
		  out[i]=retvalue;
       		  a++;
		  retvalue=emb_ctoi(in[a]);
		  if (retvalue==16 && i!=5) /* we are not at the end */
		    return NULL;
		  else if (retvalue==16 && i==5) /*we are at the end */
		    out[i]=out[i]/16;
		  else
		    out[i]+=retvalue; /* there are not error */
       	       }
	  }
	else
	  {
	     if((retvalue=emb_ctoi(in[a]))==16) return NULL;
	     out[i]=retvalue;
	  }
	a+=2;
     }
   return out;
}

u_short emb_ctoi(u_char ex)
{
   if (atoi(&ex)>0 && atoi(&ex)<10) return atoi(&ex);
   else if (ex == '0') return 0;
   else if (ex == 'a' || ex == 'A') return 10;
   else if (ex == 'b' || ex == 'B') return 11;
   else if (ex == 'c' || ex == 'C') return 12;
   else if (ex == 'd' || ex == 'D') return 13;
   else if (ex == 'e' || ex == 'E') return 14;
   else if (ex == 'f' || ex == 'F') return 15;
   else return 16; /* error code is 16 -> lol :=) */ 
}

/* convert u_char to "##:##:##...##" format */
char * emb_hex_ntoa (u_char *s)
{
   
      char *r = calloc (18, sizeof (char));
   
      sprintf (r, "%02X:%02X:%02X:%02X:%02X:%02X",
	                   s[0], s[1], s[2], s[3], s[4], s[5]);
   
      return r;
}
