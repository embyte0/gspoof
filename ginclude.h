/*
 * This file is part of Gspoof-3 (a console/gtk+ tcp/ip packet forger)
 *
 * $Name: ginclude.h $
 * $Version: 3.2 $
 * $Date: 2003/12/22 16:30:03 $
 * $Author: Embyte <embyte@madlab.it> $
 * $Copyright: Copyright (C) 2002-2003 by embyte $
 * $License: This software is under GPL version 2 of license $
 *
 */

#include <libnet.h>

struct FLAGS
{
   u_char syn:1,
     ack:1,
     fin:1,
     rst:1,
     psh:1,
     urg:1,
     ece:1,
     cwr:1;
}
f;

struct CHECKS
{
   u_char multi:1,  	/* send many packets */
     data:1,		/* include payload */
     linkl:1,		/* work with datalink */
     debug:1;		/* enable debug mode */
}
ck;

struct MULTI
{
   u_long number;
   u_long delay;
}
m;

struct ECN
{
   u_int dscp:8;
   u_int ecn_ct:2;
   u_int ecn_ce:1;
}
ipv4_tos;

u_long shost;
u_long dhost;
u_long seq;
u_long ack;
u_short id;
u_short urgp;
u_short tos;

char device[10];
char data[128];

u_char ebuf[LIBNET_ERRBUF_SIZE];
