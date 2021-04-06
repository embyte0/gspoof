/*
 * This file is part of Gspoof-3 (a console/gtk+ tcp/ip packet forger)
 *
 * $Name: console.c $
 * $Version: 3.2 $
 * $Date: 2003/12/22 16:30:03 $
 * $Author: Embyte <embyte@madlab.it> $
 * $Copyright: Copyright (C) 2002-2003 by embyte $
 * $License: This software is under GPL version 2 of license $
 *
 */

#include "console.h"
#include "common.h"

u_char ebuf[LIBNET_ERRBUF_SIZE];

/* random value */
u_long seq;
u_long ack;
u_short id;
u_short urgp;

/* boolean value */
u_short multi;
u_short ll;

/* flags opt */
u_short furg;
u_short fack;
u_short fpsh;
u_short frst;
u_short fsyn;
u_short ffin;
u_short fcwr;
u_short fece;

char device[10]; /* device (eth0, eth1, ppp0) */

u_long shost, dhost;   /* IP */
u_short sport, dport;
u_char *data; /* data (tcp payload) */

/* delay opt */
u_short delay;
u_long number;

/* ecn */
struct
{
   u_int dscp:8;
   u_int ecn_ct:2;
   u_int ecn_ce:1;
}
ipv4_tos;

/* temp variable 4 eth addr */
u_char *seth_temp;
u_char *deth_temp;

/* eth addr */
u_char *seth;
u_char *deth;

/* eth type */
u_char *ethtype;
u_short evalue;

/* other opt */
u_short tos;
u_short ttl;
u_short win;
u_short datalen; /* data (tcp payload) lenght */

/* libnet file context (new from libnet-1.1.x ) */
libnet_t *l;

/* other */
u_char keystroke;
u_short i;
char *cmd;
u_char *value;

int run_console()
{
   u_char r;
   u_short t=0;

   /* print banner */
   printf ("\n\t-----------------------\n");
   printf ("\tRunning in Console Mode\n");
   printf ("\t-----------------------\n\n");

   cmd = (char *) NULL;
   data = (char *) NULL;

   value = calloc (20, sizeof(u_char));
   seth = calloc (6, sizeof(u_char));
   deth = calloc (6, sizeof(u_char));
   ethtype = calloc (4, sizeof(u_char));

   clean_values();
   randomize();
   autoscan();

   for (;;)
     {
	print_menu();

	printf ("\n");

	if (cmd)
	  {
	     free (cmd);
	     cmd = (char *) NULL;
	  }

	do
	  {
	     if (!t)
	       {
		  print_getline (&cmd, "CMD (type 'help' for avaible commands) > ");
		  t = 1;
	       }
	     else
	       print_getline (&cmd, "CMD > ");

	     if (!*cmd) t = 0;
	  }
	while (!*cmd);

	printf ("\n");

	/* read commands */
        if (!strcmp ("1.1", cmd))
	  {
	     printf ("INTERFACE (%s) : ", device);
	     bzero (device, 10);
	     scanf ("%s", device);
             keystroke =getchar();
	  }
	else if (!strcmp ("1.2", cmd))
	  {
	     printf ("SOURCE HW ADDRESS (%X:%X:%X:%X:%X:%X) : ", seth[0], seth[1], seth[2], seth[3], seth[4], seth[5]);
	     do
	       {
		  fgets(value, 20, stdin);
		  free(seth);
		  seth = emb_hex_aton(value);
		  if (seth==NULL)
		    printf ("WRONG MAC ADDRESS! - Retype it : ");
	       }
	     while (seth==NULL);
	  }
	else if (!strcmp ("1.3", cmd))
	  {
	     printf ("DESTINATION HW ADDRESS (%X:%X:%X:%X:%X:%X) : ", deth[0], deth[1], deth[2], deth[3], deth[4], deth[5]);
	     do
	       {
		  fgets(value, 20, stdin);
		  free (deth);
		  deth = emb_hex_aton(value);
		  if (deth==NULL)
		    printf ("WRONG MAC ADDRESS! - Retype it : ");
	       }
	     while (deth==NULL);
	  }
	else if (!strcmp ("1.4", cmd))
	  {
	     do
	       {
		  printf ("ETHERNET TYPE (%s) (ip/lo) : ", ethtype);
		  fgets(ethtype, 20, stdin);
		  ethtype = dn(ethtype);
	       }
	     while (strcmp("ip", ethtype) && strcmp("lo", ethtype));
             if (strcmp(ethtype, "ip")) evalue = 0x9000; /*strcmp return 0 if strings are equal! */
	  }
	else if (!strcmp ("2.1", cmd))
	  {
	     do
	       {
		  printf ("SOURCE ADDRESS (%s) : ", libnet_addr2name4(shost, LIBNET_DONT_RESOLVE));
		  fgets(value, 20, stdin);
		  if ((shost = libnet_name2addr4(l, dn(value), LIBNET_RESOLVE))==-1)
		    printf ("Error reading source IP\n");
	       }
	     while (shost == -1);

	  }
	else if (!strcmp ("2.2", cmd))
	  {
	     do
	       {
		  printf ("DESTINATION ADDRESS (%s) : ", libnet_addr2name4(dhost, LIBNET_DONT_RESOLVE));
		  fgets(value, 20, stdin);
		  if ((dhost = libnet_name2addr4(l, dn(value), LIBNET_RESOLVE))==-1)
		    printf ("Error reading destination IP\n");
	       }
	     while (dhost == -1);
	  }
	else if (!strcmp ("2.3", cmd))
	  {
	     do
	       {
		  printf ("TIME TO LIVE (%d) : ", ttl);
		  fgets(value, 20, stdin);
		  ttl = atoi (value);
	       }
	     while (ttl > 255 || atoi(value) < 0);
	  }
	else if (!strcmp ("2.4", cmd))
	  {
	     do
	       {
		  printf ("ID NUMBER (%d) : ", id);
		  fgets(value, 20, stdin);
		  id = atoi (value);
	       }
	     while (atol(value) > 65535 || atoi(value) < 0);
	  }
	else if (!strcmp ("2.5", cmd)) /* ENC to IP RFC 3168 */
	  {
	     do
	       {
		  printf ("DIFFERENTIATED SERVICES (%d) : ", ipv4_tos.dscp);
		  fgets(value, 20, stdin);
		  ipv4_tos.dscp = atoi (value);
	       }
	     while (ipv4_tos.dscp > 63 || atoi(value) < 0);
	  }
	else if (!strcmp ("2.6", cmd))
	  {
	     do
	       {
		  printf ("ECN-CAPABLE TRANSPORT (%d) : ", ipv4_tos.ecn_ct);
		  fgets(value, 3, stdin);
		  ipv4_tos.ecn_ct = atoi (value);
		  value=dn(value);
	       }
	     while (strcmp(value, "0") && strcmp(value, "1"));
	  }
	else if (!strcmp ("2.7", cmd))
	  {
	     do
	       {
		  printf ("ECN-CE (%d) : ", ipv4_tos.ecn_ce);
		  fgets(value, 3, stdin);
		  ipv4_tos.ecn_ce=atoi(value);
		  value=dn(value);
	       }
	     while (strcmp(value, "0") && strcmp(value, "1"));
	  }
	else if (!strcmp ("3.1", cmd))
	  {
	     do
	       {
		  printf ("SOURCE PORT (%d) : ", sport);
		  fgets(value, 20, stdin);
		  sport = atoi(value);
	       }
	     while (atol(value) > 65535 || atoi(value) < 0);
	  }
	else if (!strcmp ("3.2", cmd))
	  {
	     do
	       {
		  printf ("DESTINATION PORT (%d) : ", dport);
		  fgets(value, 20, stdin);
		  dport = atoi(value);
	       }
	     while (atol(value) > 65535 || atoi(value) < 0);
	  }
	else if (!strcmp ("3.3", cmd))
	  {
	     for (;;)
	       {
		  printf ("\nFLAGS ARE NOW SET : URG %d - RST %d - ACK %d - SYN %d -  PSH %d - FIN %d - CWR %d - ECN %d\n\n",
			  furg, frst,  fack, fsyn, fpsh, ffin, fcwr, fece);
		  printf ("WHAT FLAG DO YOU WANT TO CHANGE? (URG/RST/ACK/SYN/PSH/FIN/CWR/ECE) (TYPE 'DONE' TO END) : ");
		  fgets(value, 20, stdin);

		  value = dn(value);

		  if (!strcmp("URG", value) || !strcmp("urg", value))
		    {
		       do
			 {
			    printf ("URG FLAG (%d) : ", furg);
			    fgets(value, 3, stdin);
			    furg = atoi(value);
			    value = dn(value);
			 }
		       while (strcmp(value, "0") && strcmp(value, "1"));
		    }
		  else if (!strcmp("RST", value) || !strcmp("rst", value))
		    {
		       do
			 {
			    printf ("RST FLAG (%d) : ", frst);
			    fgets(value, 3, stdin);
			    frst = atoi(value);
			    value = dn(value);
			 }
		       while (strcmp(value, "0") && strcmp(value, "1"));
		    }
		  else if (!strcmp("ACK", value) || !strcmp("ack", value))
		    {
		       do
			 {
			    printf ("ACK FLAG (%d) : ", fack);
			    fgets(value, 3, stdin);
			    fack = atoi(value);
			    value = dn(value);
			 }
		       while (strcmp(value, "0") && strcmp(value, "1"));
		    }
		  else if (!strcmp("SYN", value) || !strcmp("syn", value))
		    {
		       do
			 {
			    printf ("SYN FLAG (%d) : ", fsyn);
			    fgets(value, 3, stdin);
			    fsyn = atoi(value);
			    value = dn(value);
			 }
		       while (strcmp(value, "0") && strcmp(value, "1"));
		    }
		  else if (!strcmp("PSH", value) || !strcmp("psh", value))
		    {
		       do
			 {
			    printf ("PSH FLAG (%d) : ", fpsh);
			    fgets(value, 3, stdin);
			    fpsh = atoi(value);
			    value = dn(value);
			 }
		       while (strcmp(value, "0") && strcmp(value, "1"));
		    }
		  else if (!strcmp("FIN", value) || !strcmp("fin", value))
		    {
		       do
			 {
			    printf ("FIN FLAG (%d) : ", ffin);
			    fgets(value, 3, stdin);
			    ffin = atoi(value);
			    value = dn(value);
			 }
		       while (strcmp(value, "0") && strcmp(value, "1"));
		    }
		  else if (!strcmp("CWR", value) || !strcmp("cwr", value))
		    {
		       do
			 {
			    printf ("CWR FLAG (%d) : ", fcwr);
			    fgets(value, 3, stdin);
			    fcwr = atoi(value);
			    value = dn(value);
			 }
		       while (strcmp(value, "0") && strcmp(value, "1"));
		    }
		  else if (!strcmp("ECE", value) || !strcmp("ece", value))
		    {
		       do
			 {
			    printf ("ECE FLAG (%d) : ", ffin);
			    fgets(value, 3, stdin);
			    fece = atoi(value);
			    value = dn(value);
			 }
		       while (strcmp(value, "0") && strcmp(value, "1"));
		    }
		  else if (!strcmp("DONE", value) || !strcmp("done", value))
		    break;
	       }
	  }
	else if (!strcmp ("3.4", cmd))
	  {
	     do
	       {
		  printf ("SEQUENCE NUMBER (%lu) : ", seq);
		  fgets(value, 20, stdin);
		  seq = strtoul(value, NULL, 10);
	       }
	     while (atoi(value) < 0 || strtoll(value, NULL, 10) > 4294967295U);
	  }
	else if (!strcmp ("3.5", cmd))
	  {
	     do
	       {
		  printf ("ACKNOWLEDGEMENT NUMBER (%lu) : ", ack);
		  fgets(value, 20, stdin);
		  ack = strtoul(value, NULL, 10);
	       }
	     while (atoi(value) < 0 || strtoll(value, NULL, 10) > 4294967295U);
	  }
	else if (!strcmp ("3.6", cmd))
	  {
	     do
	       {
		  printf ("WINDOW SIZE (%d) : ", win);
		  fgets(value, 20, stdin);
		  win = atoi(value);
	       }
	     while (atoi(value) < 0 || atol (value) > 65535);
	  }
	else if (!strcmp ("3.7", cmd))
	  {
	     do
	       {
		  printf ("URG POINTER (%d) : ", urgp);
		  fgets(value, 20, stdin);
		  urgp = atoi(value);
	       }
	     while (atoi(value) < 0 || atol (value) > 65535);
	  }
	else if (!strcmp ("4.1", cmd))
	  {
	     if (data)
	       free (data);
	     data = calloc (128, sizeof(u_char));
	     printf ("INSERT DATA (OR PRESS ENTER FOR NULL): ");
	     fgets(data, 128, stdin);
             data = dn (data);
	     datalen = strlen (data);
	     if (datalen==0)
	       {
		  free (data);  /* fixed: libnet_build_tcp(): payload inconsistency */
		  data = (char *) NULL;
	       }
	  }
	else if (!strcmp ("4.2", cmd))
	  {
	     do
	       {
		  printf ("LINK LAYER OPERATIONS (1=ENABLE / 0=DISABLE) : ");
		  fgets(value, 3, stdin);
		  ll = atoi(value);
	       }
	     while (ll!=0 && ll!=1);
	  }
	else if (!strcmp ("4.3", cmd))
	  {
	     do
	       {
		  printf ("\"PSEUDO_FLOAD\" (1=ENABLE / 0=DISABLE) : ");
		  fgets(value, 3, stdin);
		  multi = atoi(value);
	       }
	     while(multi!=0 && multi!=1);

	     if (multi)
	       {
		  printf ("NUMBER : ");
		  fgets(value, 20, stdin);
		  number=strtoul(value, NULL, 10);
		  printf ("DELAY (ms) : ");
		  fgets(value, 20, stdin);
		  delay=atoi(value);
	       }
	  }
       	/* */
	else if (!strcmp ("send", cmd))
	  {
	     r = 'n';
	     do
	       {
		  printf ("%sAre you sure? (y/n) >%s ", RED, WHITE);
		  r=getchar();
	       }
	     while (r!='y' && r!='Y' && r!='n' && r!='N');

	     if (r == 'y' || r == 'Y')
	       sendpkg();
	  }
	else if(!strcmp ("quit", cmd))
	  {
	     printf ("%sGoodbye!%s\n\n", RED, WHITE);
      	     /* free memory */
	     if (cmd)
	       free (cmd);
	     if (value)
	       free (value);
	     if (seth)
	       free (seth);
	     if (deth)
	       free (deth);
	     if (data)
	       free (data);
	     if (ethtype)
	       free (ethtype);
	     return 0;
	  }
	else if(!strcmp ("reset", cmd))
	  {
	     clean_values();
	     randomize();
	     autoscan();
	  }
	else if (!strcmp ("about", cmd)) 
	  {
	     printf ("%s%s\n", RED, BANNER);
	     printf ("Author: Embyte (c) 2002-2003\n");
	     printf ("Contact: embyte@madlab.it\n");
	     printf ("Licensed under GPL domain\n\n");
	     printf ("Enjoy!%s\n", WHITE);
	     getchar();
	  }
	
	else if(!strcmp ("help", cmd))
	  {
	     printf ("Numbers (1.2, 3.2, 2.2...) : modify corresponding field\n");
	     printf ("'send' : write packet on the net!\n");
	     printf ("'reset': reset default values\n");
	     printf ("'about': print version information\n");
	     printf ("'quit' : exit from program\n");
	     printf ("'help' : print this kiddie help\n\n");
	     printf ("Read README for more info (press a Key)");
	     keystroke = getchar();
	  }
	else
	  printf ("%sError: unknow command ('%s')!%s Type 'help' for available commands\n", RED, cmd, WHITE);
     }

}

void print_menu()
{
   printf ("%s\n+------------------------------------------------+\n\n", GREEN);
   printf ("%s\tETHERNET FIELDS\n%s", RED, WHITE);
   printf ("%s1.1%s INTERFACE \t\t\t: %s\n", GREEN, WHITE, device);
   printf ("%s1.2%s SOURCE ADDRESS \t\t: %X:%X:%X:%X:%X:%X\n", GREEN, WHITE, seth[0], seth[1], seth[2], seth[3], seth[4], seth[5]);
   printf ("%s1.3%s DESTINATION ADDRESS \t: %X:%X:%X:%X:%X:%X\n",GREEN, WHITE,  deth[0], deth[1], deth[2], deth[3], deth[4], deth[5]);
   printf ("%s1.4%s ETHERNET TYPE \t\t: %s\n", GREEN, WHITE, ethtype);

   printf ("\n");

   printf ("%s\tIP FIELDS\n%s", RED, WHITE);
   printf ("%s2.1%s SOURCE ADDRESS \t\t: %s\n", GREEN, WHITE, libnet_addr2name4(shost, LIBNET_DONT_RESOLVE));
   printf ("%s2.2%s DESTINATION ADDRESS \t: %s\n", GREEN, WHITE, libnet_addr2name4(dhost, LIBNET_DONT_RESOLVE));
   printf ("%s2.3%s TIME TO LIVE \t\t: %d\n", GREEN, WHITE, ttl);
   printf ("%s2.4%s ID NUMBER \t\t\t: %d\n", GREEN, WHITE, id);
   printf ("%s2.5%s DIFFERENTIATED SERVICE \t: %d\n", GREEN, WHITE, ipv4_tos.dscp);
   printf ("%s2.6%s ECN-CAPABLE TRANSPORT \t: %d\n", GREEN, WHITE, ipv4_tos.ecn_ct);
   printf ("%s2.7%s ECN-CE \t\t\t: %d\n", GREEN, WHITE, ipv4_tos.ecn_ce);

   printf ("\n");

   printf ("%s\tTCP FIELDS\n%s", RED, WHITE);
   printf ("%s3.1%s SOURCE PORT \t\t: %d\n", GREEN, WHITE, sport);
   printf ("%s3.2%s DESTINATION PORT \t\t: %d\n", GREEN, WHITE, dport);
   printf ("%s3.3%s FLAGS \t\t\t: URG %d - RST %d\n", GREEN, WHITE, furg, frst);
   printf ("\t\t\t\t: ACK %d - SYN %d\n", fack, fsyn);
   printf ("\t\t\t\t: PSH %d - FIN %d\n", fpsh, ffin);
   printf ("\t\t\t\t: CWR %d - ECE %d\n", fcwr, fece);
   printf ("%s3.4%s SEQUENCE NUMBER \t\t: %lu\n", GREEN, WHITE, seq);
   printf ("%s3.5%s ACKNOWLEDGEMENT NUMBER \t: %lu\n", GREEN, WHITE, ack);
   printf ("%s3.6%s WINDOW SIZE \t\t: %d\n", GREEN, WHITE, win);
   printf ("%s3.7%s URG POINTER \t\t: %d\n", GREEN, WHITE, urgp);

   printf ("\n");

   printf ("%s\tOPTIONS\n%s", RED, WHITE);
   if (datalen)
     printf ("%s4.1%s PAYLOAD \t\t\t: %s (%d byte)\n", GREEN, WHITE, data, datalen);
   else
     printf ("%s4.1%s PAYLOAD \t\t\t: (VOID) (0 byte)\n", GREEN, WHITE);
   if (ll)
     printf ("%s4.2%s LINK LAYER OPERATIONS \t: ENABLED\n", GREEN, WHITE);
   else
     printf ("%s4.2%s LINK LAYER OPERATIONS \t: DISABLED\n",GREEN, WHITE);
   if (multi)
     printf ("%s4.3%s \"PSEUDO_FLOAD\" \t\t: ENABLED: NUMBER = %lu ; DELAY = %dms\n", GREEN, WHITE, number, delay);
   else
     printf ("%s4.3%s \"PSEUDO_FLOAD\" \t\t: DISABLED, SENDING 1 PACKET AT TIME\n", GREEN, WHITE);

   printf ("\n");

}

void clean_values()
{
   /* setup default values */
   memset (ethtype, 0, 4*sizeof(u_char));
   memset (deth, 0, 6*sizeof(u_char));
   evalue=0x0800;
   sprintf (ethtype, "ip");

   shost=0;
   dhost=0;
   ttl=64;
   id=0;

   sport=0;
   dport=0;
   fsyn=1;
   furg=0;
   fack=0;
   fpsh=0;
   frst=0;
   ffin=0;
   win=32767;

   /* Setup ECN */
   ipv4_tos.dscp=0x02;
   ipv4_tos.ecn_ct=ipv4_tos.ecn_ce=0;
   fcwr=0;
   fece=0;
   tos=0x00;
   
   ll=0;
   if (data)
     {
	free (data);
	datalen=0;
     }
   if (multi)
     {
	multi=0;
	number=0;
	delay=0;
     }
}

void randomize()
{
   libnet_seed_prand(l);
   id = (u_short) libnet_get_prand(LIBNET_PRu16);
   seq = libnet_get_prand(LIBNET_PRu32);
   ack = libnet_get_prand(LIBNET_PRu32);
   urgp = (u_short) libnet_get_prand(LIBNET_PRu16);

}

void autoscan()
{
   struct libnet_ether_addr *ethaddr; /* tmp eth address */

   if ((l=libnet_init (LIBNET_LINK, NULL, ebuf))==NULL)
     {
	fprintf (stderr, "\nError creating libnet file context : %s", ebuf);
	fprintf (stderr, "Have you activated a non-loopback device like eth0? (man ifconfig)\n\n");
	exit_fail();
     }

   bzero (device, 10);
   strcpy(device, libnet_getdevice(l));
   if (device == NULL)
     {
	fprintf (stderr, "\nError: cannot get device name : %s\n", libnet_geterror(l));
	exit_fail();
     }

   shost = libnet_get_ipaddr4(l);
   if (shost == -1)
     {
	fprintf (stderr, "\nError: autodetect device ip address failed: %s\n", libnet_geterror(l));
	exit_fail();
     }

   ethaddr = libnet_get_hwaddr(l);
   if (ethaddr == NULL)
     {
	fprintf (stderr, "\nError: autodetect device MAC address failed: %s\n", libnet_geterror(l));
	exit_fail();
     }

   
   memcpy (seth, ethaddr->ether_addr_octet, 6);

   /* close network descriptor */
   libnet_destroy(l);

}

void sendpkg()
{
   u_short len; /* packet lenght */
   short w=0; /* byte written */
   u_short flag=0x00;
   u_long c=0;
   /* ecn */
   u_short tos_dscp, tos_ecn_ct;

   /* control flags */
   if (ffin) flag+=TH_FIN;
   if (fsyn) flag+=TH_SYN;
   if (frst) flag+=TH_RST;
   if (fpsh) flag+=TH_PUSH;
   if (fack) flag+=TH_ACK;
   if (furg) flag+=TH_URG;
   if (fece) flag+=TH_ECE;
   if (fcwr) flag+=TH_CWR;

   /* total packet lenght */
   len = LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_TCP_H + datalen;
   /* ll=0 -> len = len - LIBNET_ETH_H (LIBNET_ETH_H is build by kernel and not libnet! */

   /* rebuild IPv4 tos field */
   tos_dscp=ipv4_tos.dscp<<2;
   tos_ecn_ct=ipv4_tos.ecn_ct<<1;
   tos=tos_dscp|tos_ecn_ct|ipv4_tos.ecn_ce;

   printf ("\n");

   if (ll)
     l = libnet_init (LIBNET_LINK, device, ebuf);
   else
     l = libnet_init (LIBNET_RAW4, NULL, ebuf);

   if (l==NULL)
     {
	fprintf (stderr, "Error creating libnet file context : %s", ebuf);
	exit_fail();
     }

   printf ("%s* Libnet file context created\n", GREEN);

   /* TCP */
   if (libnet_build_tcp(sport, dport,
			seq, ack,
			flag,
			win,
			0,
			urgp,
			LIBNET_TCP_H+datalen,
			data,
			datalen,
			l, 0)==-1)
     {
	fprintf (stderr,"Error during TCP header creation : %s\n", libnet_geterror(l));
	exit_fail();
     }
   printf ("* TCP header build\n");

   /* IP */
   if (libnet_build_ipv4(LIBNET_TCP_H + LIBNET_IPV4_H + datalen,
			 tos,
			 id,
			 0,
			 ttl,
			 IPPROTO_TCP,
			 0,
			 shost, dhost,
			 NULL, 0, l, 0)==-1)
     {
	fprintf (stderr, "Error during IP header creation : %s\n", libnet_geterror(l));
	exit_fail();
     }
   printf ("* IP header build\n");

   /* ETH */
   if (ll)
     {
	if (libnet_build_ethernet(deth, seth,
				  evalue,
				  NULL, 0, l, 0)==-1)
	  {
	     fprintf (stderr, "Error during ethernet header creation : %s\n", libnet_geterror(l));
	     exit_fail();
	  }
	printf ("* Ethernet frame build\n");

     }

   if (multi)
     {
	printf ("** Writing %lu packets (delay = %d ms): ", number, delay);
	fflush(stdout);
	for (c=0; c<number; c++)
	  {
	     w = libnet_write(l);
	     if (w==-1)
	       {
		  fprintf (stderr, "Error: %s", libnet_geterror(l));
		  exit_fail();
	       }
	     printf (". ");
	     fflush(stdout);
	     usleep(delay*1000); /*ms! */
	  }
	printf ("%sDonE! (%lu * %d byte)%s\n", RED, number, w, WHITE);
     }
   else
     {
	w = libnet_write(l);
	if (w==-1)
	  {
	     fprintf (stderr, "Error: %s", libnet_geterror(l));
	     exit_fail();
	  }
	printf("%s** Packet has been correctly send (total %d bytes) %s\n", RED, w, WHITE);
     }

   /* at the end we close libnet context */
   libnet_destroy(l);
   keystroke = getchar();
   printf ("%s", WHITE);
}

int exit_fail()
{
   libnet_destroy(l);
   if (cmd)   free (cmd);
   if (value) free (value);
   if (seth) free (seth);
   if (deth) free (deth);
   if (data) free (data);
   if (ethtype) free (ethtype);
   return -1;
}

void print_getline (char **in, const char *format, ...)
{
   va_list ap;
   unsigned short lenght=0;
   char *s;

   /* Write formatted output to stdout */
   va_start (ap, format);
   vprintf (format, ap);
   fflush (stdout);
   va_end (ap);

   for (s=*in;;)
     {
	/* ask for memory (another char) */
	s=realloc(s, (lenght+1)*sizeof(char));

	if ((*(s+lenght)=getchar())=='\n')
	  {
	     *(s+lenght)='\0';	/* clear enter */
	     break;
	  }

	lenght++;
	if (lenght==1024) /* stop here to prevent DoS */
	  break;
     }
   *in=s;
}
