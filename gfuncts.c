/*
 * This file is part of Gspoof-3 (a console/gtk+ tcp/ip packet forger)
 *
 * $Name: gfunct.c $
 * $Version: 3.2 $
 * $Date: 2003/12/22 16:30:03 $
 * $Author: Embyte <embyte@madlab.it> $
 * $Copyright: Copyright (C) 2002-2003 by embyte $
 * $License: This software is under GPL version 2 of license $
 *
 */

#include <gtk/gtk.h>
#include <libnet.h>

#include "ginclude.h"
#include "gfuncts.h"
#include "common.h"

#include "interface.h"

/* private functions */
int CheckValues();
u_short datalen; /* data (tcp payload) lenght */

int Initialize()
{
   GtkTextIter start, end;
   GtkTextTag *tag;

   TextBuffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (TextView));
   gtk_text_buffer_insert_at_cursor (TextBuffer,
				     "\nWelcome to Gspoof, V. 3.2\nWritten by Embyte (c) 2002-2003\nLicensed under GPL domain\n\n", -1);

   /* put colors */
   gtk_text_buffer_get_bounds (TextBuffer, &start, &end);
   tag = gtk_text_buffer_create_tag (TextBuffer, "banner", "foreground", "red", NULL);
   gtk_text_buffer_apply_tag (TextBuffer, tag, &start, &end);

   RestoreDefault();

   return 0;
}

int RestoreDefault()
{
   struct libnet_ether_addr *ethaddr; /* eth address */
   libnet_t *l;

   /* put default value */
   bzero (&f, 6);
   bzero (&ck, 2);
   memset (data, '\0', 128);
   memset (device, '\0', 10);

   /* loading libnet core */
   if ((l=libnet_init(LIBNET_LINK, NULL, ebuf))==NULL)
     {
	fprintf (stderr, "Error creationg libnet file context : %s\n", ebuf);
	ExitFailure();
     }

   /* we probe for device */
   strcpy (device, libnet_getdevice(l));
   if (device==NULL)
     {
	fprintf (stderr, "Error: cannot get device name : %s\n", libnet_geterror(l));
	ExitFailure();
     }

   /* we probe for device's IP and MAC */
   if ((shost = libnet_get_ipaddr4(l))==-1)
     {
	fprintf (stderr, "Error: autodetect device ip address failed: %s\n", libnet_geterror(l));
	ExitFailure();
     }
   if ((ethaddr=libnet_get_hwaddr(l))==NULL)
     {
	fprintf (stderr, "Error: autodetect device MAC address failed: %s\n", libnet_geterror(l));
	ExitFailure();
     }

   /* generate random values */
   libnet_seed_prand(l);
   id = (u_short) libnet_get_prand(LIBNET_PRu16);
   seq = libnet_get_prand(LIBNET_PRu32);
   ack = libnet_get_prand(LIBNET_PRu32);
   urgp = (u_short) libnet_get_prand(LIBNET_PRu16);

   /* setup ecn */
   ipv4_tos.dscp=0x02;
   ipv4_tos.ecn_ct=0;
   ipv4_tos.ecn_ce=0;
   UpdateTos();

   /* erase libnet context *l */
   if (l)
     libnet_destroy(l);

   /* Setup interface for default values*/
   /* Eth */
   gtk_entry_set_text (GTK_ENTRY (iface_entry), device);
   gtk_entry_set_text (GTK_ENTRY (srcmac_entry), emb_hex_ntoa(ethaddr->ether_addr_octet));
   gtk_entry_set_text (GTK_ENTRY (dstmac_entry), "");

   /* Ip */
   gtk_entry_set_text (GTK_ENTRY (srcaddr_entry), libnet_addr2name4(shost, LIBNET_DONT_RESOLVE));
   gtk_entry_set_text(GTK_ENTRY (dstaddr_entry), "");
   gtk_entry_set_text (GTK_ENTRY (ttl_entry), "64");
   gtk_entry_set_text(GTK_ENTRY (id_entry),  ltostr(id));

   /* Calculate TOS */
   gtk_entry_set_text (GTK_ENTRY (tos_entry), ltostr(tos));

   /* Tcp */
   gtk_entry_set_text (GTK_ENTRY (srcport_entry), "0");
   gtk_entry_set_text (GTK_ENTRY (dstport_entry), "0");
   gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (syn_checkbutton), TRUE);
   gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (fin_checkbutton), FALSE);
   gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (push_checkbutton),FALSE);
   gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (ack_checkbutton), FALSE);
   gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (rst_checkbutton), FALSE);
   gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (urg_checkbutton), FALSE);
   gtk_entry_set_text(GTK_ENTRY (seq_entry), ltostr(seq));
   gtk_entry_set_text(GTK_ENTRY (ack_entry), ltostr(ack));
   gtk_entry_set_text (GTK_ENTRY (win_entry), "32767");
   gtk_entry_set_text(GTK_ENTRY (urg_entry), ltostr(urgp));

   /* Set default variable values */
   f.syn=1;
   m.number=10;
   m.delay=100;

   return 0;
}

int SendPacket()
{
   /* BEGIN of variables ' declaration */
   libnet_t *l;
   char *dataptr;

   u_short sport, dport;
   u_short flag=0x00;
   short w=0; /* byte written */

   /* temp variable 4 eth addr */
   u_char *seth_temp;
   u_char *deth_temp;
   u_char *seth=(u_char *) NULL;
   u_char *deth=(u_char *) NULL;
   u_char *ethtype;
   u_short evalue=0x0000;

   /* other opt */
   u_short ttl;
   u_short win;

   u_long c;
   /* END of variables declaration */

   /* initialize libnet context (*l) */
   if (ck.linkl)
     {
	memset (device, '\0', 10);
	strncpy (device, (char *) gtk_entry_get_text(GTK_ENTRY(iface_entry)), 6);
	l=libnet_init(LIBNET_LINK, device, ebuf);
     }
   else
     l=libnet_init(LIBNET_RAW4, NULL, ebuf);

   if (l==NULL)
     {
	info ("Error creating libnet context : %s\n", ebuf);
	return -1;
     }

   if (ck.debug)
     info ("Libnet contex created\n");

   ///* reading global and necessary variables *///

   /* if we work on datalink */
   if (ck.linkl)
     {
        /* eth */
	seth_temp = (u_char *) gtk_entry_get_text(GTK_ENTRY(srcmac_entry));
	deth_temp = (u_char *) gtk_entry_get_text(GTK_ENTRY(dstmac_entry));

	seth=calloc (6, sizeof (u_char));
	deth=calloc (6, sizeof (u_char));
	if ((seth=emb_hex_aton(seth_temp))==NULL)
	  {
	     info ("Invalid source MAC address\n");
	     return -1;
	  }
	if ((deth=emb_hex_aton(deth_temp))==NULL)
	  {
	     info ("Invalid destination MAC address\n");
	     return -1;
	  }

	ethtype = (u_char *) gtk_entry_get_text (GTK_ENTRY (ethtype_combo_entry));
	if (!strcmp(ethtype, "IP"))
	  evalue = 0x0800;
	else
	  evalue = 0x0900;
     }

   /* Check values */
   if (CheckValues()<0)
     return -1;

   /* ip */
   shost = libnet_name2addr4(l, (char *) gtk_entry_get_text (GTK_ENTRY(srcaddr_entry)), LIBNET_RESOLVE);
   if (shost==-1)
     {
	info ("Invalid source ip address: %s\n", libnet_geterror(l));
	return -1;
     }
   dhost = libnet_name2addr4(l, (char *) gtk_entry_get_text (GTK_ENTRY(dstaddr_entry)), LIBNET_RESOLVE);
   if (dhost==-1)
     {
	info ("Invalid destination ip address: %s\n", libnet_geterror(l));
	return -1;
     }

   tos = atoi (gtk_entry_get_text (GTK_ENTRY(tos_entry)));
   ttl = atoi (gtk_entry_get_text (GTK_ENTRY(ttl_entry)));
   id  = atoi (gtk_entry_get_text (GTK_ENTRY(id_entry)));

   /* tcp */
   sport = atoi(gtk_entry_get_text(GTK_ENTRY(srcport_entry)));
   dport = atoi(gtk_entry_get_text (GTK_ENTRY(dstport_entry)));
   if (f.syn) flag+=TH_SYN;
   if (f.ack) flag+=TH_ACK;
   if (f.fin) flag+=TH_FIN;
   if (f.rst) flag+=TH_RST;
   if (f.psh) flag+=TH_PUSH;
   if (f.urg) flag+=TH_URG;
   if (f.ece) flag+=TH_ECE;
   if (f.cwr) flag+=TH_CWR;
   seq = strtoul (gtk_entry_get_text (GTK_ENTRY(seq_entry)), NULL, 10);
   ack = strtoul (gtk_entry_get_text (GTK_ENTRY(ack_entry)), NULL, 10);
   win = atoi (gtk_entry_get_text (GTK_ENTRY(win_entry)));
   urgp = atoi (gtk_entry_get_text (GTK_ENTRY(urg_entry)));

   /* data */
   if (ck.data)
     {
	datalen = strlen (data);
	if (!datalen)
	  {
	     info ("You have selected payload option but you haven't entered one\n");
	     return -1;
	  }
	dataptr=data;
     }
   else
     {
	datalen = 0;
	dataptr = (char *) NULL; /* fixed: libnet_build_tcp(): payload inconsistency */
     }

   if (ck.debug)
     info ("Variables have been read\n");

   /* build packet */
   if (libnet_build_tcp(sport, dport,
			seq, ack,
			flag,
			win,
			0,
			urgp,
			LIBNET_TCP_H+datalen,
			dataptr,
			datalen,
			l, 0)==-1)
     {
	info ("Error creating tcp header: %s\n", libnet_geterror(l));
	return -1;
     }

   if (ck.debug)
     info ("Tcp header build\n");

   if (libnet_build_ipv4(40+datalen,
			 tos,
			 id,
			 0,
			 ttl,
			 IPPROTO_TCP,
			 0,
			 shost, dhost,
			 NULL, 0, l, 0)==-1)
     {
	info ("Error crating ip header: %s\n", libnet_geterror(l));
	return -1;
     }

   if (ck.debug)
     info ("Ip header build\n");

   if (ck.linkl) /* add ethernet header */
     {
	if (libnet_build_ethernet (deth, seth,
				   evalue,
				   NULL, 0, l, 0)==-1)
	  {
	     info ("Error creating datalink header: %s\n", libnet_geterror(l));
	     return -1;
	  }
	if (ck.debug)
	  info ("Ethernet header build\n");
     }

   if (ck.multi)
     {
	info ("Sending %lu packets (delay = %lu ms): ", m.number, m.delay);

	for (c=0; c<m.number; c++)
	  {
	     if ((w=libnet_write(l))==-1)
	       {
		  info ("Error writing packet : %s\n", libnet_geterror(l));
		  return -1;
	       }
	     info (". ");
	     usleep (m.delay*1000);	/* ms */
	  }
	info ("\nPackets correctly written (%lu x %d bytes)\n", m.number, w);
     }
   else
     {
	if ((w=libnet_write(l))==-1)
	  {
	     info ("Error writing packet : %s\n", libnet_geterror(l));
	     return -1;
	  }
	info ("Packet correctly written (%d bytes)\n", w);
     }

   libnet_destroy(l);
   if (ck.debug)
     info ("Finished, libnet context closed\n");

   return 0;

}

int info (const char *format, ...)
{
   GtkTextIter start, end;
   GtkTextMark *mark;
   char s[128]; /* MAX 128! */

   va_list  ap;
   va_start (ap, format);
   vsprintf (s, format, ap);

   gtk_text_buffer_get_bounds (TextBuffer, &start, &end);
   gtk_text_buffer_insert (TextBuffer, &end, s, -1);
   gtk_text_buffer_get_bounds (TextBuffer, &start, &end);
   mark = gtk_text_buffer_create_mark (TextBuffer, "scrollmark", &end, FALSE);
   gtk_text_view_scroll_to_mark (GTK_TEXT_VIEW (TextView), mark, 0.2, FALSE, 0.0, 0.0);
   gtk_text_buffer_delete_mark (TextBuffer, mark);
   gdk_flush();

   while (g_main_iteration(FALSE));

   va_end (ap);

   return 0;
}

void ExitFailure()
{
   fprintf (stderr, "\nCritical error! Quitting!\n\n");
   gtk_exit(-1);
}

int CheckValues()
{
   /* ip */
   if (atoi(gtk_entry_get_text(GTK_ENTRY(ttl_entry)))<0 ||
       atoi(gtk_entry_get_text(GTK_ENTRY(ttl_entry)))>255)
     {
	info ("Invalid time to live (ttl) value\n");
	return -1;
     }
   if (atol(gtk_entry_get_text(GTK_ENTRY(id_entry)))<0 ||
       atol(gtk_entry_get_text(GTK_ENTRY(id_entry)))>65535)
     {
	info ("Invalid id value\n");
	return -1;
     }
   if (atoi(gtk_entry_get_text(GTK_ENTRY(tos_entry)))<0 ||
       atoi(gtk_entry_get_text(GTK_ENTRY(tos_entry)))>255)
     {
	info ("Invalid type of service (tos) value\n");
	return -1;
     }

   /* tcp */
   if (atol(gtk_entry_get_text(GTK_ENTRY(srcport_entry)))<0 ||
       atol(gtk_entry_get_text(GTK_ENTRY(srcport_entry)))>65535)
     {
	info ("Invalid source port value\n");
	return -1;
     }
   if (atol(gtk_entry_get_text(GTK_ENTRY(dstport_entry)))<0 ||
       atol(gtk_entry_get_text(GTK_ENTRY(dstport_entry)))>65535)
     {
	info ("Invalid destination port value\n");
	return -1;
     }
   if (strtoll(gtk_entry_get_text(GTK_ENTRY(seq_entry)), NULL, 10)<0 ||
       strtoll(gtk_entry_get_text(GTK_ENTRY(seq_entry)), NULL, 10)>4294967295U)
     {
	info ("Invalid sequence number value\n");
	return -1;
     }
   if (strtoll(gtk_entry_get_text(GTK_ENTRY(ack_entry)), NULL, 10)<0 ||
       strtoll(gtk_entry_get_text(GTK_ENTRY(ack_entry)), NULL, 10)>4294967295U)
     {
	info ("Invalid acknowledgment value\n");
	return -1;
     }
   if (atol(gtk_entry_get_text(GTK_ENTRY(win_entry)))<0 ||
       atol(gtk_entry_get_text(GTK_ENTRY(win_entry)))>65535)
     {
	info ("Invalid win size value\n");
	return -1;
     }
   if (atol(gtk_entry_get_text(GTK_ENTRY(urg_entry)))<0 ||
       atol(gtk_entry_get_text(GTK_ENTRY(urg_entry)))>65535)
     {
	info ("Invalid urg pointer value\n");
	return -1;
     }

   return 0;
}

void UpdateTos()
{
   u_short tos_dscp;
   u_short tos_ecn_ct;

   tos_dscp=ipv4_tos.dscp<<2;
   tos_ecn_ct=ipv4_tos.ecn_ct<<1;
   tos=tos_dscp|tos_ecn_ct|ipv4_tos.ecn_ce;

   gtk_entry_set_text(GTK_ENTRY(tos_entry), ltostr(tos));
}
