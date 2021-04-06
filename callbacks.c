/*
 * This file is part of Gspoof-3 (a console/gtk+ tcp/ip packet forger)
 *
 * $Name: callbacks.c $
 * $Version: 3.2 $
 * $Date: 2003/12/22 16:30:03 $
 * $Author: Embyte <embyte@madlab.it> $
 * $Copyright: Copyright (C) 2002-2003 by embyte $
 * $License: This software is under GPL version 2 of license $
 *
 */

#include "ginclude.h"
#include "callbacks.h"
#include "interface.h"
#include "support.h"
#include "gfuncts.h"
#include "common.h"

void on_new1_activate()
{
   RestoreDefault();
   info ("Restored to default values\n");
}

void on_about1_activate()
{

   GtkWidget* AboutWin = create_AboutWin ();
   gtk_widget_show (AboutWin);
}

void on_quit1_activate()
{
   gtk_exit(0);
}

void on_full_mode2_activate()
{
   ck.linkl=~ck.linkl;

   if (ck.linkl) /* work on datalink */
     gtk_widget_set_sensitive (DatalinkFrame, TRUE);
   else
     gtk_widget_set_sensitive (DatalinkFrame, FALSE);
}

void on_add_data2_activate()
{
   GtkWidget *DataWin = create_DataWin ();
   gtk_widget_show_all (DataWin);
}

void on_send_multi_packets1_activate()
{
   GtkWidget *MPackets = create_MultiPackets ();
   gtk_widget_show_all (MPackets);
}

void on_ecn_support1_activate()
{
   GtkWidget *EcnWIN = create_ECNWin ();
   gtk_widget_show_all (EcnWIN);
}

void on_syn_checkbutton_toggled()
{
   f.syn=~f.syn;
}

void on_fin_checkbutton_toggled()
{
   f.fin=~f.fin;
}

void on_push_checkbutton_toggled()
{
   f.psh=~f.psh;
}

void on_ack_checkbutton_toggled()
{
   f.ack=~f.ack;
}

void on_rst_checkbutton_toggled()
{
   f.rst=~f.rst;
}

void on_urg_checkbutton_toggled()
{
   f.urg=~f.urg;
}
void on_ece_checkbutton_toggled()
{
   f.ece=~f.ece;
}
void on_cwr_checkbutton_toggled()
{
   f.cwr=~f.cwr;
}

void on_SendButton_clicked()
{
   if (SendPacket()==-1)
     info ("Fatal error: cannot send packet!\n");
}

void on_DataButton_toggled()
{
   ck.data=~ck.data;

   if (ck.data)
     gtk_widget_set_sensitive (DataEntry, TRUE);
   else
     gtk_widget_set_sensitive (DataEntry, FALSE);
}

void on_MultiButton_toggled()
{
   ck.multi=~ck.multi;

   if (ck.multi)
     gtk_widget_set_sensitive (table2, TRUE);
   else
     gtk_widget_set_sensitive (table2, FALSE);
}

void on_NumberEntryMulti_changed()
{
   if (strtoll(gtk_entry_get_text(GTK_ENTRY(NumberEntryMulti)), NULL, 10)<0 ||
       strtoll(gtk_entry_get_text(GTK_ENTRY(NumberEntryMulti)), NULL, 10)>4294967295U)
     {
	gtk_entry_set_text(GTK_ENTRY(NumberEntryMulti), "10");
	info ("Multi mode: invalid number value\n");
     }
   else
     m.number=strtoul(gtk_entry_get_text(GTK_ENTRY(NumberEntryMulti)), NULL, 10);
}

void on_DelayEntryMulty_changed()
{
   if (strtoll(gtk_entry_get_text(GTK_ENTRY(DelayEntryMulty)), NULL, 10)<0 ||
       strtoll(gtk_entry_get_text(GTK_ENTRY(DelayEntryMulty)), NULL, 10)>4294967295U)

     {
	gtk_entry_set_text(GTK_ENTRY(DelayEntryMulty), "100");
	info ("Multi mode: invalid delay value\n");
     }
   else
     m.delay=strtoul(gtk_entry_get_text(GTK_ENTRY(DelayEntryMulty)), NULL, 10);	/* ms */
}

void on_DataEntry_changed()
{
   sprintf (data, (char *) gtk_entry_get_text (GTK_ENTRY((DataEntry))));
}

void on_dscpEntry_changed()
{
   if (atoi(gtk_entry_get_text(GTK_ENTRY(dscpEntry)))>63
       || atoi(gtk_entry_get_text(GTK_ENTRY(dscpEntry)))<0)
     {
	gtk_entry_set_text(GTK_ENTRY(dscpEntry), "2");
	info ("Differentiated service: invalid value (should be 0=<dscp<64)\n");
     }
   else
     {
	ipv4_tos.dscp=(u_short)atoi(gtk_entry_get_text(GTK_ENTRY(dscpEntry)));
	UpdateTos();
     }

}

void on_debug_check_activate()
{
   ck.debug=~ck.debug;
}

void on_MainWin_delete_event()
{
   gtk_exit(0);
}

void on_ecn_ct0_toggled()
{
   ipv4_tos.ecn_ct=0;
   UpdateTos();
}

void on_ecn_ct1_toggled()
{
   ipv4_tos.ecn_ct=1;
   UpdateTos();
}

void on_ecn_ce0_toggled()
{
   ipv4_tos.ecn_ce=0;
   UpdateTos();
}

void on_ecn_ce1_toggled()
{
   ipv4_tos.ecn_ce=1;
   UpdateTos();
}

