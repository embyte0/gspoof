/*
 * This file is part of Gspoof-3 (a console/gtk+ tcp/ip packet forger)
 *
 * $Name: interface.c $
 * $Version: 3.2 $
 * $Date: 2003/12/22 16:30:03 $
 * $Author: Embyte <embyte@madlab.it> $
 * $Copyright: Copyright (C) 2002-2003 by embyte $
 * $License: This software is under GPL version 2 of license $
 *
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include <gdk/gdkkeysyms.h>
#include <gtk/gtk.h>

#include "callbacks.h"
#include "interface.h"
#include "support.h"
#include "ginclude.h" /* define payload and multi options */
#include "common.h"

#define GLADE_HOOKUP_OBJECT(component,widget,name) \
  g_object_set_data_full (G_OBJECT (component), name, \
    gtk_widget_ref (widget), (GDestroyNotify) gtk_widget_unref)

#define GLADE_HOOKUP_OBJECT_NO_REF(component,widget,name) \
  g_object_set_data (G_OBJECT (component), name, widget)

GtkWidget* create_MainWin (void)
{
   GtkWidget *MainWin;
   GdkPixbuf *MainWin_icon_pixbuf;
   GtkWidget *vbox1;
   GtkWidget *vbox3;
   GtkWidget *menubar1;
   GtkWidget *menuitem1;
   GtkWidget *menuitem1_menu;
   GtkWidget *new1;
   GtkWidget *image25;
   GtkWidget *about1;
   GtkWidget *image26;
   GtkWidget *quit1;
   GtkWidget *image27;
   GtkWidget *options1;
   GtkWidget *options1_menu;
   GtkWidget *full_mode2;
   GtkWidget *debug_check;
   GtkWidget *add_data2;
   GtkWidget *image28;
   GtkWidget *send_multi_packets1;
   GtkWidget *image29;
   GtkWidget *image30;
   GtkWidget *MainTable;
   GtkWidget *MainFieldBox;
   GtkWidget *NetworkFrame;
   GtkWidget *network_hbox;
   GtkWidget *network_vboxsx;
   GtkWidget *label8;
   GtkWidget *label9;
   GtkWidget *label10;
   GtkWidget *label11;
   GtkWidget *label12;
   GtkWidget *network_vboxdx;
   GtkWidget *NetworkText;
   GtkWidget *Transport_Frame;
   GtkWidget *transport_hbox;
   GtkWidget *transport_vboxsx;
   GtkWidget *label19;
   GtkWidget *label18;
   GtkWidget *label16;
   GtkWidget *label15;
   GtkWidget *label14;
   GtkWidget *label13;
   GtkWidget *transport_vboxdx;
   GtkWidget *TransportText;
   GtkWidget *datalink_hbox;
   GtkWidget *datalink_vboxsx;
   GtkWidget *label4;
   GtkWidget *label5;
   GtkWidget *label6;
   GtkWidget *label7;
   GtkWidget *datalink_vboxdx;
   GtkWidget *DatalinkText;
   GtkWidget *SendBox;
   GtkWidget *SendButton;
   GtkWidget *ecn_support1;
   GtkTooltips *tooltips;

   GList *items;

   tooltips = gtk_tooltips_new ();

   MainWin = gtk_window_new (GTK_WINDOW_TOPLEVEL);
   gtk_widget_set_size_request (MainWin, 640, 480);
   gtk_window_set_title (GTK_WINDOW (MainWin), BANNER);
   gtk_window_set_position (GTK_WINDOW (MainWin), GTK_WIN_POS_CENTER);
   MainWin_icon_pixbuf = create_pixbuf ("icon.png");
   if (MainWin_icon_pixbuf)
     {
	gtk_window_set_icon (GTK_WINDOW (MainWin), MainWin_icon_pixbuf);
	gdk_pixbuf_unref (MainWin_icon_pixbuf);
     }

   vbox1 = gtk_vbox_new (FALSE, 0);
   gtk_widget_show (vbox1);
   gtk_container_add (GTK_CONTAINER (MainWin), vbox1);

   menubar1 = gtk_menu_bar_new ();
   gtk_widget_show (menubar1);
   gtk_box_pack_start (GTK_BOX (vbox1), menubar1, FALSE, FALSE, 0);

   menuitem1 = gtk_menu_item_new_with_mnemonic (_("_File"));
   gtk_widget_show (menuitem1);
   gtk_container_add (GTK_CONTAINER (menubar1), menuitem1);

   menuitem1_menu = gtk_menu_new ();
   gtk_menu_item_set_submenu (GTK_MENU_ITEM (menuitem1), menuitem1_menu);

   new1 = gtk_image_menu_item_new_with_mnemonic (_("New"));
   gtk_widget_show (new1);
   gtk_container_add (GTK_CONTAINER (menuitem1_menu), new1);

   image25 = gtk_image_new_from_stock ("gtk-clear", GTK_ICON_SIZE_MENU);
   gtk_widget_show (image25);
   gtk_image_menu_item_set_image (GTK_IMAGE_MENU_ITEM (new1), image25);

   about1 = gtk_image_menu_item_new_with_mnemonic (_("About"));
   gtk_widget_show (about1);
   gtk_container_add (GTK_CONTAINER (menuitem1_menu), about1);

   image26 = gtk_image_new_from_stock ("gtk-dialog-info", GTK_ICON_SIZE_MENU);
   gtk_widget_show (image26);
   gtk_image_menu_item_set_image (GTK_IMAGE_MENU_ITEM (about1), image26);

   quit1 = gtk_image_menu_item_new_with_mnemonic (_("Quit"));
   gtk_widget_show (quit1);
   gtk_container_add (GTK_CONTAINER (menuitem1_menu), quit1);

   image27 = gtk_image_new_from_stock ("gtk-quit", GTK_ICON_SIZE_MENU);
   gtk_widget_show (image27);
   gtk_image_menu_item_set_image (GTK_IMAGE_MENU_ITEM (quit1), image27);

   options1 = gtk_menu_item_new_with_mnemonic (_("_Options"));
   gtk_widget_show (options1);
   gtk_container_add (GTK_CONTAINER (menubar1), options1);

   options1_menu = gtk_menu_new ();
   gtk_menu_item_set_submenu (GTK_MENU_ITEM (options1), options1_menu);

   add_data2 = gtk_image_menu_item_new_with_mnemonic (_("Add data"));
   gtk_widget_show (add_data2);
   gtk_container_add (GTK_CONTAINER (options1_menu), add_data2);

   image28 = gtk_image_new_from_stock ("gtk-justify-center", GTK_ICON_SIZE_MENU);
   gtk_widget_show (image28);
   gtk_image_menu_item_set_image (GTK_IMAGE_MENU_ITEM (add_data2), image28);

   send_multi_packets1 = gtk_image_menu_item_new_with_mnemonic (_("Send multi packets"));
   gtk_widget_show (send_multi_packets1);
   gtk_container_add (GTK_CONTAINER (options1_menu), send_multi_packets1);

   image29 = gtk_image_new_from_stock ("gtk-refresh", GTK_ICON_SIZE_MENU);
   gtk_widget_show (image29);
   gtk_image_menu_item_set_image (GTK_IMAGE_MENU_ITEM (send_multi_packets1), image29);

   ecn_support1 = gtk_image_menu_item_new_with_mnemonic (_("ECN support"));
   gtk_widget_show (ecn_support1);
   gtk_container_add (GTK_CONTAINER (options1_menu), ecn_support1);

   image30 = gtk_image_new_from_stock ("gtk-yes", GTK_ICON_SIZE_MENU);
   gtk_widget_show (image30);
   gtk_image_menu_item_set_image (GTK_IMAGE_MENU_ITEM (ecn_support1), image30);

   full_mode2 = gtk_check_menu_item_new_with_mnemonic (_("Full mode"));
   gtk_widget_show (full_mode2);
   gtk_container_add (GTK_CONTAINER (options1_menu), full_mode2);

   debug_check = gtk_check_menu_item_new_with_mnemonic (_("Debug"));
   gtk_widget_show (debug_check);
   gtk_container_add (GTK_CONTAINER (options1_menu), debug_check);

   MainTable = gtk_vbox_new (FALSE, 0);
   gtk_widget_show (MainTable);
   gtk_box_pack_start (GTK_BOX (vbox1), MainTable, TRUE, TRUE, 0);

   MainFieldBox = gtk_table_new (1, 3, TRUE);
   gtk_widget_show (MainFieldBox);
   gtk_box_pack_start (GTK_BOX (MainTable), MainFieldBox, TRUE, TRUE, 0);
   gtk_container_set_border_width (GTK_CONTAINER (MainFieldBox), 1);
   gtk_table_set_col_spacings (GTK_TABLE (MainFieldBox), 1);

   NetworkFrame = gtk_frame_new (NULL);
   gtk_widget_show (NetworkFrame);
   gtk_table_attach (GTK_TABLE (MainFieldBox), NetworkFrame, 1, 2, 0, 1,
		     (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
		     (GtkAttachOptions) (GTK_FILL), 0, 0);

   network_hbox = gtk_hbox_new (FALSE, 0);
   gtk_widget_show (network_hbox);
   gtk_container_add (GTK_CONTAINER (NetworkFrame), network_hbox);
   gtk_container_set_border_width (GTK_CONTAINER (network_hbox), 5);

   network_vboxsx = gtk_vbox_new (TRUE, 0);
   gtk_widget_show (network_vboxsx);
   gtk_box_pack_start (GTK_BOX (network_hbox), network_vboxsx, TRUE, TRUE, 0);
   gtk_widget_set_size_request (network_vboxsx, 90, -1);

   label8 = gtk_label_new (_("Src addr    "));
   gtk_widget_show (label8);
   gtk_box_pack_start (GTK_BOX (network_vboxsx), label8, FALSE, FALSE, 0);
   gtk_label_set_justify (GTK_LABEL (label8), GTK_JUSTIFY_LEFT);
   gtk_misc_set_padding (GTK_MISC (label8), 2, 0);

   label9 = gtk_label_new (_("Dst addr"));
   gtk_widget_show (label9);
   gtk_box_pack_start (GTK_BOX (network_vboxsx), label9, FALSE, FALSE, 0);
   gtk_label_set_justify (GTK_LABEL (label9), GTK_JUSTIFY_LEFT);

   label10 = gtk_label_new (_("TTL"));
   gtk_widget_show (label10);
   gtk_box_pack_start (GTK_BOX (network_vboxsx), label10, FALSE, FALSE, 0);
   gtk_label_set_justify (GTK_LABEL (label10), GTK_JUSTIFY_LEFT);

   label11 = gtk_label_new (_("ID"));
   gtk_widget_show (label11);
   gtk_box_pack_start (GTK_BOX (network_vboxsx), label11, FALSE, FALSE, 0);
   gtk_label_set_justify (GTK_LABEL (label11), GTK_JUSTIFY_LEFT);

   label12 = gtk_label_new (_("TOS"));
   gtk_widget_show (label12);
   gtk_box_pack_start (GTK_BOX (network_vboxsx), label12, FALSE, FALSE, 0);
   gtk_label_set_justify (GTK_LABEL (label12), GTK_JUSTIFY_LEFT);

   network_vboxdx = gtk_vbox_new (TRUE, 0);
   gtk_widget_show (network_vboxdx);
   gtk_box_pack_start (GTK_BOX (network_hbox), network_vboxdx, TRUE, TRUE, 0);

   srcaddr_entry = gtk_entry_new ();
   gtk_widget_show (srcaddr_entry);
   gtk_box_pack_start (GTK_BOX (network_vboxdx), srcaddr_entry, FALSE, FALSE, 0);
   gtk_entry_set_max_length (GTK_ENTRY (srcaddr_entry), 15);

   dstaddr_entry = gtk_entry_new ();
   gtk_widget_show (dstaddr_entry);
   gtk_box_pack_start (GTK_BOX (network_vboxdx), dstaddr_entry, FALSE, FALSE, 0);
   gtk_entry_set_max_length (GTK_ENTRY (dstaddr_entry), 15);

   ttl_entry = gtk_entry_new ();
   gtk_widget_show (ttl_entry);
   gtk_box_pack_start (GTK_BOX (network_vboxdx), ttl_entry, FALSE, FALSE, 0);
   gtk_entry_set_max_length (GTK_ENTRY (ttl_entry), 3);

   id_entry = gtk_entry_new ();
   gtk_widget_show (id_entry);
   gtk_box_pack_start (GTK_BOX (network_vboxdx), id_entry, FALSE, FALSE, 0);
   gtk_entry_set_max_length (GTK_ENTRY (id_entry), 5);

   tos_entry = gtk_entry_new ();
   gtk_widget_show (tos_entry);
   gtk_box_pack_start (GTK_BOX (network_vboxdx), tos_entry, FALSE, FALSE, 0);
   gtk_editable_set_editable (GTK_EDITABLE (tos_entry), FALSE);

   NetworkText = gtk_label_new (_("Network Layer"));
   gtk_widget_show (NetworkText);
   gtk_frame_set_label_widget (GTK_FRAME (NetworkFrame), NetworkText);
   gtk_label_set_justify (GTK_LABEL (NetworkText), GTK_JUSTIFY_LEFT);

   Transport_Frame = gtk_frame_new (NULL);
   gtk_widget_show (Transport_Frame);
   gtk_table_attach (GTK_TABLE (MainFieldBox), Transport_Frame, 2, 3, 0, 1,
		     (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
		     (GtkAttachOptions) (GTK_FILL), 0, 0);

   transport_hbox = gtk_hbox_new (FALSE, 0);
   gtk_widget_show (transport_hbox);
   gtk_container_add (GTK_CONTAINER (Transport_Frame), transport_hbox);
   gtk_container_set_border_width (GTK_CONTAINER (transport_hbox), 6);

   transport_vboxsx = gtk_vbox_new (TRUE, 0);
   gtk_widget_show (transport_vboxsx);
   gtk_box_pack_start (GTK_BOX (transport_hbox), transport_vboxsx, TRUE, TRUE, 0);
   gtk_widget_set_size_request (transport_vboxsx, 90, -1);

   label19 = gtk_label_new (_("Src port    "));
   gtk_widget_show (label19);
   gtk_box_pack_start (GTK_BOX (transport_vboxsx), label19, FALSE, FALSE, 0);
   gtk_misc_set_padding (GTK_MISC (label19), 3, 0);

   label18 = gtk_label_new (_("Dst port"));
   gtk_widget_show (label18);
   gtk_box_pack_start (GTK_BOX (transport_vboxsx), label18, FALSE, FALSE, 0);

   vbox3 = gtk_vbox_new (FALSE, 0);
   gtk_widget_show (vbox3);
   gtk_box_pack_start (GTK_BOX (transport_vboxsx), vbox3, FALSE, FALSE, 0);

   ece_checkbutton = gtk_check_button_new_with_mnemonic (_("ECE"));
   gtk_widget_show (ece_checkbutton);
   gtk_box_pack_start (GTK_BOX (vbox3), ece_checkbutton, FALSE, FALSE, 0);

   cwr_checkbutton = gtk_check_button_new_with_mnemonic (_("CWR"));
   gtk_widget_show (cwr_checkbutton);
   gtk_box_pack_start (GTK_BOX (vbox3), cwr_checkbutton, FALSE, FALSE, 0);

   label16 = gtk_label_new (_("SEQ"));
   gtk_widget_show (label16);
   gtk_box_pack_start (GTK_BOX (transport_vboxsx), label16, FALSE, FALSE, 0);

   label15 = gtk_label_new (_("ACK"));
   gtk_widget_show (label15);
   gtk_box_pack_start (GTK_BOX (transport_vboxsx), label15, FALSE, FALSE, 0);

   label14 = gtk_label_new (_("Win Size"));
   gtk_widget_show (label14);
   gtk_box_pack_start (GTK_BOX (transport_vboxsx), label14, FALSE, FALSE, 0);

   label13 = gtk_label_new (_("URG"));
   gtk_widget_show (label13);
   gtk_box_pack_start (GTK_BOX (transport_vboxsx), label13, FALSE, FALSE, 0);

   transport_vboxdx = gtk_vbox_new (TRUE, 0);
   gtk_widget_show (transport_vboxdx);
   gtk_box_pack_start (GTK_BOX (transport_hbox), transport_vboxdx, TRUE, TRUE, 0);

   srcport_entry = gtk_entry_new ();
   gtk_widget_show (srcport_entry);
   gtk_box_pack_start (GTK_BOX (transport_vboxdx), srcport_entry, FALSE, FALSE, 0);

   dstport_entry = gtk_entry_new ();
   gtk_widget_show (dstport_entry);
   gtk_box_pack_start (GTK_BOX (transport_vboxdx), dstport_entry, FALSE, FALSE, 0);

   flags_table = gtk_table_new (3, 2, FALSE);
   gtk_widget_show (flags_table);
   gtk_box_pack_start (GTK_BOX (transport_vboxdx), flags_table, TRUE, FALSE, 0);
   gtk_table_set_col_spacings (GTK_TABLE (flags_table), 17);

   syn_checkbutton = gtk_check_button_new_with_mnemonic (_("SYN"));
   gtk_widget_show (syn_checkbutton);
   gtk_table_attach (GTK_TABLE (flags_table), syn_checkbutton, 0, 1, 0, 1,
		     (GtkAttachOptions) (GTK_FILL),
		     (GtkAttachOptions) (0), 0, 0);
   gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (syn_checkbutton), TRUE);

   fin_checkbutton = gtk_check_button_new_with_mnemonic (_("FIN"));
   gtk_widget_show (fin_checkbutton);
   gtk_table_attach (GTK_TABLE (flags_table), fin_checkbutton, 0, 1, 1, 2,
		     (GtkAttachOptions) (GTK_FILL),
		     (GtkAttachOptions) (0), 0, 0);

   push_checkbutton = gtk_check_button_new_with_mnemonic (_("PUSH"));
   gtk_widget_show (push_checkbutton);
   gtk_table_attach (GTK_TABLE (flags_table), push_checkbutton, 0, 1, 2, 3,
		     (GtkAttachOptions) (GTK_FILL),
		     (GtkAttachOptions) (0), 0, 0);

   ack_checkbutton = gtk_check_button_new_with_mnemonic (_("ACK"));
   gtk_widget_show (ack_checkbutton);
   gtk_table_attach (GTK_TABLE (flags_table), ack_checkbutton, 1, 2, 0, 1,
		     (GtkAttachOptions) (GTK_FILL),
		     (GtkAttachOptions) (0), 0, 0);

   rst_checkbutton = gtk_check_button_new_with_mnemonic (_("RST"));
   gtk_widget_show (rst_checkbutton);
   gtk_table_attach (GTK_TABLE (flags_table), rst_checkbutton, 1, 2, 1, 2,
		     (GtkAttachOptions) (GTK_FILL),
		     (GtkAttachOptions) (0), 0, 0);

   urg_checkbutton = gtk_check_button_new_with_mnemonic (_("URG"));
   gtk_widget_show (urg_checkbutton);
   gtk_table_attach (GTK_TABLE (flags_table), urg_checkbutton, 1, 2, 2, 3,
		     (GtkAttachOptions) (GTK_FILL),
		     (GtkAttachOptions) (0), 0, 0);

   seq_entry = gtk_entry_new ();
   gtk_widget_show (seq_entry);
   gtk_box_pack_start (GTK_BOX (transport_vboxdx), seq_entry, FALSE, FALSE, 0);

   ack_entry = gtk_entry_new ();
   gtk_widget_show (ack_entry);
   gtk_box_pack_start (GTK_BOX (transport_vboxdx), ack_entry, FALSE, FALSE, 0);

   win_entry = gtk_entry_new ();
   gtk_widget_show (win_entry);
   gtk_box_pack_start (GTK_BOX (transport_vboxdx), win_entry, FALSE, FALSE, 0);

   urg_entry = gtk_entry_new ();
   gtk_widget_show (urg_entry);
   gtk_box_pack_start (GTK_BOX (transport_vboxdx), urg_entry, FALSE, FALSE, 0);

   TransportText = gtk_label_new (_("Transport Layer"));
   gtk_widget_show (TransportText);
   gtk_frame_set_label_widget (GTK_FRAME (Transport_Frame), TransportText);

   DatalinkFrame = gtk_frame_new (NULL);
   gtk_widget_show (DatalinkFrame);
   gtk_table_attach (GTK_TABLE (MainFieldBox), DatalinkFrame, 0, 1, 0, 1,
		     (GtkAttachOptions) (GTK_FILL),
		     (GtkAttachOptions) (GTK_EXPAND | GTK_FILL), 0, 0);

   datalink_hbox = gtk_hbox_new (FALSE, 0);
   gtk_widget_show (datalink_hbox);
   gtk_container_add (GTK_CONTAINER (DatalinkFrame), datalink_hbox);
   gtk_container_set_border_width (GTK_CONTAINER (datalink_hbox), 5);

   datalink_vboxsx = gtk_vbox_new (TRUE, 0);
   gtk_widget_show (datalink_vboxsx);
   gtk_box_pack_start (GTK_BOX (datalink_hbox), datalink_vboxsx, TRUE, TRUE, 0);
   gtk_widget_set_size_request (datalink_vboxsx, 90, -1);

   label4 = gtk_label_new (_("Iface         "));
   gtk_widget_show (label4);
   gtk_box_pack_start (GTK_BOX (datalink_vboxsx), label4, FALSE, FALSE, 0);
   gtk_label_set_line_wrap (GTK_LABEL (label4), TRUE);
   gtk_misc_set_padding (GTK_MISC (label4), 13, 0);

   label5 = gtk_label_new (_("Src mac"));
   gtk_widget_show (label5);
   gtk_box_pack_start (GTK_BOX (datalink_vboxsx), label5, FALSE, FALSE, 0);
   gtk_label_set_justify (GTK_LABEL (label5), GTK_JUSTIFY_LEFT);

   label6 = gtk_label_new (_("Dst mac"));
   gtk_widget_show (label6);
   gtk_box_pack_start (GTK_BOX (datalink_vboxsx), label6, FALSE, FALSE, 0);
   gtk_label_set_justify (GTK_LABEL (label6), GTK_JUSTIFY_LEFT);

   label7 = gtk_label_new (_("Eth Type"));
   gtk_widget_show (label7);
   gtk_box_pack_start (GTK_BOX (datalink_vboxsx), label7, FALSE, FALSE, 0);

   datalink_vboxdx = gtk_vbox_new (TRUE, 0);
   gtk_widget_show (datalink_vboxdx);
   gtk_box_pack_start (GTK_BOX (datalink_hbox), datalink_vboxdx, TRUE, TRUE, 0);

   iface_entry = gtk_entry_new ();
   gtk_widget_show (iface_entry);
   gtk_box_pack_start (GTK_BOX (datalink_vboxdx), iface_entry, FALSE, FALSE, 0);
   gtk_entry_set_max_length (GTK_ENTRY (iface_entry), 9);

   srcmac_entry = gtk_entry_new ();
   gtk_widget_show (srcmac_entry);
   gtk_box_pack_start (GTK_BOX (datalink_vboxdx), srcmac_entry, FALSE, FALSE, 0);
   gtk_entry_set_max_length (GTK_ENTRY (srcmac_entry), 17);

   dstmac_entry = gtk_entry_new ();
   gtk_widget_show (dstmac_entry);
   gtk_box_pack_start (GTK_BOX (datalink_vboxdx), dstmac_entry, FALSE, FALSE, 0);
   gtk_entry_set_max_length (GTK_ENTRY (dstmac_entry), 17);

   ethtype_combo = gtk_combo_new ();
   items = NULL;
   items = g_list_append (items, "IP");
   items = g_list_append (items, "LOOPBACK");
   gtk_combo_set_popdown_strings (GTK_COMBO (ethtype_combo), items);
   g_object_set_data (G_OBJECT (GTK_COMBO (ethtype_combo)->popwin),
		      "GladeParentKey", ethtype_combo);
   gtk_widget_show (ethtype_combo);
   gtk_box_pack_start (GTK_BOX (datalink_vboxdx), ethtype_combo, FALSE, FALSE, 0);

   ethtype_combo_entry = GTK_COMBO (ethtype_combo)->entry;
   gtk_widget_show (ethtype_combo_entry);

   DatalinkText = gtk_label_new (_("Datalink Layer"));
   gtk_widget_show (DatalinkText);
   gtk_frame_set_label_widget (GTK_FRAME (DatalinkFrame), DatalinkText);
   gtk_label_set_justify (GTK_LABEL (DatalinkText), GTK_JUSTIFY_LEFT);

   SendBox = gtk_hbox_new (FALSE, 0);
   gtk_widget_show (SendBox);
   gtk_box_pack_start (GTK_BOX (MainTable), SendBox, FALSE, TRUE, 0);
   gtk_widget_set_usize (SendBox, -2, 70);

   SendButton = gtk_button_new_with_mnemonic (_("Send"));
   gtk_widget_show (SendButton);
   gtk_box_pack_start (GTK_BOX (SendBox), SendButton, FALSE, FALSE, 0);

   VerticalScroll = gtk_scrolled_window_new (NULL, NULL);
   gtk_widget_show (VerticalScroll);
   gtk_box_pack_start (GTK_BOX (SendBox), VerticalScroll, TRUE, TRUE, 0);
   gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (VerticalScroll), GTK_POLICY_NEVER, GTK_POLICY_ALWAYS);

   TextView = gtk_text_view_new ();
   gtk_widget_show (TextView);
   gtk_container_add (GTK_CONTAINER (VerticalScroll), TextView);
   gtk_widget_set_sensitive (TextView, FALSE);
   gtk_text_view_set_editable (GTK_TEXT_VIEW (TextView), FALSE);
   gtk_text_view_set_justification (GTK_TEXT_VIEW (TextView), GTK_JUSTIFY_LEFT);
   gtk_text_view_set_wrap_mode (GTK_TEXT_VIEW (TextView), GTK_WRAP_WORD);
   gtk_text_view_set_left_margin (GTK_TEXT_VIEW (TextView), 15);
   gtk_text_view_set_right_margin (GTK_TEXT_VIEW (TextView), 15);

   /* Datalink work disable for default */
   gtk_widget_set_sensitive (DatalinkFrame, FALSE);

   /* SIGNALS */
   g_signal_connect ((gpointer) MainWin, "delete_event",
		     G_CALLBACK (on_MainWin_delete_event),
		     NULL);

   g_signal_connect ((gpointer) new1, "activate",
		     G_CALLBACK (on_new1_activate),
		     NULL);
   g_signal_connect ((gpointer) about1, "activate",
		     G_CALLBACK (on_about1_activate),
		     NULL);
   g_signal_connect ((gpointer) quit1, "activate",
		     G_CALLBACK (on_quit1_activate),
		     NULL);
   g_signal_connect ((gpointer) full_mode2, "toggled",
		     G_CALLBACK (on_full_mode2_activate),
		     NULL);

   g_signal_connect ((gpointer) debug_check, "toggled",
		     G_CALLBACK (on_debug_check_activate),
		     NULL);

   g_signal_connect ((gpointer) add_data2, "activate",
		     G_CALLBACK (on_add_data2_activate),
		     NULL);
   g_signal_connect ((gpointer) send_multi_packets1, "activate",
		     G_CALLBACK (on_send_multi_packets1_activate),
		     NULL);
   g_signal_connect ((gpointer) ecn_support1, "activate",
		     G_CALLBACK (on_ecn_support1_activate),
		     NULL);

   g_signal_connect ((gpointer) syn_checkbutton, "toggled",
		     G_CALLBACK (on_syn_checkbutton_toggled),
		     NULL);
   g_signal_connect ((gpointer) fin_checkbutton, "toggled",
		     G_CALLBACK (on_fin_checkbutton_toggled),
		     NULL);
   g_signal_connect ((gpointer) push_checkbutton, "toggled",
		     G_CALLBACK (on_push_checkbutton_toggled),
		     NULL);
   g_signal_connect ((gpointer) ack_checkbutton, "toggled",
		     G_CALLBACK (on_ack_checkbutton_toggled),
		     NULL);
   g_signal_connect ((gpointer) rst_checkbutton, "toggled",
		     G_CALLBACK (on_rst_checkbutton_toggled),
		     NULL);
   g_signal_connect ((gpointer) urg_checkbutton, "toggled",
		     G_CALLBACK (on_urg_checkbutton_toggled),
		     NULL);
   g_signal_connect ((gpointer) ece_checkbutton, "toggled",
		     G_CALLBACK (on_ece_checkbutton_toggled),
		     NULL);
   g_signal_connect ((gpointer) cwr_checkbutton, "toggled",
		     G_CALLBACK (on_cwr_checkbutton_toggled),
		     NULL);
   g_signal_connect ((gpointer) SendButton, "clicked",
		     G_CALLBACK (on_SendButton_clicked),
		     NULL);

  /* Store pointers to all widgets, for use by lookup_widget(). */
   GLADE_HOOKUP_OBJECT_NO_REF (MainWin, MainWin, "MainWin");
   GLADE_HOOKUP_OBJECT (MainWin, vbox1, "vbox1");
   GLADE_HOOKUP_OBJECT (MainWin, menubar1, "menubar1");
   GLADE_HOOKUP_OBJECT (MainWin, menuitem1, "menuitem1");
   GLADE_HOOKUP_OBJECT (MainWin, menuitem1_menu, "menuitem1_menu");
   GLADE_HOOKUP_OBJECT (MainWin, new1, "new1");
   GLADE_HOOKUP_OBJECT (MainWin, image25, "image25");
   GLADE_HOOKUP_OBJECT (MainWin, about1, "about1");
   GLADE_HOOKUP_OBJECT (MainWin, image26, "image26");
   GLADE_HOOKUP_OBJECT (MainWin, quit1, "quit1");
   GLADE_HOOKUP_OBJECT (MainWin, image27, "image27");
   GLADE_HOOKUP_OBJECT (MainWin, options1, "options1");
   GLADE_HOOKUP_OBJECT (MainWin, options1_menu, "options1_menu");
   GLADE_HOOKUP_OBJECT (MainWin, full_mode2, "full_mode2");
   GLADE_HOOKUP_OBJECT (MainWin, add_data2, "add_data2");
   GLADE_HOOKUP_OBJECT (MainWin, image28, "image28");
   GLADE_HOOKUP_OBJECT (MainWin, send_multi_packets1, "send_multi_packets1");
   GLADE_HOOKUP_OBJECT (MainWin, image29, "image29");
   GLADE_HOOKUP_OBJECT (MainWin, MainTable, "MainTable");
   GLADE_HOOKUP_OBJECT (MainWin, MainFieldBox, "MainFieldBox");
   GLADE_HOOKUP_OBJECT (MainWin, NetworkFrame, "NetworkFrame");
   GLADE_HOOKUP_OBJECT (MainWin, network_hbox, "network_hbox");
   GLADE_HOOKUP_OBJECT (MainWin, network_vboxsx, "network_vboxsx");
   GLADE_HOOKUP_OBJECT (MainWin, label8, "label8");
   GLADE_HOOKUP_OBJECT (MainWin, label9, "label9");
   GLADE_HOOKUP_OBJECT (MainWin, label10, "label10");
   GLADE_HOOKUP_OBJECT (MainWin, label11, "label11");
   GLADE_HOOKUP_OBJECT (MainWin, label12, "label12");
   GLADE_HOOKUP_OBJECT (MainWin, network_vboxdx, "network_vboxdx");
   GLADE_HOOKUP_OBJECT (MainWin, srcaddr_entry, "srcaddr_entry");
   GLADE_HOOKUP_OBJECT (MainWin, dstaddr_entry, "dstaddr_entry");
   GLADE_HOOKUP_OBJECT (MainWin, ttl_entry, "ttl_entry");
   GLADE_HOOKUP_OBJECT (MainWin, id_entry, "id_entry");
   GLADE_HOOKUP_OBJECT (MainWin, tos_entry, "tos_entry");
   GLADE_HOOKUP_OBJECT (MainWin, NetworkText, "NetworkText");
   GLADE_HOOKUP_OBJECT (MainWin, Transport_Frame, "Transport_Frame");
   GLADE_HOOKUP_OBJECT (MainWin, transport_hbox, "transport_hbox");
   GLADE_HOOKUP_OBJECT (MainWin, transport_vboxsx, "transport_vboxsx");
   GLADE_HOOKUP_OBJECT (MainWin, label19, "label19");
   GLADE_HOOKUP_OBJECT (MainWin, label18, "label18");
   GLADE_HOOKUP_OBJECT (MainWin, label16, "label16");
   GLADE_HOOKUP_OBJECT (MainWin, label15, "label15");
   GLADE_HOOKUP_OBJECT (MainWin, label14, "label14");
   GLADE_HOOKUP_OBJECT (MainWin, label13, "label13");
   GLADE_HOOKUP_OBJECT (MainWin, transport_vboxdx, "transport_vboxdx");
   GLADE_HOOKUP_OBJECT (MainWin, srcport_entry, "srcport_entry");
   GLADE_HOOKUP_OBJECT (MainWin, dstport_entry, "dstport_entry");
   GLADE_HOOKUP_OBJECT (MainWin, flags_table, "flags_table");
   GLADE_HOOKUP_OBJECT (MainWin, syn_checkbutton, "syn_checkbutton");
   GLADE_HOOKUP_OBJECT (MainWin, fin_checkbutton, "fin_checkbutton");
   GLADE_HOOKUP_OBJECT (MainWin, push_checkbutton, "push_checkbutton");
   GLADE_HOOKUP_OBJECT (MainWin, ack_checkbutton, "ack_checkbutton");
   GLADE_HOOKUP_OBJECT (MainWin, rst_checkbutton, "rst_checkbutton");
   GLADE_HOOKUP_OBJECT (MainWin, urg_checkbutton, "urg_checkbutton");
   GLADE_HOOKUP_OBJECT (MainWin, seq_entry, "seq_entry");
   GLADE_HOOKUP_OBJECT (MainWin, ack_entry, "ack_entry");
   GLADE_HOOKUP_OBJECT (MainWin, win_entry, "win_entry");
   GLADE_HOOKUP_OBJECT (MainWin, urg_entry, "urg_entry");
   GLADE_HOOKUP_OBJECT (MainWin, TransportText, "TransportText");
   GLADE_HOOKUP_OBJECT (MainWin, DatalinkFrame, "DatalinkFrame");
   GLADE_HOOKUP_OBJECT (MainWin, datalink_hbox, "datalink_hbox");
   GLADE_HOOKUP_OBJECT (MainWin, datalink_vboxsx, "datalink_vboxsx");
   GLADE_HOOKUP_OBJECT (MainWin, label4, "label4");
   GLADE_HOOKUP_OBJECT (MainWin, label5, "label5");
   GLADE_HOOKUP_OBJECT (MainWin, label6, "label6");
   GLADE_HOOKUP_OBJECT (MainWin, label7, "label7");
   GLADE_HOOKUP_OBJECT (MainWin, datalink_vboxdx, "datalink_vboxdx");
   GLADE_HOOKUP_OBJECT (MainWin, iface_entry, "iface_entry");
   GLADE_HOOKUP_OBJECT (MainWin, srcmac_entry, "srcmac_entry");
   GLADE_HOOKUP_OBJECT (MainWin, dstmac_entry, "dstmac_entry");
   GLADE_HOOKUP_OBJECT (MainWin, ethtype_combo, "ethtype_combo");
   GLADE_HOOKUP_OBJECT (MainWin, ethtype_combo_entry, "ethtype_combo_entry");
   GLADE_HOOKUP_OBJECT (MainWin, DatalinkText, "DatalinkText");
   GLADE_HOOKUP_OBJECT (MainWin, SendBox, "SendBox");
   GLADE_HOOKUP_OBJECT (MainWin, SendButton, "SendButton");
   GLADE_HOOKUP_OBJECT (MainWin, VerticalScroll, "VerticalScroll");
   GLADE_HOOKUP_OBJECT (MainWin, TextView, "TextView");
   GLADE_HOOKUP_OBJECT (MainWin, ece_checkbutton, "ece_button");
   GLADE_HOOKUP_OBJECT (MainWin, cwr_checkbutton, "cwr_button");
   GLADE_HOOKUP_OBJECT (MainWin, vbox3, "vbox3");

   GLADE_HOOKUP_OBJECT_NO_REF (MainWin, tooltips, "tooltips");

   return MainWin;
}

GtkWidget* create_DataWin (void)
{
   GtkWidget *DataWin;
   GtkWidget *DataButton;
   GtkWidget *vbox2;
   GtkWidget *hbox2;
   GtkWidget *alignment1;
   GtkWidget *hbox3;
   GtkWidget *image24;
   GtkWidget *label2;
   GdkPixbuf *DataWin_icon_pixbuf;

   DataWin = gtk_window_new (GTK_WINDOW_TOPLEVEL);
   gtk_widget_set_extension_events (DataWin, GDK_EXTENSION_EVENTS_CURSOR);
   gtk_window_set_title (GTK_WINDOW (DataWin), _("Payload options"));
   gtk_window_set_position (GTK_WINDOW (DataWin), GTK_WIN_POS_CENTER);
   DataWin_icon_pixbuf = create_pixbuf ("icon.png");
   if (DataWin_icon_pixbuf)
     {
	gtk_window_set_icon (GTK_WINDOW (DataWin), DataWin_icon_pixbuf);
	gdk_pixbuf_unref (DataWin_icon_pixbuf);
     }

   vbox2 = gtk_vbox_new (FALSE, 0);
   gtk_widget_show (vbox2);
   gtk_container_add (GTK_CONTAINER (DataWin), vbox2);

   hbox2 = gtk_hbox_new (FALSE, 0);
   gtk_widget_show (hbox2);
   gtk_box_pack_start (GTK_BOX (vbox2), hbox2, FALSE, FALSE, 0);

   DataButton = gtk_check_button_new ();
   gtk_widget_show (DataButton);
   if (ck.data)
     gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON (DataButton), TRUE);
   else
     gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON (DataButton), FALSE);

   gtk_box_pack_start (GTK_BOX (hbox2), DataButton, FALSE, FALSE, 68);

   alignment1 = gtk_alignment_new (0.5, 0.5, 0, 0);
   gtk_widget_show (alignment1);
   gtk_container_add (GTK_CONTAINER (DataButton), alignment1);

   hbox3 = gtk_hbox_new (FALSE, 2);
   gtk_widget_show (hbox3);
   gtk_container_add (GTK_CONTAINER (alignment1), hbox3);

   image24 = gtk_image_new_from_stock ("gtk-justify-center", GTK_ICON_SIZE_BUTTON);
   gtk_widget_show (image24);
   gtk_box_pack_start (GTK_BOX (hbox3), image24, FALSE, FALSE, 0);

   label2 = gtk_label_new_with_mnemonic (_("Enable TCP payload"));
   gtk_widget_show (label2);
   gtk_box_pack_start (GTK_BOX (hbox3), label2, FALSE, FALSE, 0);
   gtk_label_set_justify (GTK_LABEL (label2), GTK_JUSTIFY_LEFT);

   DataEntry = gtk_entry_new ();
   gtk_widget_show (DataEntry);
   gtk_box_pack_start (GTK_BOX (vbox2), DataEntry, TRUE, TRUE, 0);
   gtk_widget_set_size_request (DataEntry, 300, -2);
   gtk_entry_set_max_length (GTK_ENTRY (DataEntry), 128); /* char data[128] */
   gtk_entry_set_text (GTK_ENTRY(DataEntry), data);
   if (ck.data)
     gtk_widget_set_sensitive (DataEntry, TRUE);
   else
     gtk_widget_set_sensitive (DataEntry, FALSE);

   g_signal_connect ((gpointer) DataButton, "toggled",
		     G_CALLBACK (on_DataButton_toggled),
		     NULL);

   g_signal_connect ((gpointer) DataEntry, "changed",
		     G_CALLBACK (on_DataEntry_changed),
		     NULL);

  /* Store pointers to all widgets, for use by lookup_widget(). */
   GLADE_HOOKUP_OBJECT_NO_REF (DataWin, DataWin, "DataWin");
   GLADE_HOOKUP_OBJECT (DataWin, vbox2, "vbox2");
   GLADE_HOOKUP_OBJECT (DataWin, hbox2, "hbox2");
   GLADE_HOOKUP_OBJECT (DataWin, DataButton, "DataButton");
   GLADE_HOOKUP_OBJECT (DataWin, alignment1, "alignment1");
   GLADE_HOOKUP_OBJECT (DataWin, hbox3, "hbox3");
   GLADE_HOOKUP_OBJECT (DataWin, image24, "image24");
   GLADE_HOOKUP_OBJECT (DataWin, label2, "label2");
   GLADE_HOOKUP_OBJECT (DataWin, DataEntry, "DataEntry");

   return DataWin;
}

GtkWidget* create_MultiPackets (void)
{
   GtkWidget *MultiPackets;
   GdkPixbuf *MultiPackets_icon_pixbuf;
   GtkWidget *Multi_Table;
   GtkWidget *NumberMulti;
   GtkWidget *DelayMulti;
   GtkWidget *MultiButton;
   GtkWidget *alignment2;
   GtkWidget *hbox7;
   GtkWidget *image30;
   GtkWidget *label3;

   MultiPackets = gtk_window_new (GTK_WINDOW_TOPLEVEL);
   gtk_window_set_title (GTK_WINDOW (MultiPackets), _("Pseudo-flood options"));
   gtk_window_set_position (GTK_WINDOW (MultiPackets), GTK_WIN_POS_CENTER);
   gtk_window_set_resizable (GTK_WINDOW (MultiPackets), FALSE);
   MultiPackets_icon_pixbuf = create_pixbuf ("icon.png");
   if (MultiPackets_icon_pixbuf)
     {
	gtk_window_set_icon (GTK_WINDOW (MultiPackets), MultiPackets_icon_pixbuf);
	gdk_pixbuf_unref (MultiPackets_icon_pixbuf);
     }

   Multi_Table = gtk_table_new (2, 1, TRUE);
   gtk_container_add (GTK_CONTAINER (MultiPackets), Multi_Table);

   table2 = gtk_table_new (2, 2, FALSE);
   gtk_table_attach (GTK_TABLE (Multi_Table), table2, 0, 1, 1, 2,
		     (GtkAttachOptions) (GTK_FILL),
		     (GtkAttachOptions) (GTK_EXPAND | GTK_FILL), 0, 0);
   gtk_container_set_border_width (GTK_CONTAINER (table2), 3);

   NumberMulti = gtk_label_new (_("Number"));
   gtk_table_attach (GTK_TABLE (table2), NumberMulti, 0, 1, 0, 1,
		     (GtkAttachOptions) (GTK_FILL),
		     (GtkAttachOptions) (0), 0, 0);
   gtk_label_set_justify (GTK_LABEL (NumberMulti), GTK_JUSTIFY_LEFT);
   gtk_misc_set_alignment (GTK_MISC (NumberMulti), 0, 0.5);

   DelayMulti = gtk_label_new (_("Delay (ms)"));
   gtk_table_attach (GTK_TABLE (table2), DelayMulti, 0, 1, 1, 2,
		     (GtkAttachOptions) (GTK_FILL),
		     (GtkAttachOptions) (0), 0, 0);
   gtk_label_set_justify (GTK_LABEL (DelayMulti), GTK_JUSTIFY_LEFT);
   gtk_misc_set_alignment (GTK_MISC (DelayMulti), 0, 0.5);

   NumberEntryMulti = gtk_entry_new ();
   gtk_entry_set_text (GTK_ENTRY (NumberEntryMulti), ltostr(m.number));
   gtk_table_attach (GTK_TABLE (table2), NumberEntryMulti, 1, 2, 0, 1,
		     (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
		     (GtkAttachOptions) (0), 0, 0);
   gtk_widget_set_size_request (NumberEntryMulti, 100, -2);
   gtk_entry_set_max_length (GTK_ENTRY (NumberEntryMulti), 10);

   DelayEntryMulty = gtk_entry_new ();
   gtk_entry_set_text (GTK_ENTRY (DelayEntryMulty), ltostr(m.delay));
   gtk_table_attach (GTK_TABLE (table2), DelayEntryMulty, 1, 2, 1, 2,
		     (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
		     (GtkAttachOptions) (0), 0, 0);
   gtk_widget_set_size_request (DelayEntryMulty, 100, -2);
   gtk_entry_set_max_length (GTK_ENTRY (DelayEntryMulty), 10);

   MultiButton = gtk_check_button_new ();
   if (ck.multi)
     {
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON (MultiButton), TRUE);
	gtk_widget_set_sensitive (table2, TRUE);
     }
   else
     {
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON (MultiButton), FALSE);
	gtk_widget_set_sensitive (table2, FALSE);
     }

   gtk_table_attach (GTK_TABLE (Multi_Table), MultiButton, 0, 1, 0, 1,
		     (GtkAttachOptions) (0),
		     (GtkAttachOptions) (GTK_FILL), 8, 0);

   alignment2 = gtk_alignment_new (0.5, 0.5, 0, 0);
   gtk_container_add (GTK_CONTAINER (MultiButton), alignment2);

   hbox7 = gtk_hbox_new (FALSE, 2);
   gtk_container_add (GTK_CONTAINER (alignment2), hbox7);

   image30 = gtk_image_new_from_stock ("gtk-refresh", GTK_ICON_SIZE_BUTTON);
   gtk_box_pack_start (GTK_BOX (hbox7), image30, FALSE, FALSE, 0);

   label3 = gtk_label_new_with_mnemonic (_("Enable Multi-Mode"));
   gtk_box_pack_start (GTK_BOX (hbox7), label3, FALSE, FALSE, 0);
   gtk_label_set_justify (GTK_LABEL (label3), GTK_JUSTIFY_LEFT);

   g_signal_connect ((gpointer) MultiButton, "toggled",
		     G_CALLBACK (on_MultiButton_toggled),
		     NULL);

   g_signal_connect ((gpointer) NumberEntryMulti, "changed",
		     G_CALLBACK (on_NumberEntryMulti_changed),
		     NULL);

   g_signal_connect ((gpointer) DelayEntryMulty, "changed",
		     G_CALLBACK (on_DelayEntryMulty_changed),
		     NULL);

   /* show widgets */
   gtk_widget_show (Multi_Table);
   gtk_widget_show (table2);
   gtk_widget_show (NumberMulti);
   gtk_widget_show (DelayMulti);
   gtk_widget_show (NumberEntryMulti);
   gtk_widget_show (DelayEntryMulty);
   gtk_widget_show (MultiButton);
   gtk_widget_show (alignment2);
   gtk_widget_show (hbox7);
   gtk_widget_show (image30);
   gtk_widget_show (label3);

  /* Store pointers to all widgets, for use by lookup_widget(). */
   GLADE_HOOKUP_OBJECT_NO_REF (MultiPackets, MultiPackets, "MultiPackets");
   GLADE_HOOKUP_OBJECT (MultiPackets, Multi_Table, "Multi_Table");
   GLADE_HOOKUP_OBJECT (MultiPackets, table2, "table2");
   GLADE_HOOKUP_OBJECT (MultiPackets, NumberMulti, "NumberMulti");
   GLADE_HOOKUP_OBJECT (MultiPackets, DelayMulti, "DelayMulti");
   GLADE_HOOKUP_OBJECT (MultiPackets, NumberEntryMulti, "NumberEntryMulti");
   GLADE_HOOKUP_OBJECT (MultiPackets, DelayEntryMulty, "DelayEntryMulty");
   GLADE_HOOKUP_OBJECT (MultiPackets, MultiButton, "MultiButton");
   GLADE_HOOKUP_OBJECT (MultiPackets, alignment2, "alignment2");
   GLADE_HOOKUP_OBJECT (MultiPackets, hbox7, "hbox7");
   GLADE_HOOKUP_OBJECT (MultiPackets, image30, "image30");
   GLADE_HOOKUP_OBJECT (MultiPackets, label3, "label3");

   return MultiPackets;
}

GtkWidget* create_AboutWin (void)
{
   GtkWidget *AboutWin;
   GdkPixbuf *AboutWin_icon_pixbuf;
   GtkWidget *hbox1;
   GtkWidget *image16;
   GtkWidget *label1;

   AboutWin = gtk_window_new (GTK_WINDOW_TOPLEVEL);
   gtk_window_set_title (GTK_WINDOW (AboutWin), _("About"));
   gtk_window_set_position (GTK_WINDOW (AboutWin), GTK_WIN_POS_CENTER);
   gtk_window_set_default_size (GTK_WINDOW (AboutWin), 350, 200);
   gtk_window_set_resizable (GTK_WINDOW (AboutWin), FALSE);
   AboutWin_icon_pixbuf = create_pixbuf ("icon.png");
   if (AboutWin_icon_pixbuf)
     {
	gtk_window_set_icon (GTK_WINDOW (AboutWin), AboutWin_icon_pixbuf);
	gdk_pixbuf_unref (AboutWin_icon_pixbuf);
     }

   hbox1 = gtk_hbox_new (FALSE, 0);
   gtk_widget_show (hbox1);
   gtk_container_add (GTK_CONTAINER (AboutWin), hbox1);
   gtk_container_set_border_width (GTK_CONTAINER (hbox1), 2);

   image16 = create_pixmap (AboutWin, "icon.png");
   gtk_widget_show (image16);
   gtk_box_pack_start (GTK_BOX (hbox1), image16, TRUE, TRUE, 0);

   label1 = gtk_label_new (_("\nGspoof, V. 3.2\n\nAuthor: Embyte (c) 2002-2003\nContact: embyte@madlab.it\nLicensed under GPL domain\n\nEnjoy!\n"));
   gtk_widget_show (label1);
   gtk_box_pack_end (GTK_BOX (hbox1), label1, TRUE, TRUE, 3);

  /* Store pointers to all widgets, for use by lookup_widget(). */
   GLADE_HOOKUP_OBJECT_NO_REF (AboutWin, AboutWin, "AboutWin");
   GLADE_HOOKUP_OBJECT (AboutWin, hbox1, "hbox1");
   GLADE_HOOKUP_OBJECT (AboutWin, image16, "image16");
   GLADE_HOOKUP_OBJECT (AboutWin, label1, "label1");

   return AboutWin;
}

GtkWidget*
  create_ECNWin (void)
{
   GtkWidget *ECNWin;
   GdkPixbuf *ECNWin_icon_pixbuf;
   GtkWidget *vbox4;
   GtkWidget *hbox8;
   GtkWidget *dscpLabel;
   GtkWidget *hbox9;
   GtkWidget *ecn_ctLaber;
   GtkWidget *ecn_ct0;
   GSList *ecn_ct0_group = NULL;
   GtkWidget *ecn_ct1;
   GtkWidget *hbox10;
   GtkWidget *ecn_ceLaber;
   GtkWidget *ecn_ce0;
   GSList *ecn_ce0_group = NULL;
   GtkWidget *ecn_ce1;

   ECNWin = gtk_window_new (GTK_WINDOW_TOPLEVEL);
   gtk_widget_set_size_request (ECNWin, -1, 90);
   gtk_window_set_title (GTK_WINDOW (ECNWin), _("ECN options"));
   gtk_window_set_position (GTK_WINDOW (ECNWin), GTK_WIN_POS_CENTER);
   ECNWin_icon_pixbuf = create_pixbuf ("icon.png");
   if (ECNWin_icon_pixbuf)
     {
	gtk_window_set_icon (GTK_WINDOW (ECNWin), ECNWin_icon_pixbuf);
	gdk_pixbuf_unref (ECNWin_icon_pixbuf);
     }

   vbox4 = gtk_vbox_new (FALSE, 0);
   gtk_widget_show (vbox4);
   gtk_container_add (GTK_CONTAINER (ECNWin), vbox4);

   hbox8 = gtk_hbox_new (FALSE, 0);
   gtk_widget_show (hbox8);
   gtk_box_pack_start (GTK_BOX (vbox4), hbox8, TRUE, TRUE, 0);

   dscpLabel = gtk_label_new (_("Differentiated\nservice"));
   gtk_widget_show (dscpLabel);
   gtk_box_pack_start (GTK_BOX (hbox8), dscpLabel, FALSE, FALSE, 5);
   gtk_label_set_justify (GTK_LABEL (dscpLabel), GTK_JUSTIFY_CENTER);

   dscpEntry = gtk_entry_new ();
   gtk_widget_show (dscpEntry);
   gtk_box_pack_start (GTK_BOX (hbox8), dscpEntry, TRUE, TRUE, 0);
   gtk_entry_set_max_length (GTK_ENTRY (dscpEntry), 2);
   gtk_entry_set_text (GTK_ENTRY (dscpEntry), ltostr(ipv4_tos.dscp));

   hbox9 = gtk_hbox_new (TRUE, 0);
   gtk_widget_show (hbox9);
   gtk_box_pack_start (GTK_BOX (vbox4), hbox9, TRUE, TRUE, 0);

   ecn_ctLaber = gtk_label_new (_("ECN-Capable\n transport"));
   gtk_widget_show (ecn_ctLaber);
   gtk_box_pack_start (GTK_BOX (hbox9), ecn_ctLaber, FALSE, FALSE, 5);
   gtk_label_set_justify (GTK_LABEL (ecn_ctLaber), GTK_JUSTIFY_CENTER);

   ecn_ct0 = gtk_radio_button_new_with_mnemonic (NULL, _("0"));
   gtk_widget_show (ecn_ct0);
   gtk_box_pack_start (GTK_BOX (hbox9), ecn_ct0, FALSE, FALSE, 0);
   gtk_radio_button_set_group (GTK_RADIO_BUTTON (ecn_ct0), ecn_ct0_group);
   ecn_ct0_group = gtk_radio_button_get_group (GTK_RADIO_BUTTON (ecn_ct0));

   ecn_ct1 = gtk_radio_button_new_with_mnemonic (NULL, _("1"));
   gtk_widget_show (ecn_ct1);
   gtk_box_pack_start (GTK_BOX (hbox9), ecn_ct1, FALSE, FALSE, 0);
   gtk_radio_button_set_group (GTK_RADIO_BUTTON (ecn_ct1), ecn_ct0_group);
   ecn_ct0_group = gtk_radio_button_get_group (GTK_RADIO_BUTTON (ecn_ct1));
   if (ipv4_tos.ecn_ct)
     gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (ecn_ct1), TRUE);
   
   hbox10 = gtk_hbox_new (TRUE, 0);
   gtk_widget_show (hbox10);
   gtk_box_pack_start (GTK_BOX (vbox4), hbox10, TRUE, TRUE, 0);

   ecn_ceLaber = gtk_label_new (_("ECN-CE"));
   gtk_widget_show (ecn_ceLaber);
   gtk_box_pack_start (GTK_BOX (hbox10), ecn_ceLaber, FALSE, FALSE, 5);
   gtk_label_set_justify (GTK_LABEL (ecn_ceLaber), GTK_JUSTIFY_CENTER);

   ecn_ce0 = gtk_radio_button_new_with_mnemonic (NULL, _("0"));
   gtk_widget_show (ecn_ce0);
   gtk_box_pack_start (GTK_BOX (hbox10), ecn_ce0, FALSE, FALSE, 0);
   gtk_radio_button_set_group (GTK_RADIO_BUTTON (ecn_ce0), ecn_ce0_group);
   ecn_ce0_group = gtk_radio_button_get_group (GTK_RADIO_BUTTON (ecn_ce0));

   ecn_ce1 = gtk_radio_button_new_with_mnemonic (NULL, _("1"));
   gtk_widget_show (ecn_ce1);
   gtk_box_pack_start (GTK_BOX (hbox10), ecn_ce1, FALSE, FALSE, 0);
   gtk_radio_button_set_group (GTK_RADIO_BUTTON (ecn_ce1), ecn_ce0_group);
   ecn_ce0_group = gtk_radio_button_get_group (GTK_RADIO_BUTTON (ecn_ce1));
   if (ipv4_tos.ecn_ce)
     gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (ecn_ce1), TRUE);
   
   /* signals */
   g_signal_connect ((gpointer) dscpEntry, "changed", G_CALLBACK (on_dscpEntry_changed), NULL);
   g_signal_connect ((gpointer) ecn_ct0, "toggled", G_CALLBACK (on_ecn_ct0_toggled), NULL);
   g_signal_connect ((gpointer) ecn_ct1, "toggled", G_CALLBACK (on_ecn_ct1_toggled), NULL);
   g_signal_connect ((gpointer) ecn_ce0, "toggled", G_CALLBACK (on_ecn_ce0_toggled), NULL);
   g_signal_connect ((gpointer) ecn_ce1, "toggled", G_CALLBACK (on_ecn_ce1_toggled), NULL);

  /* Store pointers to all widgets, for use by lookup_widget(). */
   GLADE_HOOKUP_OBJECT_NO_REF (ECNWin, ECNWin, "ECNWin");
   GLADE_HOOKUP_OBJECT (ECNWin, vbox4, "vbox4");
   GLADE_HOOKUP_OBJECT (ECNWin, hbox8, "hbox8");
   GLADE_HOOKUP_OBJECT (ECNWin, dscpLabel, "dscpLabel");
   GLADE_HOOKUP_OBJECT (ECNWin, dscpEntry, "dscpEntry");
   GLADE_HOOKUP_OBJECT (ECNWin, hbox9, "hbox9");
   GLADE_HOOKUP_OBJECT (ECNWin, ecn_ctLaber, "ecn_ctLaber");
   GLADE_HOOKUP_OBJECT (ECNWin, ecn_ct0, "ecn_ct0");
   GLADE_HOOKUP_OBJECT (ECNWin, ecn_ct1, "ecn_ct1");
   GLADE_HOOKUP_OBJECT (ECNWin, hbox10, "hbox10");
   GLADE_HOOKUP_OBJECT (ECNWin, ecn_ceLaber, "ecn_ceLaber");
   GLADE_HOOKUP_OBJECT (ECNWin, ecn_ce0, "ecn_ce0");
   GLADE_HOOKUP_OBJECT (ECNWin, ecn_ce1, "ecn_ce1");

   return ECNWin;
}

