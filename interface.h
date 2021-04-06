/*
 * This file is part of Gspoof-3 (a console/gtk+ tcp/ip packet forger)
 *
 * $Name: interface.h $
 * $Version: 3.2 $
 * $Date: 2003/12/22 16:30:03 $
 * $Author: Embyte <embyte@madlab.it> $
 * $Copyright: Copyright (C) 2002-2003 by embyte $
 * $License: This software is under GPL version 2 of license $
 *
 */

/* Prototypes */
GtkWidget* create_MainWin (void);
GtkWidget* create_AboutWin (void);
GtkWidget* create_DataWin (void);
GtkWidget* create_MultiPackets (void);
GtkWidget* create_ECNWin (void);

/* Define common Widget */

/* MainWin */
GtkWidget *iface_entry;
GtkWidget *srcmac_entry;
GtkWidget *dstmac_entry;
GtkWidget *ethtype_combo;
GtkWidget *ethtype_combo_entry;
GtkWidget *DatalinkFrame;

GtkWidget *srcaddr_entry;
GtkWidget *dstaddr_entry;
GtkWidget *ttl_entry;
GtkWidget *id_entry;
GtkWidget *tos_entry;

GtkWidget *srcport_entry;
GtkWidget *dstport_entry;
GtkWidget *flags_table;
GtkWidget *syn_checkbutton;
GtkWidget *fin_checkbutton;
GtkWidget *push_checkbutton;
GtkWidget *ack_checkbutton;
GtkWidget *rst_checkbutton;
GtkWidget *urg_checkbutton;
GtkWidget *ece_checkbutton;
GtkWidget *cwr_checkbutton;
GtkWidget *seq_entry;
GtkWidget *ack_entry;
GtkWidget *win_entry;
GtkWidget *urg_entry;

/* Info TextView */
GtkWidget *TextView;
GtkTextBuffer *TextBuffer;
GtkWidget *VerticalScroll;

/* DataWin */
GtkWidget *DataEntry;

/* Multi */
GtkWidget *table2;
GtkWidget *NumberEntryMulti;
GtkWidget *DelayEntryMulty;

/* ECN */
GtkWidget *dscpEntry;
