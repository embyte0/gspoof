/*
 * This file is part of Gspoof-3 (a console/gtk+ tcp/ip packet forger)
 * 
 * $Name: callbacks.h $
 * $Version: 3.2 $
 * $Date: 2003/12/22 16:30:03 $
 * $Author: Embyte <embyte@madlab.it> $
 * $Copyright: Copyright (C) 2002-2003 by embyte $
 * $License: This software is under GPL version 2 of license $
 *
 */

#include <gtk/gtk.h>

/* callback protos */
void on_new1_activate();
void on_about1_activate();
void on_quit1_activate();
void on_options1_activate();
void on_full_mode2_activate();
void on_add_data2_activate();   
void on_ecn_support1_activate();
void on_send_multi_packets1_activate();
void on_syn_checkbutton_toggled();
void on_fin_checkbutton_toggled();
void on_push_checkbutton_toggled();
void on_ack_checkbutton_toggled();
void on_rst_checkbutton_toggled();
void on_urg_checkbutton_toggled();
void on_ece_checkbutton_toggled();
void on_cwr_checkbutton_toggled();
void on_SendButton_clicked();
void on_DataButton_toggled();
void on_MultiButton_toggled();
void on_NumberEntryMulti_changed();
void on_DelayEntryMulty_changed (); 
void on_DataEntry_changed(); 
void on_dscpEntry_changed(); 
void on_debug_check_activate();
void on_MainWin_delete_event();
void on_ecn_ct0_toggled();
void on_ecn_ct1_toggled();
void on_ecn_ce0_toggled();
void on_ecn_ce1_toggled();
