/*
 * This file is part of Gspoof-3 (a console/gtk+ tcp/ip packet forger)
 * 
 * $Name: common.h $
 * $Version: 3.2 $
 * $Date: 2003/12/22 16:30:03 $
 * $Author: Embyte <embyte@madlab.it> $
 * $Copyright: Copyright (C) 2002-2003 by embyte $
 * $License: This software is under GPL version 2 of license $
 *
 */

#define BANNER "Gspoof 3 -< Console/GTK+ TCP/IP Packet Forger, V. 3.2 >-"
#define VERSION "3.2"

#define TH_ECE 0x40
#define TH_CWR 0x80

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>

char * dn (char * s);
u_char * ltostr (u_long a);
u_char * emb_hex_aton (u_char *in);
u_short emb_ctoi (u_char ex);
char * emb_hex_ntoa (u_char *s);
