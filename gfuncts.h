/*
 * This file is part of Gspoof-3 (a console/gtk+ tcp/ip packet forger)
 * 
 * $Name: gfunct.h $
 * $Version: 3.2 $
 * $Date: 2003/12/22 16:30:03 $
 * $Author: Embyte <embyte@madlab.it> $
 * $Copyright: Copyright (C) 2002-2003 by embyte $
 * $License: This software is under GPL version 2 of license $
 *
 */

int Initialize();
int RestoreDefault();
int SendPacket();
int info (const char *format, ...);
void ExitFailure(); 
void UpdateTos();
