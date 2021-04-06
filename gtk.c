/*
 * This file is part of Gspoof-3 (a console/gtk+ tcp/ip packet forger)
 *
 * $Name: gtk.c $
 * $Version: 3.2 $
 * $Date: 2003/12/22 16:30:03 $
 * $Author: Embyte <embyte@madlab.it> $
 * $Copyright: Copyright (C) 2002-2003 by embyte $
 * $License: This software is under GPL version 2 of license $
 *
 */

#include "gtk.h"
#include <stdio.h>

void run_gtk(int _argc, char ** _argv)
{
   GtkWidget *MainWin;

   printf ("\n\t------------------------\n");
   printf ("\tRunning in Graphics Mode\n");
   printf ("\t------------------------\n\n");

   gtk_set_locale ();
   gtk_init (&_argc, &_argv);

   add_pixmap_directory ("pixmap");
   add_pixmap_directory ("/usr/local/share/gspoof/pixmap");
   add_pixmap_directory ("/usr/share/gspoof/pixmap");

   MainWin = create_MainWin();

   Initialize ();

   gtk_widget_show (MainWin);
   gtk_main ();
}
