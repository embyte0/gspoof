/*
 * This file is part of Gspoof-3 (a console/gtk+ tcp/ip packet forger)
 * 
 * $Name: console.h $
 * $Version: 3.2 $
 * $Date: 2003/12/22 16:30:03 $
 * $Author: Embyte <embyte@madlab.it> $
 * $Copyright: Copyright (C) 2002-2003 by embyte $
 * $License: This software is under GPL version 2 of license $
 *
 */

#include <libnet.h>
#include <stdio.h>
#include <stdarg.h>

/* define colors */
#define CYAN "\033[9;36m"
#define RED  "\033[0;35m"
#define GREEN "\033[0;32m"
#define WHITE "\033[0;0m"

int run_console();
void print_menu();
void clean_values();
void randomize();
void autoscan();
void sendpkg();
int exit_fail();
void print_getline (char **in, const char *format, ...);
