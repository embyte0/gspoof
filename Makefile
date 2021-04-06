#
# This file is part of Gspoof-3 (a console/gtk+ tcp/ip packet forger)
#  
#  $Name: Makefile.in $
#  $Version: 3.2 $
#  $Date: 2003/12/22 16:30:03 $
#  $Author: Embyte <embyte@madlab.it> $
#  $Copyright: Copyright (C) 2002-2003 by embyte $
#  $License: This software is under GPL version 2 of license $
# 
 

CC          = gcc
CFLAGS      = -Wall -O2 
LDFLAGS     = -L/usr/lib
CPPFLAGS    = -I/usr/include
GTK_LIBS    = -Wl,--export-dynamic -lgtk-x11-2.0 -lgdk-x11-2.0 -lgdk_pixbuf-2.0 -lm -lpangoxft-1.0 -lpangox-1.0 -lpango-1.0 -latk-1.0 -lgobject-2.0 -lgmodule-2.0 -ldl -lglib-2.0  
GTK_CFLAGS  = -I/usr/include/gtk-2.0 -I/usr/lib/gtk-2.0/include -I/usr/include/atk-1.0 -I/usr/include/pango-1.0 -I/usr/X11R6/include -I/usr/include/freetype2 -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include  

prefix      = /usr/local
exec_prefix = ${prefix}
bindir      = ${exec_prefix}/bin
mandir      = ${prefix}/man
datadir     = ${prefix}/share
srcdir      = .
shtool      = @SHTOOL@

OBJS = main.o console.o common.o interface.o callbacks.o gfuncts.o support.o gtk.o 


all:	gspoof	
	
 
gspoof:	$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o gspoof -lnet $(GTK_LIBS)
	@echo
	@echo "Done! Type 'make install' (This operation could require root privileges)"
	@echo


.c.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) $(GTK_CFLAGS) -c $< -o $@


install:
	chown root:wheel gspoof
	cp -f gspoof ${exec_prefix}/bin
	rm -fR ${prefix}/share/gspoof
	mkdir ${prefix}/share/gspoof
	cp -f *.c ${prefix}/share/gspoof 
	cp -f *.h ${prefix}/share/gspoof
	cp -fR pixmap ${prefix}/share/gspoof
	cp -f Makefile ${prefix}/share/gspoof
	cp -f README ${prefix}/share/gspoof
	cp -f CHANGELOG ${prefix}/share/gspoof
	cp -f TODO ${prefix}/share/gspoof
	cp -f LICENSE ${prefix}/share/gspoof
	cp -f VERSION ${prefix}/share/gspoof
	@echo
	@echo "Try 'gspoof -h' from root, enjoy!"
	@echo
	@echo "(If something goes wrong send an email to embyte@madlab.it)"
	@echo
	
	
clean:
	rm -fR *~ *.bak *.o *.cache *.log gspoof config.status stamp-h*
	@echo
	@echo "Trash file cleaned"
	@echo "You may want to try 'make distclean' to uninstall Gspoof from system"
	@echo


distclean:
	rm -f config.h Makefile
	rm -f ${exec_prefix}/bin/gspoof
	rm -fR ${prefix}/share/gspoof
	@echo
	@echo "You box is clean"
	@echo


version:
	@echo
	@cat VERSION
	@echo

world:	gspoof install
	

help:
	@echo
	@echo "Accepted commands for Makefile:"
	@echo "make		Compile Gspoof"
	@echo "make install	Install Gspoof to ${exec_prefix}/bin and ${prefix}/share"
	@echo "make world	Compile and install"	
	@echo "make clean	Clean trash files from source directory (this)"
	@echo "make distclean	Uninstall Gspoof from system"
	@echo "make version	Show Gspoof version"
	@echo "make help	Show this help"	
	@echo
