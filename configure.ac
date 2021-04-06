#
# This file is part of Gspoof-3 (a console/gtk+ tcp/ip packet forger)
#  
#  $Name: configure.ac $
#  $Version: 3.2 $
#  $Date: 2003/12/22 16:30:03 $
#  $Author: Embyte <embyte@madlab.it> $
#  $Copyright: Copyright (C) 2002-2003 by embyte $
#  $License: This software is under GPL version 2 of license $
# 

AC_PREREQ(2.50)

AC_INIT(main.c)
AC_CONFIG_HEADER(config.h)

# Print a banner
echo -e "\nPlease wait, i'm going to configure Gspoof (have you read README?)\n"

#########
# Subst #
#########

AC_SUBST(GTKOBJS)

################
# Setup prefix #
################

AC_PREFIX_DEFAULT(/usr/local)
if test "$prefix" = "NONE"; then
   prefix="/usr/local"
   fi
   

#######################
# Checks for compiler #
#######################

AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_GCC_TRADITIONAL

#########################
# Checks for libraries. #
#########################

#
# -- libnet --
#

AC_ARG_WITH([libnet-prefix],
            AC_HELP_STRING([--with-libnet-prefix=DIR],
	                   [search for libnet in DIR/include and DIR/lib]),
            [ LIBNET_PREFIX=$withval ],
            [ LIBNET_PREFIX=/usr ])
	    
AC_CHECK_FILE([$LIBNET_PREFIX/lib/libnet.a],
              [LDFLAGS="-L$LIBNET_PREFIX/lib"
	       CPPFLAGS="-I$LIBNET_PREFIX/include" ],
              AC_MSG_ERROR([
Libnet-1.1.1 Packet Shaping Library is required!
Verify to have installed it and pass --with-libnet-prefix to configure.
Or download it from http://www.packetfactory.net/libnet ])) 
              
AC_CHECK_LIB(net, libnet_name2addr4,, 
AC_MSG_ERROR([
Libnet-1.1.1 Packet Shaping Library not found! It's required.
Download it from http://www.packetfactory.net/libnet and install. ]))

#
# -- gtk+ support --
#

ENABLE_GTK=no

AH_TEMPLATE(HAVE_GTK, gtk+ 2.x support)

PKG_CHECK_MODULES(GTK, gtk+-2.0 >= 2.0.0 pango >= 1.0 atk >= 1.0,
      	   [
      	      AC_DEFINE(HAVE_GTK)
      	      ENABLE_GTK=yes
	      GTKOBJS="interface.o callbacks.o gfuncts.o support.o gtk.o"	      
      	   ],
	   [
		AC_MSG_WARN([
Library requirements (gtk+-2.0 >= 2.0.0 pango >= 1.0 atk >= 1.0) not met; 
consider adjusting the PKG_CONFIG_PATH environment variable if your libraries 
are in a nonstandard prefix so pkg-config can find them.
Perhaps you want visit www.gtk.org and download them.

*** Compiling without GTK+ interface support.])
	   ])


##############################################
# Checks for headers and common libs/headers #
##############################################

AC_HEADER_STDC

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_MALLOC
AC_TYPE_SIGNAL
AC_FUNC_VPRINTF


##################
# Write Makefile #
##################

AC_OUTPUT(Makefile)


#################
# Print results #
#################

echo 
echo "Ok. I have done with configuration." 
echo 
echo "Results are:"
echo 
echo "PLATFORM ...... : `uname -mp`"
echo "O.S. .......... : `uname -rs` (`uname -n`)"
echo "COMPILER ...... : ${CC}"
echo "CFLAGS ........ : -Wall -O2"
echo "CPPFLAGS ...... : ${GTK_CFLAGS} ${CPPFLAGS}" 
echo "LDFLAGS ....... : ${LDFLAGS}"
echo "LIBS .......... : ${LIBS} ${GTK_LIBS}"
echo "PREFIX ........ : ${prefix}"
echo "GTK+ SUPPORT .. : ${ENABLE_GTK}"
echo
echo "Type 'make' to compile ('make help' for details)."
echo
