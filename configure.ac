# Process this file with autoconf to produce a configure script.
# Configure template for genpasswd

AC_PREREQ(2.63)
AC_INIT([genpasswd], [1.0.0], [http://oops.org])

AC_CONFIG_AUX_DIR([tools])
AM_INIT_AUTOMAKE([-Wall -Werror -Wno-override foreign no-dependencies])

AC_CONFIG_SRCDIR([genpasswd.c])
AC_CONFIG_HEADER([config.h])
AC_PREFIX_DEFAULT([/usr/local])

AC_DEFUN([AC_DATAROOTDIR_CHECKED])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MKDIR_P
AC_PROG_MAKE_SET
AM_PO_SUBDIRS

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([getopt.h locale.h libintl.h])

# Checks for library functions
AC_CHECK_LIB(crypt, crypt)
AC_CHECK_FUNCS(getopt_long,, [AC_LIBOBJ(getopt) AC_LIBOBJ(getopt1)])

AC_CONFIG_FILES([Makefile po/Makefile])

AC_OUTPUT
