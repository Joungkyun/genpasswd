/*
 * Process this file with automake to produce Makefile.in
 * Copyright (c) 2016, JoungKyun.Kim <http://oops.org>
 * All rights reserved.
 *
 * This file is part of genpaswd
 * 
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#define ENABLE_NLS

#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

// {{{ i18N support
#ifndef HAVE_LOCALE_H
	#undef ENABLE_NLS
#endif

#ifndef HAVE_LIBINTL_H
	#ifdef ENABLE_NLS
		#undef ENABLE_NLS
	#endif
#endif

#ifdef ENABLE_NLS
	#include <libintl.h>
	#include <locale.h>

	#define _(String) gettext(String)
#else
	#define _(String) (String)
#endif
// i18n support end }}}

#define SEEDS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/."
#define SEEDL 64
#ifndef null
	#define null NULL
#endif
#ifndef safe_free
	#define safe_free(x) do{if(x){free(x);x=NULL;}}while(0)
#endif

#ifndef safe_strcpy
	#define safe_strcpy(x,y,z) (strlen(y)>=z)?strncpy(x,y,z-1):strcpy(x,y)
#endif

#ifndef safe_strcat
	#define safe_strcat(x,y,z) (strlen(y)>=(z-strlen(x)))?strncat(x,y,z-1):strcat(x,y)
#endif

#define MK_MD5    0x31
#define MK_SHA256 0x35
#define MK_SHA512 0x36

#ifdef HAVE_GETOPT_LONG
static struct option long_options[] = { // {{{
	/* Options without arguments: */
	{ "help",   no_argument,       NULL, 'h' },
	{ "stdin",  no_argument,       NULL, 'i' },

	/* Options accepting an argument: */
	{ "method", required_argument, NULL, 'm' },
	{ "salt",   required_argument, NULL, 's' },
	{ 0, 0, 0, 0 }
}; // }}}
#endif

// {{{ +-- void usage (char * prog)
void usage (void) {
	fprintf (
		stderr, _(
		"%s : generate password string\n"
		"Usage: %s [OPTION]\n"
		"       -h, --help         this help messages\n"
		"       -i, --stdin        given password with STDIN\n"
		"       -m, --method=[md5|sha256|sha512] Crypt algorithm [default: sha512]\n"
		"       -s, --salt=SALT    user define salt [default: random string]\n\n"),
		PACKAGE_STRING, PACKAGE_NAME
	);
	exit (1);
}
// }}}

// {{{ +-- int validate_password (char *pass)
int validate_password (char *pass) {
	int lower = 0;
	int upper = 0;
	int num = 0;
	int special = 0;
	int i;

	int passlen = strlen (pass);

	if ( passlen < 9 ) {
		fprintf (stderr, _("BAD PASSWORD: The password is shorter than 9 characters\n"));
		return 1;
	}

	for ( i=0; i<passlen; i++ ) {
		if ( pass[i] >= 48 && pass[i] <= 57 )
			num = 1;
		else if ( pass[i] >= 65 && pass[i] <= 90 )
			upper = 1;
		else if ( pass[i] >= 97 && pass[i] <= 122 )
			lower = 1;
		else if ( pass[i] >=32 && pass[i] <= 47 )
			special = 1;
		else if ( pass[i] >=58 && pass[i] <= 64 )
			special = 1;
		else if ( pass[i] >=91 && pass[i] <= 96 )
			special = 1;
		else if ( pass[i] >=123 && pass[i] <= 126 )
			special = 1;

		if ( lower + upper + num + special > 2 )
			return 0;
	}

	fprintf (stderr, _("BAD PASSWORD: The password contains less than 3 character classes\n"));
	return 1;
}
// }}}

// {{{ +-- char * generate_salt (int type)
char * generate_salt (int type) {
	char * salt, * rsalt;
	int i, size;

	size = 8;
	if ( type > MK_MD5 )
		size *= 2;

	if ( (salt = malloc (sizeof (char) * (size + 4))) == null )
		return (char *) 0;

	rsalt = salt;

	memset (salt, 0, sizeof (char) * (size + 4));
	sprintf (salt, "$%c$", type);

	rsalt += 3;

	srand (time (null));

	for ( i=0; i<size; i++ ) {
		int key = rand () % SEEDL;
		*rsalt = SEEDS[key];
		rsalt++;
	}

	rsalt = 0;

	return salt;
}
// }}}

// {{{ +-- int main (const int argc, const char ** argv)
int main (const int argc, const char ** argv) {
	int opt;
	int method     = MK_SHA512;
	char usalt[64] = { 0, };
	char salt[32]  = { 0, };
	char *pass1    = null;
	char *pass2    = null;
	char *pass     = null;
	int stdin_flag = 0;

#ifdef ENABLE_NLS
	setlocale (LC_CTYPE, "");
	setlocale (LC_MESSAGES, "");
	bindtextdomain ("genpasswd", LANGDIR);
	textdomain ("genpasswd");
#endif

#ifdef HAVE_GETOPT_LONG
	while ( (opt = getopt_long (argc, (char *const *)argv, "him:s:", long_options, (int *) 0)) != EOF ) {
#else
	while ( (opt = getopt (argc, (char *const *)argv, "him:s:")) != EOF ) {
#endif
		switch (opt) {
			case 'i' :
				stdin_flag = 1;
				break;
			case 'm' :
				if ( strcasecmp (optarg, "md5") == 0 ) {
					method = MK_MD5;
				} else if ( strcasecmp (optarg, "sha256") == 0 ) {
					method = MK_SHA256;
				} else if ( strcasecmp (optarg, "sha512") == 0 ) {
					method = MK_SHA512;
				} else {
					fprintf (stderr, _("ERROR: invalid value of -m (%s)\n\n"), optarg);
					usage ();
				}
				break;
			case 's' :
				safe_strcpy (usalt, optarg, sizeof (usalt));
				break;
			default :
				usage ();
		}
	}

	// argc - opdind = number of command line argument
	if ( (argc - optind) > 0 )
		usage ();

	if ( strlen (usalt) > 0 ) {
		/*
		 * case given user define salt
		 */
		char salt_prefix[4] = { 0, };
		sprintf (salt_prefix, "$%c$", method);

		// check invalid salt
		if ( usalt[0] == '$' && usalt[2] == '$' ) {
			if ( strncmp (salt_prefix, usalt, 3) != 0 ) {
				char * algo;
				fprintf (stderr, _("The given salt is invalid. "));

				if ( method == MK_MD5 ) algo = "md5";
				else if ( method == MK_SHA256 ) algo = "sha256";
				else algo = "sha512";

				fprintf (stderr, _("The salt of %s is started by '$%c$'\n"), algo, method);
				exit (1);
			}

			{
				char * ptr = strchr (usalt + 3, '$');
				if ( ptr != null )
					*ptr = 0;

				safe_strcpy (salt, usalt, sizeof (salt));
			}
		} else {
			strcpy (salt, salt_prefix);
			safe_strcat (salt, usalt, sizeof (salt));
		}
	} else {
		/*
		 * case generate random salt
		 */
		char *rsalt = generate_salt (method);
		strcpy (salt, rsalt);
		safe_free (rsalt);
	}

#if 0
	while ( pass1 == null ) {
		pass = getpass ("Password: ");

		if ( validate_password (pass) )
			continue;

		pass1 = strdup (pass);
		pass = getpass ("Retype Password: ");
		pass2 = strdup (pass);

		if ( strcmp (pass1, pass2) != 0 ) {
			fprintf (stderr, "Sorry, passwords do not match.\n");
			safe_free (pass1);
			safe_free (pass2);
		}
	}
#endif
	if ( stdin_flag ) {
		int i;
		char pass[256] = { 0, };
		char * ptr;

		i = read (STDIN_FILENO, pass, sizeof (pass));

		if ( i < 0 ) {
			fprintf (stderr, _("Error: error reading from stdin: %s\n"), strerror (errno));
			exit (1);
		}

		if ( i == sizeof (pass) ) {
			if ( pass[i-1] != '\n' ) {
				fprintf (stderr, _("Error: password too long, maximum is %u\n"), 255);
				exit (1);
			}
			i--;
		}

		pass[i] = 0;
		ptr = strchr (pass, '\n');
		if ( ptr )
			*ptr = 0;

		if ( validate_password (pass) )
			exit (1);

		pass1 = strdup (pass);
	} else {
		pass = getpass (_("Password: "));

		if ( validate_password (pass) )
			exit (1);

		pass1 = strdup (pass);
		pass = getpass (_("Retype Password: "));
		pass2 = strdup (pass);

		if ( strcmp (pass1, pass2) != 0 ) {
			fprintf (stderr, _("Error: Sorry, passwords are not match.\n"));
			safe_free (pass1);
			safe_free (pass2);
			exit (1);
		}
		safe_free (pass2);
	}

	printf("%s\n", crypt (pass1, (char*) salt));
	safe_free (pass1);

	return 0;
}
// }}}
