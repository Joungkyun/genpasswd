#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include <olibc/libarg.h>
#include <errno.h>

#define SEEDS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/."
#define SEEDL 64
#ifndef null
	#define null NULL
#endif
#ifndef safe_free
#define safe_free(x) do{if(x){free(x);x=NULL;}}while(0)
#endif

#define MK_MD5    0
#define MK_SHA256 1
#define MK_SHA512 2

void usage (char * prog) {
	fprintf (
		stderr,
		"Usage: %s [OPTION]\n"
		"       -i      given password with STDIN\n"
		"       -m      Crypt method: md5 or sha256 or sha512 [default: sha512]\n"
		"       -s      user define salt [default: random string]\n\n",
		prog
	);
	exit (1);
}

int validate_password (char *pass) {
	int lower = 0;
	int upper = 0;
	int num = 0;
	int special = 0;
	int i;

	int passlen = strlen (pass);

	if ( passlen < 9 ) {
		fprintf (stderr, "BAD PASSWORD: The password is shorter than 8 characters\n");
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

	fprintf (stderr, "BAD PASSWORD: The password contains less than 3 character classes\n");
	return 1;
}

char * mksalt (int type, int size) {
	char * salt, * rsalt;
	int i;

	if ( size > 16 || size < 1 )
		size = 8;

	if ( type == MK_MD5 )
		size = 8;

	if ( (salt = malloc (sizeof (char) * (size + 4))) == null )
		return (char *) 0;

	rsalt = salt;

	memset (salt, 0, sizeof (char) * (size + 4));

	switch (type) {
		case MK_MD5 :
			strcpy (salt, "$1$");
			break;
		case MK_SHA256 :
			strcpy (salt, "$5$");
			break;
		default:
			strcpy (salt, "$6$");
	}

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

int main (const int argc, const char ** argv) {
	int opt;
	int method = -1;
	char usalt[64] = { 0, };
	char *pass1 = null;
	char *pass2 = null;
	char *pass = null;
	int stdin_flag = 0;

	_ogetopt_cmd_int = 0;
	_ogetopt_chk_int = -1;

	while ( (opt = o_getopt (argc, argv, "m:s:i", NULL)) != -1 ) {
		switch (opt) {
			case 'm' :
				if ( strcasecmp (o_optarg, "md5") == 0 ) {
					method = MK_MD5;
				} else if ( strcasecmp (o_optarg, "sha256") == 0 ) {
					method = MK_SHA256;
				} else if ( strcasecmp (o_optarg, "sha512") == 0 ) {
					method = MK_SHA512;
				} else {
					fprintf (stderr, "ERROR: invalid value of -m (%s)\n", o_optarg);
					ofree_array (o_cmdarg);
					usage ((char *) argv[0]);
				}
				break;
			case 's' :
				if ( o_optlen > 16 ) {
					fprintf (stderr, "ERROR: too long value of -s (%s)\n", o_optarg);
					usage ((char *) argv[0]);
				}

				strcpy (usalt, o_optarg);
				break;
			case 'i' :
				stdin_flag = 1;
				break;
			default :
				ofree_array (o_cmdarg);
				usage ((char *) argv[0]);
		}
	}

	// don't need cmdline argument
	/*
	if ( _ogetopt_cmd_int > 0 ) {
		fprintf (stderr, "ERROR: command line argument don't need\n");
		ofree_array (o_cmdarg);
		usage ((char *) argv[0]);
	}
	*/

	ofree_array (o_cmdarg);

	char salt[32] = { 0, };
	if ( strlen (usalt) > 0 ) {
		switch (method) {
			case MK_MD5 :
				sprintf (salt, "$1$%s$", usalt);
				break;
			case MK_SHA256 :
				sprintf (salt, "$5$%s$", usalt);
				break;
			default :
				sprintf (salt, "$6$%s$", usalt);
		}
	} else {
		char *rsalt = mksalt (method, 8);
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
			fprintf (stderr, "Error: error reading from stdin: %s\n", strerror (errno));
			exit (1);
		}

		if ( i == sizeof (pass) ) {
			if ( pass[i-1] != '\n' ) {
				fprintf (stderr, "Error: password too long, maximum is %u", 255);
				exit (1);
			}
			i--;
		}

		pass[i] = 0;
		ptr = strchr (pass, '\n');
		if ( ptr )
			*ptr = 0;

		pass1 = strdup (pass);
	} else {
		pass = getpass ("Password: ");

		if ( validate_password (pass) )
			exit (1);

		pass1 = strdup (pass);
		pass = getpass ("Retype Password: ");
		pass2 = strdup (pass);

		if ( strcmp (pass1, pass2) != 0 ) {
			fprintf (stderr, "Sorry, passwords do not match.\n");
			safe_free (pass1);
			safe_free (pass2);
			exit (1);
		}
		safe_free (pass2);
	}

	printf("%s\n", crypt(pass1, (char*) salt));
	safe_free (pass1);

	return 0;
}
