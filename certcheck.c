/* Name: Ckyever Gaviola (756550)
** Login ID: cgaviola
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define INPUTLEN 2
#define BUFFERLEN 200
#define BITS_IN_BYTES 8
#define MIN_RSA_LEN 2048
#define VALID 1
#define INVALID 0
#define DELIM ", DNS:"
#define CA_FALSE "CA:FALSE"
#define TLS_AUTHENTICATION "TLS Web Server Authentication"

/* Checks Not Before and Not After dates */
int checkDates(X509 *cert) {
	ASN1_TIME *not_before, *not_after;
	int pday, psec;
	
	/* Gets difference between NB date and the current date */
	not_before = X509_get_notBefore(cert);
	ASN1_TIME_diff(&pday, &psec, not_before, NULL);
	
	/* Current date is before the NB date */
	if (pday < 0 || psec < 0) {
		return INVALID;
	}

	/* Gets difference between the current date and NA date */
	not_after = X509_get_notAfter(cert);
	ASN1_TIME_diff(&pday, &psec, NULL, not_after);
	
	/* Current date is after the NA date */
	if (pday < 0 || psec < 0) {
		return INVALID;
	}

	return VALID;
}

/* Checks domain name matches either Common Name or Subject Alternative Name */
int checkDomain(X509 *cert, char *url) {
	char *cn, *san, *token;
	int nid, cn_result, san_result;
	X509_EXTENSION *ex;
	X509_NAME *cert_name = NULL;
	BUF_MEM *bptr = NULL;
	BIO *bio  = BIO_new(BIO_s_mem());

	/* Set default values */
	cn_result = VALID;
	san_result = VALID;

	/* Get Common Name */
	cn = malloc(BUFFERLEN * sizeof(char));
	cert_name = X509_get_subject_name(cert);
	nid = X509_NAME_get_text_by_NID(cert_name, NID_commonName, cn, BUFFERLEN);

	/* Common Name exists */
	if (nid != -1) {
		/* If it is a wildcard, remove '*' first before comparing */
		if (cn[0] == '*') {
			memmove(cn, cn+1, strlen(cn));
		}

		/* Common Name not contained in the url */
		if (strstr(url, cn) == NULL) {
			cn_result = INVALID;
		}
	}

	free(cn);
	
	/* Get Subject Alternative Name */
	nid = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
	ex = X509_get_ext(cert, nid);
	
	/* Subject Alternative Name exists */
	if (nid != -1) {
		/* Convert to a string */
		BIO_reset(bio);
		X509V3_EXT_print(bio, ex, 0, 0);
		BIO_flush(bio);
		BIO_get_mem_ptr(bio, &bptr);
		san = malloc((bptr->length + 1) * sizeof(char));
		memcpy(san, bptr->data, bptr->length);
		san[bptr->length] = '\0';
		
		/* Split into individual alternative names */
		token = strtok(san, DELIM);

		while (token != NULL) {
			/* Remove wildcard character */
			if (token[0] == '*') {
				token ++;
			}
			
			/* One of the SANs is in the url */
			if (strstr(url, token) != NULL) {
				break;
			}
			
			/* Get next SAN */
			token = strtok(NULL, DELIM);
		}

		/* We went through all SANs and did not find a match */
		if (token == NULL) {
			san_result = INVALID;
		}

		free(san);
	}
	else {
		san_result = INVALID;
	}
	
	/* URL is not valid against either CN or SAN */
	if (cn_result == INVALID && san_result == INVALID) {
		return INVALID;
	}

	return VALID;
}

/* Checks RSA key length (in bits) is greater than specified length */
int checkRSALen(X509 *cert, int min_length) {
	EVP_PKEY *pub_key;
	RSA *rsa_key;
	int key_length;
	
	/* Get public key */
	pub_key = X509_get_pubkey(cert);
	if (pub_key == NULL) {
		fprintf(stderr, "ERROR getting public key");
		exit(EXIT_FAILURE);
	}
	
	/* Get RSA key */
	rsa_key = EVP_PKEY_get1_RSA(pub_key);
	if (rsa_key == NULL) {
		fprintf(stderr, "ERROR key is not RSA");
		exit(EXIT_FAILURE);
	}

	/* Get length of RSA key in bits */
	key_length = RSA_size(rsa_key);
	key_length *= BITS_IN_BYTES;

	/* RSA key is less than the minimum length */
	if (key_length < min_length) {
		return INVALID;
	}

	return VALID;
}

/* Checks BasicConstraints for specified constraint */
int checkConstraints(X509 *cert, char* constraint) {
	X509_EXTENSION *ex;
	BUF_MEM *bptr = NULL;
	BIO *bio  = BIO_new(BIO_s_mem());
	char *bc;
	int nid, result = VALID;

	/* Get BasicConstraint */
	nid = X509_get_ext_by_NID(cert, NID_basic_constraints, -1);
	ex = X509_get_ext(cert,nid);

	/* BasicConstraint exists */
	if (nid != -1) {
		/* Convert to a string */
		BIO_reset(bio);
		X509V3_EXT_print(bio, ex, 0, 0);
		BIO_flush(bio);
		BIO_get_mem_ptr(bio, &bptr);
		bc = malloc((bptr->length + 1) *sizeof(char));
		memcpy(bc, bptr->data, bptr->length);
		bc[bptr->length] = '\0';

		/* Does not include constraint */
		if (strstr(bc, constraint) == NULL) {
			result = INVALID;
		}
	}
	
	free(bc);
	return result;
}

/* Checks Enhanced Key Usage includes specified usage */
int checkKeyUsage(X509 *cert, char *usage) {
	X509_EXTENSION *ex;
	BUF_MEM *bptr = NULL;
	BIO *bio  = BIO_new(BIO_s_mem());
	char *eku;
	int nid, result = VALID;

	/* Get Enhanced Key Usage */
	nid = X509_get_ext_by_NID(cert, NID_ext_key_usage, -1);
	ex = X509_get_ext(cert,nid);

	/* Enhanced Key Usage exists */
	if (nid != -1) {
		/* Convert to a string */
		BIO_reset(bio);
		X509V3_EXT_print(bio, ex, 0, 0);
		BIO_flush(bio);
		BIO_get_mem_ptr(bio, &bptr);
		eku = malloc((bptr->length + 1) *sizeof(char));
		memcpy(eku, bptr->data, bptr->length);
		eku[bptr->length] = '\0';

		/* Does not include correct statement */
		if (strstr(eku, usage) == NULL) {
			result = INVALID;
		}
	}
	
	free(eku);
	return result;
}

/* Checks given certificate, returning 1 for pass and 0 for fail */
int checkCert(char *filepath, char *url) {
	BIO *cert_bio = NULL;
	X509 *cert = NULL;

	/* Initialise openSSL */
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	/* Create BIO object to read certificate */
	cert_bio = BIO_new(BIO_s_file());

	/* Read certificate into BIO */
	if (!(BIO_read_filename(cert_bio, filepath))) {
		fprintf(stderr, "ERROR reading certificate BIO filname");
		exit(EXIT_FAILURE);
	}
	if (!(cert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL))) {
		fprintf(stderr, "ERROR loading certificate");
		exit(EXIT_FAILURE);
	}

	int result = VALID;	// only changes if it fails a test
	
	/* Valiate "Not Before" & "Not After" dates */
	if (checkDates(cert) == INVALID) {
		result = INVALID;
	}

	/* Validate Domain Name in CN or SAN */		
	if (checkDomain(cert,url) == INVALID) {
		result = INVALID;
	}

	/* Validate RSA key has at minimum, length of 2048 bits */
	if (checkRSALen(cert, MIN_RSA_LEN) == INVALID) {
		result = INVALID;
	}

	/* Validate BasicContraint includes CA:FALSE */
	if (checkConstraints(cert, CA_FALSE) == INVALID) {
		result = INVALID;
	}

	/* Validate Enhanced Key Usage is TLS Web Server Authetication */
	if (checkKeyUsage(cert, TLS_AUTHENTICATION) == INVALID) {
		result = INVALID;
	}

	/* Free everything else */
	X509_free(cert);
	BIO_free_all(cert_bio);

	return result;
}

int
main(int argc, char **argv) {
	char *pathlocation, *buffer, *certpath, *url;
	FILE *testfile, *outfile;
	int result, n;

	/* Get location of test file */
	if (argc != INPUTLEN) {
		fprintf(stderr, "Usage: ./certcheck path_to_testfile.csv\n");
		exit(EXIT_FAILURE);
	}
	pathlocation = argv[1];

	/* Open test file */
	testfile = fopen(pathlocation, "r");
	if (testfile == NULL) {
		perror("ERROR on file open");
		exit(EXIT_FAILURE);
	}

	/* Create output file */
	outfile = fopen("output.csv", "w");
	if (outfile == NULL) {
		perror("ERROR on creating output file");
		exit(EXIT_FAILURE);
	}

	/* Initialise buffer */
	buffer = malloc(BUFFERLEN * sizeof(char));
	if (buffer == NULL) {
		perror("ERROR on allocting buffer memory");
		exit(EXIT_FAILURE);
	}

	/* Get each line of the test file */
	while (fgets(buffer, BUFFERLEN, testfile)) {
		 if (buffer == NULL) {
		 	perror("ERROR getting next line");
			exit(EXIT_FAILURE);
		}
		
		/* Split into path location of certificate & its url */
		certpath = strtok(buffer, ",");
		url = strtok(NULL, "\n");

		/* Check certificate and print result to output file*/
		result = checkCert(certpath, url);
		n = fprintf(outfile, "%s,%s,%d\n", certpath, url, result);
		if (n < 0) {
			perror("ERROR writing to output file");
			exit(EXIT_FAILURE);
		}
	}

	/* Close all files */
	fclose(testfile);
	fclose(outfile);

	/* Free buffer */
	free(buffer);

	return 0;
}
