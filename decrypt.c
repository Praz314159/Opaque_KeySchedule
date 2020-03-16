
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#if defined(__unix__) || defined(__unix)
#ifndef unix
#define unix
#endif
#endif

#ifdef unix
#include <unistd.h>
#endif

#include "candidates.h"
#include "words.h"

size_t TXTLEN = 500;
size_t CTXTLEN;

void *xmalloc(size_t);

void die(const char *fmt, ...) __attribute__ ((noreturn));

void print_prompt() {
	/* don't print prompt is stdin is a file or pipe */
	/* this code only works on unix */
#ifdef unix
		if (isatty(fileno(stdin))) {
#endif
			printf("%s", "Enter ciphertext> ");
#ifdef unix
		}
#endif
}

size_t read_ctxt(char **line)
{
	print_prompt();

	size_t n = 0;
	*line = NULL;

	if (getline(line, &n, stdin) < 0)
		die("error reading ctxt");

	(*line)[n-=2] = '\0';

	return n;
}

/* convert {' ', 'a', ..., 'z'} to {0, 1, ..., 26} */
/* we need to do it this way since ' ' is not in the
 * same ascii range as 'a', ..., 'z' */
static inline int c2n(char c)
{
	return c == ' ' ? 0 : c-'a'+1;
}

/* convert {0, 1, ..., 26} to {' ', 'a', ..., 'z'} */
static inline char n2c(int n)
{
	return n == 0 ? ' ' : n+'a'-1;
}

int unique_shifts(const char *cand, const char *ctxt, size_t end)
{
	int i, s, shift[27] = {0};

	for (i = 0; i < end; i++) {
		s = c2n(ctxt[i]) - c2n(cand[i]);
		if (s < 0)
			s += 27;
		shift[s]++;
	}

	s = 0;
	for (i = 0; i < 27; i++)
		if (shift[i])
			s++;

	return s;
}

const char *use_plaintext_dictionary(const char *ctxt) {
	int i;
	int unique_shift_amnts[5];
	for (i = 0; i < 5; i++)
		unique_shift_amnts[i] = unique_shifts(candidates[i], ctxt, CTXTLEN);

	int min = unique_shift_amnts[0], imin = 0;
	for (i = 1; i < 5; i++) {
		if (unique_shift_amnts[i] < min) {
			min = unique_shift_amnts[i];
			imin = i;
		}
	}

	return min > 24 ? NULL : candidates[imin];
}

size_t fitness(const char *ctxt, const char *txt[])
{
	size_t i=0, len = 0;
	char *p = xmalloc(CTXTLEN+20);
	p[0] = 0;

	while (len < CTXTLEN) {
		len += (1 + strlen(txt[i]));
		strcat(p, txt[i++]);
		strcat(p, " ");
	}

	if (len > CTXTLEN) {
		len = CTXTLEN;
		p[len] = 0;
	}

	size_t u = unique_shifts(p, ctxt, len);
	free(p);
	return u;
}

const char *plaintext_search(int strict, const char *ctxt, const char *cand)
{
	size_t i, len;
	const char *rv;

	for (i = 0; i < 40; i++) {
		len = strlen(cand) + strlen(words[i]) + 1;
		char *p = xmalloc(len+1);
		p[0] = 0;
		strcat(p, cand);
		strcat(p, words[i]);
		strcat(p, " ");

		if (len > CTXTLEN) {
			len = CTXTLEN;
			p[len] = 0;
		}

		size_t u = unique_shifts(p, ctxt, len);
		if (u <= strict) {
			if (len == CTXTLEN) {
				return p;
			} else {
				rv = plaintext_search(strict, ctxt, p);
				if (rv) {
					return rv;
				}
			}
		}

		free(p);
	}

	return NULL;
}

int main(int argc, char **argv)
{
	char *ctxt;
	const char *cand;

	CTXTLEN = read_ctxt(&ctxt);

	if (CTXTLEN == TXTLEN) {
		cand = use_plaintext_dictionary(ctxt);
		if (cand) {
			printf("%s\n", cand);
			return 0;
		}
	}

	int i = 10;
	for (i = 10; i < 24; i++) {
		cand = plaintext_search(i, ctxt, "");
		if (cand) {
			printf("%s\n", cand);
			return 0;
		}
	}

	free(ctxt);
}

/* prints message and exit */
void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "decrypt: ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	if (fmt[0] && fmt[strlen(fmt)-1] != ':') {
		fputc('\n', stderr);
	} else {
		fputc(' ', stderr);
		perror(NULL);
	}

	exit(1);
}

/* malloc with error checking */
void *xmalloc(size_t n)
{
	void *p;

	if (!(p = malloc(n)))
		die("malloc():");

	return p;
}

