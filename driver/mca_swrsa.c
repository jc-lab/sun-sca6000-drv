/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2006 Sun Microsystems, Inc. All Rights Reserved.
 *
 *     Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * - Redistribution of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * - Redistribution in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *     Neither the name of Sun Microsystems, Inc. or the names of contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *     This software is provided "AS IS," without a warranty of any kind. ALL
 * EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND WARRANTIES, INCLUDING
 * ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
 * OR NON-INFRINGEMENT, ARE HEREBY EXCLUDED. SUN MICROSYSTEMS, INC. ("SUN")
 * AND ITS LICENSORS SHALL NOT BE LIABLE FOR ANY DAMAGES SUFFERED BY LICENSEE
 * AS A RESULT OF USING, MODIFYING OR DISTRIBUTING THIS SOFTWARE OR ITS
 * DERIVATIVES. IN NO EVENT WILL SUN OR ITS LICENSORS BE LIABLE FOR ANY LOST
 * REVENUE, PROFIT OR DATA, OR FOR DIRECT, INDIRECT, SPECIAL, CONSEQUENTIAL,
 * INCIDENTAL OR PUNITIVE DAMAGES, HOWEVER CAUSED AND REGARDLESS OF THE THEORY
 * OF LIABILITY, ARISING OUT OF THE USE OF OR INABILITY TO USE THIS SOFTWARE,
 * EVEN IF SUN HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 *     You acknowledge that this software is not designed, licensed or
 * intended for use in the design, construction, operation or maintenance of
 * any nuclear facility.
 */

#pragma ident	"@(#)mca_swrsa.c	1.1	05/04/12 SMI"

/*
 * Software RSA implementation -- including most of bignum.  Used in
 * KTK exchange with firmware.
 */

#ifdef LINUX
#include <linux/types.h>
#include "sol2lin.h"
#include "mca.h"
#else
#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/mca.h>
#endif

/*
 * leading 0's are permitted
 * 0 should be represented by size>=1, size>=len>=1, sign=1,
 * value[i]=0 for 0<i<len
 */
typedef struct {
	int size; /* the size of memory allocated for value (in words) */
	int len;  /* the number of words that hold valid data in value */
	int sign; /* 1 for nonnegative, -1 for negative   */
	int malloced; /* 1 if value was malloced 0 if not */
	uint32_t *value;
} BIGNUM;

typedef struct {
	int 	size;		/* key size in bits */
	BIGNUM	p;		/* p */
	BIGNUM	q;		/* q */
	BIGNUM	n;		/* n = p * q (the modulus) */
	BIGNUM	d;		/* private exponent */
	BIGNUM	e;		/* public exponent */
	BIGNUM	dmodpminus1;	/* d mod (p - 1) */
	BIGNUM	dmodqminus1;	/* d mod (q - 1) */
	BIGNUM	pinvmodq;	/* p^(-1) mod q */
	BIGNUM	p_rr;		/* 2^(2*(32*p->len)) mod p */
	BIGNUM	q_rr;		/* 2^(2*(32*q->len)) mod q */
	BIGNUM	n_rr;		/* 2^(2*(32*n->len)) mod n */
} RSAkey;

#define	BIGTMPSIZE	65

#define	big_malloc(x)	kmem_alloc(x, KM_SLEEP)

static void *
big_realloc(void *from, size_t oldsize, size_t newsize)
{
	void *rv;

	rv = kmem_alloc(newsize, KM_SLEEP);
	bcopy(from, rv, oldsize);
	kmem_free(from, oldsize);
	return (rv);
}

#define	arraysize(x) (sizeof (x) / sizeof (x[0]))

/* size in 32-bit words */
static int
big_init(BIGNUM *number, int size)
{
	number->value = big_malloc(sizeof (uint32_t) * size);
	if (number->value == NULL) {
		return (CRYPTO_HOST_MEMORY);
	}
	number->size = size;
	number->len = 0;
	number->sign = 1;
	number->malloced = 1;
	return (CRYPTO_SUCCESS);
}

/* size in 32-bit words */
static int
big_init1(BIGNUM *number, int size, uint32_t *buf, int bufsize)
{
	if ((buf == NULL) || (size > bufsize)) {
		number->value = big_malloc(sizeof (uint32_t) * size);
		if (number->value == NULL) {
			return (CRYPTO_HOST_MEMORY);
		}
		number->size = size;
		number->malloced = 1;
	} else {
		number->value = buf;
		number->size = bufsize;
		number->malloced = 0;
	}
		number->len = 0;
		number->sign = 1;

	return (CRYPTO_SUCCESS);
}

static void
big_finish(BIGNUM *number)
{
	if (number->malloced == 1) {
		kmem_free(number->value, sizeof (uint32_t) * number->size);
		number->malloced = 0;
	}
}

/*
 *  bn->size should be at least (len + 3) / 4
 * converts from byte-big-endian format to bignum format (words in
 * little endian order, but bytes within the words big endian)
 */
static void
kcl2bignum(BIGNUM *bn, uchar_t *kn, size_t len)
{
	int		i, j, offs;
	uint32_t	word;
	uchar_t		*knwordp;

	offs = len % sizeof (uint32_t);
	bn->len = len / sizeof (uint32_t);
	for (i = 0; i < len / sizeof (uint32_t); i++) {
		knwordp = &(kn[len - sizeof (uint32_t) * (i + 1)]);
		word = knwordp[0];
		for (j = 1; j < sizeof (uint32_t); j++) {
			word = (word << 8)+ knwordp[j];
		}
		bn->value[i] = word;
	}
	if (offs > 0) {
		word = kn[0];
		for (i = 1; i < offs; i++) word = (word << 8) + kn[i];
		bn->value[bn->len++] = word;
	}
	while ((bn->len > 1) && (bn->value[bn->len-1] == 0)) {
		bn->len --;
	}
}

/*
 * copies the least significant len bytes if
 * len < bn->len * sizeof (uint32_t)
 * converts from bignum format (words in little endian order, but bytes
 * within the words big endian) to byte-big-endian format
 */
static void
bignum2kcl(uchar_t *kn, BIGNUM *bn, size_t len)
{
	int		i, j, offs;
	uint32_t	word;

	if (len < sizeof (uint32_t) * bn->len) {
		for (i = 0; i < len / sizeof (uint32_t); i++) {
			word = bn->value[i];
			for (j = 0; j < sizeof (uint32_t); j++) {
				kn[len - sizeof (uint32_t) * i - j - 1] =
				    word & 0xff;
				word = word >> 8;
			}
		}
		offs = len % sizeof (uint32_t);
		if (offs > 0) {
			word = bn->value[len / sizeof (uint32_t)];
			    for (i = len % sizeof (uint32_t); i > 0; i --) {
				    kn[i - 1] = word & 0xff;
				    word = word >> 8;
			    }
		}
	} else {
		for (i = 0; i < bn->len; i++) {
			word = bn->value[i];
			for (j = 0; j < sizeof (uint32_t); j++) {
				kn[len - sizeof (uint32_t) * i - j - 1] =
				    word & 0xff;
				word = word >> 8;
			}
		}
		for (i = 0; i < len - sizeof (uint32_t) * bn->len; i++) {
			kn[i] = 0;
		}
	}
}

static int
RSA_key_init(RSAkey *key, int psize, int qsize)
{
	int plen, qlen, nlen;
	int err;

	plen = (psize + 31) / 32;
	qlen = (qsize + 31) / 32;
	nlen = plen + qlen;
	key->size = psize + qsize;
	if ((err = big_init1(&(key->p), plen, NULL, 0)) != CRYPTO_SUCCESS)
		return (err);
	if ((err = big_init1(&(key->q), qlen, NULL, 0)) != CRYPTO_SUCCESS)
		goto ret1;
	if ((err = big_init1(&(key->n), nlen, NULL, 0)) != CRYPTO_SUCCESS)
		goto ret2;
	if ((err = big_init1(&(key->d), nlen, NULL, 0)) != CRYPTO_SUCCESS)
		goto ret3;
	if ((err = big_init1(&(key->e), nlen, NULL, 0)) != CRYPTO_SUCCESS)
		goto ret4;
	if ((err = big_init1(&(key->dmodpminus1), plen, NULL, 0))
	    != CRYPTO_SUCCESS)
		goto ret5;
	if ((err = big_init1(&(key->dmodqminus1), qlen, NULL, 0))
	    != CRYPTO_SUCCESS)
		goto ret6;
	if ((err = big_init1(&(key->pinvmodq), qlen, NULL, 0))
	    != CRYPTO_SUCCESS)
		goto ret7;
	if ((err = big_init1(&(key->p_rr), plen, NULL, 0)) != CRYPTO_SUCCESS)
		goto ret8;
	if ((err = big_init1(&(key->q_rr), qlen, NULL, 0)) != CRYPTO_SUCCESS)
		goto ret9;
	if ((err = big_init1(&(key->n_rr), nlen, NULL, 0)) != CRYPTO_SUCCESS)
		goto ret10;

	return (CRYPTO_SUCCESS);

ret10:
	big_finish(&(key->q_rr));
ret9:
	big_finish(&(key->p_rr));
ret8:
	big_finish(&(key->pinvmodq));
ret7:
	big_finish(&(key->dmodqminus1));
ret6:
	big_finish(&(key->dmodpminus1));
ret5:
	big_finish(&(key->e));
ret4:
	big_finish(&(key->d));
ret3:
	big_finish(&(key->n));
ret2:
	big_finish(&(key->q));
ret1:
	big_finish(&(key->p));
	return (err);
}

static void
RSA_key_finish(RSAkey *key)
{
	big_finish(&(key->n_rr));
	big_finish(&(key->q_rr));
	big_finish(&(key->p_rr));
	big_finish(&(key->pinvmodq));
	big_finish(&(key->dmodqminus1));
	big_finish(&(key->dmodpminus1));
	big_finish(&(key->e));
	big_finish(&(key->d));
	big_finish(&(key->n));
	big_finish(&(key->q));
	big_finish(&(key->p));
}

static int
big_copy(BIGNUM *dest, BIGNUM *src)
{
	uint32_t *newptr;
	int i, len;

	len = src->len;
	while ((len > 1) && (src->value[len - 1] == 0))
		len--;
	src->len = len;
	if (dest->size < len) {
		if (dest->malloced == 1) {
			newptr = (uint32_t *)big_realloc(dest->value,
			    sizeof (uint32_t) * dest->size,
			    sizeof (uint32_t) * len);
		} else {
			newptr = (uint32_t *)
			    big_malloc(sizeof (uint32_t) * len);
			if (newptr != NULL) dest->malloced = 1;
		}
		if (newptr == NULL)
			return (CRYPTO_HOST_MEMORY);
		dest->value = newptr;
		dest->size = len;
	}
	dest->len = len;
	dest->sign = src->sign;
	for (i = 0; i < len; i++) dest->value[i] = src->value[i];

	return (CRYPTO_SUCCESS);
}

static int
big_extend(BIGNUM *number, int size)
{
	uint32_t	*newptr;
	int		i;

	if (number->size >= size)
		return (CRYPTO_SUCCESS);
	if (number->malloced) {
		number->value =
		    big_realloc(number->value,
			sizeof (uint32_t) * number->size,
			sizeof (uint32_t) * size);
	} else {
		newptr = big_malloc(sizeof (uint32_t) * size);
		if (newptr != NULL) {
			for (i = 0; i < number->size; i++) {
				newptr[i] = number->value[i];
			}
		}
		number->value = newptr;
	}

	if (number->value == NULL)
		return (CRYPTO_HOST_MEMORY);

	number->size = size;
	number->malloced = 1;
	return (CRYPTO_SUCCESS);
}

/* caller must make sure that result has at least len words allocated */
static void
big_sub_vec(uint32_t *r, uint32_t *a, uint32_t *b, int len)
{
	int i;
	uint32_t cy, ai;

	cy = 1;
	for (i = 0; i < len; i++) {
		ai = a[i];
		r[i] = ai + (~b[i]) + cy;
		if (r[i] > ai) cy = 0;
		else if (r[i] < ai) cy = 1;
	}
}


/* result=aa-bb  it is assumed that aa>=bb */
static int
big_sub_pos(BIGNUM *result, BIGNUM *aa, BIGNUM *bb)
{
	int i, shorter;
	uint32_t cy, ai;
	uint32_t *r, *a, *b;
	int err;

	if (aa->len > bb->len) shorter = bb->len;
	else shorter = aa->len;
	if (result->size < aa->len) {
		err = big_extend(result, aa->len);
		if (err != CRYPTO_SUCCESS)
			return (err);
	}

	r = result->value;
	a = aa->value;
	b = bb->value;
	result->len = aa->len;
	cy = 1;
	for (i = 0; i < shorter; i++) {
		ai = a[i];
		r[i] = ai + (~b[i]) + cy;
		if (r[i] > ai) cy = 0;
		else if (r[i] < ai) cy = 1;
	}
	for (; i < aa->len; i++) {
		ai = a[i];
		r[i] = ai + (~0) + cy;
		if (r[i] < ai) cy = 1;
	}
	result->sign = 1;
	if (cy == 0)
		return (CRYPTO_ARGUMENTS_BAD);
	else
		return (CRYPTO_SUCCESS);
}


/* returns -1 if |aa|<|bb|, 0 if |aa|==|bb| 1 if |aa|>|bb| */
static int
big_cmp_abs(BIGNUM *aa, BIGNUM *bb)
{
	int i;

	if (aa->len > bb->len) {
		for (i = aa->len - 1; i > bb->len - 1; i--) {
			if (aa->value[i] > 0)
				return (1);
		}
	} else if (aa->len < bb->len) {
		for (i = bb->len - 1; i > aa->len - 1; i--) {
			if (bb->value[i] > 0)
				return (-1);
		}
	} else i = aa->len-1;
	for (; i >= 0; i--) {
		if (aa->value[i] > bb->value[i])
			return (1);
		else if (aa->value[i] < bb->value[i])
			return (-1);
	}

	return (0);
}

/*
 * result = aa - (2^32)^lendiff * bb
 * result->size should be at least aa->len at entry
 * aa, bb, and result should be positive
 */
static void
big_sub_pos_high(BIGNUM *result, BIGNUM *aa, BIGNUM *bb)
{
	int i, lendiff;
	BIGNUM res1, aa1;

	lendiff = aa->len - bb->len;
	res1.size = result->size - lendiff;
	res1.malloced = 0;
	res1.value = result->value + lendiff;
	aa1.size = aa->size - lendiff;
	aa1.value = aa->value + lendiff;
	aa1.len = bb->len;
	aa1.sign = 1;
	(void) big_sub_pos(&res1, &aa1, bb);
	if (result->value != aa->value) {
		for (i = 0; i < lendiff; i++) {
			result->value[i] = aa->value[i];
		}
	}
	result->len = aa->len;
}


/*
 * returns 1, 0, or -1 depending on whether |aa| > , ==, or <
 *							(2^32)^lendiff * |bb|
 * aa->len should be >= bb->len
 */
static int
big_cmp_abs_high(BIGNUM *aa, BIGNUM *bb)
{
	int lendiff;
	BIGNUM aa1;

	lendiff = aa->len - bb->len;
	aa1.len = bb->len;
	aa1.size = aa->size - lendiff;
	aa1.malloced = 0;
	aa1.value = aa->value + lendiff;
	return (big_cmp_abs(&aa1, bb));
}


/*
 * result = aa * b where b is a max. 16-bit positive integer.
 * result should have enough space allocated.
 */
static void
big_mul16_low(BIGNUM *result, BIGNUM *aa, uint32_t b)
{
	int i;
	uint32_t t1, t2, ai, cy;
	uint32_t *a, *r;

	a = aa->value;
	r = result->value;
	cy = 0;
	for (i = 0; i < aa->len; i++) {
		ai = a[i];
		t1 = (ai & 0xffff) * b + cy;
		t2 = (ai >> 16) * b + (t1 >> 16);
		r[i] = (t1 & 0xffff) | (t2 << 16);
		cy = t2 >> 16;
	}
	r[i] = cy;
	result->len = aa->len + 1;
	result->sign = aa->sign;
}


/*
 * result = aa * b * 2^16 where b is a max. 16-bit positive integer.
 * result should have enough space allocated.
 */
static void
big_mul16_high(BIGNUM *result, BIGNUM *aa, uint32_t b)
{
	int i;
	uint32_t t1, t2, ai, cy, ri;
	uint32_t *a, *r;

	a = aa->value;
	r = result->value;
	cy = 0;
	ri = 0;
	for (i = 0; i < aa->len; i++) {
		ai = a[i];
		t1 = (ai & 0xffff) * b + cy;
		t2 = (ai >> 16) * b + (t1 >> 16);
		r[i] = (t1 << 16) + ri;
		ri = t2 & 0xffff;
		cy = t2 >> 16;
	}
	r[i] = (cy << 16) + ri;
	result->len = aa->len + 1;
	result->sign = aa->sign;
}

/* it is assumed that result->size is big enough */
static void
big_shiftleft(BIGNUM *result, BIGNUM *aa, int offs)
{
	int i;
	uint32_t cy, ai;

	if (offs == 0) {
		if (result != aa) {
			(void) big_copy(result, aa);
		}
		return;
	}
	cy = 0;
	for (i = 0; i < aa->len; i++) {
		ai = aa->value[i];
		result->value[i] = (ai << offs) | cy;
		cy = ai >> (32 - offs);
	}
	if (cy != 0) {
		result->len = aa->len + 1;
		result->value[result->len - 1] = cy;
	} else {
		result->len = aa->len;
	}
	result->sign = aa->sign;
}

/* it is assumed that result->size is big enough */
static void
big_shiftright(BIGNUM *result, BIGNUM *aa, int offs)
{
	int i;
	uint32_t cy, ai;

	if (offs == 0) {
		if (result != aa) {
			(void) big_copy(result, aa);
		}
		return;
	}
	cy = aa->value[0] >> offs;
	for (i = 1; i < aa->len; i++) {
		ai = aa->value[i];
		result->value[i-1] = (ai << (32 - offs)) | cy;
		cy = ai >> offs;
	}
	result->len = aa->len;
	result->value[result->len - 1] = cy;
	result->sign = aa->sign;
}


/*
 * result = aa/bb   remainder = aa mod bb
 * it is assumed that aa and bb are positive
 */
static int
big_div_pos(BIGNUM *result, BIGNUM *remainder, BIGNUM *aa, BIGNUM *bb)
{
	int err;
	int i, alen, blen, tlen, rlen, offs;
	uint32_t higha, highb, coeff;
	uint64_t highb64;
	uint32_t *a, *b;
	BIGNUM bbhigh, bblow, tresult, tmp1, tmp2;
	uint32_t tmp1value[BIGTMPSIZE];
	uint32_t tmp2value[BIGTMPSIZE];
	uint32_t tresultvalue[BIGTMPSIZE];
	uint32_t bblowvalue[BIGTMPSIZE];
	uint32_t bbhighvalue[BIGTMPSIZE];

	a = aa->value;
	b = bb->value;
	alen = aa->len;
	blen = bb->len;
	while ((alen > 1) && (a[alen - 1] == 0)) alen = alen - 1;
	aa->len = alen;
	while ((blen > 1) && (b[blen - 1] == 0)) blen = blen - 1;
	bb->len = blen;
	if ((blen == 1) && (b[0] == 0))
		/* division by zero */
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);

	if (big_cmp_abs(aa, bb) < 0) {
		if ((remainder != NULL) &&
		    ((err = big_copy(remainder, aa)) != CRYPTO_SUCCESS))
			return (err);
		if (result != NULL) {
			result->len = 1;
			result->sign = 1;
			result->value[0] = 0;
		}
		return (CRYPTO_SUCCESS);
	}

	if ((err = big_init1(&bblow, blen + 1,
	    bblowvalue, arraysize(bblowvalue))) != CRYPTO_SUCCESS)
		return (err);

	if ((err = big_init1(&bbhigh, blen + 1,
	    bbhighvalue, arraysize(bbhighvalue))) != CRYPTO_SUCCESS)
		goto ret1;

	if ((err = big_init1(&tmp1, alen + 2,
	    tmp1value, arraysize(tmp1value))) != CRYPTO_SUCCESS)
		goto ret2;

	if ((err = big_init1(&tmp2, blen + 2,
	    tmp2value, arraysize(tmp2value))) != CRYPTO_SUCCESS)
		goto ret3;

	if ((err = big_init1(&tresult, alen - blen + 2,
	    tresultvalue, arraysize(tresultvalue))) != CRYPTO_SUCCESS)
		goto ret4;

	offs = 0;
	if (blen > 1) {
		highb64 = (((uint64_t)(b[blen - 1])) << 32) |
		    ((uint64_t)(b[blen - 2]));
	} else {
		highb64 = (((uint64_t)(b[blen - 1])) << 32);
	}
	if (highb64 >= 0x1000000000000ull) {
		highb64 = highb64 >> 16;
		offs = 16;
	}
	while ((highb64 & 0x800000000000ull) == 0) {
		highb64 = highb64 << 1;
		offs++;
	}
	highb = highb64 >> 32;

	big_shiftleft(&bblow, bb, offs);
	if (offs <= 15) {
		big_shiftleft(&bbhigh, &bblow, 16);
	} else {
		big_shiftright(&bbhigh, &bblow, 16);
	}
	if (bbhigh.value[bbhigh.len - 1] == 0) {
		bbhigh.len--;
	} else {
		bbhigh.value[bbhigh.len] = 0;
	}

	big_shiftleft(&tmp1, aa, offs);
	rlen = tmp1.len - bblow.len + 1;
	tresult.len = rlen;

	tmp1.len++;
	tlen = tmp1.len;
	tmp1.value[tmp1.len - 1] = 0;
	for (i = 0; i < rlen; i++) {
		higha = (tmp1.value[tlen - 1] << 16) +
		    (tmp1.value[tlen - 2] >> 16);
		coeff = higha / (highb + 1);
		big_mul16_high(&tmp2, &bblow, coeff);
		big_sub_pos_high(&tmp1, &tmp1, &tmp2);
		bbhigh.len++;
		while (tmp1.value[tlen - 1] > 0) {
			big_sub_pos_high(&tmp1, &tmp1, &bbhigh);
			coeff++;
		}
		bbhigh.len--;
		tlen--;
		tmp1.len--;
		while (big_cmp_abs_high(&tmp1, &bbhigh) >= 0) {
			big_sub_pos_high(&tmp1, &tmp1, &bbhigh);
			coeff++;
		}
		tresult.value[rlen - i - 1] = coeff << 16;
		higha = tmp1.value[tlen - 1];
		coeff = higha / (highb + 1);
		big_mul16_low(&tmp2, &bblow, coeff);
		tmp2.len--;
		big_sub_pos_high(&tmp1, &tmp1, &tmp2);
		while (big_cmp_abs_high(&tmp1, &bblow) >= 0) {
			big_sub_pos_high(&tmp1, &tmp1, &bblow);
			coeff++;
		}
		tresult.value[rlen - i - 1] =
		    tresult.value[rlen - i - 1] + coeff;
	}

	big_shiftright(&tmp1, &tmp1, offs);

	err = CRYPTO_SUCCESS;

	if ((remainder != NULL) &&
	    ((err = big_copy(remainder, &tmp1)) != CRYPTO_SUCCESS))
		goto ret;

	if (result != NULL)
		err = big_copy(result, &tresult);

ret:
	big_finish(&tresult);
ret4:
	big_finish(&tmp1);
ret3:
	big_finish(&tmp2);
ret2:
	big_finish(&bbhigh);
ret1:
	big_finish(&bblow);
	return (err);
}

/*
 * r = r + a * digit, r and a are vectors of length len
 * returns the carry digit
 */
static uint32_t
big_mul_add_vec(uint32_t *r, uint32_t *a, int len, uint32_t digit)
{
	uint32_t cy, cy1, retcy, dlow, dhigh;
	int i;

	cy1 = 0;
	dlow = digit & 0xffff;
	dhigh = digit >> 16;
	for (i = 0; i < len; i++) {
		cy = (cy1 >> 16) + dlow * (a[i] & 0xffff) + (r[i] & 0xffff);
		cy1 = (cy >> 16) + dlow * (a[i]>>16) + (r[i] >> 16);
		r[i] = (cy & 0xffff) | (cy1 << 16);
	}
	retcy = cy1 >> 16;

	cy1 = r[0] & 0xffff;
	for (i = 0; i < len - 1; i++) {
		cy = (cy1 >> 16) + dhigh * (a[i] & 0xffff) + (r[i] >> 16);
		r[i] = (cy1 & 0xffff) | (cy << 16);
		cy1 = (cy >> 16) + dhigh * (a[i] >> 16) + (r[i + 1] & 0xffff);
	}
	cy = (cy1 >> 16) + dhigh * (a[len - 1] & 0xffff) + (r[len - 1] >> 16);
	r[len - 1] = (cy1 & 0xffff) | (cy << 16);
	retcy = (cy >> 16) + dhigh * (a[len - 1] >> 16) + retcy;

	return (retcy);
}

/* result = aa * bb  result->value should be big enough to hold the result */
static int
big_mul(BIGNUM *result, BIGNUM *aa, BIGNUM *bb)
{
	BIGNUM tmp1;
	BIGNUM *tt;
	uint32_t tmp1value[BIGTMPSIZE];
	uint32_t *r, *t, *a, *b;
	int err;
	int i, alen, blen, rsize, sign;

	if (big_cmp_abs(aa, bb) < 0) {
		tt = aa;
		aa = bb;
		bb = tt;
	}
	a = aa->value;
	b = bb->value;
	alen = aa->len;
	blen = bb->len;
	while ((alen > 1) && (a[alen - 1] == 0)) alen--;
	aa->len = alen;
	while ((blen > 1) && (b[blen - 1] == 0)) blen--;
	bb->len = blen;

	rsize = alen + blen;
	if (result->size < rsize) {
		err = big_extend(result, rsize);
		if (err != CRYPTO_SUCCESS)
			return (err);
		/* aa or bb might be an alias to result */
		a = aa->value;
		b = bb->value;
	}
	r = result->value;

	if (((alen == 1) && (a[0] == 0)) || ((blen == 1) && (b[0] == 0))) {
		result->len = 1;
		result->sign = 1;
		r[0] = 0;
	}
	sign = aa->sign * bb->sign;
	if ((alen == 1) && (a[0] == 1)) {
		for (i = 0; i < blen; i++) r[i] = b[i];
		result->len = blen;
		result->sign = sign;
		return (CRYPTO_SUCCESS);
	}
	if ((blen == 1) && (b[0] == 1)) {
		for (i = 0; i < alen; i++) r[i] = a[i];
		result->len = alen;
		result->sign = sign;
		return (CRYPTO_SUCCESS);
	}

	if ((err = big_init1(&tmp1, alen + blen,
	    tmp1value, arraysize(tmp1value))) != CRYPTO_SUCCESS)
		return (err);
	(void) big_copy(&tmp1, aa);
	t = tmp1.value;

	for (i = 0; i < alen + blen; i++) t[i] = 0;
	for (i = 0; i < blen; i++)
		t[i+alen] = big_mul_add_vec(t+i, a, alen, b[i]);
	if (t[alen + blen - 1] == 0) tmp1.len = alen + blen - 1;
	else tmp1.len = alen + blen;
	if ((err = big_copy(result, &tmp1)) != CRYPTO_SUCCESS)
		return (err);
	result->sign = sign;

	if (tmp1.malloced) big_finish(&tmp1);

	return (CRYPTO_SUCCESS);
}



/*
 * caller must ensure that  a < n,  b < n  and  ret->size >=  2 * n->len + 1
 * and that ret is not n
 */
static int
big_mont_mul(BIGNUM *ret, BIGNUM *a, BIGNUM *b, BIGNUM *n, uint32_t n0)
{
	int i, j, nlen, needsubtract;
	uint32_t *nn, *rr;
	uint32_t digit, c;
	int err;

	nlen = n->len;
	nn = n->value;

	rr = ret->value;

	if ((err = big_mul(ret, a, b)) != CRYPTO_SUCCESS)
		return (err);

	rr = ret->value;
	for (i = ret->len; i < 2 * nlen + 1; i++) rr[i] = 0;
	for (i = 0; i < nlen; i++) {
		digit = rr[i];
		digit = digit * n0;

		c = big_mul_add_vec(rr + i, nn, nlen, digit);
		j = i + nlen;
		rr[j] += c;
		while (rr[j] < c) {
			rr[j + 1] += 1;
			j++;
			c = 1;
		}
	}

	needsubtract = 0;
	if ((rr[2 * nlen]  != 0))
		needsubtract = 1;
	else {
		for (i = 2 * nlen - 1; i >= nlen; i--) {
			if (rr[i] > nn[i - nlen]) {
				needsubtract = 1;
				break;
			} else if (rr[i] < nn[i - nlen]) break;
		}
	}
	if (needsubtract)
		big_sub_vec(rr, rr + nlen, nn, nlen);
	else {
		for (i = 0; i < nlen; i++)
			rr[i] = rr[i + nlen];
	}
	for (i = nlen - 1; (i >= 0) && (rr[i] == 0); i--);
	ret->len = i+1;

	return (CRYPTO_SUCCESS);
}

static uint32_t
big_n0(uint32_t n)
{
	int i;
	uint32_t result, tmp;

	result = 0;
	tmp = 0xffffffff;
	for (i = 0; i < 32; i++) {
		if ((tmp & 1) == 1) {
			result = (result >> 1) | 0x80000000;
			tmp = tmp - n;
		} else  result = (result>>1);
		tmp = tmp >> 1;
	}

	return (result);
}

static int
big_numbits(BIGNUM *n)
{
	int i, j;
	uint32_t t;

	for (i = n->len - 1; i > 0; i--)
		if (n->value[i] != 0) break;
	t = n->value[i];
	for (j = 32; j > 0; j--) {
		if ((t & 0x80000000) == 0)
			t = t << 1;
		else
			return (32 * i + j);
	}
	return (0);
}

/* caller must make sure that a < n */
static int
big_mont_rr(BIGNUM *result, BIGNUM *n)
{
	BIGNUM rr;
	uint32_t rrvalue[BIGTMPSIZE];
	int len, i;
	int err;

	rr.malloced = 0;
	len = n->len;

	if ((err = big_init1(&rr, 2 * len + 1,
	    rrvalue, arraysize(rrvalue))) != CRYPTO_SUCCESS)
		return (err);

	for (i = 0; i < 2 * len; i++) rr.value[i] = 0;
	rr.value[2 * len] = 1;
	rr.len = 2 * len + 1;
	if ((err = big_div_pos(NULL, &rr, &rr, n)) != CRYPTO_SUCCESS)
		goto ret;
	err = big_copy(result, &rr);
ret:
	if (rr.malloced) big_finish(&rr);
	return (err);
}

/* caller must make sure that a < n */
static int
big_mont_conv(BIGNUM *result, BIGNUM *a, BIGNUM *n, uint32_t n0, BIGNUM *n_rr)
{
	BIGNUM rr;
	uint32_t rrvalue[BIGTMPSIZE];
	int len, i;
	int err;

	rr.malloced = 0;
	len = n->len;

	if ((err = big_init1(&rr, 2 * len + 1, rrvalue, arraysize(rrvalue)))
	    != CRYPTO_SUCCESS)
			return (err);

	if (n_rr == NULL) {
		for (i = 0; i < 2 * len; i++) rr.value[i] = 0;
		rr.value[2 * len] = 1;
		rr.len = 2 * len + 1;
		if ((err = big_div_pos(NULL, &rr, &rr, n)) != CRYPTO_SUCCESS)
			goto ret;
		n_rr = &rr;
	}

	if ((err = big_mont_mul(&rr, n_rr, a, n, n0)) != CRYPTO_SUCCESS)
		goto ret;
	err = big_copy(result, &rr);
ret:
	if (rr.malloced) big_finish(&rr);
	return (err);
}


#define	MAX_EXP_BIT_GROUP_SIZE 6
#define	APOWERS_MAX_SIZE (1 << (MAX_EXP_BIT_GROUP_SIZE - 1))

/*
 * computes a^e mod n
 * assumes a < n, n odd, result->value at least as long as n->value
 * This version uses strictly integer math and is safe in the kernel.
 */
static int
big_modexp(BIGNUM *result, BIGNUM *a, BIGNUM *e, BIGNUM *n, BIGNUM *n_rr)
{
	BIGNUM ma, tmp, rr;
	uint32_t mavalue[BIGTMPSIZE];
	uint32_t tmpvalue[BIGTMPSIZE];
	uint32_t rrvalue[BIGTMPSIZE];
	BIGNUM apowers[APOWERS_MAX_SIZE];
	int i, j, k, l, m, p,
	    bit, bitind, bitcount, groupbits, apowerssize;
	int err;
	uint32_t n0;

	int nbits;

	nbits = big_numbits(e);
	if (nbits < 50) {
		groupbits = 1;
		apowerssize = 1;
	} else {
		groupbits = MAX_EXP_BIT_GROUP_SIZE;
		apowerssize = 1 << (groupbits - 1);
	}

	if ((err = big_init1(&ma, n->len,
	    mavalue, arraysize(mavalue))) != CRYPTO_SUCCESS)
		return (err);
	ma.len = 1;
	ma.value[0] = 0;

	if ((err = big_init1(&tmp, 2 * n->len + 1,
	    tmpvalue, arraysize(tmpvalue))) != CRYPTO_SUCCESS)
		goto ret1;
	tmp.len = 1;
	tmp.value[0] = 1;

	n0 = big_n0(n->value[0]);

	rr.malloced = 0;
	if (n_rr == NULL) {
		if ((err = big_init1(&rr, 2 * n->len + 1,
		    rrvalue, arraysize(rrvalue))) != CRYPTO_SUCCESS)
			goto ret2;

		if (big_mont_rr(&rr, n) != CRYPTO_SUCCESS)
			goto ret3;
		n_rr = &rr;
	}

	for (i = 0; i < apowerssize; i++) apowers[i].malloced = 0;
	for (i = 0; i < apowerssize; i++) {
		if ((err = big_init1(&(apowers[i]), n->len, NULL, 0)) !=
		    CRYPTO_SUCCESS)
			goto ret;
	}

	if (big_cmp_abs(a, n) > 0) {
		if ((err = big_div_pos(NULL, &ma, a, n)) != CRYPTO_SUCCESS)
			goto ret;
		err = big_mont_conv(&ma, &ma, n, n0, n_rr);
	} else {
		err = big_mont_conv(&ma, a, n, n0, n_rr);
	}
	if (err != CRYPTO_SUCCESS) goto ret;

	(void) big_copy(&(apowers[0]), &ma);
	if ((err = big_mont_mul(&tmp, &ma, &ma, n, n0)) != CRYPTO_SUCCESS)
		goto ret;
	(void) big_copy(&ma, &tmp);

	for (i = 1; i < apowerssize; i++) {
		if ((err = big_mont_mul(&tmp, &ma,
		    &(apowers[i-1]), n, n0)) != CRYPTO_SUCCESS)
			goto ret;
		(void) big_copy(&apowers[i], &tmp);
	}

	tmp.len = 1;
	tmp.value[0] = 1;
	if ((err = big_mont_conv(&tmp, &tmp, n, n0, n_rr)) != CRYPTO_SUCCESS)
		goto ret;

	bitind = nbits % 32;
	k = 0;
	l = 0;
	p = 0;
	bitcount = 0;
	for (i = nbits / 32; i >= 0; i--) {
		for (j = bitind - 1; j >= 0; j--) {
			bit = (e->value[i] >> j) & 1;
			if ((bitcount == 0) && (bit == 0)) {
				if ((err = big_mont_mul(&tmp,
				    &tmp, &tmp, n, n0)) != CRYPTO_SUCCESS)
					goto ret;
			} else {
				bitcount++;
				p = p * 2 + bit;
				if (bit == 1) {
					k = k + l + 1;
					l = 0;
				} else {
					l++;
				}
				if (bitcount == groupbits) {
					for (m = 0; m < k; m++) {
						if ((err = big_mont_mul(&tmp,
						    &tmp, &tmp, n, n0)) !=
						    CRYPTO_SUCCESS)
							goto ret;
					}
					if ((err = big_mont_mul(&tmp, &tmp,
					    &(apowers[p >> (l + 1)]),
					    n, n0)) != CRYPTO_SUCCESS)
						goto ret;
					for (m = 0; m < l; m++) {
						if ((err = big_mont_mul(&tmp,
						    &tmp, &tmp, n, n0)) !=
						    CRYPTO_SUCCESS)
							goto ret;
					}
					k = 0;
					l = 0;
					p = 0;
					bitcount = 0;
				}
			}
		}
		bitind = 32;
	}

	for (m = 0; m < k; m++) {
		if ((err = big_mont_mul(&tmp, &tmp, &tmp, n, n0))
		    != CRYPTO_SUCCESS)
			goto ret;
	}
	if (p != 0) {
		if ((err = big_mont_mul(&tmp, &tmp,
		    &(apowers[p >> (l + 1)]), n, n0)) != CRYPTO_SUCCESS)
			goto ret;
	}
	for (m = 0; m < l; m++) {
		if ((err = big_mont_mul(&tmp, &tmp, &tmp, n, n0))
		    != CRYPTO_SUCCESS)
			goto ret;
	}

	ma.value[0] = 1;
	ma.len = 1;
	if ((err = big_mont_mul(&tmp, &tmp, &ma, n, n0)) != CRYPTO_SUCCESS)
		goto ret;
	err = big_copy(result, &tmp);
ret:
	for (i = apowerssize - 1; i >= 0; i--) {
		big_finish(&(apowers[i]));
	}
ret3:
	if (rr.malloced) big_finish(&rr);
ret2:
	if (tmp.malloced) big_finish(&tmp);
ret1:
	if (ma.malloced) big_finish(&ma);
	return (err);
}

int
mca_swrsa(char *in, size_t inlen, char *out, uchar_t *n, int nlen,
    uchar_t *e, int elen)
{
	int rv;
	RSAkey rsakey;
	BIGNUM msg;

	/* psize and qsize for RSA_key_init is in bits */
	if (RSA_key_init(&rsakey, nlen * 4, nlen * 4) != CRYPTO_SUCCESS) {
		return (CRYPTO_HOST_MEMORY);
	}

	/* size for big_init is in (32-bit) words */
	if (big_init(&msg, (inlen + sizeof (uint32_t) - 1) /
	    sizeof (uint32_t)) != CRYPTO_SUCCESS) {
		RSA_key_finish(&rsakey);
		return (CRYPTO_HOST_MEMORY);
	}

	kcl2bignum(&(rsakey.n), n, nlen);
	kcl2bignum(&(rsakey.e), e, elen);

	if ((rv = big_mont_rr(&(rsakey.n_rr), &(rsakey.n))) != CRYPTO_SUCCESS) {
		goto ret;
	}

	kcl2bignum(&msg, (uchar_t *)in, inlen);

	if (big_cmp_abs(&msg, &(rsakey.n)) > 0) {
		rv = CRYPTO_DATA_LEN_RANGE;
		goto ret;
	}
	if (big_modexp(&msg, &msg, &(rsakey.e),
	    &(rsakey.n), &(rsakey.n_rr)) != CRYPTO_SUCCESS) {
		rv = CRYPTO_HOST_MEMORY;
		goto ret;
	}
	bignum2kcl((uchar_t *)out, &msg, nlen);
	rv = CRYPTO_SUCCESS;
ret:
	big_finish(&msg);
	RSA_key_finish(&rsakey);
	return (rv);
}
