#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/kref.h>
#include <linux/ctype.h>

#include "mfs_imap_parse.h"

#ifndef DEBUG
#define IMAP_DBG(...)
#else
#define IMAP_DBG(...) pr_err("[MFS/IMAP_PARSE]: " __VA_ARGS__)
#endif

#define assert(...)

/**
 * TODO: one mfs_imap_elt_new_* create for each type
 */

/**
 * Parsing syntax
 */
#define IS_CTL(c)	(((c) >= 0 && (c) <= 31) || (c) == 127)
#define IS_LISTWC(c)	((c) == '%' || (c) == '*')
#define IS_QUOTEDSPE(c)	((c) == '"')
#define IS_RESPSPE(c)	((c) == ']')
#define IS_CR(c)	((c) == '\r')
#define IS_LF(c)	((c) == '\n')
#define IS_WHITESPE(c)	((c) == ' ' || IS_CTL(c) || IS_LISTWC(c) ||	\
	 IS_RESPSPE(c))
#define IS_NIL(s, l)							\
	(((l) > strlen("NIL")) && (memcmp(s, "NIL", strlen("NIL")) == 0))

#define IS_ATOMSPE(c)							\
	((c) == '(' || (c) == ')' || (c) == '{' || (c) == ' ' ||	\
	 IS_CTL(c)|| IS_LISTWC(c) || IS_QUOTEDSPE(c))



/**
 * Stack helper to avoid recursive functions while parsing imap lists
 */
#define DEFINE_ISTACK(name)						\
	struct imap_parse_stack name = {				\
		.idx = 0,						\
		.st = {}						\
	}

#define INIT_ISTACK(s) do {						\
	(s)->idx = 0;							\
	(s)->st[0] = NULL;						\
} while(/*CONSTCOND*/0)

#define POP_ISTACK(s)		((s)->st[(s)->idx--])
#define SPACE_ISTACK(s)		((s)->idx < ISTACK_MAX - 1)
#define EMPTY_ISTACK(s)		((s)->idx == 0)
#define PUSH_ISTACK(s, p)	((s)->st[++(s)->idx] = p)

#define IMAP_BEGIN_LIST(c, im, p, l) do {				\
	if(SPACE_ISTACK(&(c)->st)) {					\
		struct imap_elt *__in = mfs_imap_elt_new_list();	\
		if(__in != NULL) {					\
			PUSH_ISTACK(&(c)->st, im);			\
			list_add_tail(&__in->next, &im->elt);		\
			im = IMAP_ELT_MSG(__in);			\
		}							\
	}								\
	++(*(p));							\
	--(*(l));							\
} while(/*CONSTCOND*/0)

#define IMAP_END_LIST(c, im, p, l) do {					\
	if(!EMPTY_ISTACK(&(c)->st))					\
		im = POP_ISTACK(&(c)->st);				\
	++(*(p));							\
	--(*(l));							\
} while(/*CONSTCOND*/0)



static inline struct imap_elt *mfs_imap_elt_new(enum imap_elt_type type,
		size_t len)
{
	struct imap_elt *res;

	res = kmalloc(sizeof(*res) + len, GFP_KERNEL);
	if(res == NULL)
		return NULL;

	res->type = type;

	return res;
}

static inline struct imap_elt *mfs_imap_elt_resize(struct imap_elt *e,
		size_t size)
{
	return krealloc(e, sizeof(*e) + size, GFP_KERNEL);
}

static inline void mfs_imap_elt_free(struct imap_elt *m)
{
	kfree(m);
}

static inline void mfs_imap_msg_init(struct imap_msg *m)
{
	INIT_LIST_HEAD(&m->elt);
	kref_init(&m->refcnt);
}

static inline struct imap_msg *mfs_imap_msg_new(void)
{
	struct imap_msg *m;

	m = kmalloc(sizeof(*m), GFP_KERNEL);
	if(m == NULL)
		goto out;

	mfs_imap_msg_init(m);

out:
	return m;
}

static inline void mfs_imap_msg_free(struct imap_msg *m)
{
	kfree(m);
}

static inline void mfs_imap_msg_destroy(struct kref *k)
{
	struct imap_msg *m = container_of(k, struct imap_msg, refcnt);
	struct imap_msg *p = m;
	struct imap_elt *elt;
	DEFINE_ISTACK(st);

	while(!list_empty(&p->elt) || !EMPTY_ISTACK(&st)) {
		if(list_empty(&p->elt))
			p = POP_ISTACK(&st);

		elt = list_first_entry(&p->elt, struct imap_elt, next);

		if(elt->type == IET_LIST &&
				!list_empty(&IMAP_ELT_MSG(elt)->elt)) {
			assert(SPACE_ISTACK(&st));
			PUSH_ISTACK(&st, p);
			p = IMAP_ELT_MSG(elt);
		} else {
			list_del(&elt->next);
			mfs_imap_elt_free(elt);
		}
	}

	assert(p == m);
	mfs_imap_msg_free(m);
}

static inline struct imap_elt *mfs_imap_elt_new_list(void)
{
	struct imap_elt *m;

	m = mfs_imap_elt_new(IET_LIST, sizeof(struct imap_msg));
	if(m == NULL)
		goto out;

	mfs_imap_msg_init(IMAP_ELT_MSG(m));

out:
	return m;
}

static inline struct imap_elt *mfs_imap_parse_number(struct imap_parse_ctx *c,
		char const **p, size_t *len)
{
	struct imap_elt *new;
	int nb = 0, *ptr;

	new = mfs_imap_elt_new(IET_NUMBER, sizeof(unsigned int));
	if(new == NULL)
		goto out;

	while(*len != 0 && isdigit(**p)) {
		nb = nb * 10 + **p - '0';
		++(*p);
		--(*len);
	}
	IMAP_DBG("NUMBER %u\n", nb);

	ptr = IMAP_ELT_NUM(new);
	*ptr = nb;

out:
	return new;
}

static inline struct imap_elt *mfs_imap_parse_string(struct imap_parse_ctx *c,
		char const **p, size_t *len)
{
	struct imap_elt *new = NULL;
	char const *s;
	size_t l = 0;

	assert(**p == '"');

	/**
	 * Skip first quote
	 */
	++(*p);
	--(*len);
	s = *p;

	/**
	 * Find ending quote
	 */
	for(l = 0; l < *len && s[l] != '"'; ++l);

	new = mfs_imap_elt_new(IET_STRING, l + 1);
	if(new == NULL)
		goto skip_quote;

	IMAP_DBG("STRING %.*s\n", (int)l, s);

	memcpy(IMAP_ELT_STR(new), s, l);
	IMAP_ELT_STR(new)[l] = '\0';

skip_quote:
	if(s[l] != '"') {
		c->elt = new;
		new = NULL;
	} else {
		++l;
	}

	(*len) -= l;
	(*p) += l;
	return new;
}

static inline struct imap_elt *
mfs_imap_parse_string_cont(struct imap_parse_ctx *c, char const **p,
		size_t *len)
{
	struct imap_elt *new = c->elt;
	char const *s = *p;
	size_t l = 0, curlen = strlen(IMAP_ELT_STR(new));

	/**
	 * Find ending quote
	 */
	for(l = 0; l < *len && s[l] != '"'; ++l);

	new = mfs_imap_elt_resize(new, curlen + l + 1);
	if(new == NULL) {
		kfree(c->elt);
		goto skip_quote;
	}

	IMAP_DBG("STRING - CONT %.*s\n", (int)l, s);

	memcpy(IMAP_ELT_STR(new) + curlen, s, l);
	IMAP_ELT_STR(new)[curlen + l] = '\0';

skip_quote:
	if(s[l] != '"') {
		c->elt = new;
		new = NULL;
	} else {
		++l;
	}

	(*len) -= l;
	(*p) += l;
	return new;
}

static inline struct imap_elt *mfs_imap_parse_literal(struct imap_parse_ctx *c,
		char const **p, size_t *len)
{
	struct imap_elt *new = NULL;
	char const *s = *p;
	size_t nb = 0, l;

	for(l = 1; l < *len && isdigit(s[l]); ++l)
		nb = nb * 10 + (*p)[l] - '0';

	if(l > *len - 3 || s[l] != '}' || !IS_CR(s[l + 1]) || !IS_LF(s[l + 2]))
		goto out;

	(*len) -= l + 3;
	(*p) += l + 3;

	l = min(*len, nb);
	if(l == 0)
		goto out;

	new = mfs_imap_elt_new(IET_STRING, nb + 1);
	if(new == NULL)
		goto out;

	IMAP_DBG("LITERAL {%lu/%lu} - %.*s\n", l, nb, (int)l, *p);

	memcpy(IMAP_ELT_STR(new), *p, l);
	IMAP_ELT_STR(new)[l] = '\0';

	if(l < nb) {
		c->more = nb - l;
		c->elt = new;
		new = NULL;
	}

out:
	(*len) -= l;
	(*p) += l;
	return new;
}

static inline struct imap_elt *
mfs_imap_parse_literal_cont(struct imap_parse_ctx *c, char const **p,
		size_t *len)
{
	struct imap_elt *new = c->elt;
	size_t l = 0, curlen;

	l = min(*len, c->more);
	curlen = strlen(IMAP_ELT_STR(new));

	IMAP_DBG("LITERAL CONT {%lu/%lu} - %.*s\n", l, c->more, (int)l, *p);

	memcpy(IMAP_ELT_STR(new) + curlen, *p, l);
	IMAP_ELT_STR(new)[curlen + l] = '\0';

	c->more -= l;

	if(c->more)
		new = NULL;

	(*len) -= l;
	(*p) += l;

	return new;
}

static inline struct imap_elt *mfs_imap_parse_nil(struct imap_parse_ctx *c,
		char const **p, size_t *len)
{
	struct imap_elt *new = NULL;
	size_t l = strlen("NIL");

	assert(IS_NIL(*p, *len));

	new = mfs_imap_elt_new(IET_NIL, 0);

	IMAP_DBG("NIL\n");

	(*len) -= l;
	(*p) += l;

	return new;
}

static inline struct imap_elt *mfs_imap_parse_atom(struct imap_parse_ctx *c,
		char const **p, size_t *len)
{
	struct imap_elt *new = NULL;
	char const *s = *p;
	size_t l;

	for(l = 0; l < *len && !IS_ATOMSPE(s[l]); ++l);

	new = mfs_imap_elt_new(IET_ATOM, l + 1);
	if(new == NULL)
		goto out;

	new->type = IET_ATOM;

	IMAP_DBG("ATOM %.*s\n", (int)l, *p);

	memcpy(IMAP_ELT_ATOM(new), *p, l);
	IMAP_ELT_ATOM(new)[l] = '\0';

	if(l == *len) {
		c->elt = new;
		new = NULL;
	}

out:
	(*len) -= l;
	(*p) += l;
	return new;
}

static inline struct imap_elt *
mfs_imap_parse_atom_cont(struct imap_parse_ctx *c, char const **p, size_t *len)
{
	struct imap_elt *new = c->elt;
	char const *s = *p;
	size_t l, curlen = strlen(IMAP_ELT_ATOM(new));

	for(l = 0; l < *len && !IS_ATOMSPE(s[l]); ++l);

	new = mfs_imap_elt_resize(new, curlen + l + 1);
	if(new == NULL) {
		kfree(c->elt);
		goto out;
	}

	IMAP_DBG("ATOM - CONT %.*s\n", (int)l, *p);

	memcpy(IMAP_ELT_ATOM(new) + curlen, *p, l);
	IMAP_ELT_ATOM(new)[curlen + l] = '\0';

	if(l == *len) {
		c->elt = new;
		new = NULL;
	}

out:
	(*len) -= l;
	(*p) += l;
	return new;
}

static inline void mfs_imap_parse_reset_ctx(struct imap_parse_ctx *c)
{
	INIT_ISTACK(&c->st);
	c->first = NULL;
	c->msg = NULL;
	c->elt = NULL;
	c->more = 0;
}

static inline struct imap_elt *mfs_imap_parse_cont(struct imap_parse_ctx *c,
	char const **p, size_t *len)
{
	struct imap_elt *ret = NULL;

	if(c->elt == NULL)
		return ret;

	switch(c->elt->type) {
	case IET_ATOM:
		ret = mfs_imap_parse_atom_cont(c, p, len);
		break;
	case IET_STRING:
		if(c->more)
			ret = mfs_imap_parse_literal_cont(c, p, len);
		else
			ret = mfs_imap_parse_string_cont(c, p, len);
		break;
	case IET_NIL:
	case IET_LIST:
	case IET_NUMBER:
		IMAP_DBG("Not implemented yet sorry\n");
		mfs_imap_parse_reset_ctx(c);
		break;
	default:
		IMAP_DBG("Wrong elt type\n");
		mfs_imap_parse_reset_ctx(c);
	}

	return ret;
}

static inline int mfs_imap_parse_end(char const **msg, size_t *len)
{
	char const *p = *msg;
	char const *end = p + *len;
	size_t l = *len;
	int cr = 0, lf = 0;

	/**
	 * Skip aditional whitespaces
	 */
	while((p < end) && (IS_WHITESPE(*p)) && (cr == 0 || lf == 0)) {
		/**
		 * CRLF is new message so finish this message
		 */
		if(cr == 1 && IS_LF(*p))
			lf = 1;
		else if(IS_CR(*p))
			cr = 1;
		else if(cr == 1)
			cr = 0;

		++p;
		--l;
	}

	*msg = p;
	*len = l;

	return (cr == 1 && lf == 1);
}

/**
 * Create a new context for imap parsing
 */
struct imap_parse_ctx *mfs_imap_parse_new_ctx(void)
{
	struct imap_parse_ctx *ctx;

	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if(ctx == NULL)
		return ctx;

	INIT_ISTACK(&ctx->st);
	ctx->first = NULL;
	ctx->msg = NULL;
	ctx->elt = NULL;
	ctx->more = 0;

	return ctx;
}

/**
 * Delete a imap parsing context
 */
void mfs_imap_parse_del_ctx(struct imap_parse_ctx *ctx)
{
	kfree(ctx);
}

/**
 * Transform received message into structured imap message
 */
struct imap_msg *mfs_imap_parse_msg(struct imap_parse_ctx *ctx,
		char const **msg, size_t *len)
{
	struct imap_msg *im = ctx->msg, *first = ctx->first;
	struct imap_elt *new;
	char const *p = *msg, *end = *msg + *len;
	size_t l = *len;
	int msgend = 0;

	/**
	 * CRLF is empty message so finish here
	 */
	if((first == NULL) &&
			((l == 0) || (IS_CR(p[0]) && (l == 1 || IS_LF(p[1]))))) {
		l -= min(l, 2UL);
		p += min(l, 2UL);
		goto out;
	}

	if(im == NULL)
		im = mfs_imap_msg_new();

	if(im == NULL)
		goto out;

	/**
	 * If this is a multipacket message continue to fill old one
	 */
	if(first == NULL) {
		first = im;
	} else {
		new = mfs_imap_parse_cont(ctx, &p, &l);

		msgend = mfs_imap_parse_end(&p, &l);

		if(new != NULL)
			list_add_tail(&new->next, &im->elt);
	}


	while(p < end && !msgend) {
		new = NULL;

		if(isdigit(p[0]))
			new = mfs_imap_parse_number(ctx, &p, &l);
		else if(p[0] == '(')
			IMAP_BEGIN_LIST(ctx, im, &p, &l);
		else if (p[0] == ')')
			IMAP_END_LIST(ctx, im, &p, &l);
		else if (p[0] == '"')
			new = mfs_imap_parse_string(ctx, &p, &l);
		else if (p[0] == '{')
			new = mfs_imap_parse_literal(ctx, &p, &l);
		else if (IS_NIL(p, l))
			new = mfs_imap_parse_nil(ctx, &p, &l);
		else
			new = mfs_imap_parse_atom(ctx, &p, &l);

		msgend = mfs_imap_parse_end(&p, &l);

		/**
		 * Append new imap element
		 */
		if(new != NULL)
			list_add_tail(&new->next, &im->elt);
	}

out:
	/**
	 * Do garbage collecting
	 * XXX in well formed imap msg this should not happen
	 */
	if(!EMPTY_ISTACK(&ctx->st) && msgend) {
		mfs_imap_msg_put(first);
		im = ERR_PTR(-EINVAL);
	}

	/**
	 * Imap message is complete
	 */
	if(msgend) {
		mfs_imap_parse_reset_ctx(ctx);
	} else {
		ctx->first = first;
		ctx->msg = im;
		im = NULL;
	}

	*msg = p;
	*len = l;

	return im;
}

int __must_check mfs_imap_msg_get(struct imap_msg *im)
{
	return kref_get_unless_zero(&im->refcnt);
}

int mfs_imap_msg_put(struct imap_msg *im)
{
	return kref_put(&im->refcnt, mfs_imap_msg_destroy);
}
