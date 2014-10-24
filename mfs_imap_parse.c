#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/kref.h>
#include <linux/ctype.h>

#include "mfs_imap_parse.h"

#define assert(...)

/**
 * TODO: one mfs_imap_elt_new_* create for each type
 */

/**
 * Parsing syntax
 */
#define IS_CTL(c)	(((c) >= 0 && (c) <= 31) || (c) == 127)
#define IS_LISTWC(c)	((c) == '%' || (c) == '*')
#define IS_QUOTEDSPE(c)	((c) == '"' || (c) == '\\')
#define IS_RESPSPE(c)	((c) == ']')
#define IS_WHITERSPE(c)	((c) == ' ' || IS_CTL(c)|| IS_LISTWC(c)		\
		|| IS_RESPSPE(c) || (c) == '\\')
#define IS_NIL(s, l)							\
	(((l) > strlen("NIL")) && (memcmp(s, "NIL", strlen("NIL")) == 0))

#define IS_ATOMSPE(c)							\
	((c) == '(' || (c) == ')' || (c) == '{' || (c) == ' ' ||	\
	 IS_CTL(c)|| IS_LISTWC(c) || IS_QUOTEDSPE(c) || IS_RESPSPE(c))



/**
 * Stack helper to avoid recursive functions while parsing imap lists
 */
#define ISTACK_MAX 16

#define DEFINE_ISTACK(name)						\
		struct {						\
			size_t idx;					\
			struct imap_msg *st[ISTACK_MAX];		\
		} name = {						\
			.idx = 0,					\
			.st = {},					\
		}

#define POP_ISTACK(name)	((name).st[(name).idx--])
#define SPACE_ISTACK(name)	((name).idx < ISTACK_MAX - 1)
#define EMPTY_ISTACK(name)	((name).idx == 0)
#define PUSH_ISTACK(name, p)	((name).st[++(name).idx] = p)

#define IMAP_BEGIN_LIST(st, im, p, l) do {				\
	if(SPACE_ISTACK(st)) {						\
		struct imap_elt *__in = mfs_imap_elt_new_list();	\
		if(__in != NULL) {					\
			PUSH_ISTACK(st, im);				\
			list_add_tail(&__in->next, &im->elt);		\
			im = IMAP_ELT_MSG(__in);			\
		}							\
	}								\
	++(*(p));							\
	--(*(l));							\
} while(/*CONSTCOND*/0)

#define IMAP_END_LIST(st, im, p, l) do {				\
	if(!EMPTY_ISTACK(st))						\
		im = POP_ISTACK(st);					\
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

	while(!list_empty(&p->elt) || !EMPTY_ISTACK(st)) {
		if(list_empty(&p->elt))
			p = POP_ISTACK(st);

		elt = list_first_entry(&p->elt, struct imap_elt, next);

		if(elt->type == IET_LIST &&
				!list_empty(&IMAP_ELT_MSG(elt)->elt)) {
			assert(SPACE_ISTACK(st));
			PUSH_ISTACK(st, p);
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

static inline struct imap_elt *mfs_imap_parse_number(char const **p,
		size_t *len)
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
pr_err("NUMBER %u\n", nb);

	ptr = IMAP_ELT_NUM(new);
	*ptr = nb;

out:
	return new;
}

static inline struct imap_elt *mfs_imap_parse_string(char const **p,
		size_t *len)
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

	if(l == *len)
		goto out;

	new = mfs_imap_elt_new(IET_STRING, l + 1);
	if(new == NULL)
		goto skip_quote;

	memcpy(IMAP_ELT_STR(new), s, l);
	IMAP_ELT_STR(new)[l] = '\0';

skip_quote:
	++l;
out:
	(*len) -= l;
	(*p) += l;
	return new;
}

static inline struct imap_elt *mfs_imap_parse_literal(char const **p,
		size_t *len)
{
	struct imap_elt *new = NULL;
	char const *s = *p;
	size_t nb = 0, l;

	for(l = 1; l < *len && isdigit(s[l]); ++l)
		nb = nb * 10 + (*p)[l] - '0';

	if(l == *len || s[l] != '}')
		goto out;

	(*len) -= l + 1;
	(*p) += l + 1;

	l = min(*len, nb);
	if(l == 0)
		goto out;

	new = mfs_imap_elt_new(IET_STRING, l + 1);
	if(new == NULL)
		goto out;

	memcpy(IMAP_ELT_STR(new), *p, l);
	IMAP_ELT_STR(new)[l] = '\0';

out:
	(*len) -= l;
	(*p) += l;
	return new;
}

static inline struct imap_elt *mfs_imap_parse_nil(char const **p, size_t *len)
{
	struct imap_elt *new = NULL;
	size_t l = strlen("NIL");

	assert(IS_NIL(*p, *len));

	new = mfs_imap_elt_new(IET_NIL, 0);

	(*len) -= l;
	(*p) += l;

	return new;
}

static inline struct imap_elt *mfs_imap_parse_atom(char const **p,
		size_t *len)
{
	struct imap_elt *new = NULL;
	char const *s = *p;
	size_t l;

	for(l = 0; l < *len && !IS_ATOMSPE(s[l]); ++l);

	new = mfs_imap_elt_new(IET_ATOM, l + 1);
	if(new == NULL)
		goto out;

	new->type = IET_ATOM;
	memcpy(IMAP_ELT_ATOM(new), *p, l);
	IMAP_ELT_ATOM(new)[l] = '\0';

out:
	(*len) -= l;
	(*p) += l;
	return new;
}

/**
 * Transform received message into structured imap message
 */
struct imap_msg *mfs_imap_parse_msg(char const *msg, size_t len)
{
	struct imap_msg *im, *first;
	struct imap_elt *new;
	char const *p = msg, *end = msg + len;
	DEFINE_ISTACK(st);

	im = mfs_imap_msg_new();
	if(im == NULL)
		goto out;

	first = im;

	while(p < end) {
		new = NULL;

		if(isdigit(p[0]))
			new = mfs_imap_parse_number(&p, &len);
		else if(p[0] == '(')
			IMAP_BEGIN_LIST(st, im, &p, &len);
		else if (p[0] == ')')
			IMAP_END_LIST(st, im, &p, &len);
		else if (p[0] == '"')
			new = mfs_imap_parse_string(&p, &len);
		else if (p[0] == '{')
			new = mfs_imap_parse_literal(&p, &len);
		else if (IS_NIL(p, len))
			new = mfs_imap_parse_nil(&p, &len);
		else
			new = mfs_imap_parse_atom(&p, &len);

		/**
		 * Skip aditional whitespaces
		 */
		while((p < end) && (IS_WHITERSPE(*p))) {
			++p;
			--len;
		}

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
	if(!EMPTY_ISTACK(st)) {
		mfs_imap_msg_put(first);
		im = ERR_PTR(-EINVAL);
	}

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
