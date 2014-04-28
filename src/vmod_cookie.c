/*
Cookie VMOD for Varnish.

Simplifies handling of the Cookie request header.

Author: Lasse Karstensen <lasse@varnish-software.com>, July 2012.
*/

#include <stdlib.h>
#include <stdio.h>

#include "vrt.h"
#include "cache/cache.h"

#include "vcc_if.h"

#ifdef HAVE_CONFIG_H
#include "config.h"

# if STDC_HEADERS
# include <ctype.h>
# endif
#endif /* HAVE_CONFIG_H */

#define MAX_COOKIEPART 1024   /* name or value maxsize */
#define MAX_COOKIESTRING 8196 /* cookie string maxlength */
#define MAXCOOKIES 100

enum cookie_type {
	e_cookie_req = 0,
	e_cookie_resp
};

#define COOKIE_HTTP_ONLY			(1 << 1)
#define COOKIE_HTTPS_ONLY			(1 << 2)

struct cookie {
	char *name;
	char *value;
	enum cookie_type type;
	char *path, *expires, *domain;
	unsigned int flags;
	VTAILQ_ENTRY(cookie) list;
};

struct vmod_cookie {
	unsigned magic;
#define VMOD_COOKIE_MAGIC 0x4EE5FB2E
	unsigned xid;
	VTAILQ_HEAD(, cookie) cookielist;
};

static pthread_key_t key;
static pthread_once_t key_is_initialized = PTHREAD_ONCE_INIT;

static void set_cookie_ex(const struct vrt_ctx *ctx, const char *name, const char *value,
													const char *path, const char *expires, const char *domain,
													unsigned int *flags);

static void
mkkey(void) {
	AZ(pthread_key_create(&key, free));
}

int
init_function(struct vmod_priv *priv, const struct VCL_conf *conf) {
	pthread_once(&key_is_initialized, mkkey);
	return (0);
}

static void
cobj_clear(struct vmod_cookie *c) {
	c->magic = VMOD_COOKIE_MAGIC;
	VTAILQ_INIT(&c->cookielist);
	c->xid = 0;
}

static struct vmod_cookie *
cobj_get(const struct vrt_ctx *ctx) {
	struct vmod_cookie *vcp = pthread_getspecific(key);
	uint32_t xid = 0xdeadbeef;


	if(ctx->req && ctx->req->sp)
		xid = ctx->req->sp->vxid & VSL_IDENTMASK;
	else if(ctx->bo && ctx->bo->vsl && ctx->bo->vsl->wid)
		xid = ctx->bo->vsl->wid & VSL_IDENTMASK;

	if (!vcp) {
		vcp = malloc(sizeof *vcp);
		AN(vcp);
		cobj_clear(vcp);
		vcp->xid = xid;
		AZ(pthread_setspecific(key, vcp));
	}

	CHECK_OBJ_NOTNULL(vcp, VMOD_COOKIE_MAGIC);

	if (vcp->xid != xid) {
		// Reuse previously allocated storage
		cobj_clear(vcp);
		vcp->xid = xid;
	}

	return (vcp);
}

VCL_VOID
vmod_parse_resp(const struct vrt_ctx *ctx, VCL_STRING cookieheader) {
	char tokendata[MAX_COOKIESTRING];
	char *token, *tokstate, *key, *sepindex;
	char *dataptr = tokendata;
	struct vmod_cookie *vcp = cobj_get(ctx);
	CHECK_OBJ_NOTNULL(vcp, VMOD_COOKIE_MAGIC);
	char *name = NULL;
	char *value = NULL;
	char *path = NULL;
	char *expires = NULL;
	char *domain = NULL;
	unsigned int flags = 0;

	struct cookie *newcookie;

	int i = 0;

	// If called twice during the same request, clean out old state
	// before proceeding.
	while (!VTAILQ_EMPTY(&vcp->cookielist)) {
		newcookie = VTAILQ_FIRST(&vcp->cookielist);
		VTAILQ_REMOVE(&vcp->cookielist, newcookie, list);
	}

	if (cookieheader == NULL || strlen(cookieheader) == 0
	    || strlen(cookieheader) >= MAX_COOKIESTRING)
		return;

	/* strtok modifies source, fewer surprises. */
	strncpy(tokendata, cookieheader, sizeof(tokendata));

	for(dataptr = tokendata, token = strtok_r(dataptr, ";", &tokstate);
			token != NULL; token = strtok_r(NULL,";",&tokstate)) {

		char *v;

		while(isspace(*token)) token++;
		//printf("token is: %s\n", token);

		v = strchr(token, '=');
		if (v == NULL) {
			for(sepindex = strrchr(token, ' ');
				  sepindex != NULL && sepindex > token && isspace(*sepindex);
					sepindex--) *sepindex = '\0';
			while((sepindex = strrchr(token,' ')) != NULL)
				*sepindex = '\0';
			if (strcasecmp(token,"httponly") == 0)
				flags |= COOKIE_HTTP_ONLY;
			else if (strcasecmp(token,"secure") == 0)
				flags |= COOKIE_HTTPS_ONLY;
			continue;
		}
		*v++ = '\0';
		for(sepindex = strrchr(token,' ');
				sepindex != NULL && sepindex > token && isspace(*sepindex);
				sepindex--) *sepindex = '\0';
		while (isspace(*v)) *v++ = '\0';
		for(sepindex = strrchr(v, ' ');
				sepindex != NULL && sepindex > v && isspace(*sepindex);
				sepindex--) *sepindex = '\0';

		if(name == NULL && value == NULL)  {
			name = token;
			value = v;
		} else if (strcasecmp(token,"path") == 0)
			path = v;
		else if (strcasecmp(token,"expires") == 0)
			expires = v;
		else if (strcasecmp(token, "domain") == 0)
			domain = v;
		else {
			if(name && *name && value && *value) {
				set_cookie_ex(ctx, name, value, path, expires, domain, &flags);
				i++;
			}
			name = value = path = expires = domain =  NULL;
			flags = 0;
			name = token;
			value = v;
		}
	}

	if(name && *name && value && *value) {
		set_cookie_ex(ctx, name, value, path, expires, domain, &flags);
		i++;
	}
	VSL(SLT_VCL_Log, 0, "libvmod-cookie: parsed %i response cookies.", i);
}

VCL_VOID
vmod_parse(const struct vrt_ctx *ctx, VCL_STRING cookieheader) {
	char tokendata[MAX_COOKIESTRING];
	char *token, *tokstate, *key, *value, *sepindex;
	char *dataptr = tokendata;
	struct vmod_cookie *vcp = cobj_get(ctx);
	CHECK_OBJ_NOTNULL(vcp, VMOD_COOKIE_MAGIC);

	struct cookie *newcookie;

	int i = 0;

	// If called twice during the same request, clean out old state
	// before proceeding.
	while (!VTAILQ_EMPTY(&vcp->cookielist)) {
		newcookie = VTAILQ_FIRST(&vcp->cookielist);
		VTAILQ_REMOVE(&vcp->cookielist, newcookie, list);
	}

	if (cookieheader == NULL || strlen(cookieheader) == 0) {
		VSL(SLT_VCL_Log, 0, "cookie-vmod: nothing to parse");
		return;

	if (strlen(cookieheader)+1 >= MAX_COOKIESTRING)
		VSL(SLT_VCL_Log, 0, "cookie-vmod: cookie string overflowed, abort");
		return;
	}

	/* strtok modifies source, fewer surprises. */
	strncpy(tokendata, cookieheader, sizeof(tokendata));
	dataptr = tokendata;

	while (1) {
		token = strtok_r(dataptr, ";", &tokstate);
		dataptr = NULL; /* strtok() wants NULL on subsequent calls. */

		if (token == NULL) break;
		while (token[0] == ' ') token++;
		//printf("token is: %s\n", token);

		sepindex = strchr(token, '=');
		if (sepindex == NULL) {
			// could not find delimiter, this cookie is invalid. skip to the
			// next (if any)
			continue;
		}
		value = sepindex + 1;
		*sepindex = '\0';

		vmod_set(ctx, token, value);
		i++;
	}

	VSL(SLT_VCL_Log, 0, "libvmod-cookie: parsed %i cookies.", i);
}


VCL_VOID
set_cookie_ex(const struct vrt_ctx *ctx, const char *name, const char *value,
              const char *path, const char *expires, const char *domain,
							unsigned int *flags) {
	struct cookie *cookie;
	struct vmod_cookie *vcp = cobj_get(ctx);
	CHECK_OBJ_NOTNULL(vcp, VMOD_COOKIE_MAGIC);

	// Empty cookies should be ignored.
	if (strlen(name) == 0)
		return;

	VTAILQ_FOREACH(cookie, &vcp->cookielist, list) {
		if (strcmp(cookie->name, name) == 0) {
			if (value && strlen(value) > 0)
				cookie->value = WS_Printf(ctx->ws, "%s", value);
			if (path) {
				if (strlen(path) == 0)
					cookie->path = NULL;
				else {
					cookie->type = e_cookie_resp;
					cookie->path = WS_Printf(ctx->ws, "%s", path);
				}
			}
			if (expires) {
				if (strlen(expires) == 0)
					cookie->expires = NULL;
				else {
					cookie->type = e_cookie_resp;
					cookie->expires = WS_Printf(ctx->ws, "%s", expires);
				}
			}
			if (domain) {
				if(strlen(domain) == 0)
					cookie->domain = NULL;
				else {
					cookie->type = e_cookie_resp;
					cookie->domain = WS_Printf(ctx->ws, "%s", domain);
				}
			}
			if (flags) {
				if (*flags)
					cookie->type = e_cookie_resp;
				cookie->flags = *flags;
			}
			return;
		}
	}

	cookie = (struct cookie *) WS_Alloc(ctx->ws, sizeof(struct cookie));
	cookie->name = WS_Printf(ctx->ws, "%s", name);
	cookie->value = WS_Printf(ctx->ws, "%s", value);
	cookie->type = e_cookie_req;
	cookie->path = NULL;
	cookie->expires = NULL;
	cookie->domain = NULL;
	cookie->flags = 0;

	if (path) {
		cookie->type = e_cookie_resp;
		if (strlen(path) != 0)
			cookie->path = WS_Printf(ctx->ws, "%s", path);
	}
	if (expires) {
		cookie->type = e_cookie_resp;
		if (strlen(expires) != 0)
			cookie->expires = WS_Printf(ctx->ws, "%s", expires);
	}
	if (domain) {
		cookie->type = e_cookie_resp;
		if (strlen(domain) != 0)
			cookie->domain = WS_Printf(ctx->ws, "%s", domain);
	}
	if (flags) {
		cookie->type = e_cookie_resp;
		cookie->flags = *flags;
	}
	VTAILQ_INSERT_TAIL(&vcp->cookielist, cookie, list);
}

VCL_VOID
vmod_set_resp(const struct vrt_ctx *ctx, VCL_STRING name, VCL_STRING value,
														   VCL_STRING path, VCL_INT expires,
															 VCL_STRING domain)
{
  unsigned int flags = COOKIE_HTTP_ONLY;
	const char *expires_str = NULL;

	while(path && *path == ' ')
	  path++;

	if (!path || !*path)
		path = "/";

	if (expires > 0) {
		time_t now = 0;

		time(&now);
		now += expires;
		expires_str = VRT_TIME_string(ctx, (double)now);
	}

	set_cookie_ex(ctx, name, value, path, expires_str, domain, &flags);
}

VCL_VOID
vmod_set(const struct vrt_ctx *ctx, VCL_STRING name, VCL_STRING value) {
	struct cookie *newcookie;
	struct vmod_cookie *vcp = cobj_get(ctx);
	CHECK_OBJ_NOTNULL(vcp, VMOD_COOKIE_MAGIC);

	// Empty cookies should be ignored.
	if (strlen(name) == 0 || strlen(value) == 0) {
		return;
	}

	if (strlen(name)+1 >= MAX_COOKIEPART) {
		VSL(SLT_Debug, 0, "cookie-vmod: cookie string overflowed, abort");
		return;
	}
	struct cookie *cookie;

	VTAILQ_FOREACH(cookie, &vcp->cookielist, list) {
		if (strcmp(cookie->name, name) == 0) {
			cookie->value = WS_Printf(ctx->ws, "%s", value);
			return;
		}
	}

	newcookie = (struct cookie *) WS_Alloc(ctx->ws, sizeof(struct cookie));
	newcookie->name = WS_Printf(ctx->ws, "%s", name);
	newcookie->value = WS_Printf(ctx->ws, "%s", value);

	VTAILQ_INSERT_TAIL(&vcp->cookielist, newcookie, list);
}

VCL_BOOL
vmod_isset(const struct vrt_ctx *ctx, const char *name) {
	struct cookie *cookie, *tmp;
	struct vmod_cookie *vcp = cobj_get(ctx);
	CHECK_OBJ_NOTNULL(vcp, VMOD_COOKIE_MAGIC);

	VTAILQ_FOREACH_SAFE(cookie, &vcp->cookielist, list, tmp) {
		if (strcmp(cookie->name, name) == 0) {
			return 1;
		}
	}
	return 0;
}

VCL_STRING
vmod_get(const struct vrt_ctx *ctx, VCL_STRING name) {
	struct cookie *cookie, *tmp;
	struct vmod_cookie *vcp = cobj_get(ctx);
	CHECK_OBJ_NOTNULL(vcp, VMOD_COOKIE_MAGIC);

	VTAILQ_FOREACH_SAFE(cookie, &vcp->cookielist, list, tmp) {
		if (strcmp(cookie->name, name) == 0) {
			return (cookie->value);
		}
	}
	return (NULL);
}

VCL_BOOL
vmod_exists(const struct vrt_ctx *ctx, VCL_STRING name) {
	struct cookie *cookie, *tmp;
	struct vmod_cookie *vcp = cobj_get(ctx);
	CHECK_OBJ_NOTNULL(vcp, VMOD_COOKIE_MAGIC);

	VTAILQ_FOREACH_SAFE(cookie, &vcp->cookielist, list, tmp) {
		if (strcmp(cookie->name, name) == 0) {
			char *cp;
			for (cp = cookie->value; cp && isspace(*cp); cp++) ;
			return (cp && *cp != '\0');
		}
	}
	return 0;
}

VCL_BOOL
vmod_isempty(const struct vrt_ctx *ctx, VCL_STRING name) {
	struct cookie *cookie, *tmp;
	struct vmod_cookie *vcp = cobj_get(ctx);
	CHECK_OBJ_NOTNULL(vcp, VMOD_COOKIE_MAGIC);

	VTAILQ_FOREACH_SAFE(cookie, &vcp->cookielist, list, tmp) {
		if (strcmp(cookie->name, name) == 0) {
			char *cp;
			for (cp = cookie->value; cp && isspace(*cp); cp++) ;
			return (cp && *cp != '\0');
		}
	}
	return 0;
}

VCL_VOID
vmod_delete(const struct vrt_ctx *ctx, VCL_STRING name) {
	struct cookie *cookie, *tmp;
	struct vmod_cookie *vcp = cobj_get(ctx);
	CHECK_OBJ_NOTNULL(vcp, VMOD_COOKIE_MAGIC);

	VTAILQ_FOREACH_SAFE(cookie, &vcp->cookielist, list, tmp) {
		if (strcmp(cookie->name, name) == 0) {
			VTAILQ_REMOVE(&vcp->cookielist, cookie, list);
			break;
		}
	}
}

VCL_VOID
vmod_clean(const struct vrt_ctx *ctx) {
	struct cookie *cookie;
	struct vmod_cookie *vcp = cobj_get(ctx);
	CHECK_OBJ_NOTNULL(vcp, VMOD_COOKIE_MAGIC);

	while (!VTAILQ_EMPTY(&vcp->cookielist)) {
		cookie = VTAILQ_FIRST(&vcp->cookielist);
		VTAILQ_REMOVE(&vcp->cookielist, cookie, list);
	}
}

VCL_VOID
vmod_filter_except(const struct vrt_ctx *ctx, VCL_STRING whitelist) {
	char cookienames[MAX_COOKIEPART][MAXCOOKIES];
	char tmpstr[MAX_COOKIESTRING];
	struct cookie *cookie, *tmp;
	char *tokptr, *saveptr;
	int i, found = 0, num_cookies = 0;
	struct vmod_cookie *vcp = cobj_get(ctx);
	CHECK_OBJ_NOTNULL(vcp, VMOD_COOKIE_MAGIC);

	strcpy(tmpstr, whitelist);
	tokptr = strtok_r(tmpstr, ",", &saveptr);
	if (!tokptr) return;

	// parse the whitelist.
	while (1) {
		strcpy(cookienames[num_cookies], tokptr);
		num_cookies++;

		tokptr = strtok_r(NULL, ",", &saveptr);
		if (!tokptr) break;
	}

	// filter existing cookies that isn't in the whitelist.
	VTAILQ_FOREACH_SAFE(cookie, &vcp->cookielist, list, tmp) {
		found = 0;
		for (i = 0; i < num_cookies; i++) {
			if (strlen(cookie->name) == strlen(cookienames[i]) &&
			    strcmp(cookienames[i], cookie->name) == 0) {
				found = 1;
				break;
			}
		}

		if (!found) {
			VTAILQ_REMOVE(&vcp->cookielist, cookie, list);
		}
	} // foreach
}


VCL_STRING
vmod_get_string(const struct vrt_ctx *ctx) {
	struct cookie *curr;
	struct vsb *output;
	unsigned v, u;
	char *p;
	struct vmod_cookie *vcp = cobj_get(ctx);
	enum cookie_type ct = 0;
	CHECK_OBJ_NOTNULL(vcp, VMOD_COOKIE_MAGIC);

	u = WS_Reserve(ctx->ws, 0);
	p = ctx->ws->f;

	output = VSB_new_auto();
	AN(output);
	VTAILQ_FOREACH(curr, &vcp->cookielist, list) {
		ct += curr->type;

		VSB_printf(output, "%s=%s; ", curr->name, curr->value);
		if (ct > 0) {
			if (curr->type == e_cookie_resp) {
				if (curr->expires)
					VSB_printf(output,"Expires=%s; ", curr->expires);
				if (curr->path)
					VSB_printf(output,"Path=%s; ", curr->path);
				if (curr->domain)
					VSB_printf(output,"Domain=%s; ", curr->domain);
				if (curr->flags & COOKIE_HTTP_ONLY)
					VSB_printf(output,"HttpOnly; ");
				if (curr->flags & COOKIE_HTTPS_ONLY)
					VSB_printf(output,"Secure; ");
			}
		}
	}
	VSB_trim(output);
	VSB_finish(output);
	v = VSB_len(output);
	strcpy(p, VSB_data(output));

	VSB_delete(output);

	v++;
	if (v > u) {
		WS_Release(ctx->ws, 0);
		VSL(SLT_Debug, 0, "cookie-vmod: Workspace overflowed, abort");
		return (NULL);
	}
	WS_Release(ctx->ws, v);

	return (p);
}


VCL_STRING
vmod_format_rfc1123(const struct vrt_ctx *ctx, VCL_TIME ts, VCL_DURATION duration) {
        return VRT_TIME_string(ctx, ts + duration);
}

/* vi: set ts=2 sw=2 ai noet tw=0: */
