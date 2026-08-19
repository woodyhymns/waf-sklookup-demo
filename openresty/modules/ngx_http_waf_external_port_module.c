/*
 * ngx_http_waf_external_port_module
 *
 * Resolves the local port of the accepted downstream connection. When an
 * sk_lookup program assigns an unbound external destination to an internal
 * listener socket, getsockname(2) on that accepted socket retains the original
 * destination port. This module exposes that value without Lua socket takeover
 * or request-path procfs I/O.
 *
 * This is intentionally an Nginx/OpenResty source-coupled module. Build it
 * against the exact Nginx core and configure arguments used by the WAF image.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static ngx_int_t ngx_http_waf_external_port_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_waf_external_port_add_variables(ngx_conf_t *cf);

static ngx_http_variable_t ngx_http_waf_external_port_vars[] = {
    { ngx_string("waf_external_port"), NULL,
      ngx_http_waf_external_port_variable, 0, 0, 0 },
    ngx_http_null_variable
};

static ngx_http_module_t ngx_http_waf_external_port_module_ctx = {
    ngx_http_waf_external_port_add_variables, /* preconfiguration */
    NULL,                                      /* postconfiguration */

    NULL,                                      /* create main configuration */
    NULL,                                      /* init main configuration */

    NULL,                                      /* create server configuration */
    NULL,                                      /* merge server configuration */

    NULL,                                      /* create location configuration */
    NULL                                       /* merge location configuration */
};

ngx_module_t ngx_http_waf_external_port_module = {
    NGX_MODULE_V1,
    &ngx_http_waf_external_port_module_ctx,    /* module context */
    NULL,                                      /* module directives */
    NGX_HTTP_MODULE,                           /* module type */
    NULL,                                      /* init master */
    NULL,                                      /* init module */
    NULL,                                      /* init process */
    NULL,                                      /* init thread */
    NULL,                                      /* exit thread */
    NULL,                                      /* exit process */
    NULL,                                      /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_waf_external_port_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *var;
    ngx_http_variable_t *v;

    for (v = ngx_http_waf_external_port_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }
        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_waf_external_port_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_connection_t  *c;
    struct sockaddr   *sa;
    in_port_t          port;
    u_char            *p;

    (void) data;

    c = r->connection;
    if (c == NULL) {
        goto not_found;
    }

    if (c->local_sockaddr == NULL) {
        /* ngx_connection_local_sockaddr calls getsockname once and caches
         * sockaddr in the connection; the resulting variable is request
         * cacheable and does not inspect procfs. */
        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            goto not_found;
        }
    }

    sa = c->local_sockaddr;
    if (sa == NULL) {
        goto not_found;
    }

    switch (sa->sa_family) {
#if (NGX_HAVE_INET6)
    case AF_INET6:
        port = ntohs(((struct sockaddr_in6 *) sa)->sin6_port);
        break;
#endif
    case AF_INET:
        port = ntohs(((struct sockaddr_in *) sa)->sin_port);
        break;
    default:
        goto not_found;
    }

    /* Port zero is not a valid external TCP destination. Never convert an
     * unresolved address into a plausible value for a WAF policy. */
    if (port == 0) {
        goto not_found;
    }

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;
    v->len = ngx_sprintf(p, "%ui", (ngx_uint_t) port) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;

not_found:
    v->len = 0;
    v->valid = 0;
    v->no_cacheable = 0;
    v->not_found = 1;
    v->data = NULL;
    return NGX_OK;
}
