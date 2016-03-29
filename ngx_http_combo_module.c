/*
 * nginx combo module
 * author:	awayhe@yeah.net
 * history:
 *	2012-01-12 create
 *	2012-01-14 fix the bug of ngx_http_combo_is_valid_ext.
 *  2012-01-28
		1. bugfix: when strip setted and no strip version in request filename, then nginx process crashed.
		2. new feather: add path support.
 */
 
/**
 config example
-------------------------
location /combo {
	combo on;
	combo_limit 10;
	combo_mix_ext off;
	combo_strip off;
	combo_seperator '?&';
	combo_exts '.js .json .css .html .txt';
}
*/
 
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ctype.h>
 
typedef struct {
	ngx_flag_t		enable;			/* on/off to enable combo module */
	ngx_int_t		limit;			/* limit file */
	ngx_flag_t		mix_ext;		/* enable combo different ext */
	ngx_flag_t		strip;			/* if is set, then if xxx.20120112.js is not found, then try xxx.js */
	ngx_str_t		seperator;		/* seperator first char to get args, second char to seperat files, third char to identify the end. */
									/* example:
										?&		/combo?file1&file2&file3
										?&!		/combo?file1&file2&file3!anythingdummy
										!&!		/combo!file1&file2&file3!anythingdummy
										default is ?&
									*/
	ngx_str_t		exts;			/* filter extension, multi extensions start with dot [.], seperate by whitespace char */
} ngx_http_combo_conf_t;
 
static char *ngx_http_combo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_combo_create_conf(ngx_conf_t *cf);
static char *ngx_http_combo_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_combo_handler(ngx_http_request_t *r);
static ngx_chain_t* ngx_http_combo_get_chain(ngx_http_request_t *r);
static int ngx_http_combo_file(ngx_http_request_t *r, ngx_http_core_loc_conf_t* clcf, const ngx_str_t *prepath,
			const char* file, ngx_flag_t strip, ngx_chain_t *out);
static char* ngx_http_combo_cstr_t(ngx_pool_t* pool, ngx_str_t* s);
static char* ngx_http_combo_cstr_b(ngx_pool_t* pool, u_char* s, size_t len);
static ngx_str_t ngx_http_combo_get_filename(ngx_pool_t* pool, const ngx_str_t* path, const ngx_str_t *prepath, const char* file);
static int ngx_http_combo_strip_filename(ngx_str_t* filename);
static int ngx_http_combo_is_valid_ext(const char* ext, const char* exts);
static u_char* ngx_http_combo_strrnchr(u_char *s, size_t len, int c);
 
static ngx_command_t  ngx_http_combo_commands[] = {
 
	{ ngx_string("combo"),
	  NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
	  ngx_http_combo,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_combo_conf_t, enable),
	  NULL },
 
	{ ngx_string("combo_limit"),
	  NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_num_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_combo_conf_t, limit),
	  NULL},
 
	{ ngx_string("combo_seperator"),
	  NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_combo_conf_t, seperator),
	  NULL},
 
	{ ngx_string("combo_mix_ext"),
	  NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
	  ngx_conf_set_flag_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_combo_conf_t, mix_ext),
	  NULL},
 
	{ ngx_string("combo_strip"),
	  NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
	  ngx_conf_set_flag_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_combo_conf_t, strip),
	  NULL},
 
	{ ngx_string("combo_exts"),
	  NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_combo_conf_t, exts),
	  NULL},
 
 
	ngx_null_command
};
 
static ngx_http_module_t  ngx_http_combo_module_ctx = {
	NULL,						  /* preconfiguration */
	NULL,						   /* postconfiguration */
 
	NULL,						  /* create main configuration */
	NULL,						  /* init main configuration */
 
	NULL,						  /* create server configuration */
	NULL,						  /* merge server configuration */
 
	ngx_http_combo_create_conf,	/* create location configuration */
	ngx_http_combo_merge_conf	 /* merge location configuration */
};
 
static u_char ngx_combo_default_seperator[] = "?&!";
static u_char ngx_combo_default_exts[] = ".js .json .css .html .txt";
 
static ngx_str_t ngx_combo_type_js		= ngx_string("application/x-javascript");
static ngx_str_t ngx_combo_type_json	= ngx_string("text/json");
static ngx_str_t ngx_combo_type_css		= ngx_string("text/css");
static ngx_str_t ngx_combo_type_txt		= ngx_string("text/plain");
 
ngx_module_t  ngx_http_combo_module = {
	NGX_MODULE_V1,
	&ngx_http_combo_module_ctx, /* module context */
	ngx_http_combo_commands,   /* module directives */
	NGX_HTTP_MODULE,			   /* module type */
	NULL,						  /* init master */
	NULL,						  /* init module */
	NULL,						  /* init process */
	NULL,						  /* init thread */
	NULL,						  /* exit thread */
	NULL,						  /* exit process */
	NULL,						  /* exit master */
	NGX_MODULE_V1_PADDING
};
 
static char *
ngx_http_combo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_combo_conf_t *cbcf;
	ngx_http_core_loc_conf_t  *clcf;
	if (NGX_CONF_OK == ngx_conf_set_flag_slot(cf, cmd, conf)) {
		cbcf = conf;
		if (cbcf->enable) {
			clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
			clcf->handler = ngx_http_combo_handler;
		}
	}
 
	return NGX_CONF_OK;
}
 
static char*
ngx_http_combo_cstr_t(ngx_pool_t* pool, ngx_str_t* s)
{
	return ngx_http_combo_cstr_b(pool, s->data, s->len);
}
 
static char*
ngx_http_combo_cstr_b(ngx_pool_t* pool, u_char* s, size_t len)
{
	char* buf = NULL;
	if (len == 0) {
		return buf;
	}
	buf = ngx_pcalloc(pool, len + 1);
	memcpy(buf, s, len);
	buf[len] = 0;
	return buf;
}
 
static int
ngx_http_combo_is_valid_ext(const char* ext, const char* exts)
{
	char end = 0;
	const char* find = exts;
	do {
		find = strstr(find, ext);
		if (find) {
			end = *(find + strlen(ext));
			if (end == 0 || isblank(end)) {
				return 1;
			}
			++ find;
		}
	} while(find);
	return 0;
}
 
static ngx_int_t
ngx_http_combo_handler(ngx_http_request_t *r)
{
	ngx_chain_t chain;
	ngx_chain_t* out;
 
	char *file, *token, *fext, *ext;
	ngx_int_t limit;
	ngx_int_t rc;
	ngx_http_combo_conf_t  *conf;
	ngx_http_core_loc_conf_t *clcf;
	ngx_str_t prepath;
 
	file = token = fext = ext = NULL;
 
	ngx_memzero(&prepath, sizeof(ngx_str_t));
	ngx_memzero(&chain, sizeof(ngx_chain_t));
	out = &chain;
 
	if (!(r->method & (NGX_HTTP_GET))) {
		return NGX_HTTP_NOT_ALLOWED;
	}
	/* get loc config */
	conf = ngx_http_get_module_loc_conf(r, ngx_http_combo_module);
	limit = conf->limit;
 
	clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
 
	/* get the args string as file list */
	if (conf->seperator.data[0] == '?') {
		file = ngx_http_combo_cstr_t(r->pool, &(r->args));
	} else {
		/* seems not so safe to use strchr in this enviroment */
		char* sep = ngx_strchr(r->uri.data, conf->seperator.data[0]);
		if (sep && sep < (char*)(r->uri.data + r->uri.len)) {
			file = ngx_http_combo_cstr_b(r->pool, (u_char*)(sep+1), r->uri.len - (sep - (char*)r->uri.data) - 1);
		}
	}
 
	/* file list can't be empty */
	if (!file) {
		return NGX_HTTP_BAD_REQUEST;
	}

	if (conf->seperator.len > 2) {
		// no seperate, so check tail
		token = ngx_strchr(file, conf->seperator.data[2]);
		if (token) {
			*token = 0;
			token = NULL;
		}
	}
 
	/* get path */
	do {
		token = ngx_strchr(file, conf->seperator.data[1]);
		if (token) {
			if (token == file) {
				// empty file name, reset prepath.
				++file;
				ngx_memzero(&prepath, sizeof(ngx_str_t));
				continue;
			} else if (*(token-1) == '/') {
				// path
				prepath.data = (u_char*)file;
				prepath.len  = token - file;
				file = token + 1;
				continue;				
			}
			*token = 0;	/* seperate file */
		}
 
		// all the file must be the same extension
		ext = strrchr(file, '.');
		if (NULL == ext || !ngx_http_combo_is_valid_ext(ext, (const char*)conf->exts.data)) {
			return NGX_HTTP_BAD_REQUEST;
		} else if (!conf->mix_ext) {
			if (NULL == fext) {
				fext = ext;
			} else if (0 != ngx_strcmp(fext, ext)) {
				return NGX_HTTP_BAD_REQUEST;
			}
		}
 
		// prepare the output chain buffer
		if (out->buf) {
			out->next = ngx_http_combo_get_chain(r);
			if (!out->next) {
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}
			out = out->next;
		}
 
		/* read file content */
		rc = ngx_http_combo_file(r, clcf, &prepath, file, conf->strip, out);
		if (rc != NGX_HTTP_OK) {
			return rc;
		}
		if (token) {
			file = token + 1;
		}
		--limit;
	} while(token && limit);
 
	if (chain.buf) {
		r->headers_out.status = NGX_HTTP_OK;
		if (out->buf) {
			out->buf->last_buf = 1;
		}
 
		if (!conf->mix_ext) {
			/* to internal type, set mime type */
			if (ngx_strcmp(fext, ".js") == 0) {
				r->headers_out.content_type = ngx_combo_type_js;
				r->headers_out.content_type_len = ngx_combo_type_js.len;
			} else if (ngx_strcmp(fext, ".css") == 0) {
				r->headers_out.content_type = ngx_combo_type_css;
				r->headers_out.content_type_len = ngx_combo_type_css.len;
			} else if (ngx_strcmp(fext, ".json") == 0) {
				r->headers_out.content_type = ngx_combo_type_json;
				r->headers_out.content_type_len = ngx_combo_type_json.len;
			} else if (ngx_strcmp(fext, ".txt") == 0) {
				r->headers_out.content_type = ngx_combo_type_txt;
				r->headers_out.content_type_len = ngx_combo_type_txt.len;
			}
		}
		rc = ngx_http_send_header(r);
		if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
			return rc;
		}
		return ngx_http_output_filter(r, &chain);
	} else {
		return NGX_HTTP_BAD_REQUEST;
	}
}
 
static ngx_str_t
ngx_http_combo_get_filename(ngx_pool_t* pool, const ngx_str_t* path, const ngx_str_t *prepath, const char* file)
{
	int			namelen = 0;
	ngx_str_t	filename;
	u_char*		p = NULL;
 
	namelen = ngx_strlen(file);
	filename.len = path->len + prepath->len + namelen + 1;
	filename.data = ngx_pcalloc(pool, filename.len + 1);
	if (filename.data) {
		p = ngx_cpymem(filename.data, path->data, path->len);
		*p++ = '/';
		if (prepath->len) {
			p = ngx_cpymem(p, prepath->data, prepath->len);
		}
		p = ngx_cpymem(p, file, namelen);
		filename.data[filename.len] = 0;
	} else {
		filename.len = 0;
	}
	return filename;
}

static u_char*
ngx_http_combo_strrnchr(u_char *s, size_t len, int c)
{
	u_char* t = s + len ;
	while (t >= s) {
		if ((int)*t == c) {
			return t;
		}
	}
	return NULL;
}

/*
	convert xxx.yyy.123467890.zz to xxx.yyy.zz, xxx.yyy..zz also ok
*/
static int
ngx_http_combo_strip_filename(ngx_str_t *filename)
{
	/* the buffer filename will be modify */
	u_char* ext = NULL;
	u_char* dot = ngx_http_combo_strrnchr(filename->data, filename->len, '.');
	if (NULL == dot) {
		ngx_memzero(&filename, sizeof(ngx_str_t));
	} else {
		ext = dot;
		// travel all digit
		do {
			-- dot;
		} while(dot > filename->data && isdigit(*dot));
 
		if (dot == filename->data || *dot != '.') {
			ngx_memzero(filename, sizeof(ngx_str_t));
		} else {
			// (filename->data + filename->len - ext) is the length of ext with dot
			ngx_memmove(dot, ext, filename->data + filename->len - ext + 1);
			filename->len -= (ext - dot);
		}
	}
	return filename->len;
}
 
static int
ngx_http_combo_file(ngx_http_request_t *r, ngx_http_core_loc_conf_t *clcf, const ngx_str_t *prepath, const char* file, ngx_flag_t strip, ngx_chain_t *out)
{
	ngx_buf_t *b = NULL;
	ngx_str_t filename;
	ngx_open_file_info_t of;
	int	ret = NGX_HTTP_OK;
 
	filename = ngx_http_combo_get_filename(r->pool, &clcf->root, prepath, file);
	if (!filename.len) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
 
	ngx_memzero(&of, sizeof(ngx_open_file_info_t));
	of.read_ahead	= clcf->read_ahead;
	of.directio		= clcf->directio;
	of.valid		= clcf->open_file_cache_valid;
	of.min_uses		= clcf->open_file_cache_min_uses;
	of.errors		= clcf->open_file_cache_errors;
	of.events		= clcf->open_file_cache_events;
 
	do {
		if (NGX_OK == ngx_open_cached_file(clcf->open_file_cache, &filename, &of, r->pool)
			&& of.is_file) {
			break;
		}
		if (strip) {
			strip = 0; // strip only once
			if (ngx_http_combo_strip_filename(&filename)) {
				continue;
			}
		}
		// return bad request even only one file not exist.
		return NGX_HTTP_BAD_REQUEST;
	} while(1);
 
	do{
		if (NULL == (b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t))) ||
			NULL == (b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t)))) {
			ret = NGX_HTTP_INTERNAL_SERVER_ERROR;
		} else {
			b->file_pos		= 0;
			b->file_last	= of.size;
			b->in_file		= b->file_last ? 1 : 0;
			b->file->fd		= of.fd;
			b->file->log	= r->connection->log;
			b->file->directio = of.is_directio;
			out->buf = b;
 
			if (r->headers_out.last_modified_time < of.mtime) {
				r->headers_out.last_modified_time = of.mtime;
			}
		}
	} while(0);
	return ret;
}
 
static ngx_chain_t*
ngx_http_combo_get_chain(ngx_http_request_t *r)
{
	ngx_chain_t* chain = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
	if (NULL == chain) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate response buffer.");
	}
	return chain;
}
 
 
static void *
ngx_http_combo_create_conf(ngx_conf_t *cf)
{
	ngx_http_combo_conf_t  *conf;
	// init conf
	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_combo_conf_t));
	if (conf == NULL) {
		return NULL;
	}
 
	// must init to unset
	conf->enable  = NGX_CONF_UNSET;
	conf->limit	  = NGX_CONF_UNSET;
	conf->mix_ext = NGX_CONF_UNSET;
	conf->strip   = NGX_CONF_UNSET;
	return conf;
}
 
 
static char *
ngx_http_combo_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_combo_conf_t *prev = parent;
	ngx_http_combo_conf_t *conf = child;
 
	ngx_conf_merge_value(conf->enable, prev->enable, 0);
	ngx_conf_merge_value(conf->limit, prev->limit, 10);
	ngx_conf_merge_value(conf->mix_ext, prev->mix_ext, 0);
	ngx_conf_merge_value(conf->strip, prev->strip, 0);
	ngx_conf_merge_str_value(conf->seperator, prev->seperator, ngx_combo_default_seperator);
	ngx_conf_merge_str_value(conf->exts, prev->exts, ngx_combo_default_exts);
 
	if (conf->limit > 32 || conf->limit < 1) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"combo_limit must between 1 and 32.");
		return NGX_CONF_ERROR;
	}
 
	if (conf->seperator.len < 2) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"combo_seperator must at least 2 charactor.");
		return NGX_CONF_ERROR;
	}
 
	return NGX_CONF_OK;
}

