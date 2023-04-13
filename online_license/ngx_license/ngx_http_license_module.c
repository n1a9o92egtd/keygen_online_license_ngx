#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sys/resource.h>

#include "ngx_http_license_post.h"
#include "ngx_http_license_get.h"
#include "ngx_base.h"

//user include headers
#include <ctype.h>
//user config struct 
typedef struct {
	ngx_str_t on_off_flags;
} ngx_http_license_main_conf_t;

/*************our nginx's module function declare************/
//how to init when work process created
static ngx_int_t init_http_license_process(ngx_cycle_t *cycle);
//what we need todo clear when work process before exiting
static void		 exit_http_license_process(ngx_cycle_t *cycle);

//how to create user config struct
static void *	 ngx_http_license_create_main_conf(ngx_conf_t * cf);
//how to init config(for postconfiguration)
static ngx_int_t ngx_http_license_init(ngx_conf_t *cf);

//our nginx module kernel,we care this!
static ngx_int_t ngx_http_license_handler(ngx_http_request_t *r);

//define our module command,it tell nginx which argument we will need and how to parse
static ngx_command_t ngx_http_license_commands [] = { 
	{
		ngx_string("on_off_flags"),
		NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_MAIN_CONF_OFFSET,
		offsetof(ngx_http_license_main_conf_t, on_off_flags),
		NULL 
	},
	ngx_null_command
};

//define our nginx module context,it will be used in module define
static ngx_http_module_t ngx_http_license_modulte_ctx = {
    NULL,                                 		/* preconfiguration */
    ngx_http_license_init,          				/* postconfiguration */

    ngx_http_license_create_main_conf,				/* create main configuration */
    NULL,									    /* init main configuration */

    NULL,                                  		/* create server configuration */
    NULL,                                  		/* merge server configuration */

    NULL,    									/* create location configuration */
    NULL     									/* merge location configuration */
};

//define our nginx module
ngx_module_t ngx_http_license_module = {
    NGX_MODULE_V1,
    &ngx_http_license_modulte_ctx,  /* module context */
    ngx_http_license_commands,      /* module directives */
    NGX_HTTP_MODULE,             /* module type */
    NULL,                        /* init master */
    NULL,						 /* init module */
    init_http_license_process,      /* init process*/
    NULL,                        /* init thread */
    NULL,                        /* exit thread */
    exit_http_license_process,      /* exit process*/
    NULL,                        /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t init_http_license_process(ngx_cycle_t *cycle)
{
	ngx_http_license_main_conf_t *sscf;
    sscf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_license_module);
    if( sscf == NULL ){
    	return NGX_ERROR;
    }
	return NGX_OK;
}

static void exit_http_license_process(ngx_cycle_t *cycle)
{
	ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno, "demo moudle catch exit process called");
}

static void * ngx_http_license_create_main_conf(ngx_conf_t * cf)
{
	ngx_http_license_main_conf_t *conf;
    conf = ngx_pnalloc(cf->pool, sizeof(ngx_http_license_main_conf_t));
    if(!conf) 
    	return NULL;
    return conf;
}

static ngx_int_t ngx_http_license_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
	//NOTE:content phase if handler not return NGX_DECLINED,it will call ngx_http_finalize_request
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE/*NGX_HTTP_CONTENT_PHASE*/].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_license_handler;
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
		return NGX_ERROR;
	}
	*h = ngx_http_license_handler;
    return NGX_OK;
}

//NOTE:important process of below function
static ngx_int_t ngx_http_license_handler(ngx_http_request_t *r)
{
  //   u_char buf[1024];
  //   if(NgxGetRoot(buf, 1023))
		// ngx_log_error(NGX_LOG_INFO, r->connection->log, ngx_errno, "nrzs_root_dir:%s", buf);
	static ngx_uint_t ngx_http_memory_leak_killer_limit = 20 * 1024 * 1024;
	struct rusage usage;
	ngx_pid_t ngx_http_memory_leak_killer_target_pid = getpid();
  	if (getrusage(RUSAGE_SELF, &usage) != 0) {
    	return NGX_AGAIN;
  	}
  	if ((uint)usage.ru_maxrss >= ngx_http_memory_leak_killer_limit) {
    	if (ngx_http_memory_leak_killer_target_pid != 0) {
      		if (kill(ngx_http_memory_leak_killer_target_pid, SIGQUIT) == -1) {
        		return NGX_AGAIN;
      		}
    	}
  	}
	if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_POST))) {
        return NGX_HTTP_NOT_ALLOWED;
    }
	ngx_http_license_main_conf_t *sscf = NULL;
	sscf = ngx_http_get_module_main_conf(r, ngx_http_license_module);
	if( sscf == NULL ) {
		ngx_log_error(NGX_LOG_ALERT,r->connection->log,0,"handler func get demo module config error");
    	return NGX_HTTP_SERVICE_UNAVAILABLE;
    }
   	if (ngx_strncasecmp(sscf->on_off_flags.data, (u_char*)"on", sscf->on_off_flags.len) != 0) {
		return NGX_OK;
	}
	if (r->method == NGX_HTTP_GET) {
	    return ngx_http_license_get_module_handler(r);
	}
	if (r->method == NGX_HTTP_POST) {
		return ngx_http_license_post_module_handler(r);
	}
    return NGX_OK;
}

