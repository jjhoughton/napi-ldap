#include <node_api.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <ldap.h>
#include <uv.h>

// NOTE: really not sure about this, it doesn't look like init is called
// NOTE: mutliple times so i think it's safe.
static napi_ref cnx_cons_ref;

static const char cnx_name[] = "LDAPCnx";

struct ldap_cnx {
  LDAP *ld;
  ldap_conncb *ldap_callback;
  const char *sasl_mechanism;
  uv_poll_t *handle;
  // TODO: memory leak, need to clean these up
  napi_threadsfe_function reconnect_callback, disconnect_callback, callback;
};

// shouldn't this be in ldap_cnx?
static struct timeval ldap_tv = { 0, 0 };

// TODO: bind, search, close

static void
cnx_finalise (napi_env env, void *data, void *hint)
{
  struct ldap_cnx *ldap_cnx = (struct ldap_cnx *)data;
  if (ldap_cnx->ldap_callback) free (ldap_cnx->ldap_callback);
  if (ldap_cnx->handle) free (ldap_cnx->handle);
  free (ldap_cnx);
}

static void
callback_call_js (napi_env env, napi_value js_cb, void *context, void *data)
{
  uv_poll_t *handle = (uv_poll_t *)data;
  struct ldap_cnx *ldap_cnx = (struct ldap_cnx *) handle->data;
  LDAPMessage *message, *entry;
  napi_status status;
  napi_value errparam, js_result_list;
  char *err_str;
  int entry_count;

  switch (ldap_result (ldap_cnx->ld, LDAP_RES_ANY, LDAP_MSG_ALL,
		       &ldap_tv, &message))
    {
    case 0:
      // timeout occurred, which I don't think happens in async mode
    case -1:
      // We can't really do much; we don't have a msgid to callback to
      break;
    default:
      {
	int err = ldap_result2error (ld->ld, message, 0);
	// TODO: memory leak, might need to free up errparam
	if (err)
	  {
	    err_str = ldap_err2string (err);
	    status = napi_create_string_utf8 (env, err_str, strlen (err_str),
					      &errpararm);
	    assert (status == napi_ok);
	  }
	else
	  errparam = NULL;
	switch (msgtype = ldap_msgtype (message))
	  {
	  case LDAP_RES_SEARCH_REFERENCE:
	    break;
	  case LDAP_RES_SEARCH_ENTRY:
	  case LDAP_RES_SEARCH_RESULT:
	    {
	      entry_count = ldap_count_entries (ldap_cnx->ld, message);
	      
	    }
	  }
      }
    }

}

static void
event (uv_poll_t* handle, int status, int events)
{
  status = napi_call_threadsafe_function (ldap_cnx->callback, handle,
					  napi_tsfn_blocking);
}

static int
on_connect(LDAP *ld, Sockbuf *sb,
	   LDAPURLDesc *srv, struct sockaddr *addr,
	   struct ldap_conncb *ctx)
{
  int fd;
  struct ldap_cnx *ldap_cnx = (struct ldap_cnx *)ctx->lc_arg;
  napi_status status;

  if (ldap_cnx->handle == NULL)
    {
      ldap_cnx->handle = malloc (sizeof (uv_poll_t));
      ldap_get_option (ld, LDAP_OPT_DESC, &fd);
      uv_poll_init (uv_default_loop(), ldap_cnx->handle, fd);
      ldap_cnx->handle->data = ldap_cnx;
    }
  else
    {
      uv_poll_stop (ldap_cnx->handle);
    }
  uv_poll_start (ldap_cnx->handle, UV_READABLE, (uv_poll_cb)event);

  status = napi_call_threadsafe_function (ldap_cnx->reconnect_callback,
					  NULL, NULL);

  return LDAP_SUCESS;
}

static int
on_rebind (LDAP *ld, LDAP_CONST char *url, ber_tag_t request,
	   ber_int_t msgid, void *params)
{
  // this is a new *ld representing the new server connection
  // so our existing code won't work!

  return LDAP_SUCCESS;
}

static napi_value
cnx_constructor (napi_env env, napi_callback_info info)
{
  napi_status status;
  bool is_instance;
  size_t argc = 8, size;
  napi_value argv[argc];
  napi_value this, cnx_cons;
  napi_value url_v, callback, reconnect_callback, disconnect_callback;
  napi_valuetype valuetype;
  int32_t timeout, debug, varifycert, referrals;
  char *url;
  struct ldap_cnx *ldap_cnx;

  status = napi_get_cb_info (env, info, &argc, argv, &this, NULL);
  assert (status == napi_ok);

  status = napi_get_reference_value (env, cnx_cons_ref, &cnx_cons);
  assert (status == napi_ok);

  status = napi_instanceof (env, this, cnx_cons, &is_instance);
  assert (status == napi_ok);

  if (!is_instance)
    {
      napi_throw_error (env, NULL,
			"This is supposed to be a class and as such "
			"you need to declare it as a new instance.");
      return NULL;
    }

  if (argc != 8)
    {
      napi_throw_error (env, NULL, "This class requires 8 arguments");
      return NULL;
    }

  callback = argv[0];
  reconnect_callback = argv[1];
  disconnect_callback = argv[2];
  url_v = argv[3];

  status = napi_typeof (env, callback, &valuetype);
  assert (status == napi_ok);
  if (valuetype != napi_function)
    {
      napi_throw_error (env, NULL, "Callback is not a function");
      return NULL;
    }

  status = napi_typeof (env, reconnect_callback, &valuetype);
  assert (status == napi_ok);
  if (valuetype != napi_function)
    {
      napi_throw_error (env, NULL, "reconnect callback is not a function");
      return NULL;
    }

  status = napi_typeof (env, disconnect_callback, &valuetype);
  assert (status == napi_ok);
  if (valuetype != napi_function)
    {
      napi_throw_error (env, NULL, "disconnect callback is not a function");
      return NULL;
    }

  /**
   * I'm gonna need to make threadsafe versions of these function
   * so this is kind of superflouse
  status = napi_set_named_property (env, this, "Callback", callback);
  assert (status == napi_ok);
  status = napi_set_named_property (env, this,
				    "ReconnectCallback", reconnect_callback);
  assert (status == napi_ok);
  status = npai_set_named_property (env, this,
				    "DisconnectCallback", disconnect_callback);
  assert (status == napi_ok);
  */

  if (napi_get_value_int32 (env, argv[4], &timeout) != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to parse timeout");
      return NULL;
    }

  if (napi_get_value_int32 (env, argv[5], &debug) != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to parse debug level");
      return NULL;
    }

  if (napi_get_value_int32 (env, argv[6], &varifycert) != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to parse verify cert");
      return NULL;
    }

  if (napi_get_value_int32 (env, argv[7], &referrals) != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to parse referrls");
      return NULL;
    }

  if (napi_get_value_utf8 (env, url_v, NULL, 0, &size) != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to parse url");
      return NULL;
    }
  // TODO: memory leak. I'm not sure what the lifetime of this should be yet!!!
  url = malloc (++size);
  if (napi_get_value_utf8 (env, url_v, url, size, &size) != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to parse url");
      return NULL;
    }

  ldap_cnx = malloc (sizeof (struct ldap_cnx));
  memset (ldap_cnx, 0, sizeof (struct ldap_cnx));
  ldap_cnx->ldap_callback = malloc (sizeof (struct ldap_cnx));

  if (ldap_initialize (&(ld->ld), *url) != LDAP_SUCCESS)
    {
      napi_throw_error (env, NULL, "Error intializing ldap");
      free (url);
      return;
    }

  status = napi_create_threadsafe_function (env, callback, NULL, NULL, 0, 1,
					    NULL, NULL, NULL,
					    callback_call_js,
					    ldap_cnx->callback);
  assert (status == napi_ok);
  status = napi_create_threadsafe_function (env, reconnect_callback,
					    NULL, NULL, 0, 1,
					    NULL, NULL, NULL, NULL,
					    ldap_cnx->reconnect_callback);
  assert (status == napi_ok);
  status = napi_create_threadsafe_function (env, disconnect_callback,
					    NULL, NULL, 0, 1,
					    NULL, NULL, NULL, NULL,
					    ldap_cnx->disconnect_callback);
  assert (status == napi_ok);

  ldap_set_option (ldap_cnx->ld, LDAP_OPT_PROTOCOL_VERSION,  &ver);
  ldap_set_option (NULL,         LDAP_OPT_DEBUG_LEVEL,       &debug);
  ldap_set_option (ldap_cnx->ld, LDAP_OPT_CONNECT_CB,  ldap_cnx->ldap_callback);
  ldap_set_option (ldap_cnx->ld, LDAP_OPT_NETWORK_TIMEOUT,   &ntimeout);
  ldap_set_option (ldap_cnx->ld, LDAP_OPT_X_TLS_REQUIRE_CERT,&verifycert);
  ldap_set_option (ldap_cnx->ld, LDAP_OPT_X_TLS_NEWCTX,      &zero);

  ldap_set_option (ldap_cnx->ld, LDAP_OPT_REFERRALS,         &referrals);
  if (referrals)
    ldap_set_rebind_proc(ldap_cnx->ld, on_rebind, ld);

  status = napi_wrap (env, this, ldap_cnx, cnx_finalise, NULL, NULL);
  assert (status == napi_ok);

  return NULL;
}

static napi_value
init (napi_env env, napi_value exports)
{
  napi_status status;
  napi_value cnx_cons;
  napi_property_descriptor properties[] = {};

  status = napi_define_class (env, cnx_name, NAPI_AUTO_LENGTH,
			      cnx_constructor, NULL, 0,
			      properties, &cnx_cons);
  assert (status == napi_ok);

  status = napi_create_reference (env, cnx_cons, 1, &cnx_cons_ref);
  assert (status == napi_ok);

  status =napi_set_named_property (env, exports, cnx_name, cnx_cons);
  assert (status == napi_ok);

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init);
