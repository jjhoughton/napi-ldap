#include <node_api.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <ldap.h>
#include <uv.h>

extern napi_ref cookie_cons_ref;

// NOTE: really not sure about this, it doesn't look like init is called
// NOTE: mutliple times so i think it's safe.
static napi_ref cnx_cons_ref;

static const char cnx_name[] = "LDAPCnx";

struct ldap_cnx
{
  LDAP *ld;
  ldap_conncb *ldap_callback;
  const char *sasl_mechanism;
  uv_poll_t *handle;
  // TODO: memory leak, need to clean these up
  napi_threadsafe_function reconnect_callback, disconnect_callback, callback;
};

// shouldn't this be in ldap_cnx?
static struct timeval ldap_tv = { 0, 0 };

static napi_value
cnx_search (napi_env env, napi_callback_info info)
{
  napi_status status;
  size_t argc = 6;
  napi_value this, argv[argc], cookie_cons, msgid_js;
  napi_valuetype valuetype;
  struct ldap_cnx *ldap_cnx;
  bool is_instance;
  LDAPControl *page_control[2];
  struct berval **cookie_wrap, *cookie;
  char *base, *filter, *attrs;
  char *attrlist[255], *buf, **ap;
  int scope, pagesize, msgid = 0;
  size_t size;

  status = napi_get_cb_info (env, info, &argc, argv, &this, NULL);
  assert (status == napi_ok);

  status = napi_unwrap (env, this, (void **)&ldap_cnx);
  assert (status == napi_ok);

  if (argc != 6)
    {
      napi_throw_error (env, NULL, "This function requires six arguments");
      return NULL;
    }
  
  status = napi_typeof (env, argv[0], &valuetype);
  assert (status == napi_ok);
  if (valuetype != napi_string)
    {
      napi_throw_error (env, NULL, "base needs to be of type string");
      return NULL;
    }
  status = napi_typeof (env, argv[1], &valuetype);
  assert (status == napi_ok);
  if (valuetype != napi_string)
    {
      napi_throw_error (env, NULL, "filter needs to be of type string");
      return NULL;
    }
  status = napi_typeof (env, argv[2], &valuetype);
  assert (status == napi_ok);
  if (valuetype != napi_string)
    {
      napi_throw_error (env, NULL, "attrs must be of type string");
      return NULL;
    }
  status = napi_typeof (env, argv[3], &valuetype);
  assert (status == napi_ok);
  if (valuetype != napi_number)
    {
      napi_throw_error (env, NULL, "scope must be of type number");
      return NULL;
    }
  status = napi_typeof (env, argv[4], &valuetype);
  assert (status == napi_ok);
  if (valuetype != napi_number)
    {
      napi_throw_error (env, NULL, "pagesize must of type number");
      return NULL;
    }
  status = napi_typeof (env, argv[5], &valuetype);
  assert (status == napi_ok);
  if (valuetype != napi_null ||
      valuetype != napi_undefined ||
      valuetype != napi_object)
    {
      napi_throw_error (env, NULL,
			"Cookie either needs to be an instance of "
			"a cookie or null/undefined");
      return NULL;
    }

  if (valuetype == napi_object)
    {
      status = napi_get_reference_value (env, cookie_cons_ref, &cookie_cons);
      assert (status == napi_ok);
      status = napi_instanceof (env, argv[5], cookie_cons, &is_instance);
      assert (status == napi_ok);

      if (!is_instance)
        {
          napi_throw_error (env, NULL, "Cookie is not an instance of a Cookie");
          return NULL;
        }

      status = napi_unwrap (env, argv[5], (void **) &cookie_wrap);
      assert (status == napi_ok);
      cookie = *cookie_wrap;
    }
  else cookie = NULL;

  status = napi_get_value_string_utf8 (env, argv[0], NULL, 0, &size);
  assert (status == napi_ok);
  base = malloc (++size);
  status = napi_get_value_string_utf8 (env, argv[0], base, size, &size);
  assert (status == napi_ok);

  status = napi_get_value_string_utf8 (env, argv[1], NULL, 0, &size);
  assert (status == napi_ok);
  filter = malloc (++size);
  status = napi_get_value_string_utf8 (env, argv[1], filter, size, &size);
  assert (status == napi_ok);

  status = napi_get_value_string_utf8 (env, argv[2], NULL, 0, &size);
  assert (status == napi_ok);
  attrs = malloc (++size);
  status = napi_get_value_string_utf8 (env, argv[2], attrs, size, &size);

  status = napi_get_value_int32 (env, argv[3], &scope);
  assert (status == napi_ok);

  status = napi_get_value_int32 (env, argv[4], &pagesize);
  assert (status == napi_ok);

  memset (&page_control, 0, sizeof (page_control));

  for (ap = attrlist; (*ap = strsep (&buf, " \t,")) != NULL;)
    if (**ap != '\0')
      if (++ap >= &attrlist[266])
        break;

  if (pagesize > 0)
    {
      if (cookie)
        ldap_create_page_control (ldap_cnx->ld, pagesize,
                                  cookie, 0, &page_control[0]);
      else
        ldap_create_page_control (ldap_cnx->ld, pagesize,
                                  NULL, 0, &page_control[0]);
    }

  ldap_search_ext (ldap_cnx->ld, base, scope, filter, (char **) attrlist, 0,
                   page_control, NULL, NULL, 0, &msgid);
  if (pagesize > 0)
    ldap_control_free (page_control[0]);

  free (base);
  free (filter);
  free (attrs);

  status = napi_create_int32 (env, msgid, &msgid_js);
  assert (status == napi_ok);

  return msgid_js;
}

static napi_value
cnx_close (napi_env env, napi_callback_info info)
{
  napi_status status;
  napi_value this, js_ret;
  size_t argc = 0;
  int ret;
  struct ldap_cnx *ldap_cnx;

  status = napi_get_cb_info (env, info, &argc, NULL, &this, NULL);
  assert (status == napi_ok);

  status = napi_unwrap (env, this, (void **) &ldap_cnx);
  assert (status == napi_ok);

  ret = ldap_unbind (ldap_cnx->ld);
  status = napi_create_int32 (env, ret, &js_ret);
  assert (status == napi_ok);

  return js_ret;
}

static napi_value
cnx_bind (napi_env env, napi_callback_info info)
{
  napi_status status;
  size_t argc = 2, size;
  napi_value this, argv[argc], js_ret;
  struct ldap_cnx *ldap_cnx = NULL;
  napi_valuetype dn_vt, pwd_vt;
  char *dn, *password;
  int ret;

  status = napi_get_cb_info (env, info, &argc, argv, &this, NULL);
  assert (status == napi_ok);

  if (argc != 2)
    {
      napi_throw_error (env, NULL, "This function requires two arguments");
      return NULL;
    }

  status = napi_typeof (env, argv[0], &dn_vt);
  assert (status == napi_ok);
  if (dn_vt != napi_string && dn_vt != napi_null && dn_vt != napi_undefined)
    {
      napi_throw_error (env, NULL,
			"DN must be of type string or undefined/null");
      return NULL;
    }
  status = napi_typeof (env, argv[1], &pwd_vt);
  assert (status == napi_ok);
  if (pwd_vt != napi_string && pwd_vt != napi_null && pwd_vt != napi_undefined)
    {
      napi_throw_error (env, NULL,
			"password must be of type string or undefined/null");
      return NULL;
    }

  if (dn_vt == napi_string)
    {
      status = napi_get_value_string_utf8 (env, argv[0], NULL, 0, &size);
      assert (status == napi_ok);
      dn = malloc (++size);
      status = napi_get_value_string_utf8 (env, argv[0], dn, size, &size);
      assert (status == napi_ok);
    }
  else dn = NULL;

  if (pwd_vt == napi_string)
    {
      status = napi_get_value_string_utf8 (env, argv[1], NULL, 0, &size);
      assert (status == napi_ok);
      password = malloc (++size);
      status = napi_get_value_string_utf8 (env, argv[1], password, size, &size);
      assert (status == napi_ok);
    }
  else password = NULL;

  status = napi_unwrap (env, this, (void **)&ldap_cnx);
  assert (status == napi_ok);

  ret = ldap_simple_bind (ldap_cnx->ld, dn, password);
  status = napi_create_int32 (env, ret, &js_ret);
  assert (status == napi_ok);
  return js_ret;
}

static void
cnx_finalise (napi_env env, void *data, void *hint)
{
  struct ldap_cnx *ldap_cnx = (struct ldap_cnx *) data;
  if (ldap_cnx->ldap_callback) free (ldap_cnx->ldap_callback);
  if (ldap_cnx->handle) free (ldap_cnx->handle);
  free (ldap_cnx);
}

static int
is_binary (char *attrname)
{
  return (!strcmp(attrname, "jpegPhoto") ||
	  !strcmp(attrname, "photo") ||
	  !strcmp(attrname, "personalSignature") ||
	  !strcmp(attrname, "userCertificate") ||
	  !strcmp(attrname, "cACertificate") ||
	  !strcmp(attrname, "authorityRevocationList") ||
	  !strcmp(attrname, "certificateRevocationList") ||
	  !strcmp(attrname, "deltaRevocationList") ||
	  !strcmp(attrname, "crossCertificatePair") ||
	  !strcmp(attrname, "x500UniqueIdentifier") ||
	  !strcmp(attrname, "audio") ||
	  !strcmp(attrname, "javaSerializedObject") ||
	  !strcmp(attrname, "thumbnailPhoto") ||
	  !strcmp(attrname, "thumbnailLogo") ||
	  !strcmp(attrname, "supportedAlgorithms") ||
	  !strcmp(attrname, "protocolInformation") ||
	  !strcmp(attrname, "objectGUID") ||
	  !strcmp(attrname, "objectSid") ||
	  strstr(attrname, ";binary"));
}

static void
handle_result_events (napi_env env, napi_value js_cb,
		      struct ldap_cnx *ldap_cnx, LDAPMessage *message,
		      napi_value errparam, napi_value this)
{
  int entry_count, i, j, bin;
  struct berval **vals;
  LDAPMessage *entry;
  napi_status status;
  napi_value js_result_list, js_result, js_attr_vals, js_val, result_container,
    js_cookie_wrap, cookie_cons, js_message;
  char *dn, *attrname;
  BerElement *berptr = NULL;
  char buf[16];
  void *data;
  size_t size;
  int num_vals;
  LDAPControl **server_ctrls;
  struct berval *cookie = NULL, **cookie_wrap = NULL;

  entry_count = ldap_count_entries (ldap_cnx->ld, message);
  status = napi_create_array_with_length (env, entry_count, &js_result_list);
  assert (status == napi_ok);
  for (entry = ldap_first_entry (ldap_cnx->ld, message), i = 0;
       entry;
       entry = ldap_next_entry (ldap_cnx->ld, entry), i++)
    {
      status = napi_create_object (env, &js_result);
      assert (status == napi_ok);

      sprintf (buf, "%d", i);
      status = napi_set_named_property (env, js_result, buf, js_result_list);
      assert (status == napi_ok);

      dn = ldap_get_dn (ldap_cnx->ld, entry);
      for (attrname = ldap_first_attribute (ldap_cnx->ld, entry, &berptr);
	   attrname;
	   attrname = ldap_next_attribute (ldap_cnx->ld, entry, berptr))
	{
	  vals = ldap_get_values_len(ldap_cnx->ld, entry, attrname);
	  num_vals = ldap_count_values_len (vals);
	  status = napi_create_array_with_length (env, num_vals, &js_attr_vals);
	  assert (status == napi_ok);
	  status = napi_set_named_property (env, js_result,
					    attrname, js_attr_vals);
	  assert (status == napi_ok);
	  bin = is_binary (attrname);

	  for (j = 0; j < num_vals; j++)
	    {
	      sprintf (buf, "%d", j);
	      size = vals[j]->bv_len;
	      if (bin)
		{
		  status = napi_create_buffer (env, size, &data, &js_val);
		  assert (status == napi_ok);
		  memcpy (data, vals[j]->bv_val, size);
		}
	      else
		{
		  status = napi_create_string_utf8 (env, vals[j]->bv_val, size,
						    &js_val);
		  assert (status == napi_ok);
		}
	      status = napi_set_named_property (env, js_attr_vals, buf, js_val);
	      assert (status == napi_ok);
	    }
	  ldap_value_free_len (vals);
	  ldap_memfree (attrname);
	}
      status = napi_create_string_utf8 (env, dn, NAPI_AUTO_LENGTH, &js_val);
      assert (status == napi_ok);
      status = napi_set_named_property (env, js_result, "dn", js_val);
      assert (status == napi_ok);
    }

  status = napi_create_object (env, &result_container);
  assert (status == napi_ok);
  status = napi_set_named_property (env, result_container, "data",
                                    js_result_list);
  assert (status == napi_ok);

  ldap_parse_result (ldap_cnx->ld, message,
		     NULL, // int* errcodep
		     NULL, // char** matcheddnp
		     NULL, // char** errmsp
		     NULL, // char*** referralsp
		     &server_ctrls,
		     0     // freeit
		     );
  if (server_ctrls)
    {
      ldap_parse_page_control (ldap_cnx->ld, server_ctrls, NULL, &cookie);
      if (!cookie || cookie->bv_val == NULL || !*cookie->bv_val)
	{
	  if (cookie)
	    ber_bvfree (cookie);
	}
      else
	{
	  status = napi_create_object (env, &js_cookie_wrap);
	  assert (status == napi_ok);
	  status = napi_get_reference_value (env, cookie_cons_ref,
					     &cookie_cons);
	  assert (status == napi_ok);
	  status = napi_new_instance (env, cookie_cons, 0, NULL,
				      &js_cookie_wrap);
	  status = napi_unwrap (env, js_cookie_wrap, (void **)&cookie_wrap);
	  assert (status == napi_ok);
	  *cookie_wrap = cookie;
	}
      ldap_controls_free (server_ctrls);
    }

  status = napi_create_int32 (env, ldap_msgid (message), &js_message);
  assert (status == napi_ok);
  napi_value argv[] = { errparam, js_message, result_container };

  status = napi_call_function (env, this, js_cb, 3, argv, NULL);
  assert (status == napi_ok);
}

static void
callback_call_js (napi_env env, napi_value js_cb, void *context, void *data)
{
  char *err_str = NULL;
  uv_poll_t *handle = (uv_poll_t *)data;
  struct ldap_cnx *ldap_cnx = (struct ldap_cnx *) handle->data;
  LDAPMessage *message;
  napi_status status;
  napi_value errparam, js_message;
  napi_value this = (napi_value) context;
  int err, msgtype, res, msgid;

  res = ldap_result (ldap_cnx->ld, LDAP_RES_ANY, LDAP_MSG_ALL,
                     &ldap_tv, &message);

  if (res == 0 || res == -1)
    {
      ldap_msgfree (message);
      return;
    }

  err = ldap_result2error (ldap_cnx->ld, message, 0);
  // TODO: memory leak, might need to free up errparam
  if (err)
    {
      err_str = ldap_err2string (err);
      status = napi_create_string_utf8 (env, err_str, NAPI_AUTO_LENGTH,
                                        &errparam);
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
      handle_result_events (env, js_cb, ldap_cnx,
                            message, errparam, this);
      break;
    case LDAP_RES_BIND:
      {
        msgid = ldap_msgid (message);

        if (err == LDAP_SASL_BIND_IN_PROGRESS)
          {
            // TODO: we don't support sasl yet
          }

        status = napi_create_int32 (env, msgid, &js_message);
        assert (status == napi_ok);
        napi_value argv[] = { errparam, js_message };
        status = napi_call_function (env, this, js_cb, 3, argv, NULL);
        assert (status == napi_ok);
        break;
      }
    case LDAP_RES_MODIFY:
    case LDAP_RES_MODDN:
    case LDAP_RES_ADD:
    case LDAP_RES_DELETE:
    case LDAP_RES_EXTENDED:
     {
        status = napi_create_int32 (env, ldap_msgid (message),
                                    &js_message);
        assert (status == napi_ok);
        napi_value argv[] = { errparam, js_message };
        status = napi_call_function (env, this, js_cb, 2, argv, NULL);
        assert (status == napi_ok);
        break;
      }
    default:
      {
        //emit an error
        // Nan::ThrowError("Unrecognized packet");
      }
    }

  ldap_msgfree (message);
  return;
}

static void
cnx_event (uv_poll_t* handle, int _status, int events)
{
  napi_status status;
  struct ldap_cnx *ldap_cnx = (struct ldap_cnx *) handle->data;
  status = napi_call_threadsafe_function (ldap_cnx->callback, handle,
					  napi_tsfn_blocking);
  assert (status == napi_ok);
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
  uv_poll_start (ldap_cnx->handle, UV_READABLE, (uv_poll_cb)cnx_event);

  status = napi_call_threadsafe_function (ldap_cnx->reconnect_callback,
					  NULL, napi_tsfn_blocking);
  assert (status == napi_ok);

  return LDAP_SUCCESS;
}

static void
on_disconnect (LDAP *ld, Sockbuf *sb,
	       struct ldap_conncb *ctx)
{
  struct ldap_cnx *lc = (struct ldap_cnx *)ctx->lc_arg;
  napi_status status;

  if (lc->handle) uv_poll_stop (lc->handle);
  status = napi_call_threadsafe_function(lc->disconnect_callback,
					 NULL, napi_tsfn_blocking);
  assert (status == napi_ok);
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
  napi_value this, cnx_cons;
  napi_value url_v, callback, reconnect_callback, disconnect_callback;
  napi_valuetype valuetype;
  int32_t timeout, debug, verifycert, referrals;
  char *url;
  struct ldap_cnx *ldap_cnx;
  int ver = LDAP_VERSION3;
  int zero = 0;
  napi_extended_error_info *errinfo;

  napi_value connect_str, reconnect_str, disconnect_str;

  struct
  {
    napi_value callback, reconnect_callback, disconnect_callback;
    napi_value url, timeout, debug, verifycert, referrals;
  } args;

  assert (&args.callback == args);
  memset (args, 0, sizeof (args));

  status = napi_get_cb_info (env, info, &argc, (napi_value *)args, &this, NULL);
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

  if (napi_get_value_int32 (env, argv[6], &verifycert) != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to parse verify cert");
      return NULL;
    }

  if (napi_get_value_int32 (env, argv[7], &referrals) != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to parse referrls");
      return NULL;
    }

  if (napi_get_value_string_utf8 (env, url_v, NULL, 0, &size) != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to parse url");
      return NULL;
    }
  url = malloc (++size);
  if (napi_get_value_string_utf8 (env, url_v, url, size, &size) != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to parse url");
      return NULL;
   }

  ldap_cnx = malloc (sizeof (struct ldap_cnx));
  memset (ldap_cnx, 0, sizeof (struct ldap_cnx));
  ldap_cnx->ldap_callback = malloc (sizeof (struct ldap_conncb));
  ldap_cnx->ldap_callback->lc_add = on_connect;
  ldap_cnx->ldap_callback->lc_del = on_disconnect;
  ldap_cnx->ldap_callback->lc_arg = ldap_cnx;

  if (ldap_initialize (&(ldap_cnx->ld), url) != LDAP_SUCCESS)
    {
      napi_throw_error (env, NULL, "Error intializing ldap");
      free (url);
      return NULL;
    }

  // NOTE: don't need to use these as everything is in the same thread
  status = napi_create_string_utf8 (env, "connect", NAPI_AUTO_LENGTH,
                                    &connect_str);
  assert (status == napi_ok);
  status = napi_create_string_utf8 (env, "reconnect", NAPI_AUTO_LENGTH,
                                    &reconnect_str);
  assert (status == napi_ok);
  status = napi_create_string_utf8 (env, "disconnect", NAPI_AUTO_LENGTH,
                                    &disconnect_str);
  assert (status == napi_ok);

  /*
  status = napi_create_threadsafe_function (env, callback, NULL,
                                            connect_str, 0, 1,
					    NULL, NULL, this,
					    callback_call_js,
					    &ldap_cnx->callback);
  assert (status == napi_ok);

  status = napi_create_threadsafe_function (env, reconnect_callback,
					    NULL, reconnect_str, 0, 1,
					    NULL, NULL, NULL, NULL,
					    &ldap_cnx->reconnect_callback);
  assert (status == napi_ok);
  status = napi_create_threadsafe_function (env, disconnect_callback,
					    NULL, disconnect_str, 0, 1,
					    NULL, NULL, NULL, NULL,
					    &ldap_cnx->disconnect_callback);
  assert (status == napi_ok);
  */
  struct timeval ntimeout = { timeout/1000, (timeout%1000) * 1000 };

  ldap_set_option (ldap_cnx->ld, LDAP_OPT_PROTOCOL_VERSION,  &ver);
  ldap_set_option (NULL,         LDAP_OPT_DEBUG_LEVEL,       &debug);
  ldap_set_option (ldap_cnx->ld, LDAP_OPT_CONNECT_CB,  ldap_cnx->ldap_callback);
  ldap_set_option (ldap_cnx->ld, LDAP_OPT_NETWORK_TIMEOUT,   &ntimeout);
  ldap_set_option (ldap_cnx->ld, LDAP_OPT_X_TLS_REQUIRE_CERT,&verifycert);
  // NOTE: this line segfaults no idea why
  //ldap_set_option (ldap_cnx->ld, LDAP_OPT_X_TLS_NEWCTX,      &zero);


  ldap_set_option (ldap_cnx->ld, LDAP_OPT_REFERRALS,         &referrals);
  if (referrals)
    ldap_set_rebind_proc (ldap_cnx->ld, on_rebind, ldap_cnx);

  status = napi_wrap (env, this, ldap_cnx, cnx_finalise, NULL, NULL);
  assert (status == napi_ok);

  free (url);

  return this;
}

void
cnx_init (napi_env env, napi_value exports)
{
  napi_status status;
  napi_value cnx_cons;
  napi_property_descriptor properties[] =
    {
     { "bind", 0, cnx_bind, 0, 0, 0, napi_default, 0 },
     { "search", 0, cnx_search, 0, 0, 0, napi_default, 0 },
     { "close", 0, cnx_close, 0, 0, 0, napi_default, 0 }
    };

  status = napi_define_class (env, cnx_name, NAPI_AUTO_LENGTH,
			      cnx_constructor, NULL, 3,
			      properties, &cnx_cons);
  assert (status == napi_ok);

  status = napi_create_reference (env, cnx_cons, 1, &cnx_cons_ref);
  assert (status == napi_ok);

  status =napi_set_named_property (env, exports, cnx_name, cnx_cons);
  assert (status == napi_ok);
}
