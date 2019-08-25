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
  napi_async_context async_context;
  //napi_value reconnect_callback, disconnect_callback, callback;
  //napi_value this;
  napi_ref reconnect_callback_ref, disconnect_callback_ref, callback_ref;
  napi_ref this_ref;
  napi_env env;
};

// shouldn't this be in ldap_cnx?
static struct timeval ldap_tv = { 0, 0 };

static inline void
cnx_errinfo (napi_env env)
{
  napi_status status;
  const napi_extended_error_info *errinfo;

  status = napi_get_last_error_info (env, &errinfo);
  assert (status == napi_ok);

  puts (errinfo->error_message);
}

/**
 * For debugging
static void
cnx_log (napi_env env, napi_value value)
{
  napi_value global, console, log, argv[] = { value };
  napi_status status;

  status = napi_get_global (env, &global);
  assert (status == napi_ok);
  status = napi_get_named_property (env, global, "console", &console);
  assert (status == napi_ok);
  status = napi_get_named_property (env, console, "log", &log);
  assert (status == napi_ok);
  status = napi_call_function (env, global, log, 1, argv, NULL);
  assert (status == napi_ok);
}
*/

static napi_value
cnx_check_tls (napi_env env, napi_callback_info info)
{
  struct ldap_cnx *ldap_cnx;
  int is_tls;
  napi_value this, ret;
  napi_status status;

  status = napi_get_cb_info (env, info, 0, NULL, &this, NULL);
  assert (status == napi_ok);

  status = napi_unwrap (env, this, (void **) &ldap_cnx);
  assert (status == napi_ok);

  is_tls = ldap_tls_inplace (ldap_cnx->ld);
  status = napi_create_int32 (env, is_tls, &ret);
  assert (status == napi_ok);

  return ret;
}

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
  if (valuetype != napi_number && valuetype != napi_undefined)
    {
      napi_throw_error (env, NULL, "pagesize must of type number");
      return NULL;
    }
  if (valuetype == napi_number)
    {
      status = napi_get_value_int32 (env, argv[4], &pagesize);
      assert (status == napi_ok);
    }
  else
    pagesize = 1 << 31;


  status = napi_typeof (env, argv[5], &valuetype);
  assert (status == napi_ok);
  if (valuetype != napi_null &&
      valuetype != napi_undefined &&
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

  //printf ("pagesize %d\n", pagesize);

  memset (&page_control, 0, sizeof (page_control));

  buf = attrs;

  for (ap = attrlist; (*ap = strsep (&buf, " \t,")) != NULL;)
    if (**ap != '\0')
      if (++ap >= &attrlist[255])
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

static napi_value
cnx_delete (napi_env env, napi_callback_info info)
{
  struct ldap_cnx *ldap_cnx;
  int return_code;
  size_t size, argc = 1;
  char *dn;
  napi_value this, ret, argv[argc];
  napi_status status;
  napi_valuetype valuetype;

  status = napi_get_cb_info (env, info, &argc, argv, &this, NULL);
  assert (status == napi_ok);

  status = napi_unwrap (env, this, (void **) &ldap_cnx);
  assert (status == napi_ok);

  if (argc != 1)
    {
      napi_throw_error (env, NULL, "This function requires one argument");
      return NULL;
    }

  status = napi_typeof (env, *argv, &valuetype);
  assert (status == napi_ok);  
  if (valuetype != napi_string)
    {
      napi_throw_error (env, NULL, "DN needs to be of type string");
      return NULL;
    }

  status = napi_get_value_string_utf8 (env, *argv, NULL, 0, &size);
  assert (status == napi_ok);
  dn = malloc (++size);
  status = napi_get_value_string_utf8 (env, *argv, dn, size, &size);
  assert (status == napi_ok);

  return_code = ldap_delete (ldap_cnx->ld, dn);

  free (dn);

  status = napi_create_int32 (env, return_code, &ret);
  assert (status == napi_ok);

  return ret;
}

static napi_value
cnx_add (napi_env env, napi_callback_info info)
{
  struct ldap_cnx *ldap_cnx;
  size_t size, argc = 2;
  char *dn, buf[20], *mod_type, *mod_value;
  bool is_array;
  int msgid;
  uint32_t array_length, vals_length, i, j;
  napi_value this, argv[argc], attrs, obj, ret = NULL, attr, vals, val;
  napi_valuetype valuetype;
  napi_status status;
  LDAPMod **ldapmods;

  status = napi_get_cb_info (env, info, &argc, argv, &this, NULL);
  assert (status == napi_ok);

  status = napi_unwrap (env, this, (void **) &ldap_cnx);
  assert (status == napi_ok);

  if (argc != 2)
    {
      napi_throw_error (env, NULL, "This function requires two arguments");
      return NULL;
    }

  status = napi_typeof (env, *argv, &valuetype);
  assert (status == napi_ok);  
  if (valuetype != napi_string)
    {
      napi_throw_error (env, NULL, "DN needs to be of type string");
      return NULL;
    }

  attrs = argv[1];

  status = napi_is_array (env, attrs, &is_array);
  assert (status == napi_ok);
  if (!is_array)
    {
      napi_throw_error (env, NULL, "Attributes should be an array");
      return NULL;
    }

  status = napi_get_value_string_utf8 (env, *argv, NULL, 0, &size);
  assert (status == napi_ok);
  dn = malloc (++size);
  status = napi_get_value_string_utf8 (env, *argv, dn, size, &size);
  assert (status == napi_ok);

  status = napi_get_array_length (env, attrs, &array_length);
  assert (status == napi_ok);

  size = sizeof (LDAPMod *) * (array_length + 1);
  ldapmods = (LDAPMod **) malloc (size);
  memset (ldapmods, 0, size);
  for (i = 0; i < array_length; i++)
    {
      sprintf (buf, "%d", i);
      status = napi_get_named_property (env, attrs, buf, &obj);
      assert (status == napi_ok);

      status = napi_typeof (env, obj, &valuetype);
      assert (status == napi_ok);
      if (valuetype != napi_object)
        {
          napi_throw_error (env, NULL, "Attribute must be an object");
          goto out;
        }

      status = napi_get_named_property (env, obj, "attr", &attr);
      assert (status == napi_ok);
      status = napi_get_named_property (env, obj, "vals", &vals);
      assert (status == napi_ok);

      status = napi_typeof (env, attr, &valuetype);
      assert (status == napi_ok);
      if (valuetype != napi_string)
        {
          napi_throw_error (env, NULL, "attr must be a string");
          goto out;
        }
      status = napi_is_array (env, vals, &is_array);
      assert (status == napi_ok);
      if (!is_array)
        {
          napi_throw_error (env, NULL, "vals must be an array");
          goto out;
        }

      ldapmods[i] = (LDAPMod *) malloc (sizeof (LDAPMod));
      memset (ldapmods[i], 0, sizeof (LDAPMod));

      ldapmods[i]->mod_op = LDAP_MOD_ADD;

      status = napi_get_value_string_utf8 (env, attr, NULL, 0, &size);
      assert (status == napi_ok);
      mod_type = malloc (++size);
      status = napi_get_value_string_utf8 (env, attr, mod_type, size, &size);
      assert (status == napi_ok);
      ldapmods[i]->mod_type = mod_type;

      status = napi_get_array_length (env, vals, &vals_length);
      assert (status == napi_ok);
      size = sizeof (char *) * (vals_length + 1);
      ldapmods[i]->mod_values = malloc (size);
      memset (ldapmods[i]->mod_values, 0, size);
      for (j = 0; j < vals_length; j++)
        {
          sprintf (buf, "%d", j);
          status = napi_get_named_property (env, vals, buf, &val);
          assert (status == napi_ok);
          status = napi_typeof (env, val, &valuetype);
          assert (status == napi_ok);
          if (valuetype != napi_string)
            {
              napi_throw_error (env, NULL, "Napi val is not a string");
              goto out;
            }
          status = napi_get_value_string_utf8 (env, val, NULL, 0, &size);
          assert (status == napi_ok);
          mod_value = malloc (++size);
          status = napi_get_value_string_utf8 (env, val, mod_value,
                                               size, &size);
          assert (status == napi_ok);
          ldapmods[i]->mod_values[j] = mod_value;
        }
    }

  msgid = ldap_add (ldap_cnx->ld, dn, ldapmods);
  status = napi_create_int32 (env, msgid, &ret);
  assert (status == napi_ok);
  
 out:
  free (dn);
  ldap_mods_free (ldapmods, 1);
  return ret;
}

static napi_value
cnx_modify (napi_env env, napi_callback_info info)
{
  struct ldap_cnx *ldap_cnx;
  uint32_t i, j, array_length, vals_length;
  int msgid;
  size_t argc = 2, size;
  bool is_array;
  napi_value this, argv[argc], ret = NULL, mod_handle;
  napi_value op, attr, vals, val, attrs;
  char *dn, *mod_op, *mod_type, buf[20], *mod_value;
  napi_valuetype valuetype;
  napi_status status;
  LDAPMod **ldapmods;

  status = napi_get_cb_info (env, info, &argc, argv, &this, NULL);
  assert (status == napi_ok);

  status = napi_unwrap (env, this, (void **) &ldap_cnx);
  assert (status == napi_ok);

  if (argc != 2)
    {
      napi_throw_error (env, NULL, "This function requires two arguments");
      return NULL;
    }

  status = napi_typeof (env, argv[0], &valuetype);
  assert (status == napi_ok);
  if (valuetype != napi_string)
    {
      napi_throw_error (env, NULL, "DN needs to be of type string");
      return NULL;
    }

  attrs = argv[1];

  status = napi_is_array (env, attrs, &is_array);
  assert (status == napi_ok);
  if (!is_array)
    {
      napi_throw_error (env, NULL, "Attributes should be an array");
      return NULL;
    }

  status = napi_get_value_string_utf8 (env, argv[0], NULL, 0, &size);
  assert (status == napi_ok);
  dn = malloc (++size);
  status = napi_get_value_string_utf8 (env, argv[0], dn, size, &size);
  assert (status == napi_ok);

  status = napi_get_array_length (env, attrs, &array_length);
  assert (status == napi_ok);

  size = sizeof (LDAPMod *) * (array_length + 1);
  ldapmods = (LDAPMod **) malloc (sizeof (LDAPMod *) * (array_length + 1));
  memset (ldapmods, 0, size);
  for (i = 0; i < array_length; i++)
    {
      sprintf (buf, "%d", i);
      status = napi_get_named_property (env, attrs, buf, &mod_handle);
      assert (status == napi_ok);

      status = napi_typeof (env, mod_handle, &valuetype);
      assert (status == napi_ok);
      if (valuetype != napi_object)
        {
          napi_throw_error (env, NULL, "Attribute must be an object");
          goto out;
        }

      status = napi_get_named_property (env, mod_handle, "op", &op);
      assert (status == napi_ok);
      status = napi_typeof (env, mod_handle, &valuetype);
      assert (status == napi_ok);
      if (valuetype != napi_string)
        {
          napi_throw_error (env, NULL, "op must be a string");
          goto out;
        }

      status = napi_get_named_property (env, mod_handle, "attr", &attr);
      assert (status == napi_ok);
      status = napi_typeof (env, attr, &valuetype);
      assert (status == napi_ok);
      if (valuetype != napi_string)
        {
          napi_throw_error (env, NULL, "attr must be a string");
          goto out;
        }

      status = napi_get_named_property (env, mod_handle, "vals", &vals);
      assert (status == napi_ok);
      status = napi_is_array (env, vals, &is_array);
      assert (status == napi_ok);
      if (!is_array)
        {
          napi_throw_error (env, NULL, "vals must be an array");
          goto out;
        }

      status = napi_get_value_string_utf8 (env, op, NULL, 0, &size);
      assert (status == napi_ok);
      mod_op = malloc (++size);
      status = napi_get_value_string_utf8 (env, op, mod_op, size, &size);
      assert (status == napi_ok);

      if (!strcmp (mod_op, "add"))
        ldapmods[i]->mod_op = LDAP_MOD_ADD;
      else if (!strcmp (mod_op, "delete"))
        ldapmods[i]->mod_op = LDAP_MOD_DELETE;
      else
        ldapmods[i]->mod_op = LDAP_MOD_REPLACE;

      free (mod_op);

      status = napi_get_value_string_utf8 (env, attr, NULL, 0, &size);
      assert (status == napi_ok);
      mod_type = malloc (++size);
      status = napi_get_value_string_utf8 (env, attr, mod_type, size, &size);
      assert (status == napi_ok);
      ldapmods[i]->mod_type = mod_type;

      status = napi_get_array_length (env, vals, &vals_length);
      assert (status == napi_ok);
      size = sizeof (char *) * (vals_length + 1);
      ldapmods[i]->mod_values = malloc (size);
      memset (ldapmods[i]->mod_values, 0, size);
      for (j = 0; j < vals_length; j++)
        {
          sprintf (buf, "%d", j);
          status = napi_get_named_property (env, vals, buf, &val);
          assert (status == napi_ok);
          status = napi_typeof (env, val, &valuetype);
          assert (status == napi_ok);
          if (valuetype != napi_string)
            {
              napi_throw_error (env, NULL, "value must be a string");
              goto out;
            }
          status = napi_get_value_string_utf8 (env, val, NULL, 0, &size);
          assert (status == napi_ok);
          mod_value = malloc (++size);
          status = napi_get_value_string_utf8 (env, val, mod_value,
                                               size, &size);
          assert (status == napi_ok);
          ldapmods[i]->mod_values[j] = mod_value;
        }
    }

  msgid = ldap_modify (ldap_cnx->ld, dn, ldapmods);
  status = napi_create_int32 (env, msgid, &ret);
  assert (status == napi_ok);

 out:
  free (dn);
  ldap_mods_free (ldapmods, 1);
  return ret;
}

static napi_value
cnx_rename (napi_env env, napi_callback_info info)
{
  struct ldap_cnx *ldap_cnx;
  char *dn = NULL, *newrdn = NULL;
  size_t argc = 2, size;
  int res;
  napi_value this, argv[argc], ret = NULL;
  napi_valuetype dn_type, newrdn_type;
  napi_status status;

  status = napi_get_cb_info (env, info, &argc, argv, &this, NULL);
  assert (status == napi_ok);

  status = napi_unwrap (env, this, (void **) &ldap_cnx);
  assert (status == napi_ok);

  if (argc != 2)
    {
      napi_throw_error (env, NULL, "This function requires two arguments");
      return NULL;
    }

  status = napi_typeof (env, argv[0], &dn_type);
  assert (status == napi_ok);
  if (dn_type != napi_string)
    {
      napi_throw_error (env, NULL, "The first argument needs to be a string");
      return NULL;
    }
  status = napi_typeof (env, argv[1], &newrdn_type);
  assert (status == napi_ok);
  if (newrdn_type != napi_string)
    {
      napi_throw_error (env, NULL, "The second argument needs to be a string");
      return NULL;
    }

  status = napi_get_value_string_utf8 (env, argv[0], NULL, 0, &size);
  assert (status == napi_ok);
  dn = malloc (++size);
  status = napi_get_value_string_utf8 (env, argv[0], dn, size, &size);
  assert (status == napi_ok);

  status = napi_get_value_string_utf8 (env, argv[1], NULL, 0, &size);
  assert (status == napi_ok);
  newrdn = malloc (++size);
  status = napi_get_value_string_utf8 (env, argv[1], newrdn, size, &size);
  assert (status == napi_ok);

  ldap_rename (ldap_cnx->ld, dn, newrdn, NULL, 1, NULL, NULL, &res);

  status = napi_create_int32 (env, res, &ret);
  assert (status == napi_ok);

  free (dn);
  free (newrdn);
  return ret;
}

static napi_value
cnx_abandon (napi_env env, napi_callback_info info)
{
  struct ldap_cnx *ldap_cnx;
  int msgid;
  size_t argc = 1, res;
  napi_value this, argv[argc], ret;
  napi_valuetype valuetype;
  napi_status status;

  status = napi_get_cb_info (env, info, &argc, argv, &this, NULL);
  assert (status == napi_ok);

  status = napi_unwrap (env, this, (void **) &ldap_cnx);
  assert (status == napi_ok);

  if (argc != 1)
    {
      napi_throw_error (env, NULL, "This function requires one argument");
      return NULL;
    }

  status = napi_typeof (env, argv[0], &valuetype);
  assert (status == napi_ok);
  if (valuetype != napi_number)
    {
      napi_throw_error (env, NULL, "message id needs to be a number");
      return NULL;
    }

  status = napi_get_value_int32 (env, argv[0], &msgid);
  assert (status == napi_ok);

  res = ldap_abandon (ldap_cnx->ld, msgid);
  status = napi_create_int32 (env, res, &ret);
  assert (status == napi_ok);

  return ret;
}

static napi_value
cnx_errorstring (napi_env env, napi_callback_info info)
{
  struct ldap_cnx *ldap_cnx;
  int err;
  napi_value this, message;
  napi_status status;

  status = napi_get_cb_info (env, info, 0, NULL, &this, NULL);
  assert (status == napi_ok);

  status = napi_unwrap (env, this, (void **) &ldap_cnx);
  assert (status == napi_ok);

  ldap_get_option (ldap_cnx->ld, LDAP_OPT_RESULT_CODE, &err);

  status = napi_create_string_utf8(env, ldap_err2string (err),
                                   NAPI_AUTO_LENGTH, &message);
  assert (status == napi_ok);

  return message;
}

static napi_value
cnx_errno (napi_env env, napi_callback_info info)
{
  struct ldap_cnx *ldap_cnx;
  int err;
  napi_value this, ret;
  napi_status status;

  status = napi_get_cb_info (env, info, 0, NULL, &this, NULL);
  assert (status == napi_ok);

  status = napi_unwrap (env, this, (void **) &ldap_cnx);
  assert (status == napi_ok);

  ldap_get_option (ldap_cnx->ld, LDAP_OPT_RESULT_CODE, &err);

  status = napi_create_int32 (env, err, &ret);
  assert (status == napi_ok);

  return ret;
}

static napi_value
cnx_fd (napi_env env, napi_callback_info info)
{
  struct ldap_cnx *ldap_cnx;
  napi_value this, ret;
  napi_status status;
  int fd;

  status = napi_get_cb_info (env, info, 0, NULL, &this, NULL);
  assert (status == napi_ok);

  status = napi_unwrap (env, this, (void **) &ldap_cnx);
  assert (status == napi_ok);

  ldap_get_option (ldap_cnx->ld, LDAP_OPT_DESC, &fd);

  status = napi_create_int32 (env, fd, &ret);
  assert (status == napi_ok);

  return ret;
}

static napi_value
cnx_install_tls (napi_env env, napi_callback_info info)
{
  struct ldap_cnx *ldap_cnx;
  int res;
  napi_value this, ret;
  napi_status status;

  status = napi_get_cb_info (env, info, 0, NULL, &this, NULL);
  assert (status == napi_ok);

  status = napi_unwrap (env, this, (void **) &ldap_cnx);
  assert (status == napi_ok);

  res = ldap_install_tls (ldap_cnx->ld);
  status = napi_create_int32 (env, res, &ret);
  assert (status == napi_ok);

  return ret;
}

static napi_value
cnx_start_tls (napi_env env, napi_callback_info info)
{
  struct ldap_cnx *ldap_cnx;
  int msgid;
  napi_value this, ret;
  napi_status status;

  status = napi_get_cb_info (env, info, 0, NULL, &this, NULL);
  assert (status == napi_ok);

  status = napi_unwrap (env, this, (void **) &ldap_cnx);
  assert (status == napi_ok);

  ldap_start_tls (ldap_cnx->ld, NULL, NULL, &msgid);
  status = napi_create_int32 (env, msgid, &ret);
  assert (status == napi_ok);

  return ret;
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
  return (!strcmp (attrname, "jpegPhoto") ||
	  !strcmp (attrname, "photo") ||
	  !strcmp (attrname, "personalSignature") ||
	  !strcmp (attrname, "userCertificate") ||
	  !strcmp (attrname, "cACertificate") ||
	  !strcmp (attrname, "authorityRevocationList") ||
	  !strcmp (attrname, "certificateRevocationList") ||
	  !strcmp (attrname, "deltaRevocationList") ||
	  !strcmp (attrname, "crossCertificatePair") ||
	  !strcmp (attrname, "x500UniqueIdentifier") ||
	  !strcmp (attrname, "audio") ||
	  !strcmp (attrname, "javaSerializedObject") ||
	  !strcmp (attrname, "thumbnailPhoto") ||
	  !strcmp (attrname, "thumbnailLogo") ||
	  !strcmp (attrname, "supportedAlgorithms") ||
	  !strcmp (attrname, "protocolInformation") ||
	  !strcmp (attrname, "objectGUID") ||
	  !strcmp (attrname, "objectSid") ||
	  strstr (attrname, ";binary"));
}

static napi_value
handle_result_events (napi_env env, struct ldap_cnx *ldap_cnx,
                      LDAPMessage *message)
{
  int entry_count, i, j, bin;
  struct berval **vals;
  LDAPMessage *entry;
  napi_status status;
  napi_value js_result_list, js_result, js_attr_vals, js_val, result_container,
    js_cookie_wrap, cookie_cons;
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
      status = napi_set_named_property (env, js_result_list, buf, js_result);
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

  return result_container;
}

static void
cnx_event (uv_poll_t *handle, int _status, int events)
{
  char *err_str = NULL;
  struct ldap_cnx *ldap_cnx = (struct ldap_cnx *) handle->data;
  LDAPMessage *message;
  napi_status status;
  napi_value errparam, js_message, js_cb, this, result_container;
  int err, msgtype, res, msgid;
  napi_env env = ldap_cnx->env;
  napi_handle_scope scope;
  napi_value argv[3];

  res = ldap_result (ldap_cnx->ld, LDAP_RES_ANY, LDAP_MSG_ALL,
                     &ldap_tv, &message);
  //printf ("event res %x\n", res);

  if (res == 0 || res == -1)
    {
      ldap_msgfree (message);
      return;
    }

  status = napi_open_handle_scope (env, &scope);
  assert (status == napi_ok);

  status = napi_get_reference_value (env, ldap_cnx->callback_ref, &js_cb);
  assert (status == napi_ok);

  status = napi_get_reference_value (env, ldap_cnx->this_ref, &this);
  assert (status == napi_ok);

  //printf ("pid %d\n", getpid ());

  err = ldap_result2error (ldap_cnx->ld, message, 0);

  if (err)
    {
      err_str = ldap_err2string (err);
      status = napi_create_string_utf8 (env, err_str, NAPI_AUTO_LENGTH,
                                        &errparam);
      assert (status == napi_ok);
    }
  else
    {
      status = napi_get_undefined (env, &errparam);
      assert (status == napi_ok);
    }

  switch (msgtype = ldap_msgtype (message))
    {
    case LDAP_RES_SEARCH_REFERENCE:
      break;
    case LDAP_RES_SEARCH_ENTRY:
    case LDAP_RES_SEARCH_RESULT:
      {
        result_container = handle_result_events (env, ldap_cnx, message);
        
        msgid = ldap_msgid (message);
        //printf ("msgid %d\n", msgid);
        status = napi_create_int32 (env, msgid, &js_message);
        assert (status == napi_ok);
        
        argv[0] = errparam;
        argv[1] = js_message;
        argv[2] = result_container;

        //cnx_log (env, result_container);

        // TODO: if you get status == napi_pending_exception then console.erro
        // TODO: the result of napi_get_and_clear_last_exception (env, &error);

        status = napi_make_callback (env, ldap_cnx->async_context, this,
                                     js_cb, 3, argv, NULL);
        assert (status == napi_ok);
        break;
      }
    case LDAP_RES_BIND:
      {
        msgid = ldap_msgid (message);
        //printf ("msgid bind %d\n", msgid);

        if (err == LDAP_SASL_BIND_IN_PROGRESS)
          {
            // TODO: we don't support sasl yet
          }

        status = napi_create_int64 (env, msgid, &js_message);
        assert (status == napi_ok);
        argv[0] = errparam;
        argv[1] = js_message;
        status = napi_make_callback (env, ldap_cnx->async_context, this,
                                     js_cb, 2, argv, NULL);
        assert (status == napi_ok);

        // TODO: if you get status == napi_pending_exception then console.erro
        // TODO: the result of napi_get_and_clear_last_exception (env, &error);

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
        argv[0] = errparam;
        argv[1] = js_message;
        status = napi_make_callback (env, ldap_cnx->async_context, this,
                                     js_cb, 2, argv, NULL);
        assert (status == napi_ok);

        // TODO: if you get status == napi_pending_exception then console.erro
        // TODO: the result of napi_get_and_clear_last_exception (env, &error);

        break;
      }
    default:
      {
        //emit an error
        // Nan::ThrowError("Unrecognized packet");
      }
    }

  ldap_msgfree (message);

  status = napi_close_handle_scope (ldap_cnx->env, scope);
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
  napi_value reconnect_callback, this;

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

  status = napi_get_reference_value (ldap_cnx->env,
                                     ldap_cnx->reconnect_callback_ref,
                                     &reconnect_callback);
  assert (status == napi_ok);
  status = napi_get_reference_value (ldap_cnx->env,
                                     ldap_cnx->this_ref,
                                     &this);
  assert (status == napi_ok);

  status = napi_make_callback (ldap_cnx->env, ldap_cnx->async_context, this,
                               reconnect_callback, 0, NULL, NULL);
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
  /*
  status = napi_call_threadsafe_function (lc->disconnect_callback,
					  NULL, napi_tsfn_blocking);
  */
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
  napi_value this, cnx_cons, resource_name;
  napi_valuetype valuetype;
  int32_t timeout, debug, verifycert, referrals;
  char *url;
  struct ldap_cnx *ldap_cnx;
  int ver = LDAP_VERSION3;
  //int zero = 0;

  struct
  {
    napi_value callback, reconnect_callback, disconnect_callback;
    napi_value url, timeout, debug, verifycert, referrals;
  } args;

  assert ((void *)&args.callback == (void *)&args);
  memset (&args, 0, sizeof (args));

  status = napi_get_cb_info (env, info, &argc, (napi_value *)&args, &this, NULL);
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

  status = napi_typeof (env, args.callback, &valuetype);
  assert (status == napi_ok);
  if (valuetype != napi_function)
    {
      napi_throw_error (env, NULL, "Callback is not a function");
      return NULL;
    }

  status = napi_typeof (env, args.reconnect_callback, &valuetype);
  assert (status == napi_ok);
  if (valuetype != napi_function)
    {
      napi_throw_error (env, NULL, "reconnect callback is not a function");
      return NULL;
    }

  status = napi_typeof (env, args.disconnect_callback, &valuetype);
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

  if (napi_get_value_int32 (env, args.timeout, &timeout) != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to parse timeout");
      return NULL;
    }

  if (napi_get_value_int32 (env, args.debug, &debug) != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to parse debug level");
      return NULL;
    }

  if (napi_get_value_int32 (env, args.verifycert, &verifycert) != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to parse verify cert");
      return NULL;
    }

  if (napi_get_value_int32 (env, args.referrals, &referrals) != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to parse referrls");
      return NULL;
    }

  if (napi_get_value_string_utf8 (env, args.url, NULL, 0, &size) != napi_ok)
    {
      napi_throw_error (env, NULL, "Failed to parse url");
      return NULL;
    }
  url = malloc (++size);
  if (napi_get_value_string_utf8 (env, args.url, url, size, &size) != napi_ok)
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

  // NOTE: don't need to use these as everything is in the same thread
  status = napi_create_string_utf8 (env, "eventloop", NAPI_AUTO_LENGTH,
                                    &resource_name);
  assert (status == napi_ok);
  // TODO: destroy this
  status = napi_async_init (env, NULL, resource_name,
                            &ldap_cnx->async_context);
  assert (status == napi_ok);

  ldap_cnx->env = env;

  // TODO: dereference these!!!
  status = napi_create_reference (env, this, 1, &ldap_cnx->this_ref);
  assert (status == napi_ok);
  status = napi_create_reference (env, args.reconnect_callback, 1,
                                   &ldap_cnx->reconnect_callback_ref);
  assert (status == napi_ok);
  status = napi_create_reference (env, args.disconnect_callback, 1,
                                   &ldap_cnx->disconnect_callback_ref);
  assert (status == napi_ok);
  status = napi_create_reference (env, args.callback, 1,
                                   &ldap_cnx->callback_ref);
  assert (status == napi_ok);

  status = napi_wrap (env, this, ldap_cnx, cnx_finalise, NULL, NULL);
  assert (status == napi_ok);

  if (ldap_initialize (&(ldap_cnx->ld), url) != LDAP_SUCCESS)
    {
      napi_throw_error (env, NULL, "Error intializing ldap");
      free (url);
      return NULL;
    }


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
     { "search", 0, cnx_search, 0, 0, 0, napi_default, 0 },
     { "delete", 0, cnx_delete, 0, 0, 0, napi_default, 0 },
     { "bind", 0, cnx_bind, 0, 0, 0, napi_default, 0 },
     { "add", 0, cnx_add, 0, 0, 0, napi_default, 0 },
     { "modify", 0, cnx_modify, 0, 0, 0, napi_default, 0 },
     { "rename", 0, cnx_rename, 0, 0, 0, napi_default, 0 },
     { "abandon", 0, cnx_abandon, 0, 0, 0, napi_default, 0 },
     { "errorstring", 0, cnx_errorstring, 0, 0, 0, napi_default, 0 },
     { "close", 0, cnx_close, 0, 0, 0, napi_default, 0 },
     { "errno", 0, cnx_errno, 0, 0, 0, napi_default, 0 },
     { "fd", 0, cnx_fd, 0, 0, 0, napi_default, 0 },
     { "installtls", 0, cnx_install_tls, 0, 0, 0, napi_default, 0 },
     { "starttls", 0, cnx_start_tls, 0, 0, 0, napi_default, 0 },
     { "checktls", 0, cnx_check_tls, 0, 0, 0, napi_default, 0 }
    };

  status = napi_define_class (env, cnx_name, NAPI_AUTO_LENGTH,
			      cnx_constructor, NULL, 14,
			      properties, &cnx_cons);
  assert (status == napi_ok);

  status = napi_create_reference (env, cnx_cons, 1, &cnx_cons_ref);
  assert (status == napi_ok);

  status =napi_set_named_property (env, exports, cnx_name, cnx_cons);
  assert (status == napi_ok);
}
