#include <node_api.h>
#include <sasl/sasl.h>
#include <assert.h>
#include <stdlib.h>
#include "cnx.h"

struct sasl_defaults
{
  char *mechanism;
  char *user;
  char *password;
  char *realm;
  char *proxy_user;
  char *sec_props;
};

static int
sasl_callback (LDAP * ldap_cnx, unsigned flags, void *_defaults, void *in)
{
  struct sasl_defaults *defaults = (struct sasl_defaults *) _defaults;
  sasl_interact_t *interact = (sasl_interact_t *) in;
  const char *dflt = interact->defresult;

  while (interact->id != SASL_CB_LIST_END)
    {
      switch (interact->id)
	{
	case SASL_CB_AUTHNAME:
	  dflt = defaults->user;
	  break;
	case SASL_CB_PASS:
	  dflt = defaults->password;
	  break;
	case SASL_CB_GETREALM:
	  dflt = defaults->realm;
	  break;
	case SASL_CB_USER:
	  dflt = defaults->proxy_user;
	  break;
	}

      interact->result = (dflt && *dflt) ? dflt : "";
      interact->len = strlen ((const char *) interact->result);
      ++interact;
    }

  if (defaults)
    {
      if (defaults->mechanism)
	free (defaults->mechanism);
      if (defaults->user)
	free (defaults->user);
      if (defaults->password)
	free (defaults->password);
      if (defaults->realm)
	free (defaults->realm);
      if (defaults->proxy_user)
	free (defaults->proxy_user);
      if (defaults->sec_props)
	free (defaults->sec_props);

      free (defaults);
    }

  return LDAP_SUCCESS;
}

napi_value
sasl_bind (napi_env env, napi_callback_info info)
{
  napi_status status;
  size_t argc = 6, size;
  napi_value this, argv[argc], js_ret;
  napi_valuetype vt;

  int msgid, res;
  LDAPControl **sctrlsp = NULL;
  LDAPMessage *message = NULL;

  struct ldap_cnx *ldap_cnx;
  struct sasl_defaults *defaults;

  status = napi_get_cb_info (env, info, &argc, argv, &this, NULL);
  assert (status == napi_ok);

  status = napi_unwrap (env, this, (void **) &ldap_cnx);
  assert (status == napi_ok);

  if (argc != 6)
    {
      napi_throw_error (env, NULL, "This function requires six arguments");
      return NULL;
    }

  if (ldap_cnx->ld == NULL)
    {
      napi_throw_error (env, NULL,
			"LDAP connection has not been established");
      return NULL;
    }

  defaults = malloc (sizeof (struct sasl_defaults));

  status = napi_typeof (env, argv[0], &vt);
  assert (status == napi_ok);

  if (vt != napi_string)
    defaults->mechanism = NULL;
  else
    {
      status = napi_get_value_string_utf8 (env, argv[0], NULL, 0, &size);
      assert (status == napi_ok);
      defaults->mechanism = malloc (++size);
      status = napi_get_value_string_utf8 (env, argv[0], defaults->mechanism,
					   size, &size);
      assert (status == napi_ok);
    }

  status = napi_typeof (env, argv[1], &vt);
  assert (status == napi_ok);

  if (vt != napi_string)
    defaults->user = NULL;
  else
    {
      status = napi_get_value_string_utf8 (env, argv[1], NULL, 0, &size);
      assert (status == napi_ok);
      defaults->user = malloc (++size);
      status = napi_get_value_string_utf8 (env, argv[1], defaults->user,
					   size, &size);
      assert (status == napi_ok);
    }


  status = napi_typeof (env, argv[2], &vt);
  assert (status == napi_ok);

  if (vt != napi_string)
    defaults->password = NULL;
  else
    {
      status = napi_get_value_string_utf8 (env, argv[2], NULL, 0, &size);
      assert (status == napi_ok);
      defaults->password = malloc (++size);
      status = napi_get_value_string_utf8 (env, argv[2], defaults->password,
					   size, &size);
      assert (status == napi_ok);
    }

  status = napi_typeof (env, argv[3], &vt);
  assert (status == napi_ok);

  if (vt != napi_string)
    defaults->realm = NULL;
  else
    {
      status = napi_get_value_string_utf8 (env, argv[3], NULL, 0, &size);
      assert (status == napi_ok);
      defaults->realm = malloc (++size);
      status = napi_get_value_string_utf8 (env, argv[3], defaults->realm,
					   size, &size);
      assert (status == napi_ok);
    }

  status = napi_typeof (env, argv[4], &vt);
  assert (status == napi_ok);

  if (vt != napi_string)
    defaults->proxy_user = NULL;
  else
    {
      status = napi_get_value_string_utf8 (env, argv[4], NULL, 0, &size);
      assert (status == napi_ok);
      defaults->proxy_user = malloc (++size);
      status = napi_get_value_string_utf8 (env, argv[4], defaults->proxy_user,
					   size, &size);
      assert (status == napi_ok);
    }

  status = napi_typeof (env, argv[5], &vt);
  assert (status == napi_ok);

  if (vt != napi_string)
    defaults->sec_props = NULL;
  else
    {
      status = napi_get_value_string_utf8 (env, argv[5], NULL, 0, &size);
      assert (status == napi_ok);
      defaults->sec_props = malloc (++size);
      status = napi_get_value_string_utf8 (env, argv[5], defaults->sec_props,
					   size, &size);
      assert (status == napi_ok);
    }

  if (defaults->sec_props)
    {
      res = ldap_set_option (ldap_cnx->ld, LDAP_OPT_X_SASL_SECPROPS,
			     defaults->sec_props);
      if (res != LDAP_SUCCESS)
	{
	  napi_throw_error (env, NULL, ldap_err2string (res));
	  return NULL;
	}
    }

  ldap_cnx->sasl_mechanism = NULL;

  res = ldap_sasl_interactive_bind (ldap_cnx->ld, NULL, defaults->mechanism,
				    sctrlsp, NULL, LDAP_SASL_QUIET,
				    sasl_callback, defaults,
				    message, &ldap_cnx->sasl_mechanism,
				    &msgid);

  if (res != LDAP_SASL_BIND_IN_PROGRESS && res != LDAP_SUCCESS)
    {
      napi_throw_error (env, NULL, ldap_err2string (res));
      return NULL;
    }

  status = napi_create_int32 (env, msgid, &js_ret);
  assert (status == napi_ok);
  return js_ret;
}

int
sasl_bind_next (LDAPMessage ** message, struct ldap_cnx *ldap_cnx)
{
  LDAPControl **sctrlsp = NULL;
  int res;
  int msgid;
  while (true)
    {
      res = ldap_sasl_interactive_bind (ldap_cnx->ld, NULL, NULL,
					sctrlsp, NULL, LDAP_SASL_QUIET,
					NULL, NULL, *message,
					&ldap_cnx->sasl_mechanism, &msgid);

      if (res != LDAP_SASL_BIND_IN_PROGRESS)
	break;

      ldap_msgfree (*message);

      if (ldap_result (ldap_cnx->ld, msgid, LDAP_MSG_ALL, NULL, message) ==
	  -1)
	{
	  ldap_get_option (ldap_cnx->ld, LDAP_OPT_RESULT_CODE, &res);
	  break;
	}
    }

  return res;
}
