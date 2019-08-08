#include <node_api.h>

#include <assert.h>
#include <stdio.h>

#include <ldap.h>

// NOTE: really not sure about this, it doesn't look like init is called
// NOTE: mutliple times so i think it's safe.
static napi_ref cnx_cons_ref;

static const char cnx_name[] = "LDAPCnx";

struct ldap_cnx {
  LDAP *ld;
  ldap_conncb *ldap_callback;
  const char *sasl_mechanism;
};

// TODO: bind, search, close

static napi_value
cnx_constructor (napi_env env, napi_callback_info info)
{
  napi_status status;
  bool is_instance;
  size_t argc = 0;
  napi_value argv[argc];
  napi_value _this, cnx_cons;
  
  status = napi_get_cb_info (env, info, &argc, argv, &_this, NULL);
  assert (status == napi_ok);

  status = napi_get_reference_value (env, cnx_cons_ref, &cnx_cons);
  assert (status == napi_ok);

  status = napi_instanceof (env, _this, cnx_cons, &is_instance);
  assert (status == napi_ok);

  if (!is_instance)
    {
      napi_throw_error (env, NULL,
			"This is supposed to be a class and as such "
			"you need to declare it as a new instance.");
      return NULL;
    }

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
