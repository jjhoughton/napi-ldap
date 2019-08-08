#include <node_api.h>

static napi_value
cnx_init (napi_env env, napi_callback_info info)
{

  return NULL;
}

static napi_value
init (napi_env env, napi_value exports)
{
  napi_value cnx_fn;

  if (napi_create_function (env, NULL, 0, cnx_init, NULL, &cnx_fn) != napi_ok)
    {
      napi_throw_error (env, NULL, "Unable to wrap native cnx_init function");
      return exports;
    }

  if (napi_set_named_property (env, exports, "LDAPCnx", cnx_fn) != napi_ok)
    {
      napi_throw_error (env, NULL, "Unable to populate exports with cxn_fn");
      return exports;
    }

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init);
