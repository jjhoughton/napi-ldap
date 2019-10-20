#include <node_api.h>

void cnx_init (napi_env env, napi_value exports);
void cookie_init (napi_env env, napi_value exports);

static napi_value
init (napi_env env, napi_value exports)
{
  cnx_init (env, exports);
  cookie_init (env, exports);

  return exports;
}

NAPI_MODULE (NODE_GYP_MODULE_NAME, init);
