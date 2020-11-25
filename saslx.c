#include <node_api.h>
#include <ldap.h>
#include "cnx.h"

napi_value
sasl_bind (napi_env env, napi_callback_info info)
{
  napi_throw_error (env, NULL, "LDAP module was not built with SASL support");
  return NULL;
}

int
sasl_bind_next (LDAPMessage ** message, struct ldap_cnx *ldap_cnx)
{
  return -1;
}
