#include <node_api.h>
#include <ldap.h>
#include <uv.h>

#ifndef __CNX_H__
#define __CNX_H__

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

#endif