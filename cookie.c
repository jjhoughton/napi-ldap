#include <node_api.h>

#include <stdlib.h>
#include <assert.h>

#include <ldap.h>

static const char cookie_name[] = "Cookie";

// NOTE: really not sure about this, it doesn't look like init is called
// NOTE: mutliple times so i think it's safe.
napi_ref cookie_cons_ref;

static void
cookie_finalise (napi_env env, void *data, void *hint)
{
  struct berval **berval = (struct berval **)data;
  if (berval == NULL) return;
  if (*berval == NULL)
    {
      free (berval);
      return;
    }
  ber_bvfree (*berval);
  free (data);
}

static napi_value
set_from_string (napi_env env, napi_callback_info info)
{
  napi_status status;
  size_t argc = 1;
  napi_value arg, this;
  napi_valuetype valuetype;
  struct berval **cookie;

  status = napi_get_cb_info (env, info, &argc, &arg, &this, NULL);
  assert (status == napi_ok);

  if (argc < 1)
    {
      napi_throw_error (env, NULL, "This function requires one argument");
      return NULL;
    }

  status = napi_typeof (env, arg, &valuetype);
  assert (status == napi_ok);
  if (valuetype != napi_string)
    {
      napi_throw_error (env, NULL, "Argument has to be of type string");
      return NULL;
    }

  status = napi_unwrap (env, arg, (void **)&cookie);
  assert (status == napi_ok);

  if (*cookie == NULL)
    *cookie = malloc (sizeof (struct berval));
  else
    free ((*cookie)->bv_val);

  status = napi_get_value_string_utf8 (env, arg, NULL,
                                       0, &(*cookie)->bv_len);
  assert (status == napi_ok);
  (*cookie)->bv_val = malloc ((*cookie)->bv_len + 1);
  status = napi_get_value_string_utf8 (env, arg, (*cookie)->bv_val,
                                       (*cookie)->bv_len + 1,
                                       &(*cookie)->bv_len);
  assert (status == napi_ok);

  return this;
}

static napi_value
cookie_constructor (napi_env env, napi_callback_info info)
{
  napi_status status;
  napi_value this, cookie_cons;
  size_t argc = 1;
  napi_value argv[argc];
  bool is_instance;
  struct berval **cookie = NULL;
  napi_valuetype valuetype;

  status = napi_get_cb_info (env, info, &argc, argv, &this, NULL);
  assert (status == napi_ok);

  status = napi_get_reference_value (env, cookie_cons_ref, &cookie_cons);
  assert (status == napi_ok);

  status = napi_instanceof (env, this, cookie_cons, &is_instance);
  assert (status == napi_ok);

  if (!is_instance)
    {
      napi_throw_error (env, NULL,
			"This is supposed to be a class and as such "
			"you need to declare it as a new instance.");
      return NULL;
    }

  if (argc > 1)
    {
      napi_throw_error (env, NULL, "This class requires 1 or 0 arguments");
      return NULL;
    }

  if (argc == 1)
    {
      status = napi_typeof (env, argv[0], &valuetype);
      assert (status == napi_ok);
      if (valuetype != napi_string)
	{
	  napi_throw_error (env, NULL, "Argument has to be of type string");
	  return NULL;
	}
    }

  cookie = malloc (sizeof (void *));
  *cookie = NULL;

  status = napi_wrap (env, this, cookie, cookie_finalise, NULL, NULL);
  assert (status == napi_ok);

  if (argc == 1)
    set_from_string (env, info);

  return NULL;
}

static napi_value
to_string (napi_env env, napi_callback_info info)
{
  size_t argc = 0;
  napi_value this, ret;
  napi_status status;
  struct berval **cookie;

  status = napi_get_cb_info (env, info, &argc, NULL, &this, NULL);
  assert (status == napi_ok);

  status = napi_unwrap (env, this, (void **)&cookie);
  assert (status == napi_ok);

  if (*cookie == NULL) return NULL;

  status = napi_create_string_utf8 (env, (*cookie)->bv_val,
				    (*cookie)->bv_len, &ret);
  assert (status == napi_ok);
  return ret;
}

void
cookie_init (napi_env env, napi_value exports)
{
  napi_value cookie_cons;
  napi_status status;
  napi_property_descriptor properties[] =
    {
     { "toString", 0, to_string, 0, 0, 0, napi_default, 0 },
     { "setFromString", 0, set_from_string, 0, 0, 0, napi_default, 0 }
    };

  status = napi_define_class (env, cookie_name, NAPI_AUTO_LENGTH,
			      cookie_constructor, NULL, 2,
			      properties, &cookie_cons);
  assert (status == napi_ok);

  status = napi_create_reference (env, cookie_cons, 1, &cookie_cons_ref);
  assert (status == napi_ok);

  status = napi_set_named_property (env, exports, cookie_name, cookie_cons);
  assert (status == napi_ok);
}
