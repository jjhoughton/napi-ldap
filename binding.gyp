{
  "variables": {
    "BUILD_OPENLDAP%": "<!(echo ${BUILD_OPENLDAP:-0})"
  },
  "targets": [
    {
      "target_name": "napi_ldap",
      "sources": [ "./main.c", "./cnx.c", "./cookie.c", "./sasl.c" ],
      "include_dirs": ["/usr/local/include"],
      "defines": ["LDAP_DEPRECATED"],
      "ldflags": ["-L/usr/local/lib"],
      "cflags": ["-Wall", "-Wextra"],
      "conditions": [[
        "<(BUILD_OPENLDAP)==1",
        {
          "dependencies": [
            "deps/openldap.gyp:openldap"
          ],
          "libraries": [
            "../deps/openldap-2.4.50/libraries/libldap/libldap.a",
            "../deps/openldap-2.4.50/libraries/liblber/liblber.a",
            "-lresolv",
            "-lsasl2"
          ],
          "include_dirs": ["deps/openldap-2.4.50/include"]
        },
        {
          "libraries": ["-lldap"],
        }
      ]]
    }
  ]
}
