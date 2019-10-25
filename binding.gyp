{
  "targets": [
    {
      "target_name": "napi_ldap",
      "sources": [ "./main.c", "./cnx.c", "./cookie.c", "./sasl.c" ],
      "include_dirs": ["/usr/local/include"],
      "libraries": ["-lldap"],
      "defines": ["LDAP_DEPRECATED"],
      "ldflags": ["-L/usr/local/lib"],
      "cflags": ["-Wall", "-Wextra"]
    }
  ]
}
