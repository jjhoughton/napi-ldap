{
  "targets": [
    {
      "target_name": "napi_ldap",
      "sources": [ "./main.c" ],
      "include_dirs": ["/usr/local/include"],
      "libraries": ["-lldap"],
      "defines": ["LDAP_DEPRICATED"],
      "ldflags": ["-L/usr/local/lib"],
      "cflags": ["-Wall"]
    }
  ]
}
