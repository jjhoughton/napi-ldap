{
  "variables": {
    "BUILD_OPENLDAP%": "<!(echo ${BUILD_OPENLDAP:-0})",
    "NODE_VERSION": "<!(node --version | cut -d. -f1 | cut -dv -f2)",
    "SASL": "<!(test -f /usr/include/sasl/sasl.h && echo y || echo n)"
  },
  "targets": [
    {
      "target_name": "napi_ldap",
      "sources": [ "./main.c", "./cnx.c", "./cookie.c" ],
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
	    "-lresolv"
	  ],
	  "include_dirs": ["deps/openldap-2.4.50/include"]
	},
	{
          "conditions": [[
            'OS=="linux" and NODE_VERSION > 9', {
              "libraries": [
                "../deps/libldap.a", "../deps/liblber.a", "-lresolv"
              ],
              "include_dirs": [ "deps/include" ]
            }, {
              "libraries": [ "-lldap" ]
            }
          ]]
	}
      ], [
        "SASL==\"y\"", {
          "libraries": [ "-lsasl2" ],
          "sources": [ "./sasl.c" ]
        }, {
          "sources": [ "./saslx.c" ]
        }
      ]]
    }
  ],
  "conditions": [
    [
      "OS==\"mac\"",
      {
        "link_settings": {
          "libraries": [
            "-lldap"
          ]
        },
        "xcode_settings": {
          'OTHER_LDFLAGS': [
            '-L/usr/local/lib'
          ]
        }
      }
    ]
  ]

}
