{
  "variables": {
    "BUILD_OPENLDAP%": "<!(echo ${BUILD_OPENLDAP:-0})",
    "NODE_VERSION": "<!(node --version | cut -d. -f1 | cut -dv -f2)",
    "SASL": "<!(test -f /usr/include/sasl/sasl.h && echo y || echo n)",
    "REDHAT_RELEASE": "<!(test ! -e /etc/redhat-release || cat /etc/redhat-release | cut -d' ' -f3 | cut -d'.' -f 1)"
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
	    "-lresolv",
	    "-lsasl2"
	  ],
	  "include_dirs": ["deps/openldap-2.4.50/include"]
	},
	{
          "conditions": [[
            'NODE_VERSION > 9', {
              "conditions": [[
                'OS=="linux"', {
		  "conditions": [[
                    "REDHAT_RELEASE == 6", {
                      "libraries": [
		        "../deps/RHEL6/libldap.a", "../deps/RHEL6/liblber.a"
                      ]
                    }, {
                      "libraries": [
                        "../deps/RHEL7/libldap.a", "../deps/RHEL7/liblber.a"
                      ]
                    }
		  ]]
                }, {
                  "libraries": [ "../deps/OSX/libldap.a", "../deps/OSX/liblber.a" ]
                }
              ]],
              "libraries": [ "-lresolv", "-lsasl2" ],
              "include_dirs": [ "deps/include" ]
            }, {
              "libraries": [ "-lldap" ]
            }
          ]]
	}
      ], [
        "SASL==\"y\"", {
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
