{
  "targets": [{
    "target_name": "openldap",
    "dependencies": [
      "openssl.gyp:openssl"
    ],
    "type": "none",
    "actions": [{
      "action_name": "download",
      "inputs": [],
      "outputs": [
	"openldap-2.4.50.tgz"
      ],
      "action": [
	"curl", "-o", "openldap-2.4.50.tgz", "http://repository.linagora.org/OpenLDAP/openldap-release/openldap-2.4.50.tgz"
      ]
    }, {
      "action_name": "build",
      "inputs": [],
      "outputs": [
	"openldap-2.4.50/libraries/libldap/.libs/libldap.a",
	"openldap-2.4.50/libraries/liblber/.libs/liblber.a",
      ],
      "action": [
	"./build_openldap.sh", '<(node_root_dir)/include/node'
      ]
    }]
  }]
}
