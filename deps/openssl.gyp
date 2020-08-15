{
  "targets": [{
    "target_name": "openssl",
    "type": "none",
    "actions": [{
      "action_name": "download",
      "inputs": [],
      "outputs": [
	"openssl-1.1.1g.tar.gz"
      ],
      "action": [
	"curl", "-o", "openssl-1.1.1g.tar.gz", "http://artfiles.org/openssl.org/source/openssl-1.1.1g.tar.gz"
      ]
    }, {
      "action_name": "build",
      "inputs": [],
      "outputs": [
	"openssl-1.1.1g/libcrypto.so.1.1",
	"openssl-1.1.1g/libssl.so.1.1",
      ],
      "action": [
	"./build_openssl.sh", '<(node_root_dir)/include/node'
      ]
    }]
  }]
}
