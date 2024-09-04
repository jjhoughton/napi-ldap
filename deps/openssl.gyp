{
  "targets": [{
    "target_name": "openssl",
    "type": "none",
    "actions": [{
      "action_name": "download",
      "inputs": [],
      "outputs": [
	"openssl-1.1.1k.tar.gz"
      ],
      "action": [
	"curl", "-o", "openssl-1.1.1k.tar.gz", "https://openssl.org/source/old/1.1.1/openssl-1.1.1k.tar.gz"
      ]
    }, {
      "action_name": "build",
      "inputs": [],
      "outputs": [
	"openssl-1.1.1k/libcrypto.so.1.1",
	"openssl-1.1.1k/libssl.so.1.1",
      ],
      "action": [
	"./build_openssl.sh", '<(node_root_dir)/include/node'
      ]
    }]
  }]
}
