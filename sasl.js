var LDAP = require(".");

var assert = require("assert");

var ldap;

var uri = process.env.TEST_SASL_URI || "ldap://localhost:1234";

ldap = new LDAP({ uri: uri }, function(err) {
  console.log("connect");
  assert.ifError(err);
  ldap.saslbind(
    {
      mechanism: "PLAIN",
      user: "test_user",
      password: "bad password",
      securityproperties: "none"
    },
    function(err) {
      console.log("!!!");
      assert.ifError(!err);
      done();
    }
  );
});
