/*jshint globalstrict:true, node:true, trailing:true, mocha:true unused:true */

"use strict";

var LDAP = require("../");
var assert = require("assert");
var fs = require("fs");
var ldap;

describe("LDAPS", function() {
  it("Should fail TLS on cert validation", function(done) {
    this.timeout(10000);
    ldap = new LDAP(
      {
        uri: "ldaps://localhost:1235",
        base: "dc=sample,dc=com",
        attrs: "*"
      },
      function(err) {
        assert.ifError(err ? null : true);
        ldap.close();
        done();
      }
    );
  });
  it("Should connect", function(done) {
    this.timeout(10000);
    ldap = new LDAP(
      {
        uri: "ldaps://localhost:1235",
        base: "dc=sample,dc=com",
        attrs: "*",
        validatecert: false
      },
      function(err) {
        assert.ifError(err);
        done();
      }
    );
  });
  it("Should search via TLS", function(done) {
    ldap.search(
      {
        filter: "(cn=babs)",
        scope: LDAP.SUBTREE
      },
      function(err, res) {
        assert.ifError(err);
        assert.equal(res.length, 1);
        assert.equal(res[0].sn[0], "Jensen");
        assert.equal(res[0].dn, "cn=Babs,dc=sample,dc=com");
        done();
      }
    );
  });
  it("Should findandbind()", function(done) {
    ldap.findandbind(
      {
        base: "dc=sample,dc=com",
        filter: "(cn=Charlie)",
        attrs: "*",
        password: "foobarbaz"
      },
      function(err, data) {
        assert.ifError(err);
        done();
      }
    );
  });
  it("Should fail findandbind()", function(done) {
    ldap.findandbind(
      {
        base: "dc=sample,dc=com",
        filter: "(cn=Charlie)",
        attrs: "cn",
        password: "foobarbax"
      },
      function(err, data) {
        assert.ifError(err ? null : true);
        done();
      }
    );
  });
  it("Should still have TLS", function() {
    assert(ldap.tlsactive());
    ldap.close();
    ldap = null;
  });
  /**
   * Unfortunately openssl now validates the hostname is correct. This means
   * that these tests now break. I'm not sure how to fix this o skipping for
   * now.
   */
  it.skip("Should validate cert", function(done) {
    this.timeout(10000);
    ldap = new LDAP(
      {
        uri: "ldaps://localhost:1235",
        base: "dc=sample,dc=com",
        attrs: "*",
        timeout: 5e3,
        ntimeout: 5e3,
        validatecert: true,
        ca: "test/certs/ca.crt"
      },
      function(err) {
        assert.ifError(err);
        assert(ldap.tlsactive());
        ldap.search(
          {
            filter: "(cn=babs)",
            scope: LDAP.SUBTREE
          },
          function(err, res) {
            assert.ifError(err);
            assert.equal(res.length, 1);
            assert.equal(res[0].sn[0], "Jensen");
            assert.equal(res[0].dn, "cn=Babs,dc=sample,dc=com");
            ldap.close();
            ldap = null;
            done();
          }
        );
      }
    );
  });
  it("Should not validate cert", function(done) {
    this.timeout(10000);
    ldap = new LDAP(
      {
        uri: "ldaps://localhost:1235",
        base: "dc=sample,dc=com",
        attrs: "*",
        timeout: 5e3,
        ntimeout: 5e3,
        validatecert: true,
        ca: "test/certs/wrongca.crt"
      },
      function(err) {
        assert.ok(err instanceof Error);
        ldap.close();
        done();
      }
    );
  });
});
