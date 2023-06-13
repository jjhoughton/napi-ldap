/*jshint globalstrict:true, node:true, trailing:true, mocha:true unused:true */

"use strict";

var LDAP = require("../");
var assert = require("assert");
var fs = require("fs");
var child_process = require('child_process');
var ldap;

var ldapConfig = {
  schema: "ldaps://",
  host: "localhost:1235"
};
var uri = ldapConfig.schema + ldapConfig.host;

describe("Issues", function() {
  it("Should fix Issue #80", function(done) {
    ldap = new LDAP(
      {
        uri: uri,
        validatecert: LDAP.LDAP_OPT_X_TLS_NEVER
      },
      function(err) {
        assert.ifError(err);
        done();
      }
    );
  });
  it("Should search after Issue #80", function(done) {
    ldap.search(
      {
        base: "dc=sample,dc=com",
        filter: "(objectClass=*)"
      },
      function(err, res) {
        assert.ifError(err);
        assert.equal(res.length, 6);
        ldap.close();
        done();
      }
    );
  });
  it("Connect context should be ldap object - Issue #84", function(done) {
    ldap = new LDAP({
      uri: uri,
      validatecert: LDAP.LDAP_OPT_X_TLS_NEVER,
      connect: function() {
        assert(typeof this.bind === "function");
        setTimeout(function() {
          ldap.bind(
            {
              binddn: "cn=Manager,dc=sample,dc=com",
              password: "secret"
            },
            function(err) {
              assert.ifError(err);
              done();
            }
          );
        }, 10);
      }
    });
  });
  it("Base scope should work - Issue #81", function(done) {
    assert.equal(ldap.DEFAULT, 4, "ldap.DEFAULT const is not zero");
    assert.equal(LDAP.DEFAULT, 4, "LDAP.DEFAULT const is not zero");
    assert.equal(LDAP.LDAP_OPT_X_TLS_TRY, 4);
    ldap.search(
      {
        base: "dc=sample,dc=com",
        scope: ldap.BASE,
        filter: "(objectClass=*)"
      },
      function(err, res) {
        assert.equal(res.length, 1, "Unexpected number of results");
        ldap.search(
          {
            base: "dc=sample,dc=com",
            scope: LDAP.SUBTREE,
            filter: "(objectClass=*)"
          },
          function(err, res) {
            assert.ifError(err);
            assert.equal(res.length, 6, "Unexpected number of results");
            ldap.search(
              {
                base: "dc=sample,dc=com",
                scope: LDAP.ONELEVEL,
                filter: "(objectClass=*)"
              },
              function(err, res) {
                assert.ifError(err);
                assert.equal(res.length, 4, "Unexpected number of results");
                ldap.close();
                done();
              }
            );
          }
        );
      }
    );
  });
  it("should fix jjhoughton/napi-ldap #10", async function() {
    const port = 12345;

    function start_ldap_server() {
      return new Promise((resolve, reject) => {
        const server = child_process.fork(
          `${__dirname}/mock_ldap_server/mock_ldap_server.js`,
          [ port, 'dc=sample,dc=com' ]);
        server.on('message', () => { resolve(server); });
        server.on('exit', (code) => { reject(new Error(`ldap server exited with code ${code}`)); });
      });
    }

    function stop_ldap_server(server, client) {
      return new Promise((resolve, reject) => {
        client.options.disconnect = function() { resolve(); };
        server.kill();
      });
    }

    function bind(ldap, options) {
      return new Promise((resolve, reject) => {
        ldap.bind(options, (err) => {
          if (err) { reject(new Error(err)); } else { resolve(); }
        });
      });
    }

    // Start a fake LDAP server that we can terminate to simulate a
    // connection closing due to idle timeout
    let server = await start_ldap_server();

    const ldap = new LDAP({ uri: `ldap://127.0.0.1:${port}` });

    await bind(ldap, { binddn: 'cn=manager,dc=sample,dc=com', password: 't3st' });

    // Stop the server then restart it; this closes the active
    // connection
    await stop_ldap_server(server, ldap);
    server = await start_ldap_server();

    // Another bind should reconnect and then succeed
    await bind(ldap, { binddn: 'cn=manager,dc=sample,dc=com', password: 't3st' });

    // Stop the server to cleanup
    await stop_ldap_server(server, ldap);
  });
});
