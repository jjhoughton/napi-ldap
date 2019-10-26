/*jshint globalstrict:true, node:true, trailing:true, mocha:true unused:true */

"use strict";

var LDAP = require("../");

var assert = require("assert");

var ldap;

var uri = "ldap://localhost:1234";

describe("Check error handling inside c", function() {
  it("Throw in the connect callback", function(done) {
    try {
      new LDAP({
        uri: uri,
        connect: function() {
          ldap = this;
          throw new Error("oh no");
        }
      });
      ldap.close();
      done(new Error("This should throw an excpetion and it didn't"));
    } catch (e) {
      assert.equal(e.message, "oh no");
      ldap.close();
      done();
    }
  });
  it("Throw in the disconnect callback", function(done) {
    new LDAP({
      uri: uri,
      connect: function() {
        setTimeout(() => {
          try {
            this.close();
            done(new Error("This should throw an exception"));
          } catch (e) {
            assert.equal(e.message, "oh no :(");
            done();
          }
        }, 1e1);
      },
      disconnect: function() {
        throw new Error("oh no :(");
      }
    });
  });
});
