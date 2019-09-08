/*jshint globalstrict:true, node:true, trailing:true, mocha:true unused:true */

'use strict';

var LDAP = require('../');
var assert = require('assert');
var ldap;
var errors = {};;

var ldapConfig = {
  schema: "ldaps://",
  host: "localhost:1235"
};
var uri = ldapConfig.schema + ldapConfig.host;

ldap = new LDAP(
  {
    uri: uri,
    validatecert: LDAP.LDAP_OPT_X_TLS_NEVER
  }
);

setInterval(function() {
    ldap.search({
        base:   'dc=sample,dc=com',
        filter: '(objectClass=*)',
        scope:  LDAP.SUBTREE
    }, function(err, res) {
        if (err) {
            if (!errors[err.message]) {
                errors[err.message] = 0;
            }
            errors[err.message]++;
            // assert(ldap.tlsactive());
            return;
        }
    });
}, 10);

setInterval(function() {
    console.log('✓ ' + new Date());
    console.log(ldap.stats);
    console.log(errors);
    console.log('');
}, 10000);
