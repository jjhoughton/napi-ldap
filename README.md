napi-ldap 1.0.2
===============

OpenLDAP client bindings for Node.js.

A rewrite of Jeremy's ldap client using the new official n-api https://github.com/jeremycx/node-LDAP

Contributing
===

Any contributions are certainly welcome. Please email your patches to `joshua` dot `houghton` at `yandex` dot `ru` or submit a pull request on github.

Thanks to:
===
* Jeremy Childs
* James Moxon
* Petr Běhan
* YANG Xudong
* Victor Powell
* Many other contributors

Dependencies
===

Node >= 8

Install
=======

You do not need OpenLDAP installed unless you are using node8 as this library ships with it's own precompiled version.

You will need to ensure the Cyrus SASL libraries are install.

For SASL authentication support the Cyrus SASL devel package needs to also be installed.

If you would like this package to compile its own version of OpenLDAP and link against it upon running yarn then you can do so by specifying `BUILD_OPENLDAP=1 yarn` you will probably need to install libdb-devel for this to work as well as the cyrus-sasl-devel package.

Alternatively if you'd like to install OpenLDAP systemwide and link against that then you can do so by specifying `USE_SYSTEM_LDAP=1 yarn`, just be aware that OpenLDAP needs to be compiled against the same version of OpenSSL that node uses. With regards to Centos6 and Centos7 this is not the case. You can see what version of OpenSSL node uses by running `node -e 'console.log(process.versions)'`. You will need to set this opion when running on ARM.

Reconnection
==========
If the connection fails during operation, the client library will handle the reconnection, calling the function specified in the connect option. This callback is a good place to put bind()s and other things you want to always be in place.

You must close() the instance to stop the reconnect behavior.

During long-running operation, you should be prepared to handle errors robustly - there is no telling when the underlying driver will be in the process of automatically reconnecting. `ldap.search()` and friends will happily return a `Timeout` or `Can't contact LDAP server` error if the server has temporarily gone away. So, though you **may** want to implement your app in the `new LDAP()` callback, it's perfectly acceptable (and maybe even recommended) to ignore the ready callback in `new LDAP()` and proceed anyway, knowing the library will eventually connect when it is able to.

API
===

    new LDAP(options, readyCallback);

Options are provided as a JS object:

```js
var LDAP = require('napi-ldap');

var ldap = new LDAP({
    uri:             'ldap://server',   // string
    validatecert:    false,             // Verify server certificate, default LDAP.LDAP_OPT_X_TLS_HARD, see TLS section on how to set this up
    ca:              '/chain.crt',      // full path of the TLS certificate chain, see TLS section
    timeout:         1000,              // response timeout in milliseconds, default 1000ms
    ntimeout:        2000,              // network timeout in milliseconds, default 2000ms
    base:            'dc=com',          // default base for all future searches
    attrs:           '*',               // default attribute list for future searches
    filter:          '(objectClass=*)', // default filter for all future searches
    scope:           LDAP.SUBTREE,      // default scope for all future searches
    debug:           0,                 // set to 1 to see OpenLDAP debug information
    connect:         function(),        // optional function to call when connect/reconnect occurs
    disconnect:      function(),        // optional function to call when disconnect occurs        
}, function(err) {
    // connected and ready    
});

```

The connect handler is called on initial connect as well as on reconnect, so this function is a really good place to do a bind() or any other things you want to set up for every connection.

```js
var ldap = new LDAP({
    uri: 'ldap://server',
    connect: function() {
        this.bind({
            binddn: 'cn=admin,dc=com',
            password: 'supersecret'
        }, function(err) {
           ...
        });
    }
}
```

TLS
===
TLS can be used via the ldaps:// protocol string in the URI attribute on
instantiation. Certificate verificate does not work automatically however, I
believe this is due to node statically linking to OpenSSL although as of
yet I'm not sure. To turn certificate verification off you can set the
`verifycert` attribute to `LDAP.LDAP_OPT_X_TLS_NEVER`.

To enable certificate
verification run the following command to save the certificate chain of
your ldap server to a file where `ldap.jumpcloud.com` would be the ip/domainname
of your ldap server.

```
openssl s_client -showcerts -connect ldap.jumpcloud.com:636 </dev/null 2>/dev/null | sed -ne '/-BEGIN/,/-END/p' > chain.crt
```
Next set `validatecert` to `LDAP.LDAP_OPT_X_TLS_HARD` or one of the following
options bellow and set `ca` to the full path of your certificate chain.

```js
var LDAP=require('napi-ldap');

LDAP.LDAP_OPT_X_TLS_NEVER  = 0;
LDAP.LDAP_OPT_X_TLS_HARD   = 1;
LDAP.LDAP_OPT_X_TLS_DEMAND = 2;
LDAP.LDAP_OPT_X_TLS_ALLOW  = 3;
LDAP.LDAP_OPT_X_TLS_TRY    = 4;
```

ldap.bind()
===
Calling open automatically does an anonymous bind to check to make
sure the connection is actually open. If you call `bind()`, you
will upgrade the existing anonymous bind.

    ldap.bind(bind_options, function(err));

Options are binddn and password:

```js
bind_options = {
    binddn: '',
    password: ''
}
```
Aliased to `ldap.simplebind()` for backward compatibility.


ldap.saslbind()
===
Upgrade the existing anonymous bind to an authenticated bind using SASL.

    ldap.saslbind([bind_options,] function(err));

Options are: 

* mechanism - If not provided SASL library will select based on the best 
  mechanism available on the server.
* user - Authentication user if required by mechanism
* password - Authentication user's password if required by mechanism
* realm - Non-default SASL realm if required by mechanism
* proxyuser - Authorization (proxy) user if supported by mechanism
* securityproperties - Optional SASL security properties

All parameters are optional.  For example a GSSAPI (Kerberos) bind can be
initiated as follows:

```
	ldap.saslbind(function(err) { if(err) throw err; });
```

For details refer to the [SASL documentation](http://cyrusimap.org/docs/cyrus-sasl).


ldap.search()
===
    ldap.search(search_options, function(err, data));

Options are provided as a JS object:

```js
search_options = {
    base: 'dc=com',
    scope: LDAP.SUBTREE,
    filter: '(objectClass=*)',
    attrs: '*'
}
```

If one omits any of the above options, then sensible defaults will be used. One can also provide search defaults as part of instantiation.

Scopes are specified as one of the following integers:

```js
var LDAP=require('napi-ldap');

LDAP.BASE = 0;
LDAP.ONELEVEL = 1;
LDAP.SUBTREE = 2;
LDAP.SUBORDINATE = 3;
LDAP.DEFAULT = -1;
```

List of attributes you want is passed as simple string - join their names
with space if you need more ('objectGUID sAMAccountName cname' is example of
valid attrs filter). '\*' is also accepted.

Results are returned as an array of zero or more objects. Each object
has attributes named after the LDAP attributes in the found
record(s). Each attribute contains an array of values for that
attribute (even if the attribute is single-valued - having to check typeof()
before you can act on /anything/ is a pet peeve of
mine). The exception to this rule is the 'dn' attribute - this is
always a single-valued string.

Example of search result:

```js
[ { gidNumber: [ '2000' ],
  objectClass: [ 'posixAccount', 'top', 'account' ],
  uidNumber: [ '3214' ],
  uid: [ 'fred' ],
  homeDirectory: [ '/home/fred' ],
  cn: [ 'fred' ],
  dn: 'cn=fred,dc=ssimicro,dc=com' } ]
```

Attributes themselves are usually returned as strings. There is a list of known
binary attribute names hardcoded in C++ binding sources. Those are always
returned as Buffers, but the list is incomplete so far. 

Paged Search Results
===

LDAP servers are usually limited in how many items they are willing to return -
for example 1000 is Microsoft AD LDS default limit. To get around this limit
for larger directories, you have to use paging (as long as the server supports
it, it's an optional feature). To get paged search, add the "pagesize" attribute
to your search request:

```js
search_options = {
    ...,
    pagesize: n
}
ldap.search(search_options, on_data);

function on_data(err,data,cookie) {
  // handle errors, deal with received data and...
  if (cookie) { // more data available
    search_options.cookie = cookie;
    ldap.search(search_options, on_data);
  } else {
    // search is complete
  }
}
```

RootDSE
===

As of version 1.2.0 you can also read the rootDSE entry of an ldap server.
To do so, simply issue a read request with base set to an empty string:

```js
search_options = {
  base: '',
  scope: Connection.BASE,
  attrs: '+'
  // ... other options as necessary
}
```

ldap.findandbind()
===

    ldap.findandbind(fb_options, function(err, data))

Options are exactly like the search options, with the addition of a
"password" attribute:

```js
fb_options = {
    base: '',
    filter: '',
    scope: '',
    attrs: '',
    password: ''
}
```

Calls the callback with the record it authenticated against as the
`data` argument.

`findandbind()` does two convenient things: It searches LDAP for
a record that matches your search filter, and if one (and only one)
result is retured, it then uses a second connection with the same
options as the primary connection to attempt to authenticate to
LDAP as the user found in the first step.

The idea here is to bind your main LDAP instance with an "admin-like"
account that has the permissions to search. Your (hidden) secondary
connection will be used only for authenticating users.

In contrast, the `bind()` method will, if successful, change the
authentication on the primary connection.

```js
ldap.bind({
    binddn: 'cn=admin,dc=com',
    password: 'supersecret'
}, function(err, data) {
   if (err) {
       ...
   }
   // now we're authenticated as admin on the main connection
   // and thus have the correct permissions for search
   
   ldap.findandbind({
       filter: '(&(username=johndoe)(status=enabled))',
       attrs: 'username homeDirectory'
   }, function(err, data) {
      if (err) {
          ...
      }
      // our main connection is still cn=admin
      // but there's a hidden connection bound
      // as "johndoe"
      console.log(data[0].homeDirectory[0]);
   }
}

```

If you ensure that the "admin" user (or whatever you bind as for
the main connection) can not READ the password field, then
passwords will never leave the LDAP server -- all authentication
is done my the LDAP server itself.


ldap.add()
===

    ldap.add(dn, [attrs], function(err))

dn is the full DN of the record you want to add, attrs to be provided
as follows:

```js
var attrs = [
    { attr: 'objectClass',  vals: [ 'organizationalPerson', 'person', 'top' ] },
    { attr: 'sn',           vals: [ 'Smith' ] },
    { attr: 'badattr',      vals: [ 'Fried' ] }
]
```

ldap.modify()
===

    ldap.modify(dn, [ changes ], function(err))

Modifies the provided dn as per the changes array provided. Ops are
one of "add", "delete" or "replace".

```js
var changes = [
    { op: 'add',
      attr: 'title',
      vals: [ 'King of Callbacks' ]
    }
]
```

ldap.rename()
===

    ldap.rename(dn, newrdn, function(err))

Will rename the entry to the new RDN provided.

Example:

```js
ldap.rename('cn=name,dc=example,dc=com', 'cn=newname')
```

ldap.remove()
===

    ldap.remove(dn, function(err))

Deletes an entry.

Example:

```js
ldap.remove('cn=name,dc=example,dc=com', function(err) {
  if (err) {
    // Could not delete entry
  }
});
```

Escaping
===
Yes, Virginia, there's such a thing as LDAP injection attacks.

There are a few helper functions to ensure you are escaping your input properly.

**escapefn(type, template)**
Returns a function that escapes the provided parameters and inserts them into the provided template:

```js
var LDAP = require('napi-ldap');
var userSearch = LDAP.escapefn('filter', 
    '(&(objectClass=%s)(cn=%s))');

...
ldap.search({
    filter: userSearch('posixUser', username),
    scope: LDAP.SUBTREE
}, function(err, data) {
    ...
});
```
Since the escaping rules are different for DNs vs search filters, `type` should be one of `'filter'` or `'dn'`.

To escape a single string, `LDAP.stringEscapeFilter`:

```js
var LDAP=require('napi-ldap');
var user = "John O'Doe";

LDAP.stringEscapeFilter('(username=' + user + ')');
// ==> '(username=John O\'Doe)'
```

Note there is no function for string escaping a DN - DN escaping has special rules for escaping the beginning and end of values in the DN, so the best way to safely escape DNs is to use the `escapefn` with a template:

```js
var LDAP = require('napi-ldap');
var escapeDN = LDAP.escapefn('dn', 
    'cn=%s,dc=sample,dc=com');

...
var safeDN = escapeDN(" O'Doe");
// => "cn=\ O\'Doe,dc=sample,dc=com"

```

Running the Tests
===

On Linux install `openldap-servers`, cd to the `test` directory and run
`./run_server` in order to run the OpenLDAP server. On another terminal
in the root directory of this project run `yarn && yarn test`.

On MacOS it's a litte harder to run the tests. I personally ran
`./run_server` on a Linux box (see above) and port forwarded ports 1234 and 1235
like so: `ssh -L 1234:localhost:1234 -L 1235:localhost:1235 homeserver`
and then ran the tests locally on my mac with `yarn test`

Bugs
===
Domain errors don't work properly. Domains are deprecated as of node 4,
so I don't think I'm going to track it down. If you need domain handling,
let me know.

TODO Items
===
Basically, these are features I don't really need myself.

* Filter escaping
