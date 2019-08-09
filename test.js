const exp = require(".");

console.log(exp);

console.log(exp.LDAPCnx);

//console.log(exp.LDAPCnx());
/*
for (let i = 0; i < 1; i++) {
  let p = new exp.LDAPCnx();
}
global.gc();
setTimeout(() => {}, 1e2);
*/
let p = new exp.LDAPCnx();
console.log(p);
