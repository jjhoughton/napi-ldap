const ldap = require('ldapjs');

const port = process.argv[2];
const name = process.argv[3];

process.on('disconnect', () => {
  process.exit();
});

const server = ldap.createServer();

server.bind(name, (request, response) => {
	response.end();
});

server.listen(port, () => {
  process.send({status: 'started'});
});
