const Dsig = require('../lib/dsig');

var dsig = new Dsig(`${__dirname}/../token/token.pfx`);

try {
    dsig.openSession('12345678');
    var xml = '<library><book><name>Harry Potter</name></book></library>';
    console.log(dsig.computeSignature(xml, 'book'));
} catch(e) {
    console.error(e);
} finally {
    dsig.closeSession();
}
