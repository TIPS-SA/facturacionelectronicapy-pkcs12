const fs = require('fs');
const forge = require('node-forge');
const ocsp = require('ocsp');

class Token {
    constructor(file) {
        const pkcs12 = fs.readFileSync(file);
        this.p12Der = forge.asn1.fromDer(pkcs12.toString('binary'));
    }

    openSession(pin, index = this.index) {
        this.p12Asn1 = forge.pkcs12.pkcs12FromAsn1(this.p12Der, false, pin);
    }

    closeSession() {
        this.p12Asn1 = undefined;
    }

    getPrivateKey() {
        for (let i = 0; i < this.p12Asn1.safeContents.length; i++) {
            if (this.p12Asn1.safeContents[i].safeBags[0].key) {
                return forge.pki.privateKeyToPem(this.p12Asn1.safeContents[i].safeBags[0].key);
            }
        }
        return null;
    }

    getCertificate() {
        for (let i = 0; i < this.p12Asn1.safeContents.length; i++) {
            if (this.p12Asn1.safeContents[i].safeBags[0].cert) {
                const b64 = forge.pki.certificateToPem(this.p12Asn1.safeContents[i].safeBags[0].cert);
                const l = b64.split('\n');
                l.pop();
                l.pop();
                l[0] = '';
                return l.join('\n');
            }
        }
        return null;
    }

    validez() {
        let certificado;
        for (let i = 0; i < this.p12Asn1.safeContents.length; i++) {
            if (this.p12Asn1.safeContents[i].safeBags[0].cert) {
                certificado = this.p12Asn1.safeContents[i].safeBags[0].cert;
            }
        }
        return certificado.validity;
    }

    ocsp() {
        let certificado;
        for (let i = 0; i < this.p12Asn1.safeContents.length; i++) {
            if (this.p12Asn1.safeContents[i].safeBags[0].cert) {
                certificado = this.p12Asn1.safeContents[i].safeBags[0].cert;
            }
        }
        return new Promise((resolve, reject) => {
            ocsp.check({
                cert: forge.pki.certificateToPem(certificado),
                issuer: certificado.issuer.getField('CN').value === 'Entidad Certificadora Publica ADSIB' ? fs.readFileSync(`${__dirname}/../ca/firmadigital_bo.crt`) : fs.readFileSync(`${__dirname}/../ca/privada.crt`)
            }, (err, res) => {
                if (res) {
                    resolve(res);
                } else {
                    switch (err.message) {
                        case 'Expected at least one response':
                        case 'AuthorityInfoAccess not found in extensions':
                        resolve({ type: 'unknown' });
                        break;
                        default:
                        reject(err);
                    }
                }
            });
        });
    }

    signature(xml, privateKey) {
        const md = forge.md.sha256.create();
        md.update(xml, 'utf8');
        var key = forge.pki.privateKeyFromPem(privateKey);
        return key.sign(md);
    }
}

module.exports = Token;

