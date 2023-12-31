const convert = require('xml-js');
const crypto = require('crypto');
const Token = require('./token');
const xmldom = require("xmldom");
const c14n = require("xml-c14n")();

class Dsig {
    constructor(file) {
        this.token = new Token(file);
        this.signOpt = {
            compact: true,
            ignoreComment: true,
            spaces: 2,
            fullTagEmptyElement: false
        };
        this.signedInfo = {
            CanonicalizationMethod: {
                _attributes: {
                    Algorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#'
                }
            },
            SignatureMethod: {
                _attributes: {
                    Algorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
                }
            },
            Reference: {
                _attributes: {
                    URI: ''
                },
                Transforms: {
                    Transform: [
                        {
                            _attributes: {
                                Algorithm: 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'
                            }
                        }, {
                            _attributes: {
                                Algorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#'
                            }
                        }
                    ]
                },
                DigestMethod: {
                    _attributes: {
                        Algorithm: 'http://www.w3.org/2001/04/xmlenc#sha256'
                    }
                },
                DigestValue: ''
            }
        };
    }

    openSession(pin) {
        this.token.openSession(pin);
    }

    closeSession() {
        try {
            this.token.closeSession();
        } catch (error) {
        }
    }

    computeSignature(xml, tag) {
        const doc = convert.xml2js(xml, this.signOpt);
        const root = Object.keys(doc).filter(key => key !== '_declaration');
        if (root.length !== 1) {
            throw new Error('No se pudo determinar la raiz del documento.');
        }
        const _attributes = {
            xmlns: 'http://www.w3.org/2000/09/xmldsig#'
        };
        if (tag) {
            /*if (doc[root[0]][tag]) {
                doc[root[0]][tag]._attributes = { id: tag };
            } else {
                throw new Error('Tag no encontrado.');
            }*/
            let id = doc[root[0]][tag]._attributes.Id;
            this.signedInfo.Reference._attributes.URI = `#${id}`;
        }
        if (doc[root[0]]._attributes) {
            const attributes = Object.keys(doc[root[0]]._attributes);
            for (let i = 0; i < attributes.length; i++) {
                if (attributes[i].startsWith('xmlns:')) {
                    _attributes[attributes[i]] = doc[root[0]]._attributes[attributes[i]];
                }
            }
        }
//        const hash = this.digest(convert.js2xml({ [root[0]]: doc[root[0]] }, this.signOpt).split('\r').join('&#xD;\n'));

       
    //console.log("root a", doc[root[0]]);
    //console.log("root b", doc[root[0]][tag]);

        console.log("hash numero 5 " + this.digest(convert.js2xml({ [root[0]]: doc[root[0]] }, this.signOpt).split('\r').join('')) );
        console.log("hash numero 5 " + this.digest(convert.js2xml({ [root[0]]: doc[root[0]] }, this.signOpt).split('\r\n').join('')) );
        
        console.log("hash numero 6 " + this.digest(convert.js2xml(doc[root[0]], this.signOpt).split('\r').join('\n')) );
        console.log("hash numero 7 " + this.digest(convert.js2xml(doc[root[0]][tag], this.signOpt).split('\r').join('\r\n')) );
        console.log("hash numero 7 " + this.digest(convert.js2xml(doc[root[0]][tag], this.signOpt).split('\r\n').join('')) );
        console.log("hash numero 1 " + this.digest(convert.js2xml({ [root[0]]: doc[root[0]][tag] }, this.signOpt)) );
        console.log("hash numero 9 " + this.digest(convert.js2xml({ [root[0]]: doc[root[0]] }, this.signOpt)) );
        console.log("hash numero 10 " + this.digest(convert.js2xml(doc[root[0]][tag], this.signOpt)).replace('<dVerFor>150</dVerFor>', '') );
        console.log("hash numero 11 " + this.digest(convert.js2xml(doc[root[0]][tag])).replace('<dVerFor>150</dVerFor>', '') );
        console.log("hash numero 12 " + this.digest(convert.js2xml(doc[root[0]])).replace('<dVerFor>150</dVerFor>', '') );

        console.log("hash numero 8 " + this.digest(convert.js2xml({ [root[0]]: doc[root[0]] })) );
        console.log("");
        console.log("");

        console.log("tag " + tag);

        let textoAFirmar = convert.js2xml(doc[root[0]], this.signOpt);
        textoAFirmar = textoAFirmar.replace('<dVerFor>150</dVerFor>', '');
        //console.log("XML a firmar A ==== ", textoAFirmar);


        //const hash = this.digest(convert.js2xml({ [root[0]]: doc[root[0]] }, this.signOpt).split('\r').join('&#xD;\n'));
        let hash = this.digest(textoAFirmar);
        console.log(hash);
        hash = this.digest(textoAFirmar.split('\r').join('&#xD;\n'));
        console.log(hash);
        hash = this.digest(textoAFirmar.split('\r\n').join(''));
        console.log(hash);
        this.signedInfo.Reference.DigestValue = hash;
        const signedInfoXML = convert.js2xml({
            SignedInfo: {
                _attributes,
                CanonicalizationMethod: this.signedInfo.CanonicalizationMethod,
                SignatureMethod: this.signedInfo.SignatureMethod,
                Reference: this.signedInfo.Reference
            }
        }, this.signOpt).split('\n').map(e => e.trim()).join('\n');
        let signature = this.signatureValue(signedInfoXML);
        doc[root[0]].Signature = {
            _attributes: {
                xmlns: 'http://www.w3.org/2000/09/xmldsig#'
            },
            SignedInfo: this.signedInfo,
            SignatureValue: signature,
            KeyInfo: {
                X509Data: {
                    X509Certificate: this.certificate.split('\r').join('')
                }
            }
        };
        let flag = false;
        return convert.js2xml(doc, this.signOpt).split('\n').map(e => {
            if (e.indexOf('<Signature') >= 0) {
                flag = true;
            }
            if (e.indexOf('</Signature>') >= 0) {
                flag = false;
                return e.trim();
            }
            if (flag) {
                return e.trim();
            } else {
                return e;
            }
        }).join('\n').replace('</Signature>\n', '</Signature>').split('\r').join('&#xD;\n');
    }

    digest(xml) {
        var sha256 = crypto.createHash('sha256');
        sha256.update(xml, 'utf8');
        return sha256.digest('base64');
    }

    signatureValue(xml) {
        let privateKey = this.token.getPrivateKey();
        this.certificate = this.token.getCertificate();
        let signature = this.token.signature(xml, privateKey);
        return Buffer.from(signature, 'binary').toString('base64');
    }

    getCertificate() {
        let certificate = this.token.getCertificate();
        return `-----BEGIN CERTIFICATE-----${certificate}\n-----END CERTIFICATE-----`;
    }
}

module.exports = Dsig;

