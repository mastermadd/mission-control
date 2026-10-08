// Disposable TLS identity generated in memory for the native API tests only.
import {generateKeyPairSync,sign} from 'node:crypto';

function der(tag,...items) {
  const body=Buffer.concat(items.map(item=>Buffer.isBuffer(item)?item:Buffer.from(item)));
  let length;
  if(body.length<128)length=Buffer.from([body.length]);
  else {const hex=body.length.toString(16);const bytes=Buffer.from(hex.length%2?'0'+hex:hex,'hex');length=Buffer.concat([Buffer.from([128+bytes.length]),bytes]);}
  return Buffer.concat([Buffer.from([tag]),length,body]);
}
const sequence=(...items)=>der(0x30,...items);
const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
const signatureAlgorithm=Buffer.from('300d06092a864886f70d01010b0500','hex');
const name=sequence(der(0x31,sequence(Buffer.from('0603550403','hex'),der(0x0c,'router.test'))));
const alternativeName=sequence(Buffer.from('0603551d11','hex'),der(0x04,sequence(der(0x82,'router.test'))));
const body=sequence(der(0xa0,der(0x02,[2])),der(0x02,[1]),signatureAlgorithm,name,
  sequence(der(0x17,'200101000000Z'),der(0x17,'400101000000Z')),name,
  publicKey.export({format:'der',type:'spki'}),der(0xa3,sequence(alternativeName)));
const certificate=sequence(body,signatureAlgorithm,der(0x03,Buffer.from([0]),sign('sha256',body,privateKey)));
export const key=privateKey.export({format:'pem',type:'pkcs8'});
export const cert='-----BEGIN CERTIFICATE-----\n'+certificate.toString('base64').match(/.{1,64}/g).join('\n')+'\n-----END CERTIFICATE-----\n';
