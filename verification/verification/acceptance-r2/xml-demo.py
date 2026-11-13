"""Exercise actual selected-node verification with freshly generated signatures."""
from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree
from signxml import XMLSigner, XMLVerifier, SignatureConfiguration


key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
cfg = SignatureConfiguration(require_x509=False)


def show(label, root, selected):
    print('\n' + label)
    print('Selected element:', selected.tag)
    try:
        result = XMLVerifier().verify(root, expected_signed_element=selected,
                                      expect_config=cfg)
        print('Verified reference:', etree.tostring(result.signed_xml).decode())
    except Exception as error:
        print(type(error).__name__ + ':', error)


envelope = etree.fromstring(b'<Envelope><Invoice Id="order"><Amount>42</Amount></Invoice></Envelope>')
original = envelope[0]
envelope.replace(original, XMLSigner().sign(original, key=key, reference_uri='#order'))
signed = envelope[0]
show('A signed invoice selected from the input tree', envelope, signed)

envelope.remove(signed)
archive = etree.SubElement(envelope, 'Archive')
archive.append(signed)
replacement = etree.SubElement(envelope, 'Invoice', Id='business')
etree.SubElement(replacement, 'Amount').text = '999'
print('\nA valid signature remains in the archive')
try:
    verified = XMLVerifier().verify(envelope, expect_config=cfg)
    print('Cryptographically signed amount:', verified.signed_xml.find('Amount').text)
except Exception as error:
    print(type(error).__name__ + ':', error)
show('Selecting the replacement business invoice', envelope, replacement)

root = etree.fromstring(b'<Envelope Id="root"><Invoice><Amount>42</Amount></Invoice></Envelope>')
root = XMLSigner().sign(root, key=key, reference_uri='#root')
show('Selecting an intact descendant of a signed envelope', root, root.find('Invoice'))
