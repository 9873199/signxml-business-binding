from copy import deepcopy
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree
from signxml import XMLSigner,XMLVerifier,SignatureConfiguration,InvalidInput,InvalidSignature

def test_mixed_id_spelling_keeps_legacy_resolution_but_never_covers_shadow():
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    root=etree.fromstring(b'<Envelope><Invoice Id="order">42</Invoice></Envelope>')
    node=root[0];root.replace(node,XMLSigner().sign(node,key=key,reference_uri='#order'))
    shadow=etree.SubElement(root,'Invoice',ID='order');shadow.text='999'
    config=SignatureConfiguration(require_x509=False)
    old=XMLVerifier().verify(root,expect_config=config)
    assert old.signed_xml.text=='42'
    bound=XMLVerifier().verify(root,expected_signed_element=root[0],expect_config=config)
    assert bound.signed_xml.text=='42'
    with pytest.raises((InvalidInput,InvalidSignature)):
        XMLVerifier().verify(root,expected_signed_element=shadow,expect_config=config)

def test_one_valid_reference_does_not_return_when_another_digest_fails():
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    root=etree.fromstring(b'<Envelope><Invoice Id="a">A</Invoice><Invoice Id="b">B</Invoice></Envelope>')
    root=XMLSigner().sign(root,key=key,reference_uri=['#a','#b'])
    root[1].text='tampered'
    with pytest.raises(InvalidSignature):
        XMLVerifier().verify(root,expected_signed_element=root[0],expect_config=SignatureConfiguration(require_x509=False,expect_references=2))
