"""References must come from the actually verified signature and original tree."""
from copy import deepcopy

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree
from signxml import (XMLSigner, XMLVerifier, SignatureConfiguration,
                     InvalidInput, InvalidSignature, methods)


def build_two_signatures():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = etree.Element('Envelope')
    for identity in ('a', 'b'):
        node = etree.Element('Invoice', Id=identity)
        node.text = identity
        root.append(XMLSigner().sign(node, key=key, reference_uri='#' + identity))
    return root


def build_external_reference():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = etree.fromstring(b'<Envelope><Invoice><Amount>42</Amount></Invoice></Envelope>')
    external = deepcopy(root[0])
    signature = XMLSigner(method=methods.detached).sign(
        external, key=key, reference_uri='urn:generated:invoice')
    root.append(signature)
    called = []
    def resolver(uri):
        called.append(uri)
        assert uri == 'urn:generated:invoice'
        return external
    return root, root[0], resolver, called


def test_unverified_second_signature_cannot_supply_coverage():
    root = build_two_signatures()
    root[1].text = 'modified unsigned business value'
    options = {'expect_config': SignatureConfiguration(require_x509=False)}
    assert XMLVerifier().verify(root, **options).signed_xml.text == 'a'
    with pytest.raises((InvalidInput, InvalidSignature)):
        XMLVerifier().verify(root, expected_signed_element=root[1], **options)


def test_resolved_external_copy_cannot_authenticate_input_element():
    root, selected, resolver, calls = build_external_reference()
    options = {'uri_resolver': resolver,
               'expect_config': SignatureConfiguration(require_x509=False)}
    assert XMLVerifier().verify(root, **options).signed_xml.find('Amount').text == '42'
    assert calls == ['urn:generated:invoice']
    with pytest.raises((InvalidInput, InvalidSignature)):
        XMLVerifier().verify(root, expected_signed_element=selected, **options)


if __name__ == '__main__':
    # Feature-free controls on the fixed starting revision, never model scores.
    root = build_two_signatures()
    root[1].text = 'modified unsigned business value'
    cfg = SignatureConfiguration(require_x509=False)
    assert XMLVerifier().verify(root, expect_config=cfg).signed_xml.text == 'a'
    root, _, resolver, calls = build_external_reference()
    assert XMLVerifier().verify(root, uri_resolver=resolver,
                                expect_config=cfg).signed_xml.find('Amount').text == '42'
    assert calls == ['urn:generated:invoice']
    print('PASS genuine first signature with invalid second; genuine external URI resolved locally')
