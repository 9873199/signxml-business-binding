"""Real XML signature tests for binding the selected business element by identity."""
from copy import deepcopy
import pytest
from lxml import etree
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from signxml import XMLSigner,XMLVerifier,SignatureConfiguration,InvalidInput,InvalidSignature

@pytest.fixture(scope='module')
def key():
 k=rsa.generate_private_key(public_exponent=65537,key_size=2048)
 return k

def verify(root,selected=None,references=1,configured=False):
 options={'expect_config':SignatureConfiguration(require_x509=False,expect_references=references)}
 if configured:options['expected_signed_element']=selected
 return XMLVerifier().verify(root,**options)

def signed_invoice(key):
 root=etree.fromstring(b'<Envelope><Invoice Id="order"><Amount>42</Amount></Invoice></Envelope>')
 child=root[0];root.replace(child,XMLSigner().sign(child,key=key,reference_uri='#order'))
 return root,root[0]

def test_original_interface_preserved(key):
 root,node=signed_invoice(key)
 result=verify(root)
 assert result.signed_xml.find('Amount').text=='42'

def test_same_original_element_is_accepted(key):
 root,node=signed_invoice(key)
 result=verify(root,node,configured=True)
 assert result.signed_xml.find('Amount').text=='42'

def test_wrapped_signed_invoice_does_not_authenticate_replacement(key):
 root,signed=signed_invoice(key)
 root.remove(signed);archive=etree.SubElement(root,'Archive');archive.append(signed)
 business=etree.SubElement(root,'Invoice',Id='business');etree.SubElement(business,'Amount').text='999'
 assert verify(root).signed_xml.find('Amount').text=='42'
 with pytest.raises((InvalidInput,InvalidSignature)):verify(root,business,configured=True)

@pytest.mark.parametrize('attachment',['detached','another-tree'])
def test_equal_bytes_are_not_same_element(key,attachment):
 root,signed=signed_invoice(key);copy=deepcopy(signed)
 assert etree.tostring(copy)==etree.tostring(signed)
 if attachment=='another-tree':etree.Element('Other').append(copy)
 with pytest.raises((InvalidInput,InvalidSignature)):verify(root,copy,configured=True)

def test_ancestor_reference_covers_business_descendant(key):
 root=etree.fromstring(b'<Envelope Id="root"><Invoice><Amount>42</Amount></Invoice></Envelope>')
 root=XMLSigner().sign(root,key=key,reference_uri='#root');business=root.find('Invoice')
 assert verify(root,business,configured=True).signed_xml.find('Invoice/Amount').text=='42'
 assert verify(root,root,configured=True).signed_xml.find('Invoice/Amount').text=='42'

@pytest.mark.parametrize('part',['Signature','SignedInfo','KeyInfo'])
def test_enveloped_signature_removed_content_is_not_covered(key,part):
 root=etree.fromstring(b'<Envelope Id="root"><Invoice>42</Invoice></Envelope>')
 root=XMLSigner().sign(root,key=key,reference_uri='#root')
 # The signature is genuine, but its own subtree was removed before digesting
 # the ancestor reference. Ancestor membership alone cannot prove coverage.
 assert verify(root).signed_xml.find('Invoice').text=='42'
 ns={'ds':'http://www.w3.org/2000/09/xmldsig#'}
 selected=root.find('ds:Signature',ns)
 if part!='Signature':selected=selected.find('ds:'+part,ns)
 assert selected is not None
 with pytest.raises((InvalidInput,InvalidSignature)):verify(root,selected,configured=True)

def test_signed_ancestor_does_not_cover_outside_sibling(key):
 root,node=signed_invoice(key);sibling=etree.SubElement(root,'Invoice');etree.SubElement(sibling,'Amount').text='42'
 with pytest.raises((InvalidInput,InvalidSignature)):verify(root,sibling,configured=True)

@pytest.mark.parametrize('selected_id',['a','b'])
def test_multiple_references_bind_the_correct_original_node(key,selected_id):
 root=etree.fromstring(b'<Envelope><Invoice Id="a">A</Invoice><Invoice Id="b">B</Invoice><Invoice Id="c">C</Invoice></Envelope>')
 root=XMLSigner().sign(root,key=key,reference_uri=['#a','#b'])
 selected=root.xpath('./Invoice[@Id="'+selected_id+'"]')[0]
 results=verify(root,selected,references=2,configured=True)
 assert len(results)==2

def test_multiple_references_do_not_cover_unsigned_third_node(key):
 root=etree.fromstring(b'<Envelope><Invoice Id="a">A</Invoice><Invoice Id="b">B</Invoice><Invoice Id="c">C</Invoice></Envelope>')
 root=XMLSigner().sign(root,key=key,reference_uri=['#a','#b'])
 with pytest.raises((InvalidInput,InvalidSignature)):verify(root,root[2],references=2,configured=True)

@pytest.mark.parametrize('attribute',['Id','ID'])
def test_duplicate_id_is_rejected(key,attribute):
 root,node=signed_invoice(key);duplicate=etree.SubElement(root,'Shadow');duplicate.set(attribute,'order')
 with pytest.raises((InvalidInput,InvalidSignature)):verify(root,node,configured=True)

def test_content_modification_still_fails_cryptography(key):
 root,node=signed_invoice(key);node.find('Amount').text='43'
 with pytest.raises(InvalidSignature):verify(root,node,configured=True)

def test_namespaced_id_reference(key):
 ns='urn:business:identity';attribute='{'+ns+'}document'
 root=etree.Element('Invoice',nsmap={'b':ns});root.set(attribute,'selected');root.text='42'
 signed=XMLSigner().sign(root,key=key,reference_uri='#selected',id_attribute='document')
 result=XMLVerifier().verify(signed,expected_signed_element=signed,id_attribute='document',expect_config=SignatureConfiguration(require_x509=False))
 assert result.signed_xml.text=='42'
