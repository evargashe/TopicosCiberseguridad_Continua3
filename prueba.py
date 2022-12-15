""" from oscrypto import tls
from certvalidator import CertificateValidator, errors

session = tls.TLSSession(manual_validation=True)
connection = tls.TLSSocket('meet.google.com', 443 , session=session)

try:
    validator = CertificateValidator(connection.certificate, connection.intermediates)
    result = validator.validate_tls(connection.hostname)
    cert_1 = result.__getitem__(0)
    cert_2 = result.__getitem__(1)
    cert_3 = result.__getitem__(2)
    print(hex(result.__getitem__(1).serial_number))
except (errors.PathValidationError):
    print("The certificate did not match hostname") """



""" import pem
from cryptography import x509


certs = pem.parse_file("./TrustStore/ChromeRootsPEM.txt") """
""" import os
import re
from oscrypto import tls
from certvalidator import CertificateValidator, errors
from flask_wtf.file import FileField
from asn1crypto import pem
from asn1crypto.x509 import Certificate



CERTIFICATES = {}

def load(filename=None):
    if filename is None:
        return []
    list_cert = []
    with open(f'./TrustStore/{filename}', 'rb') as f:
        for _, _, der_bytes in pem.unarmor(f.read(), multiple=True):
            list_cert.append(Certificate.load(der_bytes))

    return list_cert

def loadCertificates():

    if CERTIFICATES.get('has'):
        return
    CERTIFICATES.update({
        'mozillaCertificates': load('MozillaRootsPEM.txt'),
        'chromeCertificates': load('ChromeRootsPEM.txt'),
        'edgeCertificates': load('EdgeRootsPEM.txt'),
        'has': True,
    })

def verificateReporitory(url):
    dataCertificate = dict(
        bool_mozilla=False,
        bool_chrome=False,
        bool_edge=False,
        mozillaTrustLevel=1,
        chromeTrustLevel=1,
        edgeTrustLevel=1,
    )
    try:
        connection = tls.TLSSocket(url, 443, session=tls.TLSSession(manual_validation=True))
    except Exception as e:
        return 'has not certificate digital'
    
    validator = CertificateValidator(connection.certificate, connection.intermediates)

    certification_chain = validator.validate_tls(connection.hostname)
    root_certificate = certification_chain[0]
    root = root_certificate.key_identifier_value
    loadCertificates()

    for mozilla_certificate in CERTIFICATES.get('mozillaCertificates'):
        certificates = mozilla_certificate.key_identifier_value
        if root == certificates:
            dataCertificate.update({'bool_mozilla': True})

    for chrome_certificate in CERTIFICATES.get('chromeCertificates'):
        certificates = chrome_certificate.key_identifier_value
        if root == certificates:
            dataCertificate.update({'bool_chrome': True})

    for edge_certificate in CERTIFICATES.get('edgeCertificates'):
        certificates = edge_certificate.key_identifier_value
        if root == certificates:
            dataCertificate.update({'bool_edge': True})

    #dataCertificate['name'] = root_certificate.subject.human_friendly
    return dataCertificate

result = verificateReporitory('meet.google.com')
print(result)

 """


""" from urllib.parse import urlparse

domain = urlparse('https://www.google.com/foo/bar').netloc
print(domain) # --> www.example.test
 """
""" import re
url = 'https://www.youtube.com/'
host = re.search(r'https://([^/?:]*)', url).group(1)
print(host) """

""" 
import os
import re
from oscrypto import tls
from certvalidator import CertificateValidator, errors
from flask_wtf.file import FileField
from asn1crypto import pem
from asn1crypto.x509 import Certificate

def file_to_certificate_object_list(filename=None):
    if filename is None:
        return []
    certificates_list = []
    with open(f'./TrustStore/{filename}', 'rb') as f:
        for _, _, der_bytes in pem.unarmor(f.read(), multiple=True):
            certificates_list.append(Certificate.load(der_bytes))

    return certificates_list

CERTIFICATES = {}
CERTIFICATES.update({
        'mozilla_certificates': file_to_certificate_object_list('MozillaRootsPEM.txt'),
        'chrome_certificates': file_to_certificate_object_list('ChromeRootsPEM.txt'),
        'edge_certificates': file_to_certificate_object_list('EdgeRootsPEM.txt'),
        'has_certificates': True,
    })

c = CERTIFICATES.get('chrome_certificates')

for i in c:
        try:
            print("-"*10)
            print(i.subject)
            print(i.subject.human_friendly)
            print(i.serial_number)
            print(i.not_valid_before, i.not_valid_after)
            print(i.public_key.algorithm, i.public_key.bit_size)
            print(i.sha1_fingerprint)
            print(i.key_usage_value.native)
            print(i.key_identifier_value)
        except Exception as e:
            print("ERROR") """
    



""" import ssl
import socket
import OpenSSL
from pprint import pprint
from datetime import datetime


def get_certificate(host, port=443, timeout=10):
    context = ssl.create_default_context()
    conn = socket.create_connection((host, port))
    sock = context.wrap_socket(conn, server_hostname=host)
    sock.settimeout(timeout)
    try:
        der_cert = sock.getpeercert(True)
    finally:
        sock.close()
    return ssl.DER_cert_to_PEM_cert(der_cert)


certificate = get_certificate('example.com')
x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)

result = {
    'subject': dict(x509.get_subject().get_components()),
    'issuer': dict(x509.get_issuer().get_components()),
    'serialNumber': x509.get_serial_number(),
    'version': x509.get_version(),
}

extensions = (x509.get_extension(i) for i in range(x509.get_extension_count()))
extension_data = {e.get_short_name(): str(e) for e in extensions}
result.update(extension_data)
pprint(result) """



import ssl
import socket
import OpenSSL
from pprint import pprint
from datetime import datetime

import re


def get_certificate(host, port=443, timeout=10):
    context = ssl.create_default_context()
    conn = socket.create_connection((host, port))
    sock = context.wrap_socket(conn, server_hostname=host)
    sock.settimeout(timeout)
    try:
        der_cert = sock.getpeercert(True)
    finally:
        sock.close()
    return ssl.DER_cert_to_PEM_cert(der_cert)


certificate = get_certificate('www.unsa.edu.pe')
x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)


x = x509.get_notAfter()
notAfter = re.sub('Z', "", x)
print(notAfter)
result = {
    'subject': dict(x509.get_subject().get_components()),
    'issuer': dict(x509.get_issuer().get_components()),
    'serialNumber': x509.get_serial_number(),
    'version': x509.get_version(),
    #'notBefore': datetime.strptime(x509.get_notBefore(), '%Y%m%d%H%M%S'),
    #'notAfter': datetime.strptime(x509.get_notAfter(), '%Y%m%d%H%M%S'),
}

extensions = (x509.get_extension(i) for i in range(x509.get_extension_count()))
extension_data = {e.get_short_name(): str(e) for e in extensions}
result.update(extension_data)
#pprint(extension_data.get(b'basicConstraints'))

pprint(result)




""" from urllib.request import ssl, socket

import datetime, smtplib


hostname = 'www.google.com'

port = '443'


context = ssl.create_default_context()


with socket.create_connection((hostname, port)) as sock:

    with context.wrap_socket(sock, server_hostname = hostname) as ssock:

        certificate = ssock.getpeercert()

print(certificate['notBefore']) """


""" 
from flask import Flask, render_template, request
from urllib.parse import urlparse
from flask import flash
from werkzeug.utils import secure_filename

import re
import ssl, os
import certifi


import socket
import OpenSSL
from pprint import pprint
import datetime


import os
import re
from oscrypto import tls
from certvalidator import CertificateValidator, errors
from flask_wtf.file import FileField
from asn1crypto import pem
from asn1crypto.x509 import Certificate


from flask import redirect


from urllib.request import socket

import datetime, smtplib


def get_certificate(host, port=443, timeout=10):
    context = ssl.create_default_context()
    conn = socket.create_connection((host, port))
    sock = context.wrap_socket(conn, server_hostname=host)
    sock.settimeout(timeout)
    try:
        der_cert = sock.getpeercert(True)
    finally:
        sock.close()
    return ssl.DER_cert_to_PEM_cert(der_cert)


#validate URL

def isValidURL(str):
    regex = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    if (str == None):
        return False
    if(re.search(regex, str)):
        return True
    else:
        return False

#get certificate digital ssl

def certificatessl(host):

    port = '443'
    address = (host, port)
    # Retrieve the server certificate and validate
    #cert = ssl.get_server_certificate(address, ca_certs=os.path.relpath(certifi.where()))
    cert = ssl.get_server_certificate(address)
    return cert

def visualizationCD(hostname):
    port = '443'
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as sock:

        with context.wrap_socket(sock, server_hostname = hostname) as ssock:

            certificate = ssock.getpeercert()
    return certificate

def publicKey(host):
    certificate = get_certificate(host)
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
    public = dict(x509.get_issuer().get_components())
    key = public.get(b'CN')
    return key


def basicConstraints(host):
    certificate = get_certificate(host)
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
    public = dict(x509.get_issuer().get_components())
    extensions = (x509.get_extension(i) for i in range(x509.get_extension_count()))
    extension_data = {e.get_short_name(): str(e) for e in extensions}
    #result.update(extension_data)
    bC = extension_data.get(b'basicConstraints')
    return bC


#Certificate root
def certificateRoot(url):
    port = "443"
    session = tls.TLSSession(manual_validation=True)
    connection = tls.TLSSocket(url , 443 , session=session)
    #try:
    validator = CertificateValidator(connection.certificate, connection.intermediates)
    result = validator.validate_tls(connection.hostname)
    return result



#R5: Se verifica si el certificado raíz de la cadena de certificación se encuentra en el repositorio del: 
#(i) Microsoft Edge, (ii) Mozilla Firefox y (iii) Google Chrome.


CERT = {}

def load(filename=None):
    if filename is None:
        return []
    list_cert = []
    with open(f'./TrustStore/{filename}', 'rb') as f:
        for _, _, der_bytes in pem.unarmor(f.read(), multiple=True):
            list_cert.append(Certificate.load(der_bytes))
    return list_cert

def loadCertificates():

    if CERT.get('has'):
        return
    CERT.update({
        'mozillaCertificates': load('MozillaRootsPEM.txt'),
        'chromeCertificates': load('ChromeRootsPEM.txt'),
        'edgeCertificates': load('EdgeRootsPEM.txt'),
        'has': True,
    })

def verificateReporitory(url):
    dataCertificate = dict(
        bool_mozilla=False,
        bool_chrome=False,
        bool_edge=False,
        level_mozilla=1,
        level_chrome=1,
        level_edge=1,
    )
    try:
        connection = tls.TLSSocket(url, 443, session=tls.TLSSession(manual_validation=True))
    except Exception as e:
        return 'has not certificate digital'
    

    validator = CertificateValidator(connection.certificate, connection.intermediates)
    certification_chain = validator.validate_tls(connection.hostname)
    root_certificate = certification_chain[0]
    loadCertificates()

    for mozilla_certificate in CERT.get('mozillaCertificates'):
        if  mozilla_certificate.key_identifier_value == root_certificate.key_identifier_value:
            dataCertificate.update({'bool_mozilla': True})

    for chrome_certificate in CERT.get('chromeCertificates'):
        if chrome_certificate.key_identifier_value == root_certificate.key_identifier_value:
            dataCertificate.update({'bool_chrome': True})

    for edge_certificate in CERT.get('edgeCertificates'):
        if edge_certificate.key_identifier_value == root_certificate.key_identifier_value:
            dataCertificate.update({'bool_edge': True})

    dataCertificate['name'] = root_certificate.subject.human_friendly
    return dataCertificate


print(verificateReporitory('www.steamcommunity.com'))

 """




