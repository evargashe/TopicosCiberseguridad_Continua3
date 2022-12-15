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
    cert = ssl.get_server_certificate(address, ca_certs=os.path.relpath(certifi.where()))
    #cert = ssl.get_server_certificate(address)
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

def verificateReporitory(host):
    url = urlparse(host).netloc
    dataCertificate = dict(
        bool_edge=False,
        bool_chrome=False,
        bool_mozilla=False,
        #level_mozilla=1,
        #level_chrome=1,
        #level_edge=1,
    )
    try:
        connection = tls.TLSSocket(url, 443, session=tls.TLSSession(manual_validation=True))
    except Exception as e:
        return 'has not certificate digital'
    
    validator = CertificateValidator(connection.certificate, connection.intermediates)

    try:
        certification_chain = validator.validate_tls(connection.hostname)
    except Exception as e:
        return dataCertificate

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

    #dataCertificate['name'] = root_certificate.subject.human_friendly
    return dataCertificate






