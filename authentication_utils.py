
import logging
import base64
import requests

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    padding, rsa, utils
)


class Authentication_utils:

    def __init__(self):
        return

    def authenticateClient(self, data, message):

        certificateOfClient = bytes(base64.b64decode(message["certificate"]))
        cert = x509.load_der_x509_certificate(certificateOfClient, default_backend())
        signature = base64.b64decode(message["signature"])

        # validate certificate client chain
        logging.warning("Validating certificates..")
        certClient, certCit0008 = self.validateCertClientChain(data, message)
        # certificado client - certificado cartao de cidadao 0008

        # get revogate list
        # verify if client is in revocate list
        # check validate of certificate
        # def self.validate_first_certificate(certificate_to_validate, certificate_to_validate_with)
        logging.warning("Validating EC de Autenticacao do Cartao de Cidadao 0008")
        if (self.validations(certClient, certCit0008)):
            logging.warning("validating Cartao de cidadao 002")
            cert_above, cert_cit002 = self.validateCert2(certCit0008)
            # certificado cidadao 0008 - certificado cartao de cidadao 002
            if(self.validations(certCit0008, cert_cit002)):
                cert_above2, cert_RaizE_Multicert = self.validateCert2emeio(cert_cit002)
                # certificado carttao cidadao 002 - certificado ECRaizEstado Multicert
                logging.warning("validating before ECRaizEstado-Multicert")
                if(self.validations(cert_cit002, cert_RaizE_Multicert)):
                    onecert, certRoot = self.validateCert3(cert_RaizE_Multicert)
                    # certificado ECRaizEstado - certificado Multicert
                    if(self.validations(cert_RaizE_Multicert, certRoot)):
                        logging.warning("HEEEEREEEE BIIITCHHH")
                


        # validate signature
        logging.warning("Validating signature..")
        
        try:
            cert.public_key().verify(signature, bytes(str(data), "utf-8"), padding.PKCS1v15(), hashes.SHA1() )
            logging.warning( 'Verification of signature succeeded' )
            return True
        except Exception as e:
            logging.warning(str(e))
            logging.warning( 'Verification of signature failed' )
            return False

    def validations(self, certificate_to_validate, certificate_to_validate_with):
        if (self.verifyCert(certificate_to_validate, certificate_to_validate_with)):
            clr_cert = self.getCLR(certificate_to_validate)
            if self.validateSignature(certificate_to_validate_with, clr_cert):
                if (self.cert_in_crl(certificate_to_validate, clr_cert) == None):
                    logging.warning("Certificate {} validated.".format(certificate_to_validate))
                    return True
            else:
                logging.warning("Certificate {} not validated.".format(certificate_to_validate))
        return False
   
    
    def getCLR(self, certCommonName):
        link = ""
        for extensions in certCommonName.extensions:
            if extensions.oid._name == "cRLDistributionPoints":
                dPoints = extensions.value
                for dPoint in dPoints:
                    link = dPoint.full_name[0].value
        
        logging.warning(link)
        r = requests.get(link)

        # load crl
        try:
            crl = x509.load_pem_x509_crl(r.content, default_backend())
            return crl
        except:
            crl = x509.load_der_x509_crl(r.content, default_backend())
            return crl


    def validateSignature(self, certCommonName, clr_cert):
        return clr_cert.is_signature_valid(certCommonName.public_key())
    
    def cert_in_crl(self, certCommonName, crl):
        return crl.get_revoked_certificate_by_serial_number(certCommonName.serial_number)

    def validateCertClientChain(self, data, message):
        # certificado client - certificado cartao de cidadao 0008
        certClient = "False"
        certCommonName = "False"
        var = bytes(base64.b64decode(message["certificate"]))
        cert = x509.load_der_x509_certificate(var, default_backend())
        certClient = cert.issuer
        for i in certClient:
            logging.warning(i)
            if i.oid._name == "commonName":
                certName = i.value

        logging.warning(cert)    

        path_of_file = ("EC de Autenticacao do Cartao de Cidadao {}.cer").format(certName[-4:])
        try:
            f = open(path_of_file, "rb").read()
            try:
                certCommonName = x509.load_pem_x509_certificate(f, default_backend())
                return cert, certCommonName
            except:
                certCommonName = x509.load_der_x509_certificate(f, default_backend())
                return cert, certCommonName
        except:
            logging.warning("Certificate not found.")
            return cert, certCommonName

    def validateCert2(self, cert_to_validate):
        # certificado cidadao 0008 - certificado cartao de cidadao 002
        certName = ""
        certCartaodeCidadao = ""
        cert_to_validate2 = cert_to_validate.issuer
        for i in cert_to_validate2:
            logging.warning(i)
            if i.oid._name == "commonName":
                certName = i.value

        logging.warning(cert_to_validate2)    

        path_of_file = ("Cartao de Cidadao {}.cer").format(certName[-3:])
        try:
            f = open(path_of_file, "rb").read()
            try:
                certCartaodeCidadao = x509.load_pem_x509_certificate(f, default_backend())
                return cert_to_validate, certCartaodeCidadao
            except:
                certCartaodeCidadao = x509.load_der_x509_certificate(f, default_backend())
                return cert_to_validate, certCartaodeCidadao
        except:
            logging.warning("Certificate not found.")
            return cert_to_validate, certCartaodeCidadao

    def validateCert2emeio(self, cert_to_validate):
        # certificado carttao cidadao 002 - certificado ECRaizEstado
        certName = ""
        certCartaodeCidadao = ""
        cert_to_validate2 = cert_to_validate.issuer
        for i in cert_to_validate2:
            logging.warning(i)
            if i.oid._name == "commonName":
                certName = i.value

        logging.warning(cert_to_validate2)    

        path_of_file = ("ECRaizEstado-Multicert.cer")
        try:
            f = open(path_of_file, "rb").read()
            try:
                certCartaodeCidadao = x509.load_pem_x509_certificate(f, default_backend())
                return cert_to_validate, certCartaodeCidadao
            except:
                certCartaodeCidadao = x509.load_der_x509_certificate(f, default_backend())
                return cert_to_validate, certCartaodeCidadao
        except:
            logging.warning("Certificate not found.")
            return cert_to_validate, certCartaodeCidadao

    
    def validateCert3(self, cert_to_validate):
        # certificado ECRaizEstado - certificado Multicert
        certName = ""
        certRoot = ""
        cert_to_validate2 = cert_to_validate.issuer
        for i in cert_to_validate2:
            logging.warning(i)
            if i.oid._name == "commonName":
                certName = i.value
        logging.warning("THIS IS THE ISSUER OF THE BALTIMORE CERT!!!!:")
        logging.warning(cert_to_validate)
        logging.warning("OR IS IT THIIIS ONEEE????!!!:")
        logging.warning(certName)

        path_of_file = ("MCRootCA.cer")
        try:
            f = open(path_of_file, "rb").read()
            try:
                certRoot = x509.load_pem_x509_certificate(f, default_backend())
                return cert_to_validate, certRoot
            except:
                certRoot = x509.load_der_x509_certificate(f, default_backend())
                return cert_to_validate, certRoot
        except:
            logging.warning("Certificate not found.")
            return cert_to_validate, certRoot

    
    def verifyCert(self, certClient, certCommonName):
        logging.warning(certClient)
        logging.warning(certCommonName)
        certCommonName.public_key().verify(certClient.signature, certClient.tbs_certificate_bytes, padding.PKCS1v15(), certClient.signature_hash_algorithm)
        return True
