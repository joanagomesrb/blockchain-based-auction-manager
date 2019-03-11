
from rsa_cypher import RSACypher
import logging
import socket
import json
import base64

import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import (
    padding, rsa, utils
)
from PyKCS11 import *

pkcs11 = PyKCS11Lib()
pkcs11.load('/usr/local/lib/libpteidpkcs11.so')

LOCAL_IP = "127.0.0.1"
PORT_MAN = 8081 # The manager server port
PORT_REP = 8082 # The repository server port

class ClientActions:

    def __init__(self):
        logging.info("Connecting a client")
        self.rsa_cypher = RSACypher()
        self.receipt_identificator = 0

    def authenticateFirst(self, data):
        slots = pkcs11.getSlotList()
        for slot in slots:
            if 'CARTAO DE CIDADAO' in pkcs11.getTokenInfo( slot ).label:
                datainbytes = bytes(str(data), 'utf-8')

                session = pkcs11.openSession( slot )
                privKey = session.findObjects([( CKA_CLASS, CKO_PRIVATE_KEY),(CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
                
                signature = bytes(session.sign( privKey, datainbytes, Mechanism(CKM_SHA1_RSA_PKCS)))

                certificate = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE), (CKA_LABEL, "CITIZEN AUTHENTICATION CERTIFICATE")])[0]
                certDer = bytes(session.getAttributeValue(certificate, [CKA_VALUE], True )[0])

                session.closeSession()
        return signature, certDer

    def sendRequestAndWait(self, target, data):
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        if(target == "manager"):
            sendTo = "auctionManager"
            serverToSend = (LOCAL_IP, PORT_MAN)
        #elif(target == "repository"):
        else:
            sendTo = "auctionRepository"
            serverToSend = (LOCAL_IP, PORT_REP)


        try:
            send_data_as_string = json.dumps(data)
            logging.warning("Sending {} bytes to {}".format(len(send_data_as_string), str(serverToSend)))

            sendBytes = self.__socket.sendto(send_data_as_string.encode("UTF-8"), serverToSend)

            self.__socket.settimeout(3)
            recv_data, server = self.__socket.recvfrom(4096)
            logging.warning("Received {!r} from {}".format(recv_data, server))

            if(server == ('127.0.0.1', PORT_MAN)):
                decodedData = recv_data.decode()
                data1 = json.loads(decodedData)
                data0 = data1["info"]
                data = data0["info"]
            elif(server == ('127.0.0.1', PORT_REP)):
                    decodedData = recv_data.decode()
                    data2 = json.loads(decodedData)
                    logging.warning("AM I HERE")
                    try:
                        data1 = data2["info"]
                        data0 = data1["info"]
                        data = data0["info"]
                    except:
                        data = data2
    
            logging.warning(data)
            

            if recv_data:
                react_as = None
                if(data["id"] == "cryptopuzzle_to_solve"):
                    react_as = self.solve_cryptopuzzle(data)
                    return True
                if(data["id"] == "bid"):
                    logging.warning("AQUUAUAIIIII!!!")
                    if(self.validateSignature(data0, data2)):
                        react_as = "bid finished"
                        logging.warning("Signature validated, saving receipt..")
                        self.saveReceipt(data2["info"])
                        return True
                elif(data["id"]) == "finish action":
                    react_as = True
                elif(data["id"] == "auction_creation"):
                    if(self.validateSignature(data0, data1)):
                        react_as = "bid finished"
                        return True
                else:
                    logging.error("Unkown operation id.")
                
                if(react_as == "bid finished"):
                    return True
                elif(react_as != None) and (react_as != "bid finished"):
                    return True
                else:
                    logging.error("Something went wrong. Ups..")

            # if recv_data != None:
            #     return json.loads(recv_data)
        
        except socket.timeout as e:
            logging.error("No response from server, closing socket.")
        # finally:
        #     self.__socket.close()
        #     logging.warning("Socket closed")
        
        return None

    def validateSignature(self, data, message):

        logging.warning(data)
        logging.warning(message)
        info1 = message["info"]
        message_inBytes = bytes(str(info1),"utf-8")
        signatureb = base64.b64decode(message["signature_of_repository"])
        
        
        public_key = self.rsa_cypher.load_public_key("repository")
        
        var = public_key.verify(    signatureb,
                                    message_inBytes,
                                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                salt_length=padding.PSS.MAX_LENGTH),
                                    hashes.SHA256())
        
        return True

    def solve_cryptopuzzle(self, data):
        logging.warning("Solving puzzle")
        result = "something"
        self.makeBid(result)
        return True

    def makeBid(self, proof):
        # Choose auction
        # How much to bet
        name = input("Name: ")
        value = int(input("Bid: "))
        bid = {"name": name, "id": "bid", "value": value, "cryptopuzzle_result": proof}

        logging.warning("Signing message...")

        signatureOfClient, certificateOfClient = self.authenticateFirst(bid)
        signatureOfClientb64 = base64.b64encode(signatureOfClient)
        certificateOfClientb64 = base64.b64encode(certificateOfClient)
        
        bid_to_send = {"info": bid, "signature": signatureOfClientb64.decode('utf-8'), "certificate": certificateOfClientb64.decode('utf-8')}
        
        stat = self.sendBid(bid_to_send)
        return True

    def sendBid(self, bid_to_send):
        logging.warning("SENDING BID...")
        self.sendRequestAndWait("Repository", bid_to_send)
        return True

    def saveReceipt(self, data):
        self.receipt_identificator += 1
        name_of_file = ("receipt_{}.txt").format(self.receipt_identificator)
        f = open(name_of_file, "w")
        f.write(str(data))
        f.close