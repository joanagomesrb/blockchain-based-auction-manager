from rsa_cypher import RSACypher
from authentication_utils import Authentication_utils
import logging
import socket
import json
import base64
import requests
import binascii

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    padding, rsa, utils
)

from PyKCS11 import *
pkcs11 = PyKCS11Lib()
pkcs11.load('/usr/local/lib/libpteidpkcs11.so')


LOCAL_IP = "127.0.0.1"
PORT_MAN = 8081 # The manager server port
PORT_REP = 8082 # The repository server port


class ManagerActions:
    def __init__(self):
        self.__stop_listening = False
        self.rsa_cypher = RSACypher()
        self.waitingList = list()
        self.public_key = ""
        self.private_key = ""
        self.auctions = dict()
        self.authentication_module = Authentication_utils()

    def startConnections(self):
        self.public_key, self.private_key = self.rsa_cypher.generate_key_pair("Manager")
        self.startListening()
        
    def stopConnections(self):
        logging.warning("Manager is going to stop listening...")
        self.__stop_listening = True

    def startListening(self):
        self.ip = LOCAL_IP
        self.port = PORT_MAN
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        serverAddress = (self.ip, self.port)

        logging.warning("Manager is trying to listening on {0}:{1}".format(self.ip, PORT_MAN))

        self.socket.bind(serverAddress)

        self.loop()

    def loop(self):

        while True:
            if(self.__stop_listening and self.waitingList is []):
                logging.warning("Manager is not listening.")
                return None
            elif(self.waitingList):
                logging.warning(self.waitingList)         
                rawData, address = self.waitingList[0]
                del self.waitingList[0]
            else:
                logging.warning("Manager is listening!")
                self.socket.settimeout(None)
                rawData, address = self.socket.recvfrom(8192)

            decodedData = rawData.decode()
            message = json.loads(decodedData)
            data = message["info"]

            logging.warning(str(data).encode("UTF-8"))
            
            logging.warning("Received {} bytes from {}".format(len(rawData), address))

            if rawData:
                var = 0
                react_as = None
                
                # first authenticate client
                if self.authentication_module.authenticateClient(data, message):
                    if data["id"] == "auction_creation":
                            react_as = self.handleAuctionCreationRequest(data, message)
                        #data["id"] = "finish action"                    
                    # elif data["id"] == "response_to_auction_request":
                    #     logging.warning("received message from repository")
                    #     react_as = True
                    elif data["id"] == "bid":
                        react_as = self.handleBidValidationRequest(data, message)
                    else:
                        logging.error("Unkown operation id.")
                    
                    if var == 0:
                        if react_as != None:
                            logging.warning("sending data that is %s", react_as)
                            self.socket.sendto(json.dumps(react_as).encode(), address)
                        else:
                            logging.error("Something went wrong. Ups..")
                else:
                    logging.error("Disconecting client..")

    def validateSignature(self, data, message):
        
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


    def handleAuctionCreationRequest(self, data, message):

        # id tem de ser createAuction
        #data["id"] = "createAuction"
        self.auctions[data["name"]] = 0
        msg_to_send = data
        logging.warning(message)

        msg = self.signMessage(msg_to_send)


        msg_to_send2 = self.sendReqtoRep(msg)
        return msg_to_send2

    def handleBidValidationRequest(self, data, message):
        if data["name"] in self.auctions.keys():
            logging.warning("AQUI")
            if self.auctions[data["name"]] < data["value"]:
                logging.warning("OU AQUI")
                self.auctions[data["name"]] = data["value"]
                message_to_send = self.signMessage(message)
                return message_to_send
        return "not valid"

    def signMessage(self, message):

        message_inBytes = bytes(str(message), 'utf-8')
        signature = self.private_key.sign(
                                    message_inBytes,
                                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                    hashes.SHA256()
                                    )

        logging.warning(type(signature))
        signature_b64 = base64.b64encode(signature).decode("utf-8")


        send_message = {"info": message, "signature_of_manager": signature_b64}

        return send_message


    def sendReqtoRep(self, message):
        var = True
        self.socket.sendto(json.dumps(message).encode(), (LOCAL_IP, PORT_REP))

        while var:
            rawData, address = self.socket.recvfrom(4096)
            logging.warning("HERE1")
            if(address != ("127.0.0.1", PORT_REP)):
                logging.warning("HERE2")
                self.waitingList.append((rawData,address))
                continue
            logging.warning("HERE3")
            decodedData = rawData.decode()
            data1 = json.loads(decodedData)
            logging.warning("Received {} bytes from {}".format(len(rawData), address))
            data0 = data1["info"]
            data = data0["info"]
            logging.warning(data1)

            var = False
            if rawData:
                react_as = None
                if data["id"] == "auction_creation":
                    if(self.validateSignature(data, data1)):
                        data["id"] == "auction_creation"
                        react_as = True
                else:
                    logging.error("Unkown operation id.")

                if react_as != None:
                    logging.warning("Auction request concluded")
                    return data1
                else:
                    logging.error("Something went wrong. Ups..")