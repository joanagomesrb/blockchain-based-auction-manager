from rsa_cypher import RSACypher
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import (
    padding, rsa, utils
)
import logging
import socket
import json
import base64
import binascii

from auction_blockchain import *

from PyKCS11 import *
pkcs11 = PyKCS11Lib()
pkcs11.load('/usr/local/lib/libpteidpkcs11.so')

LOCAL_IP = "127.0.0.1"
PORT_MAN = 8081 # The Manager server port
PORT_REP = 8082 # The repository server port


class RepositoryActions:
    def __init__(self):
        self.__stop_listening = False
        self.auctionsChain = []
        self.rsa_cypher = RSACypher()
        self.public_key = ""
        self.private_key = ""
        self.waitingList = list()
        

    def startConnections(self):
        self.public_key, self.private_key = self.rsa_cypher.generate_key_pair("Repository")
        self.startListening()
        
    def stopConnections(self):
        logging.warning("Repository is going to stop listening...")
        self.__stop_listening = True

    def sendReqtoManager(self, message):
        var = True
        self.socket.sendto(json.dumps(message).encode(), (LOCAL_IP, PORT_MAN))
        react_as = False
        while var:
            rawData, address = self.socket.recvfrom(8192)
            if(address != ("127.0.0.1", PORT_MAN)):
                self.waitingList.append((rawData,address))
                continue
            decodedData = rawData.decode()
            data0 = json.loads(decodedData)
            logging.warning(data0)
            data1 = data0["info"]
            data = data1["info"]

            var = False
            if rawData:
                react_as = None
                if data["id"] == "bid":
                    react_as = data0
                else:
                    logging.error("Unkown operation id.")

                if react_as != None:
                    logging.warning("Repository request concluded")
                else:
                    logging.error("Something went wrong. Ups..")
        return react_as

    def startListening(self):
        self.ip = LOCAL_IP
        self.port = PORT_REP
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        serverAddress = (self.ip, self.port)

        logging.warning("Repository is trying to listening on {0}:{1}".format(self.ip, PORT_REP))

        self.socket.bind(serverAddress)

        self.loop()

    def loop(self):

        while True:
            if self.__stop_listening and self.waitingList is []:
                logging.warning("Repository is not listening.")
                return None
            elif(self.waitingList):                
                rawData, address = self.waitingList[0]
                del self.waitingList[0]
            else:
                logging.warning("Repository is listening!")
                self.socket.settimeout(None)
                rawData, address = self.socket.recvfrom(4096)

            decodedData = rawData.decode()
            message = json.loads(decodedData)
            logging.warning(message)
            data = message["info"]
            logging.warning(data)
            
            logging.warning("Received {} bytes from {}".format(len(rawData), address))

            if rawData:
                react_as = None
                if data["id"] == "cryptopuzzle":
                    react_as = self.sendCryptopuzzle(data)
                elif data["id"] == "auction_creation":
                    if(self.validateSignature(data, message)):
                        react_as = self.handleAuctionCreationRequest(data, message)
                elif data["id"] == "bid":
                    #must validate signature of client
                    #must validate cryptopuzzle solution
                    react_as = self.handleBidCreationRequest(data, message)
                else:
                    logging.error("Unkown operation id.")

                if react_as != None:
                    self.socket.sendto(json.dumps(react_as).encode(), address)
                    logging.warning("sending message to %s ...", address)
                else:
                    logging.error("Something went wrong. Ups..")

    def validateSignature(self, data, message):
        message_inBytes = bytes(str(data),"utf-8")
        signatureb = base64.b64decode(message["signature_of_manager"])
        
        public_key = self.rsa_cypher.load_public_key("manager")
        try:
            var = public_key.verify(    signatureb,
                                        message_inBytes,
                                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                    salt_length=padding.PSS.MAX_LENGTH),
                                        hashes.SHA256())
            logging.warning("Signature validated.")
            return True
        except:
            logging.warning("Signature invalid")
        
        return False
        
    
    def sendCryptopuzzle(self, data):
        logging.warning("sendCryptopuzzle func")
        this_is_cryptopuzzle = {"id": "cryptopuzzle_to_solve"}
        return this_is_cryptopuzzle

    def handleAuctionCreationRequest(self, data, message):
        logging.warning("handleAuctionCreationRequest")
        #actually create an auction blockchain
        if(len(self.auctionsChain) >= 1):
            for chain in self.auctionsChain:
                if(data["name"] == chain.auctionName):
                    logging.warning("Auction name %s already exists! Request denied and discarded." %(data["name"]))
                    return False
            
        newBlockchain = Blockchain(data["name"])
        self.auctionsChain.append(newBlockchain)
        logging.warning("Auction with the name %s was created successufly!" %(data["name"]))
        msg_to_return = self.signMessage(message)
        logging.warning(msg_to_return)
        return msg_to_return

    def handleBidCreationRequest(self, data, message):
        logging.warning("handleBidCreationRequest")
        #actually create an bid on auction blockchain
        if(len(self.auctionsChain) >= 1):
            for blockchain in self.auctionsChain:
                if(data["name"] == blockchain.auctionName):
                    if blockchain.auctionType == "english":
                        state = self.sendReqtoManager(message)
                        logging.warning("PRINTING STATE; AFTER COMMING FROM MANAGER")
                        logging.warning(state)
                        if(state):
                            blockchain.newBlock(data["cryptopuzzle_result"], blockchain.chain[-1]["previous_hash"], data["value"], message["signature"])
                            msg_to_send = self.signMessage(state)                            
                            logging.warning("Bid to auction name %s was created successufly!" %(data["name"]))
                            return msg_to_send
                    else:
                        #criar blind
                        pass
        
        logging.warning("Bid to auction name %s was unsuccessufly!" %(data["name"]))
        return {"id": "Unsuccessufly"}


    def signMessage(self, message):
       
        message_inBytes = bytes(str(message), 'utf-8')
        signature = self.private_key.sign(
                                    message_inBytes,
                                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                    hashes.SHA256()
                                    )

        signature_b64 = base64.b64encode(signature)

        send_message = {"info": message, "signature_of_repository": signature_b64.decode('utf-8')}
        return send_message
        

    def authenticateClient(self, data, message):
        slots = pkcs11.getSlotList()
        for slot in slots:
            session = pkcs11.openSession( slot )
            pubKeyHandle = session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY),(CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
            pubKeyDer = session.getAttributeValue( pubKeyHandle, [CKA_VALUE], True )[0]
            session.closeSession

            pubKey = load_der_public_key( bytes(pubKeyDer), default_backend() )

            signature = base64.b64decode(message["signature"])
        try:
            pubKey.verify( signature, bytes(str(data), "utf-8"), padding.PKCS1v15(), hashes.SHA1() )
            logging.warning( 'Verification of authenticity succeeded' )
            return True
        except Exception as e:
            logging.warning(str(e))
            logging.warning( 'Verification authenticity failed' )
            return False
