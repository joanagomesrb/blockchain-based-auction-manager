# Blockchain based Auction Manager

Project developed for academic purposes in the context of the subject Segurança at Universidade de Aveiro.

The objective of this project is to develop a system enabling users to create and participate in auctions. The system is composed by an auction manager,
an auction repository and client applications. The system supports the following security features:

* Bids’ confidentiality, integrity and authentication: Bids may contain secret material which can only be disclosed in special occasions, cannot be modified once accepted and cannot be forged on someone else’s behalf; 

* Bid acceptance control and confirmation: bids can only be accepted if fulfilling special criteria (in terms of structure), a source quenching mechanism must be used to reduce the amount of submitted bids, and accepted bids are unequivocally confirmed as such;

* Bid author identity and anonymity: Bids should be linked to subjects using their Portuguese Citizen Card. However, submitted
bids should remain anonymous until the end of the auction.

* Honesty assurance: The auction repository must provide public access to all auctions and their bids, either finished or still active, and provide evidences of its honesty on each answer to a client request. Furthermore, the auction repository cannot have access to any kind of information that may enable it to act differently to different clients.

## Auction Manager

This server exposes a connection endpoint through which clients can exchange structured requests/responses with it.
The Auction Manager is the system component that creates an auction upon a client request. Upon such request, the Action Manager instantiates a new auction in the Auction Repository. The Auction Manager is also the component that may perform special bid
validations requested by the auction creator.

## Auction Repository

This server exposes a connection endpoint through which clients can exchange structured requests/responses with it.
This component stores a list of auctions. Each auction is implemented by a blockchain, with a bid per block.
The Auction Repository closes an active auction upon a request made by the Auction Manager or upon reaching the auction’s time limit.
Clients send new bids directly to the Auction Repository. The rate at which bids are sent can be controlled by a mechanism called cryptopuzzle, or proof-of-work.

## Auction Client
An Auction Client is an application that interacts with a user, enabling they to create and participate in auctions. This application needs to interact with the user Citizen Card in order to authenticate auction creation/termination requests or bids.
For each bid added to an auction, the Auction Client stores its receipt in non-volatile memory for an à posteriori validation. This is fundamental for preventing both servers from cheating by manipulating the sequence of bids in a auction.

## Dependencies:
* [cryptography](https://cryptography.io): ciphers, encryption, decryption, key support, etc
* [PyKCS11](https://bitbucket.org/PyKCS11/pykcs11): PKCS\#11 python interface for smart card
