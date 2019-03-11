
from auctionClient_actions import *
import time, sys


class Client:

    def __init__(self):
        self.client_actions = ClientActions()
        self.loop()


    def loop(self):

        while True:
            print("\nChoose an action:")
            print("1 - Trade shared secret with manager")
            print("2 - Request an auction")
            print("3 - Make a bid")
            print("4 - Close connection")
            print(">>")
            try:
                op = int(input())
            except KeyboardInterrupt:
                print("Press CTRL-C again within 2 seconds to quit")
                time.sleep(2)
                sys.exit(2)
            if((op != 1) and (op != 2) and (op != 3) and (op != 4)):
                    print("Something went wrong! Try again please.")              
            else:
                if op == 1:
                    print("Not done yet")
                elif op == 2:
                    self.createAuctionReq()
                elif op == 3:
                    self.makeBidReq()
                elif op == 4:
                    print("Not done yet")
                    #self.close()
                else:
                    print("Unkown option! Please try again.")

    
        

    def createAuctionReq(self):
        print("There is some parameters to complete first.\n")
        # auction name handling
        tmp = True
        print("Name of the auction (it should start with a letter but there is no confirmation yet ahah and len < 12 characters): ")
        while tmp:
            print(">>")
            try:
                auctionName = input()
            except KeyboardInterrupt:
                print("Press CTRL-C again within 2 seconds to quit")
                time.sleep(2)
                sys.exit(2)
            except:
                print("ERROR: auction name is incorrect! Try again.")
            else:
                if(len(auctionName) <= 12):
                    print("You chose %s to be the name of the autcion." % auctionName)
                    tmp = False
                else:
                    print("ERROR: auction name must have less than 12 characers! Try again.")
        # aucion type handling
        type1 = "English Auction"
        type2 = "Blind Auction"
        print("Choose a type of auction:")
        print("1 - English auction - open ascending price")
        print("2 - Blind auction - value of bids are hiden")
        tmp = True
        while tmp:
            print(">>")
            try:
                auctionType = int(input())
            except KeyboardInterrupt:
                print("Press CTRL-C again within 2 seconds to quit")
                time.sleep(2)
                sys.exit(2)
            except:
                print("ERROR: choose type '1' or '2'.")
            else:
                if((auctionType != 1) and (auctionType != 2)):
                    print("ERROR: type must be '1' or '2'! Try again.")
                else:
                    if(auctionType == 1):
                        print("You choose %s to be the type of the autcion." % type1)
                    elif(auctionType == 2):
                        print("You choose %s to be the type of the autcion." % type2)
                    tmp = False


        # auction time handling
        ########### TO DO ############

        # short description handling
        print("Add a short description to the aucion please (40 characters or less).")
        print("Press Enter to finish.")
        tmp = True
        while tmp:
            print(">>")
            try:
                auctionDescription = input()
            except KeyboardInterrupt:
                print("Press CTRL-C again within 2 seconds to quit")
                time.sleep(2)
                sys.exit(2)
            except:
                print("ERROR: something went wrong! Try again")
            finally:
                if(len(auctionDescription) > 40):
                    print("ERROR: Description too long or too short! Try again.")
                else:
                    print("A description has been added to your request!")
                    tmp = False


        info = {"name": auctionName, "id": "auction_creation", "type": auctionType, "bidBase": 0,
                            "time": "", "description": auctionDescription }

        
        # get signature, pub key and certificate of client
        # signature --> sha1_rsa(sign(data, priv key))
        print("Before sending message you must sign it! Insert a smartcard.")
        signatureOfClient, certificateOfClient = self.client_actions.authenticateFirst(info)
        print(signatureOfClient)
        signatureOfClientb64 = base64.b64encode(signatureOfClient)
        certificateOfClientb64 = base64.b64encode(certificateOfClient)

        auctionRequest = {"info": info, "signature": signatureOfClientb64.decode('utf-8'), "certificate": certificateOfClientb64.decode('utf-8') }
        print(auctionRequest)
        # send file to auction manager
        self.client_actions.sendRequestAndWait("manager", auctionRequest)

    def makeBidReq(self):
        print("First you need to solve a cryptopuzzle. Sending request to repository!")
        #cryptopuzzleRequest = {"id": "cryptopuzzle"}
        sendMessage = {"info": {"id": "cryptopuzzle"}}
        self.client_actions.sendRequestAndWait("repository", sendMessage)





if __name__ == "__main__":
    
    try:
        c = Client()
    except KeyboardInterrupt:
        print("\n")
        try:
            print("Press CTRL-C again within 2 seconds to quit")
            time.sleep(2)
            sys.exit(2)
        except KeyboardInterrupt:
            print("CTRL-C pressed twice: Quitting!")
