# encoding: utf-8
#from time import time
import json, hashlib
import time

class Blockchain:
    def __init__(self, aN, aT="english"):
        self.auctionName = aN
        self.chain = []
        self.auctionType = aT

        self.newBlock(2, 1, 0, "None")
    
    #def nameToString(self):
     #   return 

    def newBlock(self, proof, previousHash, bidValue, bidAuthor):

        block = { "index": len(self.chain) + 1, "timestamp": time.time(), "proof": proof,
                    "previous_hash": previousHash or self.hashFunction(self.chain[-1]), "bid_value": bidValue, "bid_author": bidAuthor}
        self.chain.append(block)
        return block
    
    def validatedChain(self, chain):
        
        idx = 0
        last_block = chain[0]
        while idx < len(chain):
            currentBlock = chain[idx]
            hashOfLBlock = self.hashFunction(last_block)
            if(hashOfLBlock != currentBlock['previou_hash']):
                return False
            elif not self.valid_proof(last_block['proof'], currentBlock['proof'], hashOfLBlock):
                return False
            else:
                last_block = currentBlock
                idx += 1
        return True


    def hashFunction(self, block):

        block_asString = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_asString).hexdigest()

    # cryptopuzzle or proof of work
    def proof_of_work(self, last_block):
  
        last_proof = last_block['proof']
        last_hash = self.hashFunction(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    # validation of the cryptopuzzle or proof of work
    @staticmethod
    def valid_proof(last_proof, proof, last_hash):

        guess = ("{}{}{}".format(last_proof, proof, last_hash)).encode()
        #guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

