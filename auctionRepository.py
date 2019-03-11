from auctionRepository_actions import RepositoryActions
import logging
import sys
import time

class Repository:
    def __init__(self):
        self.repository_actions = RepositoryActions()

    def start(self):
        self.repository_actions.startConnections()

    def stop(self):
        self.repository_actions.stopConnections()

if __name__ == "__main__":
    
    try:
        m = Repository()
        m.start()
    except KeyboardInterrupt:
        print("\n")
        try:
            print("Press CTRL-C again within 2 seconds to quit")
            time.sleep(2)
            sys.exit(2)
        except KeyboardInterrupt:
            print("CTRL-C pressed twice: Quitting!")