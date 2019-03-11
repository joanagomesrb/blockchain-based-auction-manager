from auctionManager_actions import ManagerActions
import logging
import sys
import time

class Manager:
    def __init__(self):
        self.manager_actions = ManagerActions()

    def start(self):
        self.manager_actions.startConnections()

    def stop(self):
        self.manager_actions.stopConnections()

if __name__ == "__main__":
    
    try:
        m = Manager()
        m.start()
    except KeyboardInterrupt:
        print("\n")
        try:
            print("Press CTRL-C again within 2 seconds to quit")
            time.sleep(2)
            sys.exit(2)
        except KeyboardInterrupt:
            print("CTRL-C pressed twice: Quitting!")


