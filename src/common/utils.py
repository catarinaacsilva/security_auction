# coding: utf-8

import os
import sys
import base64
import time
import datetime
import json
import logging
from Crypto.Hash import SHA256
from threading import Thread, Event
from datetime import datetime, timedelta
import dateutil.parser


colors = {'blue': '\033[94m', 'pink': '\033[95m', 'green': '\033[92m', 'red' : '\033[91m'}


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def toBase64(content):
    '''
    Converts content to base64 in order to send to server
    '''
    return base64.urlsafe_b64encode(content).decode()


def validate_blockchain(bids, seed):
    '''
    Validate BlockChain of Bids
    '''

    prev_hash = bids[0]["PREV_HASH"]
    for bid in bids[1:]:
        bid.pop('KEY', None)
        hash = SHA256.new(data=json.dumps(bid).encode("UTF-8")).hexdigest()
        if prev_hash != hash : return False
        prev_hash = bid["PREV_HASH"]

    return True if prev_hash == seed else False


def fromBase64(base64string):
    '''
    Decodes base64 content received from server
    '''
    return base64.urlsafe_b64decode(base64string)


def actual_timestamp():
    '''
    Returns actual timestamp
    '''
    return time.time()


def print_timer(dt_str, lines):
    '''
    Prints a timer
    '''
    while True:
        sys.stdout.write("\033[s")
        dt = dateutil.parser.parse(dt_str)
        seconds = (dt - datetime.now()).total_seconds()
        clean(lines = lines)
        if seconds <= 0:
            print(colorize('ENDS IN:        ', 'pink') + colorize('AUCTION ENDED', 'red'))
            sys.stdout.write("\033[u")
            sys.stdout.flush()
            time.sleep(0.5)
            break
        print(colorize('ENDS IN:        ', 'pink') + str(timedelta(seconds=seconds)))
        sys.stdout.write("\033[u")
        sys.stdout.flush()
        time.sleep(0.5)


def clean(clean = False, lines = 2):
    '''
    Cleans previous lines on terminal
    '''
    if clean:
        sys.stdout.write("\033[K")
        sys.stdout.flush()
        return
    sys.stdout.write("\033[" + str(lines) + "F")
    sys.stdout.write("\033[K")
    sys.stdout.flush()


def colorize(string, color):
    '''
    Colorize String For Terminal
    '''
    if not color in colors: return string
    return colors[color] + string + '\033[0m'


# Check if a number is positive (greater than zero)
def check_positive_number(number):
    return number > 0


# Check if a int port number is valid
# Valid is bigger than base port number
def check_port(port, base=1024):
    ivalue = int(port)
    if ivalue <= base:
        raise argparse.ArgumentTypeError("%s is an invalid positive int value" % value)
    return ivalue


# Load raw file from disk
# Used to load the keys pairs from the disk
def load_file_raw(path):
    with open(path, 'rb') as f: content = f.read()
    return content

# classe para gerir as ligações dos multiplos clientes
class OpenConnections:
    def __init__(self):
        self.openConns = {}

    def add(self, data):
        nonce = os.urandom(16)
        self.openConns[nonce] = data
        return nonce

    def value(self, key):
        return self.openConns.get(key, None)

    def pop(self, nonce):
        return self.openConns.pop(nonce, None)

    def __str__(self):
        return self.openConns.__str__()

    def __repr__(self):
        return self.openConns.__repr__()


# Periodic Jobs
# Run a function (func) every period (in seconds)
class PeriodicJob(Thread):
    def __init__(self, period, func, args=[], kwargs={}):
        Thread.__init__(self)
        self.daemon = False
        self.stopped = Event()
        self.period = period
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.t = time.time()
        self.count = 1

    def stop(self):
        self.stopped.set()
        self.join()

    def run(self):
        wait_time = max(self.t + self.count * self.period - time.time(), 0)
        while not self.stopped.wait(wait_time):
            self.func(*self.args, **self.kwargs)
            self.count += 1
            wait_time = max(self.t + self.count * self.period - time.time(), 0)

# Socket class that delays offers from bids
# It checks for ACTION equals to  OFFER and RECEIPT
# in order to delay of advance bid offers
class DelaySocket:
    def __init__(self, sock, b_size=8192):
        self.sock = sock
        self.cache = {}
        self.auction_pending = set()
        self.b_size = b_size
        self.logger = logging.getLogger('DS')
        self.logger.setLevel(logging.DEBUG)

    def recvfrom(self):
        if self.cache:
            blocked_auctions = self.cache.keys()
            valid_auctions = [x for x in blocked_auctions if x not in self.auction_pending]
            if len(valid_auctions) > 0:
                auction_id = valid_auctions[0]
                bids = self.cache[auction_id]
                msg = bids.pop()
                if len(bids) == 0:
                    self.cache.pop(auction_id)
                    self.logger.debug('Pending Bid for Auction %d', auction_id)
                return msg
        done = False
        msg = None
        while not done:
            self.logger.debug('Waiting on UDP scoket...')
            data, addr = self.sock.recvfrom(self.b_size)
            j = json.loads(data)
            if j['ACTION'] == 'OFFER':
                auction_id = int(j['MESSAGE']['AUCTION'])
                if auction_id in self.auction_pending:
                    self.logger.debug('Delay Bid for Auction %d', auction_id)
                    if auction_id in self.cache:
                        self.cache[auction_id] = [(j, addr)]
                    else:
                        self.cache[auction_id].append((j, addr))
                else:
                    self.logger.debug('Non OFFER action...')
                    done = True
                    msg = (j, addr)
            else:
                self.logger.debug('Non OFFER action...')
                done = True
                msg = (j, addr)
        return msg

    def sendto(self, msg, addr):
        if msg['ACTION'] == 'RECEIPT':
            auction_id = msg['AUCTION_ID']
            if auction_id in self.auction_pending:
                self.auction_pending.remove(auction_id)
                self.logger.debug('Auction $d no longer blocked...', auction_id)
        self.sock.sendto(json.dumps(msg).encode('UTF-8'), addr)
