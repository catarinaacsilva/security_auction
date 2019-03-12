# coding: utf-8

import sqlite3
import logging


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('RDB')
logger.setLevel(logging.DEBUG)


class MDB:
    def __init__(self, path='src/auction_manager/manager.db'):
        self.db = sqlite3.connect(path)

    def store_auction(self, user_cc, auction_id, code=None):
        cursor = self.db.cursor()
        cursor.execute('INSERT INTO auctions(cc, auction_id) VALUES (?,?)', (user_cc, auction_id))
        if code is not None:
            cursor.execute('INSERT INTO codes(auction_id, code) VALUES (?,?)', (auction_id, code))
        self.db.commit()

    def store_secret(self, auction_id, sequence, secret, identity):
        cursor = self.db.cursor()
        cursor.execute('INSERT INTO bids(auction_id, sequence, secret, identity) VALUES (?,?,?,?)', (auction_id, sequence, secret, identity))
        self.db.commit()

    def get_secrets(self, auction_id):
        cursor = self.db.cursor()
        cursor.execute('SELECT auction_id, sequence, secret FROM bids WHERE auction_id = ?', (auction_id,))
        return cursor.fetchall()
    
    def get_secret(self, auction_id, sequence):
        cursor = self.db.cursor()
        cursor.execute('SELECT secret FROM bids WHERE auction_id = ? AND sequence = ?', (auction_id, sequence))
        return cursor.fetchone()[0]

    def times(self, auction_id, identity):
        cursor = self.db.cursor()
        cursor.execute('SELECT COUNT(*) FROM bids WHERE auction_id = ? AND identity = ?', (auction_id, identity))
        rv = cursor.fetchone()
        return rv[0]

    def get_code(self, auction_id):
        cursor = self.db.cursor()
        cursor.execute('SELECT code FROM codes WHERE auction_id = ?', (auction_id,))
        return cursor.fetchone()

    def get_owner(self, auction_id):
        cursor = self.db.cursor()
        cursor.execute('SELECT cc FROM auctions WHERE auction_id = ?', (auction_id, ))
        return cursor.fetchone()[0]

    def close(self):
        self.db.commit()
        self.db.close()
