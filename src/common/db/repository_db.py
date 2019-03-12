# coding: utf-8

import sqlite3
import logging
import json
import os
from datetime import datetime, timedelta
from Crypto.Hash import SHA256
from ..cryptmanager import *
from ..utils import fromBase64, toBase64


logging.basicConfig(level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('RDB')
logger.setLevel(logging.DEBUG)


class RDB:
    def __init__(self, path='src/auction_repository/repository.db'):
        self.db = sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES)

    def store_auction(self, title, desc, atype, subtype, duration):
        start = datetime.now()
        stop = (start + timedelta(seconds=duration)) if duration > 0 else 0
        cursor = self.db.cursor()
        # Seed para a primeira bid usar na hash (blockchain)
        seed = os.urandom(32).hex()
        cursor.execute('INSERT INTO auctions(title, desc, type, subtype, duration, start, stop, seed) VALUES(?,?,?,?,?,?,?,?)',
                (title, desc, atype, subtype, duration, start, stop, seed))
        rv = cursor.lastrowid
        self.db.commit()
        return rv

    def list_auctions(self):
        cursor = self.db.cursor()
        cursor.execute('SELECT * FROM auctions ORDER BY open DESC')
        return cursor.fetchall()

    def get_auctions(self, auction_ids):
        cursor = self.db.cursor()
        placeholder= '?'
        placeholders= ', '.join(placeholder for id in auction_ids)
        query = 'SELECT * FROM auctions WHERE id IN (%s)' % placeholders
        cursor.execute(query, auction_ids)
        return cursor.fetchall()

    def get_bid(self, auction_id, sequence):
        cursor = self.db.cursor()
        cursor.execute('SELECT * FROM bids WHERE auction_id = ? AND sequence = ?', (auction_id, sequence))
        return cursor.fetchone()

    def get_bids(self, auction_id):
        cursor = self.db.cursor()
        cursor.execute('SELECT open FROM auctions WHERE id = ?', (auction_id,))
        still_open = cursor.fetchone()[0] > 0

        logger.debug('AUCTION %d STILL OPEN: %s', auction_id, still_open)

        cursor.execute('SELECT * FROM bids WHERE auction_id = ? ORDER BY sequence ASC', (auction_id,))
        bids_db = cursor.fetchall()

        bids = []

        if still_open:
            for bid in bids_db:
                bids.append({'PREV_HASH': bid[2], 'IDENTITY': bid[3], 'VALUE': bid[4]})
        else:
            secrets = cursor.execute('SELECT secret FROM secrets WHERE auction_id = ? ORDER BY sequence ASC', (auction_id,))
            secrets = cursor.fetchall()
            for i in range(0, len(bids_db)):
                bids.append({'PREV_HASH': bids_db[i][2], 'IDENTITY': bids_db[i][3], 'VALUE': bids_db[i][4], 'KEY': toBase64(secrets[i][0])})

        return list(reversed(bids))

    def get_last_sequence(self, auction_id):
        ls = -1

        cursor = self.db.cursor()
        cursor.execute('SELECT sequence FROM bids WHERE auction_id = ? ORDER BY sequence DESC', (auction_id,))
        row = cursor.fetchone()

        if row is not None:
            ls = row[0]

        return ls

    def get_last_bid(self, auction_id):
        s = self.get_last_sequence(auction_id)
        if s >= 0:
            return self.get_bid(auction_id, s)
        return None

    def close_auctions(self):
        now = datetime.now()
        cursor = self.db.cursor()
        cursor.execute('SELECT id, stop FROM auctions WHERE open = 1 AND duration > 0')
        rows = cursor.fetchall()

        rv = []

        for row in rows:
            if now >= row[1]:
                rv.append(row[0])
                cursor.execute('UPDATE auctions SET open = 0 WHERE id = ?', (row[0],))
        self.db.commit()

        return rv

    def is_claimed(self, auction_id):
        cursor = self.db.cursor()
        cursor.execute('SELECT claimed FROM auctions WHERE id = ?', (auction_id,))
        return cursor.fetchone()[0] == 1

    def mark_claimed(self, auction_id):
        cursor = self.db.cursor()
        if not self.is_claimed(auction_id):
            cursor = self.db.cursor()
            cursor.execute('UPDATE auctions SET claimed = 1 WHERE id = ?', (auction_id,))
            self.db.commit()

    def store_winner(self, auction_id, sequence):
        cursor = self.db.cursor()
        cursor.execute('INSERT INTO winners (auction_id, sequence) VALUES(?,?)', (auction_id, sequence))
        self.db.commit()

    def is_winner(self, auction_id, sequence):
        cursor = self.db.cursor()
        cursor.execute('SELECT * FROM winners WHERE auction_id = ? AND sequence = ?', (auction_id, sequence))
        row = cursor.fetchone()
        if row is not None:
            return True
        return False

    def store_secrets(self, secrets):
        # prepare secrets (from dict to list)
        vals = []
        for secret in secrets:
            val = [secret['AUCTION_ID'], secret['SEQUENCE'], fromBase64(secret['SECRET'])]
            vals.append(val)
        # store multiple
        if len(vals) > 0:
            cursor = self.db.cursor()
            cursor.executemany("INSERT INTO secrets VALUES (?,?,?)", vals)
            self.db.commit()

    def find_store_winner(self, auction_id):
        logger.debug('FIND STORE WINNER (AUCTION_ID %d)', auction_id)

        cursor = self.db.cursor()

        cursor.execute('SELECT type, open FROM auctions WHERE id = ?', (auction_id,))
        auction = cursor.fetchone()

        # Still open
        if auction[1] > 0:
            logger.debug('AUCTION STILL OPEN...')
            return False

        hidden_value = (auction[0] == 2)

        cursor.execute('SELECT sequence, value FROM bids WHERE auction_id = ? ORDER BY sequence ASC', (auction_id,))
        value_tuples = [ list(x) for x in cursor.fetchall() ]

        # There are no bids
        if not value_tuples:
            logger.debug('DID NOT FOUND BIDS...')
            return False

        if hidden_value:
            cursor.execute('SELECT secret FROM secrets WHERE auction_id = ? ORDER BY sequence ASC', (auction_id,))
            secrets = cursor.fetchall()
            for i in range(0, len(value_tuples)):
                value_tuples[i][1] = int(decrypt(secrets[i][0], fromBase64(value_tuples[i][1])).decode())

        max_bid = max(value_tuples, key = lambda vt: vt[1])
        sequence = max_bid[0]
        self.store_winner(auction_id, sequence)
        return True

    def is_close(self, auction_id):
        cursor = self.db.cursor()
        cursor.execute('SELECT open FROM auctions WHERE id = ?', (auction_id,))
        return cursor.fetchone()[0] == 0
    
    def close_auction(self, auction_id):
        if not self.is_close(auction_id):
            cursor = self.db.cursor()
            cursor.execute('UPDATE auctions SET open = 0 WHERE id = ?', (auction_id,))
            self.db.commit()

    def store_bid(self, auction_id, identity, value):
        ls = self.get_last_sequence(auction_id)

        sequence = 0
        if ls < 0:
            prev_hash = self.get_auctions([auction_id])[0][8]
        else:
            last_bid = self.get_bid(auction_id, ls)
            last_bid_dict = {'PREV_HASH': last_bid[2], 'IDENTITY': last_bid[3],
                    'VALUE': last_bid[4]}
            prev_hash = SHA256.new(data=json.dumps(last_bid_dict).encode("UTF-8")).hexdigest()
            sequence = ls + 1

        cursor = self.db.cursor()
        cursor.execute('INSERT INTO bids(auction_id, sequence, prev_hash, identity, value) VALUES(?,?,?,?,?)',(auction_id, sequence, prev_hash, identity, value))
        self.db.commit()

        return (prev_hash, sequence)

    def close(self):
        self.db.commit()
        self.db.close()
