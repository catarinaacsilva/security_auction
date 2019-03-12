import os
import sys
from random import randint
import random
import time
from Crypto.Hash import SHA256

'''
    Override __getitem__ from dict to delete keys that are expired
'''
class ExpiringDict(dict):
    def __init__(self, *args):
        dict.__init__(self, args)

    def __getitem__(self, key):
        '''
            Delete key if already expired
        '''
        actual_time = time.time()
        val = dict.__getitem__(self, key)
        if (val[1] < actual_time):
            self.pop('key', None)
            return None
        return val

class CryptoPuzzle:

    # Saves puzzles sent to clients
    sent_puzzles = ExpiringDict()

    def create_puzzle(self, certificate):
        '''
            Creates puzzle to solve

            inputs:
                certificate - certificate of user that will solve the puzzle
            output:
                puzzle - hashed result of hashed certificate xor random value
                starts_with - beggining of random value used on hash function (0 - 70%)
                ends_with - ending of random value used on hash function

            There are 2 bytes left between starts_with and ends_with that the
                user needs to find out using brute force
        '''
        certificate_digest = SHA256.new(data=certificate).digest()
        solution = os.urandom( len(certificate_digest) )
        plain = self.string_xor(certificate_digest, solution)
        puzzle = SHA256.new(data=plain).hexdigest()

        starts_with_index = randint(0, int( len(certificate_digest) * random.uniform(0, 0.7) ) )
        ends_with_index = starts_with_index + 2

        starts_with = solution[:starts_with_index]
        ends_with = solution[ends_with_index:]

        self.sent_puzzles[certificate] = (puzzle, time.time() + 120)

        return puzzle, starts_with, ends_with

    def validate_solution(self, certificate, solution):
        '''
            Validates possible solution, also returns false if the puzzle is expired (60 seconds)
        '''
        certificate_digest = SHA256.new(data=certificate).digest()
        return self.sent_puzzles[certificate][0] == SHA256.new( data= self.string_xor(certificate_digest, solution) ).hexdigest() if self.sent_puzzles[certificate] else False

    def solve_puzzle(self, puzzle, certificate, starts_with, ends_with):
        '''
            Try to solve puzzle (user side)
        '''
        certificate_digest = SHA256.new(data=certificate).digest()
        sw = self.string_xor(certificate_digest[:len(starts_with)], starts_with)
        ew = self.string_xor(certificate_digest[len(starts_with)+2:], ends_with)
        cert = certificate_digest[len(starts_with):len(starts_with)+2]

        attempt = self.build_attempt(sw, ew, cert)
        while (puzzle != SHA256.new( data= attempt[0] ).hexdigest()):
            attempt = self.build_attempt(sw, ew, cert)
        return starts_with + attempt[1] + ends_with

    def build_attempt(self, starts_with, ends_with, cert):
        '''
            Build an attempt of a solution
        '''
        attempt = os.urandom(2)
        return (starts_with + self.string_xor(cert, attempt) + ends_with, attempt)

    def string_xor(self, stringA, stringB):
        '''
            XOR between 2 bytes string
        '''
        return bytes(x ^ y for x, y in zip(stringA, stringB))
