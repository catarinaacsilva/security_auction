# coding: utf-8

import os
import socket
import json
import logging
import base64
import argparse
import signal
from functools import partial
from ipaddress import ip_address
from datetime import datetime
from ..common.utils import check_positive_number, check_port, load_file_raw, OpenConnections, toBase64, fromBase64, PeriodicJob, DelaySocket
from ..common.cryptmanager import server_encrypt, server_decrypt
from ..common.db.repository_db import RDB
from ..common.certmanager import CertManager
from ..common.cryptopuzzle import CryptoPuzzle


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('AR')
logger.setLevel(logging.DEBUG)


def send_end_auctions(addr):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('',0))
    sock.sendto(json.dumps({'ACTION':'CLOSE_AUCTIONS'}).encode('UTF-8'), addr)


def signal_handler(addr, signal, frame):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('',0))
    sock.sendto(json.dumps({'ACTION':'EXIT'}).encode('UTF-8'), addr)


def main(args):
    addr = (str(args.ip_ar), args.port_ar)
    addr_man = (str(args.ip_am), args.port_am)
    pk = load_file_raw('src/auction_repository/keys/private_key.pem')
    oc = OpenConnections()
    db = RDB()
    cp =  CryptoPuzzle()

    signal.signal(signal.SIGINT, partial(signal_handler, addr))

    pj = PeriodicJob(args.close_period, send_end_auctions, args=[addr])

    # switch case para tratar de mensagens
    mActions = {'CHALLENGE': challenge,
            'STORE': store,
            'LIST' : list_auctions,
            'CRYPTOPUZZLE': cryptopuzzle,
            'OFFER': offer,
            'VALIDATE_BID_REPLY': validate_bid,
            'STORE_SECRET_REPLY': store_secret_reply,
            'CLOSE_AUCTIONS': close_auctions,
            'TERMINATE_AUCTION': terminate_auction,
            'RECLAIM': reclaim,
            'VALIDATE_RECLAIM_REPLY': validate_reclaim_reply,
            'DISCLOSURE_REPLY': disclosure_reply,
            'EXIT': exit}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(addr)
    #socket que atrasa ofertas quando outra esta a ser validada (consistencia da base de dados)
    dsock = DelaySocket(sock)
    #periodicamente termina os leilões por time out
    pj.start()

    logger.info('Auction Repository running...')
    done = False
    while not done:
        j, addr = dsock.recvfrom()
        logger.debug('JSON = %s', j)
        done = mActions[j['ACTION']](j, dsock, addr, pk, oc, cp, addr_man, db, pj)


def challenge(j, sock, addr, pk, oc, cp, addr_man, db, pj):
    challenge = fromBase64(j['CHALLENGE'])
    certificate = fromBase64(j['CERTIFICATE'])

    cert = CertManager.get_cert_by_name('repository.crt')
    cm = CertManager(cert = cert, priv_key=pk)
    cr = cm.sign(challenge)

    nonce = oc.add(certificate)

    reply = {'ACTION': 'CHALLENGE_REPLY',
            'CHALLENGE_RESPONSE': toBase64(cr),
            'CERTIFICATE': toBase64(cert),
            'NONCE': toBase64(nonce)}
    logger.debug('CLIENT REPLY = %s', reply)
    sock.sendto(reply, addr)
    return False


def store(j, sock, addr, pk, oc, cp, addr_man, db, pj):
    cert = CertManager.get_cert_by_name('repository.crt')
    data = json.loads(server_decrypt(j, cert, pk))
    logger.debug('DATA = %s', data)

    auction_id = db.store_auction(data['TITLE'], data['DESCRIPTION'],
            data['TYPE'], data['SUBTYPE'],data['AUCTION_EXPIRES'])
    nonce = data['NONCE']
    data = {'NONCE':nonce, 'AUCTION_ID':auction_id}

    cert = CertManager.get_cert_by_name('manager.crt')
    reply = server_encrypt('STORE_REPLY', data, cert)
    logger.debug('MANAGER REPLY = %s', reply)
    sock.sendto(reply, addr)
    return False


def list_auctions(j, sock, addr, pk, oc, cp, addr_man, db, pj):
    nonce = fromBase64(j['NONCE'])
    auction_id = None
    if 'AUCTION_ID' in j:
        auction_id = j['AUCTION_ID']

    if auction_id is None or isinstance(auction_id, list):

        if auction_id is None:
            auctions = db.list_auctions()
        else:
            auctions = db.get_auctions(auction_id)

        for_client = []
        for auction in auctions:
            l = {
                    'AUCTION_ID' : auction[0],
                    'TITLE' : auction[1],
                    'TYPE'  : auction[3],
                    'STATUS': auction[9] == 1,
                    'CLAIMED' : auction[10] == 1
                }
            for_client.append(l)
        message = {'NONCE':toBase64(nonce), 'LIST':for_client}
    else:
        row = db.get_auctions([auction_id])[0]

        claimed = False
        if db.is_claimed(auction_id):
            claimed = True

        auction = {}
        bids = db.get_bids(auction_id)

        auction['AUCTION_ID'] = row[0]
        auction['TITLE'] = row[1]
        auction['DESCRIPTION'] = row[2]
        auction['TYPE'] = row[3]
        auction['SUBTYPE'] = row[4]
        auction['ENDING_TIMESTAMP'] = row[7].isoformat()
        auction['SEED'] = row[8]
        auction['BIDS'] = bids
        auction['STATUS'] = row[9] == 1
        auction['CLAIMED'] = claimed
        message = {'NONCE':toBase64(nonce), 'AUCTION':auction}

    cert = CertManager.get_cert_by_name('repository.crt')
    cm = CertManager(cert = cert, priv_key = pk)
    sl = cm.sign(json.dumps(message).encode('UTF-8'))

    reply = {'ACTION': 'LIST_REPLY','SIGNATURE': toBase64(sl),
            'CERTIFICATE': toBase64(cert),'MESSAGE': message}
    logger.debug('CLIENT REPLY = %s', reply)
    sock.sendto(reply, addr)
    return False


def cryptopuzzle(j, sock, addr, pk, oc, cp, addr_man, db, pj):
    auction_id = j['AUCTION_ID']
    certificate = fromBase64(j['IDENTITY'])
    (puzzle, starts, ends) = cp.create_puzzle(certificate)
    nonce = j['NONCE']
    message = { 'PUZZLE':puzzle,
                'STARTS_WITH': toBase64(starts),
                'ENDS_WITH':toBase64(ends),
                'NONCE': nonce}

    cert = CertManager.get_cert_by_name('repository.crt')

    cm = CertManager(cert = cert, priv_key = pk)

    signature = cm.sign(json.dumps(message).encode('UTF-8'))
    reply = { 'ACTION': 'CRYPTOPUZZLE_REPLY',
            'MESSAGE': message,
            'SIGNATURE': toBase64(signature),
            'CERTIFICATE': toBase64(cert)}
    logger.debug('CLIENT REPLY = %s', reply)
    sock.sendto(reply, addr)
    return False


def offer(j, sock, addr, pk, oc, cp, addr_man, db, pj):
    message = j['MESSAGE']
    auction_id = int(message["AUCTION"])
    solution = fromBase64(message['SOLUTION'])

    # Verificar CryptoPuzzle
    if not cp.validate_solution(fromBase64(message['IDENTITY']), solution):
        reply={'ACTION':'RECEIPT',
                'STATE': 'NOT OK',
                'AUCTION_ID': auction_id,
                'ERROR':'INVALID OR LATE CRYPTOPUZZLE'}
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(reply, addr)
        return False

    auction = db.get_auctions([auction_id])[0]
    now = datetime.now()
    
    if auction[9] == 0 or now > auction[7]:
        reply={'ACTION':'RECEIPT',
                'STATE': 'NOT OK',
                'AUCTION_ID': auction_id,
                'ERROR':'AUCTION CLOSED'}
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(reply, addr)
        return False

    hidden_value = (auction[3] == 2)
    hidden_identity = (auction[4] == 2)

    # Se isto acontecer o client nao compriu a norma... error
    if not 'MANAGER_SECRET' in j:
        reply={'ACTION':'RECEIPT',
                'STATE': 'NOT OK',
                'AUCTION_ID': auction_id,
                'ERROR':'AUCTION REQUIREMENTS NOT MET'}
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(reply, addr)
        return False

    nonce = toBase64(oc.add((addr, int(message["AUCTION"]), j['MANAGER_SECRET'], message['IDENTITY'], hidden_identity, j['CERTIFICATE'])))

    # Isto funciona porque foi implementado um novo socket que faz delay a bids
    # Ou seja, se já existe uma bid em processamento para um leilão
    # as novas que chegam ficam em fila de espera
    # Outras mensagens avançam normalmente
    last_bid = db.get_last_bid(int(message["AUCTION"]))

    lb = None
    if last_bid is not None:
        lb = {'SEQUENCE': last_bid[1], 'VALUE': toBase64(str(last_bid[4]).encode("UTF-8"))}

    data = {'MESSAGE':message,
            'SIGNATURE': j['SIGNATURE'],
            'NONCE':nonce,
            'HIDDEN_VALUE': hidden_value,
            'HIDDEN_IDENTITY' : hidden_identity,
            'AUCTION_TYPE': auction[3],
            'AUCTION_SUB_TYPE': auction[4],
            'MANAGER_SECRET' : j['MANAGER_SECRET'],
            'LAST_BID': lb,
            'CERTIFICATE' : j['CERTIFICATE']}
    cert = CertManager.get_cert_by_name('manager.crt')
    request = server_encrypt('VALIDATE_BID', data, cert)
    logger.debug('MANAGER REQUEST = %s', request)
    sock.sendto(request, addr_man)
    return False


def validate_bid(j, sock, addr, pk, oc, cp, addr_man, db, pj):
    cert = CertManager.get_cert_by_name('repository.crt')
    data = json.loads(server_decrypt(j, cert, pk))
    logger.debug('DATA = %s', data)
    nonce = fromBase64(data['NONCE'])
    addr_client, auction_id, secret, identity, hidden_identity, certificate = oc.pop(nonce)

    state = data['STATE']

    if state == "NOT OK":
        reply = {'ACTION': 'RECEIPT', 'AUCTION_ID': auction_id, 'STATE': state, 'ERROR': data['ERROR']}
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(reply, addr_client)
        return False

    onion1 = data['ONION_1']
    onion0 = onion1['ONION_0']
    identity = onion0['IDENTITY']
    value = onion0['VALUE']
    auction_id = onion0['AUCTION']

    prev_hash, sequence = db.store_bid(auction_id, identity, value)

    cm = CertManager(cert = CertManager.get_cert_by_name('repository.crt'), priv_key = pk)

    onion2 = {'ONION_1': onion1,
            'SIGNATURE': data['SIGNATURE'],
            'PREV_HASH': prev_hash,
            'SEQUENCE': sequence}
    signature_repository = cm.sign(json.dumps(onion2).encode('UTF-8'))
    reply = {'ACTION': 'RECEIPT',
            'STATE' : 'OK',
            'AUCTION_ID': auction_id,
            'RECEIPT': {"ONION_2" : onion2, 'SIGNATURE': toBase64(signature_repository)}}

    nonce = oc.add((addr_client, reply))
    data = {'AUCTION_ID': auction_id,
            'SEQUENCE': sequence,
            'SECRET': secret,
            'IDENTITY': identity,
            'HIDDEN_IDENTITY': hidden_identity,
            'CERTIFICATE': certificate,
            'NONCE': toBase64(nonce)}

    cert = CertManager.get_cert_by_name('manager.crt')
    request = server_encrypt('STORE_SECRET', data, cert)
    logger.debug('MANAGER REQUEST = %s', request)
    sock.sendto(request, addr_man)
    return False


def store_secret_reply(j, sock, addr, pk, oc, cp, addr_man, db, pj):
    cert = CertManager.get_cert_by_name('repository.crt')
    data = json.loads(server_decrypt(j, cert, pk))
    logger.debug('DATA = %s', data)
    nonce = fromBase64(data['NONCE'])
    addr_client, reply = oc.pop(nonce)

    logger.debug('CLIENT REPLY = %s', reply)
    sock.sendto(reply, addr_client)
    return False


def close_auctions(j, sock, addr, pk, oc, cp, addr_man, db, pj):
    cert = CertManager.get_cert_by_name('manager.crt')
    auction_ids = db.close_auctions()
    for auction_id in auction_ids:
        data = {'AUCTION_ID': auction_id}
        request = server_encrypt('DISCLOSURE', data, cert)
        logger.debug('MANAGER REQUEST = %s', request)
        sock.sendto(request, addr_man)
    return False


def terminate_auction(j, sock, addr, pk, oc, cp, addr_man, db, pj):
    cert = CertManager.get_cert_by_name('repository.crt')
    data = json.loads(server_decrypt(j, cert, pk))
    logger.debug('DATA = %s', data)

    auction_id = data['AUCTION_ID']
    nonce = data['NONCE']

    db.close_auction(auction_id)

    # Reply to close the auction
    data = {'NONCE': nonce}
    cert = CertManager.get_cert_by_name('manager.crt')
    reply = server_encrypt('TERMINATE_AUCTION_REPLY', data, cert)
    logger.debug('MANAGER REPLY = %s', reply)
    sock.sendto(reply, addr)

    # Ask to disclosure the bids secrets
    data = {'AUCTION_ID': auction_id}
    request = server_encrypt('DISCLOSURE', data, cert)
    logger.debug('MANAGER REQUEST = %s', request)
    sock.sendto(request, addr)
    return False


def disclosure_reply(j, sock, addr, pk, oc, cp, addr_man, db, pj):
    cert = CertManager.get_cert_by_name('repository.crt')
    data = json.loads(server_decrypt(j, cert, pk))
    logger.debug('DATA = %s', data)

    db.store_secrets(data['SECRETS'])
    winner = db.find_store_winner(data['AUCTION_ID'])

    if winner:
        logger.debug('FOUND WINNER...')

    return False


def reclaim(j, sock, addr, pk, oc, cp, addr_man, db, pj):
    s = fromBase64(j['SIGNATURE'])
    message = j['MESSAGE']
    nonce = fromBase64(message['NONCE'])
    certificate = oc.pop(nonce)
    cm = CertManager(cert = certificate)
    reply = {'ACTION':'RECLAIM_REPLY'}

    if not cm.verify_certificate():
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'INVALID CERTIFICATE'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(reply, addr)
        return False

    if not cm.verify_signature(s, json.dumps(j['MESSAGE']).encode('UTF-8')):
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'INVALID SIGNATURE'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(reply, addr)
        return False

    receipt = message['RECEIPT']

    onion2 = receipt['ONION_2']
    s = fromBase64(receipt['SIGNATURE'])

    cm = CertManager(cert = CertManager.get_cert_by_name('repository.crt'), priv_key = pk)

    if not cm.verify_signature(s, json.dumps(onion2).encode('UTF-8')):
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'INVALID SIGNATURE (ONION 2)'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(reply, addr)
        return False

    sequence = onion2['SEQUENCE']
    nonce = oc.add((addr, sequence))

    data = {'ONION_1': onion2['ONION_1'],
            'SIGNATURE': onion2['SIGNATURE'],
            'CERTIFICATE': toBase64(certificate),
            'NONCE': toBase64(nonce)}

    cert = CertManager.get_cert_by_name('manager.crt')
    request = server_encrypt('VALIDATE_RECLAIM', data, cert)
    logger.debug('MANAGER REQUEST = %s', request)
    sock.sendto(request, addr_man)
    return False


def validate_reclaim_reply(j, sock, addr, pk, oc, cp, addr_man, db, pj):
    cert = CertManager.get_cert_by_name('repository.crt')
    data = json.loads(server_decrypt(j, cert, pk))
    logger.debug('DATA = %s', data)
    nonce = fromBase64(data['NONCE'])
    reply = {'ACTION':'RECLAIM_REPLY'}

    addr_client, sequence = oc.pop(nonce)
    auction_id = data['AUCTION_ID']
    #last_sequence = db.get_last_sequence(data['AUCTION_ID'])

    if db.is_claimed(auction_id):
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'ACTION ALREADY CLAIMED'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(reply, addr_client)
        return False

    if not db.is_winner(auction_id, sequence):
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'NOT WINNING BID'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(reply, addr_client)
        return False

    db.mark_claimed(auction_id)

    reply['STATE'] = 'OK'
    logger.debug('CLIENT REPLY = %s', reply)
    sock.sendto(reply, addr_client)
    return False


def exit(j, sock, addr, pk, oc, cp, addr_man, db, pj):
    logger.debug("EXIT")
    db.close()
    pj.stop()
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Auction Repository')
    parser.add_argument('--ip_ar', type=ip_address, help='ip address auction repository', default='127.0.0.1')
    parser.add_argument('--port_ar', type=check_port, help='ip port action repository', default=5002)
    parser.add_argument('--ip_am', type=ip_address, help='ip address action manager', default='127.0.0.1')
    parser.add_argument('--port_am', type=check_port, help='ip port action manager', default=5001)
    parser.add_argument('--close_period', type=check_positive_number, help='period (seconds) for auto job that closes auctions', default=30)
    args = parser.parse_args()
    main(args)
