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
from ..common.utils import check_port, load_file_raw, OpenConnections, toBase64, fromBase64
from ..common.cryptmanager import server_encrypt, server_decrypt
from ..common.db.manager_db import MDB
from ..common.certmanager import CertManager
from ..common.cryptmanager import decrypt
from ..common.dynamiccode import DynamicCode


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('AM')
logger.setLevel(logging.DEBUG)


def signal_handler(addr, signal, frame):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('',0))
    sock.sendto(json.dumps({'ACTION':'EXIT'}).encode('UTF-8'), addr)


def main(args):
    addr = (str(args.ip_am), args.port_am)
    addr_rep = (str(args.ip_ar), args.port_ar)
    pk = load_file_raw('src/auction_manager/keys/private_key.pem')
    oc = OpenConnections()
    db = MDB()

    signal.signal(signal.SIGINT, partial(signal_handler, addr))

    # switch case para tratar das mensagens
    mActions = {'CHALLENGE': challenge,
            'CREATE':validate_auction,
            'STORE_REPLY': store,
            'STORE_SECRET': store_secret,
            'VALIDATE_BID': validate_bid,
            'VALIDATE_RECLAIM': validate_reclaim,
            'TERMINATE' : terminate,
            'TERMINATE_AUCTION_REPLY': terminate_reply,
            'DISCLOSURE': disclosure,
            'EXIT': exit}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(addr)

    logger.info('Auction Manager running...')
    done = False
    while not done:
        data, addr = sock.recvfrom(8192)
        j = json.loads(data)
        logger.debug('JSON = %s', j)
        done = mActions[j['ACTION']](j, sock, addr, pk, oc, addr_rep, db)


def challenge(j, sock, addr, pk, oc, addr_rep, db):
    challenge = fromBase64(j['CHALLENGE'])
    certificate = fromBase64(j['CERTIFICATE'])

    cert = CertManager.get_cert_by_name('manager.crt')
    cm = CertManager(cert = cert, priv_key=pk)
    cr = cm.sign(challenge)

    nonce = oc.add(certificate)

    reply = {'ACTION': 'CHALLENGE_REPLY',
            'CHALLENGE_RESPONSE': toBase64(cr),
            'CERTIFICATE': toBase64(cert),
            'NONCE': toBase64(nonce)}
    logger.debug('CLIENT REPLY = %s', reply)
    sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
    return False

def terminate(j, sock, addr, pk, oc, addr_rep, db):
    s = fromBase64(j['SIGNATURE'])
    message = j['MESSAGE']
    nonce = fromBase64(message['NONCE'])
    cm = CertManager(cert = oc.pop(nonce))
    reply = {'ACTION':'TERMINATE_REPLY'}

    if not cm.verify_certificate():
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'INVALID CERTIFICATE'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    if not cm.verify_signature(s, json.dumps(j['MESSAGE']).encode('UTF-8')):
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'INVALID SIGNATURE'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    # Verify if request comes from owner
    if db.get_owner(message['AUCTION_ID']) != cm.get_identity()[1]:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'You are not the owner of this auction.'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    nonce = oc.add(addr)
    cert = CertManager.get_cert_by_name('repository.crt')
    data = {'NONCE': toBase64(nonce), 'AUCTION_ID': message['AUCTION_ID']}
    request = server_encrypt('TERMINATE_AUCTION', data, cert)
    logger.debug('REPOSITORY REQUEST = %s', request)
    sock.sendto(json.dumps(request).encode('UTF-8'), addr_rep)
    return False


def terminate_reply(j, sock, addr, pk, oc, addr_rep, db):
    cert = CertManager.get_cert_by_name('manager.crt')
    data = json.loads(server_decrypt(j, cert, pk))
    logger.debug('DATA = %s', data)

    nonce = fromBase64(data['NONCE'])
    addr_client = oc.pop(nonce)

    reply = {'ACTION': 'TERMINATE_REPLY', 'STATE': 'OK'}
    logger.debug('CLIENT REPLY = %s', reply)
    sock.sendto(json.dumps(reply).encode('UTF-8'), addr_client)

    return False


def validate_auction(j, sock, addr, pk, oc, addr_rep, db):
    reply = {'ACTION':'CREATE_REPLY'}

    s = fromBase64(j['SIGNATURE'])
    message = json.loads(j['MESSAGE'])
    nonce = fromBase64(message['NONCE'])
    cm = CertManager(cert = oc.pop(nonce))

    if not cm.verify_certificate():
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'INVALID CERTIFICATE'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    if not cm.verify_signature(s, j['MESSAGE'].encode('UTF-8')):
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'INVALID SIGNATURE'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    if 'TITLE' not in message:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'MISSING TITLE'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    if 'DESCRIPTION' not in message:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'MISSING DESCRIPTION'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    if 'TYPE' not in message:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'MISSING TYPE'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    atype = message['TYPE']
    if atype != 1 and atype != 2:
        logger.debug("type = %d", atype)
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'INVALID TYPE'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    if 'SUBTYPE' not in message:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'MISSING SUBTYPE'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    subtype = message['SUBTYPE']
    if subtype != 1 and subtype != 2:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'INVALID SUBTYPE'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    if 'AUCTION_EXPIRES' not in message:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'MISSING AUCTION_EXPIRES'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    expires = message['AUCTION_EXPIRES']
    if expires < 0:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'AUCTION_EXPIRES LESS THAN ZERO'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    code = None
    if 'CODE' in message:
        code = message.pop('CODE')
        result, msg = DynamicCode.check_code(code)
        if not result:
            reply['STATE'] = 'NOT OK'
            reply['ERROR'] = msg
            logger.debug('CLIENT REPLY = %s', reply)
            sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
            return False

    nonce = oc.add((cm.get_identity()[1], addr, code))
    message['ACTION'] = 'STORE'
    message['NONCE'] = toBase64(nonce)
    cert = CertManager.get_cert_by_name('repository.crt')
    request = server_encrypt('STORE', message, cert)
    logger.debug("REPOSITORY STORE = %s", request)
    sock.sendto(json.dumps(request).encode('UTF-8'), addr_rep)
    return False


def store(j, sock, addr, pk, oc, addr_rep, db):
    cert = CertManager.get_cert_by_name('manager.crt')
    data = json.loads(server_decrypt(j, cert, pk))
    logger.debug('DATA = %s', data)
    nonce = fromBase64(data['NONCE'])
    auction_id = data['AUCTION_ID']
    user_cc, user_addr, code = oc.pop(nonce)
    db.store_auction(user_cc, auction_id, code)
    reply = {'ACTION': 'CREATE_REPLY', 'STATE':'OK'}
    logger.debug('CLIENT REPLY = %s', reply)
    sock.sendto(json.dumps(reply).encode('UTF-8'), user_addr)
    return False


def validate_reclaim(j, sock, addr, pk, oc, addr_rep, db):
    cert = CertManager.get_cert_by_name('manager.crt')
    data = json.loads(server_decrypt(j, cert, pk))
    logger.debug('DATA = %s', data)

    cm = CertManager(cert = cert, priv_key = pk)
    certificate = fromBase64(data['CERTIFICATE'])
    nonce = data['NONCE']

    onion1 = data['ONION_1']
    s = fromBase64(data['SIGNATURE'])

    if not cm.verify_signature(s, json.dumps(onion1).encode('UTF-8')):
        data = {'STATE': 'NOT OK', 'ERROR': 'INVALID SIGNATURE (ONION 1)', 'NONCE': nonce}
        cert = CertManager.get_cert_by_name('repository.crt')
        reply = server_encrypt('VALIDATE_RECLAIM_REPLY', data, cert)
        logger.debug('REPOSITORY REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)

    onion0 = onion1['ONION_0']
    s = fromBase64(onion1['SIGNATURE'])

    cm = CertManager(cert = fromBase64(data['CERTIFICATE']))

    if not cm.verify_signature(s, json.dumps(onion0).encode('UTF-8')):
        data = {'STATE': 'NOT OK', 'ERROR': 'INVALID SIGNATURE (ONION 0)', 'NONCE': nonce}
        cert = CertManager.get_cert_by_name('repository.crt')
        reply = server_encrypt('VALIDATE_RECLAIM_REPLY', data, cert)
        logger.debug('REPOSITORY REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    data = {'AUCTION_ID': int(onion0['AUCTION']), 'STATE': 'OK', 'NONCE': nonce}
    cert = CertManager.get_cert_by_name('repository.crt')
    reply = server_encrypt('VALIDATE_RECLAIM_REPLY', data, cert)
    logger.debug('REPOSITORY REPLY = %s', reply)
    sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
    return False


def validate_bid(j, sock, addr, pk, oc, addr_rep, db):
    cert = CertManager.get_cert_by_name('manager.crt')
    data = json.loads(server_decrypt(j, cert, pk))
    logger.debug('DATA = %s', data)

    cm = CertManager(cert = cert, priv_key = pk)

    nonce = data['NONCE']
    message = data['MESSAGE']
    signature = data['SIGNATURE']
    hidden_value = data['HIDDEN_VALUE']
    hidden_identity = data['HIDDEN_IDENTITY']
    identity = fromBase64(data['MESSAGE']['IDENTITY'])
    value = fromBase64(data['MESSAGE']['VALUE'])
    certificate = fromBase64(data['CERTIFICATE'])
    message = data['MESSAGE']
    auction_id = int(message['AUCTION'])
    secret = cm.decrypt(fromBase64(data['MANAGER_SECRET']))

    if data['LAST_BID'] is not None:
        las_bid_sequence = data['LAST_BID']['SEQUENCE']
        last_bid_value = fromBase64(data['LAST_BID']['VALUE'])
    else:
        last_bid_value = None

    if hidden_identity:
        certificate = decrypt(secret, certificate)
        raw_identity = decrypt(secret, identity)
        identity = int(raw_identity.decode().split(' - ')[1])
    else:
        raw_identity = identity
        identity = int(raw_identity.decode().split(' - ')[1])

    if hidden_value:
        value = int(decrypt(secret, value).decode())
        if last_bid_value is not None:
            last_bid_secret = db.get_secret(auction_id, las_bid_sequence)
            last_bid_value = int(decrypt(last_bid_secret, fromBase64(last_bid_value)).decode())
    else:
        value = int(value)
        if last_bid_value is not None:
            last_bid_value = int(fromBase64(last_bid_value).decode())

    if last_bid_value == None : last_bid_value = 0
    cm = CertManager(cert = certificate)

    if not cm.verify_certificate():
        data = {'STATE': 'NOT OK', 'ERROR': 'INVALID CERTIFICATE', 'NONCE': nonce}
        cert = CertManager.get_cert_by_name('repository.crt')
        reply = server_encrypt('VALIDATE_BID_REPLY', data, cert)
        logger.debug('REPOSITORY REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    if not cm.verify_signature(fromBase64(signature), json.dumps(message).encode('UTF-8')):
        data = {'STATE': 'NOT OK', 'ERROR': 'INVALID SIGNATURE', 'NONCE': nonce}
        cert = CertManager.get_cert_by_name('repository.crt')
        reply = server_encrypt('VALIDATE_BID_REPLY', data, cert)
        logger.debug('REPOSITORY REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    if value <= last_bid_value and data['AUCTION_TYPE'] == 1:
        logger.debug('INVALID VALUE %d %d', value, last_bid_value)
        data = {'STATE': 'NOT OK', 'ERROR': 'INVALID VALUE', 'NONCE': nonce}
        cert = CertManager.get_cert_by_name('repository.crt')
        reply = server_encrypt('VALIDATE_BID_REPLY', data, cert)
        logger.debug('REPOSITORY REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    # Check dynamic code
    code = db.get_code(auction_id)
    if code is not None:
        code = code[0]
    times = db.times(auction_id, raw_identity)
    if code is not None and not DynamicCode.run_dynamic(identity, value, times, last_bid_value, code):
        data = {'STATE': 'NOT OK',
                'ERROR': 'Your offer was not accepted by the dynamic code.', 'NONCE': nonce}
        cert = CertManager.get_cert_by_name('repository.crt')
        reply = server_encrypt('VALIDATE_BID_REPLY', data, cert)
        logger.debug('REPOSITORY REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    cm = CertManager(cert = CertManager.get_cert_by_name('manager.crt'), priv_key = pk)
    onion = {'ONION_0': message, 'SIGNATURE': signature}
    data = {'ONION_1': onion,
            'SIGNATURE': toBase64(cm.sign(json.dumps(onion).encode('UTF-8'))),
            'NONCE': nonce, 'STATE': 'OK'}

    cert = CertManager.get_cert_by_name('repository.crt')
    reply = server_encrypt('VALIDATE_BID_REPLY', data, cert)
    logger.debug('REPOSITORY REPLY = %s', reply)
    sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
    return False


def store_secret(j, sock, addr, pk, oc, addr_rep, db):
    cert = CertManager.get_cert_by_name('manager.crt')
    data = json.loads(server_decrypt(j, cert, pk))
    logger.debug('DATA = %s', data)

    cm = CertManager(cert = cert, priv_key = pk)
    nonce = data['NONCE']
    auction_id = data['AUCTION_ID']
    secret = cm.decrypt(fromBase64(data['SECRET']))
    hidden_identity = data['HIDDEN_IDENTITY']
    identity = fromBase64(data['IDENTITY'])
    certificate = fromBase64(data['CERTIFICATE'])
    sequence = data['SEQUENCE']

    if hidden_identity:
        certificate = decrypt(secret, certificate)
        identity = decrypt(secret, identity)

    db.store_secret(auction_id, sequence, secret, identity)

    data = {'STATE': 'OK', 'NONCE': nonce}
    cert = CertManager.get_cert_by_name('repository.crt')
    reply = server_encrypt('STORE_SECRET_REPLY', data, cert)
    logger.debug('REPOSITORY REPLY = %s', reply)
    sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
    return False


def disclosure(j, sock, addr, pk, oc, addr_rep, db):
    cert = CertManager.get_cert_by_name('manager.crt')
    data = json.loads(server_decrypt(j, cert, pk))
    logger.debug('DATA = %s', data)

    auction_id = data['AUCTION_ID']
    #nonce = data['NONCE']

    rows = db.get_secrets(auction_id)

    if rows is None:
        data = {'AUCTION_ID': auction_id, 'SECRETS':[]}
    else:
        secrets = []
        for row in rows:
            secret = {'AUCTION_ID': row[0],
                    'SEQUENCE': row[1],
                    'SECRET': toBase64(row[2])}
            secrets.append(secret)
        data = {'AUCTION_ID': auction_id, 'SECRETS': secrets}

    cert = CertManager.get_cert_by_name('repository.crt')
    reply = server_encrypt('DISCLOSURE_REPLY', data, cert)
    logger.debug('REPOSITORY REPLY = %s', reply)
    sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
    return False


def exit(j, sock, addr, pk, oc, addr_rep, db):
    logger.debug("EXIT")
    db.close()
    return True

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Auction Manager')
    parser.add_argument('--ip_ar', type=ip_address, help='ip address auction repository', default='127.0.0.1')
    parser.add_argument('--port_ar', type=check_port, help='ip port action repository', default=5002)
    parser.add_argument('--ip_am', type=ip_address, help='ip address action manager', default='127.0.0.1')
    parser.add_argument('--port_am', type=check_port, help='ip port action manager', default=5001)
    args = parser.parse_args()
    main(args)
