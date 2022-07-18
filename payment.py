# -*- coding: utf-8 -*-
import requests
import time
import json
import pika
import threading
from threading import Thread
import os

# import bech32m

working_queue_2k = "xch-faucet-2k"
working_queue_100k = "xch-faucet-100k"
working_queue_global = "xch-global"
mquser = 'user'
mqpass = 'pass'
mqhost = "srv"
mqport = 5672
queues = "xch-faucet-2k","xch-faucet-100k"
payout_json = {"wallet_id": 1, "additions": []}
payout_json_without_dups = {"wallet_id": 1, "additions": []}
check = []

"""Reference implementation for Bech32m and segwit addresses."""
from typing import List, Optional, Tuple
from chia.types.blockchain_format.sized_bytes import bytes32

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_polymod(values: List[int]) -> int:
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp: str) -> List[int]:
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


M = 0x2BC830A3


def bech32_verify_checksum(hrp: str, data: List[int]) -> bool:
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == M


def bech32_create_checksum(hrp: str, data: List[int]) -> List[int]:
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ M
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp: str, data: List[int]) -> str:
    """Compute a Bech32 string given HRP and data values."""
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join([CHARSET[d] for d in combined])


def bech32_decode(bech: str) -> Tuple[Optional[str], Optional[List[int]]]:
    """Validate a Bech32 string, and determine HRP and data."""
    if (any(ord(x) < 33 or ord(x) > 126 for x in bech)) or (bech.lower() != bech and bech.upper() != bech):
        return (None, None)
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return (None, None)
    if not all(x in CHARSET for x in bech[pos + 1:]):
        return (None, None)
    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos + 1:]]
    if not bech32_verify_checksum(hrp, data):
        return (None, None)
    return hrp, data[:-6]


def convertbits(data: List[int], frombits: int, tobits: int, pad: bool = True) -> List[int]:
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise ValueError("Invalid Value")
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("Invalid bits")
    return ret


def encode_puzzle_hash(puzzle_hash: bytes32, prefix: str) -> str:
    encoded = bech32_encode(prefix, convertbits(puzzle_hash, 8, 5))
    return encoded


def decode_puzzle_hash(address: str) -> bytes32:
    hrpgot, data = bech32_decode(address)
    if data is None:
        raise ValueError("Invalid Address")
    decoded = convertbits(data, 5, 8, False)
    decoded_bytes = bytes(decoded)
    return decoded_bytes


###CHIA-PAYMENT-PART###


def encode_address(address=None):
    try:
        data = decode_puzzle_hash(address)
        return "0x" + str(data.hex())
    except ValueError:
        logs("INVALID ADDRESS " + str(address) + " WAS REPLACED")
        return "0xb36d42f9834d9435a7647b21386f83efa03c9eb618c03eeb60848fa8b955c91a"


def logs(message):
    with open('json_log.txt', 'a') as f:
        f.write(message)
        f.close()


def check_sync_status(server=None):
    url = 'http://' + str(server) + ':5001/get_sync_status'
    payload = '{}'
    headers = {'Content-type': 'application/json'}
    r = requests.post(url, data=payload, headers=headers)
    data = r.json()
    if data['synced'] == True:
        return "Synced"
    elif data['synced'] == False:
        return "Not synced"


def get_balance(server=None):
    url = 'http://' + str(server) + ':5001/get_wallet_balance'
    payload = {"wallet_id": 1}
    payload_fixed = str(payload).replace("'", "\"")
    headers = {'Content-type': 'application/json'}
    r = requests.post(url, data=payload_fixed, headers=headers)
    data = r.json()
    return data['wallet_balance']['confirmed_wallet_balance'],data['wallet_balance']['spendable_balance']


def get_queue(wrk_queue):
    pika_conn_params = pika.ConnectionParameters(host=mqhost, port=mqport,
                                                 credentials=pika.credentials.PlainCredentials(mquser, mqpass), )
    connection = pika.BlockingConnection(pika_conn_params)
    channel = connection.channel()
    queue = channel.queue_declare(queue=wrk_queue, durable=True, exclusive=False, auto_delete=False)
    return queue.method.message_count


def send_payout_multi(payload=None, server=None):
    url = 'http://' + str(server) + ':5001/send_transaction_multi'
    headers = {'Content-Type': 'application/json'}
    sync_check = check_sync_status(server=server)
    fixed = json.loads(json.dumps(payload))
    fixed2 = json.loads(json.dumps(payload['additions']))
    unique = {each['puzzle_hash']: each for each in fixed2}.values()
    print("fixed2", fixed2)
    print("unique", *unique)
    for uniq in unique:
        payout_json_without_dups["additions"].append(uniq)
    print("clean uniqe", payout_json_without_dups)
    if sync_check == "Synced":
        print("Sync OK!")
        amount_check = int(get_balance(server=server)[0])
        amount = 0
        for line in payout_json_without_dups["additions"]:  # count total payout
            amount = amount + line['amount']
        print("Calculated amount is : " + str(amount))
        print("Available amount is : " + str(amount_check))
        if amount_check > amount:
            print("Amount OK!")
            r = requests.post(url, data=json.dumps(payout_json_without_dups), headers=headers)
            data = r.json()
            logs(str(data) + '\n')
            print("REQUEST " + str(data))
            if data['success'] == True:
                print(data['transaction_id'])
                check.append("Success")
                return data['transaction_id']
            elif data['success'] == False:
                print(data['error'])
                check.append("False")
                return "Error"
        else:
            print("Amount error")
            print(amount_check)
            check.append("False")
            return "Error"
    else:
        print("Sync Error")
        print(sync_check)
        check.append("False")
        return "Error"


class Get_message(Thread):
    def __init__(self, name,queue):
        """Инициализация потока"""
        Thread.__init__(self)
        self.name = name
        self.queue = queue

    def run(self):
        """Запуск потока"""
        credentials = pika.PlainCredentials(mquser, mqpass)
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host='srv1.crypto-faucet.ml', credentials=credentials, heartbeat=300,
                                      blocked_connection_timeout=150))
        channel = connection.channel()
        channel.queue_declare(queue=self.queue, durable=True)
        method_frame, header_frame, body = channel.basic_get(queue=self.queue)
        if body is None:
            print("Queue : " + str(working_queue_100k) + " is empty.")
            connection.close()
            return ''
        else:
            print(" [x] Received xch address %r" % body.decode())
            puzzle_hash = encode_address(body.decode())
            print(" [x] Converted to puzzle_hash %r" % puzzle_hash)
            print("get msg queue ", self.queue)
            if self.queue == "xch-faucet-2k":
                payout_json["additions"].append({"amount": 2000, "puzzle_hash": puzzle_hash})
            elif self.queue == "xch-faucet-100k":
                payout_json["additions"].append({"amount": 100000, "puzzle_hash": puzzle_hash})
            elif self.queue == "xch-global":
                payout_json["additions"].append({"amount": 200000, "puzzle_hash": puzzle_hash})
            wait = True
            while wait is True:
                if check == ['Success']:
                    channel.basic_ack(delivery_tag=method_frame.delivery_tag)
                    connection.close()
                    wait = False
                elif check == ['False']:
                    print("False")
                    connection.close()
                    wait = False
                else:
                    time.sleep(0.5)
                    msg = "%s is slepping" % self.name


class Payout(Thread):
    def __init__(self, name):
        """Инициализация потока"""
        Thread.__init__(self)
        self.name = name

    def run(self):
        """Запуск потока"""
        print("PAYING-THREAD-START")
        print(payout_json)
        send_payout_multi(payload=payout_json, server="192.168.0.145")


def create_get_message_threads(msg,queue):
    for i in range(msg):
        name = "Get message thread #%s" % (i + 1)
        my_thread = Get_message(name,queue)
        my_thread.start()
    name2 = "Payout thread"
    my_thread2 = Payout(name2)
    count = 0
    while count != msg:
        count = 0
        for line in payout_json['additions']:  # count total payout
            count = count + 1
    my_thread2.start()
    my_thread2.join()
    my_thread.join()

if os.path.isfile("pgw.lock") is False:
    with open("pgw.lock", "w") as file:
        file.write("pgw-locked")
    for queue in queues:
        print("Запущено потоков начало: %i." % threading.active_count())
        if __name__ == "__main__":
            msg = get_queue(wrk_queue=queue)
            print("Number of messages", queue, msg)
            if msg >= 20:
                wait = True
                while wait is True:
                    current_amount = get_balance(server="192.168.0.145")
                    if current_amount[0] == current_amount[1]:
                        wait = False
                    else:
                        time.sleep(30)
                if msg >= 1 and msg <= 100:
                    print("------------------------NEW CYCLE------------------------")
                    create_get_message_threads(msg,queue)
                    print("------------------------END------------------------")
                elif msg >= 100 and msg <= 500:
                    print("------------------------NEW 100 CYCLE------------------------")
                    create_get_message_threads(100,queue)
                    print("------------------------END------------------------")
                elif msg >= 501 and msg <= 800:
                    print("------------------------NEW 500 CYCLE------------------------")
                    create_get_message_threads(500,queue)
                    print("------------------------END------------------------")
                else:
                    print("------------------------Waiting for messages------------------------")
                print("Запущено потоков: %i." % threading.active_count())
                while threading.active_count() > 2:
                    print("Запущено потоков: %i." % threading.active_count())
                    time.sleep(0.5)
                print("Запущено потоков конец: %i." % threading.active_count())
            else:
                print("not enough msg", queue)
        payout_json = {"wallet_id": 1, "additions": []}
        payout_json_without_dups = {"wallet_id": 1, "additions": []}
        check = []
    os.remove("pgw.lock")
else:
    print("file locked")
