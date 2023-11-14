import json
import socket
from datetime import datetime

from param import A, G, P
from tcp import BUF_SIZE, start_tcp_server


def verify(p, g, y, c_list, a_list, e_list):
    for c, a, e in zip(c_list, a_list, e_list):
        if a not in [0, 1]:
            raise ValueError('a must be 0 or 1')
        if a == 0 and c % p != pow(g, e, p):
            return False
        if a == 1 and (c * y) % p != pow(g, e, p):
            return False
    return True


p_bits = 256

payload = A
payload_bytes = json.dumps(payload).encode('utf-8')


def handle_conn(conn: socket.socket):
    data = conn.recv(BUF_SIZE)
    if not data:
        return
    now = datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] data length {len(data)}")

    try:
        # extract y, c
        data = json.loads(data.decode('utf-8'))
        print(f'received data: {data}')
        y = data['y']
        c = data['c']
    except Exception as e:
        print(e)

    # send a
    conn.send(payload_bytes)

    data = conn.recv(BUF_SIZE)
    if not data:
        return
    try:
        # verify prover response
        e_list = json.loads(data.decode('utf-8'))
        print(f'received e_list: {e_list}')
        if verify(P[p_bits], G, y, c, A, e_list):
            print('Verified')
        else:
            print('Not verified')
    except Exception as e:
        print(e)

    # send ack
    conn.send(b'ack')


if __name__ == '__main__':
    start_tcp_server('10.0.0.2', 22222, handle_conn)
