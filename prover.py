import json
import random
import socket
from datetime import datetime

from param import G, N, P, X
from tcp import BUF_SIZE, start_tcp_client

x_bits = 256
p_bits = 256


def calculate_zkp(p, g, n):
    r_list = [random.randint(0, p - 2) for _ in range(n)]
    c_list = [pow(g, r, p) for r in r_list]
    return r_list, c_list


def calculate_challenges(x, p, r_list, a_list):
    if len(r_list) != len(a_list):
        raise ValueError('r_list and a_list must have the same length')
    e_list = [a * ((x + r) % (p - 1)) - (a - 1) * r for r, a in zip(r_list, a_list)]
    return e_list


def handle_conn(conn: socket.socket):
    y = pow(G, X[x_bits], P[p_bits])
    r_list, c_list = calculate_zkp(P[p_bits], G, N)
    payload = {"y": y, "c": c_list}
    payload_bytes = json.dumps(payload).encode('utf-8')

    conn.send(payload_bytes)

    data = conn.recv(BUF_SIZE)
    if not data:
        return
    now = datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] data length {len(data)}")

    # decode a_list
    a_list = json.loads(data.decode('utf-8'))
    print(f'received a_list: {a_list}')
    e_list = calculate_challenges(X[x_bits], P[p_bits], r_list, a_list)
    print(f'calculated e_list: {e_list}')

    # send e_list
    e_list_bytes = json.dumps(e_list).encode('utf-8')
    conn.send(e_list_bytes)

    # receive ack
    data = conn.recv(BUF_SIZE)
    if not data:
        return
    now = datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] data length {len(data)}")
    print(f'received ack: {data}')


if __name__ == '__main__':
    print(f'x_bits: {x_bits}, p_bits: {p_bits}')
    start_tcp_client('10.0.0.2', 22222, handle_conn)
