import socket

BUF_SIZE = 40960


def start_tcp_server(host, port, handler_func):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(1)
        try:
            while True:
                client_sock, addr = s.accept()
                print(f'accepted {addr}')

                handler_func(client_sock)
        except KeyboardInterrupt or Exception:
            s.close()


def start_tcp_client(remote_host, remote_port, handler_func):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.connect((remote_host, remote_port))
        try:
            handler_func(s)
        except KeyboardInterrupt or Exception:
            s.close()
