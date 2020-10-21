from socket import socket


def recvuntil(conn: socket, marker: bytes) -> bytes:
    buff = b""
    while ((chunk := conn.recv(len(marker)))) != marker:
        buff += chunk
    return buff


def decode(conn: socket):
    while True:
        result = recvuntil(conn, b"\0")
        if result == b"":
            return
        yield result


def encode(data) -> bytes:
    def is_iterable(x) -> bool:
        try:
            iter(x)
            return True
        except TypeError:
            return False

    def _encode(data_) -> bytes:
        encoded = b""
        for elem in data_:
            if isinstance(elem, int):
                encoded += str(elem).encode()
            elif isinstance(elem, str):
                encoded += elem.encode()
            elif isinstance(elem, bytes):
                encoded += elem
            elif is_iterable(elem):
                encoded += encode(elem)
                continue
            encoded += b"\0"
        return encoded

    return _encode(data) + b"\0"
