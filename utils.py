from socket import socket


def is_valid_name(name: str) -> bool:
    """Validate string contents against blocklist.

    Args:
        name: String to validate.
    """
    BLOCKLIST = set('/\\<>:"/\|?*')
    return len(set(name) & BLOCKLIST) == 0


def recv_n(conn: socket, size: int, CHUNK_SIZE: int = 4096):
    """Read specified amount of data from socket.

    Args:
        conn: Recieving socket.
        size: Amount of data to read.
        CHUNK_SIZE: Size of chunk to read per iteration.
    """
    total_read = 0
    while total_read < size and (chunk := conn.recv(CHUNK_SIZE)) != b"":
        remaining = size - total_read
        yield chunk[:remaining] if remaining < CHUNK_SIZE else chunk
        total_read += len(chunk)


def recvuntil(conn: socket, marker: bytes) -> bytes:
    """Read content from socket up to inline marker.

    The marker must come in a len(marker) boundary; an embedded pattern
    matching the marker will not be matched against.

    Args:
        conn: Recieving socket.
        marker: Pattern to stop against once found.
    """
    buff = b""
    while ((chunk := conn.recv(len(marker)))) != marker:
        buff += chunk
    return buff


def decode(conn: socket):
    """Decode data in chunks.

    Args:
        conn: Recieving socket.
    """
    while True:
        result = recvuntil(conn, b"\0")
        if result == b"":
            return
        yield result


def encode(data: list) -> bytes:
    """Encode data prior to transmission.

    Recursively encode data into bytestream for serialisation.

    Args:
        data: List of data to encode.
    """

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
