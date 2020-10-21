#!/usr/bin/python
import os
import sys
import socket

import utils
import exc


def _decode_chunk(conn: socket.socket) -> bytes:
    """Decode chunk of encoded data from connection.

    Args:
        conn: Connection to server.

    Returns:
        bytes: Decoded bytestring from response.

    Raises:
        exc.BadReponse: Buffer is empty.
    """
    try:
        return next(utils.decode(conn))
    except StopIteration as e:
        raise exc.BadResponse("invalid server response") from e


def check_status(conn: socket.socket) -> None:
    """Check if server response was indicates success.

    Args:
        conn: Connection to server.

    Raises:
        exc.RequestFailure: Server response indicates failure.
    """
    status = _decode_chunk(conn).decode()
    if status != "OK":
        reason = _decode_chunk(conn)
        raise exc.RequestFailure(f"[{status}]: {reason}")


def cmd_list(conn: socket.socket) -> None:
    """Send LIST command to server.

    Args:
        conn: Connection to server.

    Raises:
        exc.RequestFailure: Response indicates failure.
        exc.InvalidResponse: Response is invalid.
    """
    conn.send(utils.encode(["LIST"]))
    check_status(conn)

    it = utils.decode(conn)
    for name in it:
        size = next(it)
        print(int(size), "\t", name.decode())


def cmd_grab(conn: socket.socket, fin: str, fout: str) -> None:
    """Send GRAB command to server.

    Args:
        conn: Connection to server.
        fin: Name of file on server.
        fout: Name of file to download to.

    Raises:
        exc.RequestFailure: Response indicates failure.
        exc.InvalidResponse: Response is invalid.
    """
    conn.send(utils.encode(["GRAB", fin]))

    fsize = int(_decode_chunk(conn))
    with open(fout, "wb") as f:
        f.write(conn.recv(fsize))

    check_status(conn)


def cmd_push(conn: socket.socket, fin: str, fout: str) -> None:
    """Send PUSH command to server.

    Args:
        conn: Connection to server.
        fin: Name of file to upload.
        fout: Name of file on server.

    Raises:
        IOError: Unable to read file locally.
        exc.RequestFailure: Response indicates failure.
    """
    try:
        with open(fin, "rb") as f:
            payload = f.read()
    except (FileNotFoundError, PermissionError) as e:
        raise IOError(f"unable to read file: {fin}", file=sys.stderr) from e

    conn.send(utils.encode(["PUSH", fout, os.path.getsize(fin), payload]))
    check_status(conn)


def create_client(saddr: str, sport: int) -> None:
    """Create connection to server.

    Args:
        saddr: Server address.
        sport: Server port.
    """
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.connect((saddr, sport))
    return s


def main(argc: int, argv) -> None:
    if argc < 4:
        print(f"usage: {argv[0]} <server> <port> [cmd]", file=sys.stderr)
        sys.exit(1)

    saddr, sport, cmd, *args = argv[1:]

    try:
        sport = int(sport)
    except ValueError:
        print("invalid port number", file=sys.stderr)
        sys.exit(1)

    try:
        handler = {"LIST": cmd_list, "GRAB": cmd_grab, "PUSH": cmd_push}[cmd.upper()]
    except KeyError:
        print("invalid command", file=sys.stderr)
        sys.exit(1)

    try:
        with create_client(saddr, sport) as client:
            handler(client, *args)
    except TypeError:
        print("invalid command arguments", file=sys.stderr)
    except ConnectionRefusedError:
        print("unable to connect to server", file=sys.stderr)
        sys.exit(1)
    except ConnectionResetError:
        print("server disconnected", file=sys.stderr)
        sys.exit(1)
    except IOError as e:
        print(f"an IO error occured: {e.message}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"closing client", file=sys.stderr)


if __name__ == "__main__":
    main(len(sys.argv), sys.argv)
