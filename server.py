#!/usr/bin/python
import os
import sys
import socket

import utils
import exc


def deserialise(*types):
    """Deserialise client request into specified types.
    """

    def convert(t, x: bytes):
        """Attempt to convert a bytestring into a specified type.

        Raises:
            exc.BadRequest: Client request is invalid.
        """
        handler = {str: lambda x: x.decode(), int: lambda x: int(x.decode())}
        try:
            return handler[t](x)
        except ValueError as e:
            raise exc.BadRequest("invalid payload encoding") from e

    def _inner(f):
        def _f(conn):
            args = []
            for type_, chunk in zip(types, utils.decode(conn)):
                args.append(convert(type_, chunk))

            if len(args) != len(types):
                raise exc.BadRequest("improper command arguments")
            return f(conn, *args)

        return _f

    return _inner


def cmd_list(conn: socket.socket):
    """List all files in current working directory.

    Produce a generator of: fname1, fsize1, fname2, fsize2, ...

    Args:
        conn: Client connection.
    """
    for f in filter(os.path.isfile, os.listdir()):
        yield f
        yield os.path.getsize(f)


@deserialise(str)
def cmd_grab(conn: socket.socket, fname: str):
    """Read and upload file to client.

    Read file contents into buffer and return with its size in a list.

    Args:
        conn: Client connection.
        fname: Name of file to upload.

    Raises:
        IOError: Unable to read file locally.
        exc.BadRequest: fname contains an invalid character.
    """
    if not utils.is_valid_name(fname):
        raise exc.BadRequest("invalid filename")

    try:
        with open(fname, "rb") as f:
            buf = f.read()
    except (FileNotFoundError, PermissionError) as e:
        raise IOError("unable to read file") from e
    return [len(fname), buf]


@deserialise(str, int)
def cmd_push(conn: socket.socket, fname, size):
    """Read and download file from client.

    Read file contents from client then write.

    Args:
        conn: Client connection.
        fname: Name of file to write to.

    Raises:
        ValueError: invalid file size.
        IOError: Unable to write to file locally.
        exc.BadRequest: filename contains invalid character.
    """
    if not utils.is_valid_name(fname):
        raise exc.BadRequest("invalid filename")

    try:
        size = int(size)
        assert size >= 0
    except (ValueError, AssertionError) as e:
        raise ValueError("invalid file size") from e

    if os.path.exists(fname):
        raise exc.BadRequest("file already exists")

    try:
        with open(fname, "wb") as f:
            for chunk in utils.recv_n(conn, size):
                f.write(chunk)
    except (FileNotFoundError, PermissionError) as e:
        raise IOError("unable to write file") from e


@deserialise(str)
def manage_client(conn: socket.socket, cmd: str) -> None:
    """Manage client connections by facilitating commands.

    Args:
        conn: Client connection.
        cmd: Command to execute.
    """
    peername = conn.getpeername()[:2]

    try:
        handler = {"LIST": cmd_list, "GRAB": cmd_grab, "PUSH": cmd_push}[cmd]
    except KeyError as e:
        raise exc.BadRequest("invalid command") from e
    failure = True
    try:
        results = ["OK", handler(conn)]
        failure = False
    except ConnectionResetError:
        raise
    except (OSError, IOError) as e:
        results = ["KO", e.args[0]]
    except Exception as e:
        results = ["KO", e.message]
    finally:
        conn.send(utils.encode(results))

    print("[*] {} {} {} {}".format(*peername, ["OK", "KO"][failure], cmd))


def create_server(sport: int, sdir: str, n_conn: int = 1) -> socket.socket:
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)

    os.chdir(sdir)

    s.bind(("::", sport))
    s.listen(n_conn)
    return s


def manage_connections(server: socket.socket) -> None:
    """Dispatch client connections to command handlers.

    Args:
        server: Server socket.
    """
    print("server up and running {0} {1}".format(*server.getsockname()))
    while True:
        conn, addr = server.accept()
        try:
            manage_client(conn)
        except ConnectionResetError:
            print("client disconnected")
            continue
        conn.close()


def main(argc: int, argv) -> None:
    if argc == 2:
        sport, sdir = argv[1], "."
    elif argc < 3:
        print(f"usage: {argv[0]} <port> <?dir>", file=sys.stderr)
        sys.exit(1)
    else:
        sport, sdir = argv[1:]

    try:
        sport = int(sport)
    except ValueError:
        print("invalid port number", file=sys.stderr)
        sys.exit(1)

    try:
        with create_server(sport, sdir) as server:
            manage_connections(server)
    except KeyboardInterrupt:
        print("shutting down server")


if __name__ == "__main__":
    main(len(sys.argv), sys.argv)
