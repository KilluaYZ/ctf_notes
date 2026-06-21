import select
import socket
import ssl
import sys


HOST = "1ead20b2b3561fa9fbde91f9.tcp-ctf2.dasctf.com"
PORT = 9999


def main() -> None:
    raw_sock = socket.create_connection((HOST, PORT))
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    sock = context.wrap_socket(raw_sock, server_hostname=HOST)

    print(f"[+] Connected to {HOST}:{PORT} over TLS")
    print("[+] Type commands like `ls`, `cat /flag`, then Ctrl+C to quit")

    try:
        while True:
            readable, _, _ = select.select([sock, sys.stdin], [], [])

            if sock in readable:
                data = sock.recv(4096)
                if not data:
                    print("\n[-] Remote closed the connection")
                    break
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()

            if sys.stdin in readable:
                line = sys.stdin.buffer.readline()
                if not line:
                    break
                sock.sendall(line)
    finally:
        sock.close()


if __name__ == "__main__":
    main()
