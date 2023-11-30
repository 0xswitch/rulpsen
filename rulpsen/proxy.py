from .http_objects import HTTPrequest, HTTPResponse

from rich import print
import random
import ssl
import socket
import os
from OpenSSL import crypto
import gzip
import brotli
from datetime import datetime
from re import match

class HandleTLS():

    def __init__(self, uuid, certHandler, request, active_connexion, timeout=2, verbose=False, debug=False, interception_callback=None):
        self.uuid = uuid
        self.remote_server_timeout = timeout
        self.certHandler = certHandler
        self.request = request
        self.active_connexion = active_connexion
        self.verbose = verbose
        self.debug = debug
        self.interception_callback = interception_callback

    def print_info(self, x):
        if self.verbose:
            print(f"[green][+][/]\[{self.uuid}] {x}")

    def print_danger(self, x, force=False):
        if self.verbose or force:
            print(f"[yellow][-][/]\[{self.uuid}] {x}")

    def print_error(self, x):
        print(f"[red][!][/]\[{self.uuid}] {x}")

    def print_debug(self, x):
        if self.debug:
            print(f"[blue][.][/]\[{self.uuid}] {x}")

    def cert_gen(self, hostname=None):

        CERT_FILE = f"/home/{os.environ['USER']}/.config/rulpsen/certificates/{hostname}.pem"

        # maybe the certificate has been previously generated
        if os.path.exists(CERT_FILE):
            return (CERT_FILE, self.certHandler.KEY_FILE)

        # create required  x509 extension
        dns = crypto.X509Extension(b"subjectAltName", critical=False, value=b"DNS:" + hostname.encode("utf-8"))

        # creating fake certificate signed by the trusted CA
        cert = crypto.X509()
        cert_template = crypto.load_certificate_request(crypto.FILETYPE_PEM, crypto.dump_certificate_request(crypto.FILETYPE_PEM, self.certHandler.cert_template))

        cert.set_serial_number(random.getrandbits(64))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(31536000)
        cert.set_subject(cert_template.get_subject())
        cert.set_issuer(self.certHandler.ca_cert.get_subject())
        cert.set_pubkey(self.certHandler.cert_template.get_pubkey())
        cert.add_extensions([dns, self.certHandler.keyusage, self.certHandler.eku])
        cert.set_version(2)
        cert.sign(self.certHandler.ca_key, 'sha1024')

        with open(CERT_FILE, "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))

        return (CERT_FILE, self.certHandler.KEY_FILE)


    def decode_chunked(self, data):
        decoded = b""
        splited = data.split(b"\r\n")
        i = 0
        while i < len(splited) :
            if i % 2 == 1:
                decoded += splited[i]
            i += 1
        return decoded


    def get_client_request(self, client, server, no_parsing=False):
        request = HTTPrequest(self.uuid)
        http_header = b""
        http_body = b""

        # read until end of HTTP headers
        while (client_data := client.recv(256)):
            http_header += client_data
            # send data to the real server at the same time
            server.send(client_data)
            if b"\r\n\r\n" in http_header:
                break

        end_of_header = http_header.index(b"\r\n\r\n")
        # maybe we read a bit of the request content too

        http_body = http_header[end_of_header+4:]
        http_header = http_header[:end_of_header+4]

        # parsing the headers
        request.add_headers(http_header)
        # extraction method, uri and version
        request.extract_request_information(http_header)

        self.print_debug("receveid client headers")

        # according to rfc 9110 the Content-Length is mandatory if there is data and no Transfer-Encoding is set
        if "Content-Length" in request.headers:
            remaining_to_read = int(request.headers['Content-Length']) - len(http_body)
            # reading until the whole data is received and sending to server right after
            while remaining_to_read != 0:
                if remaining_to_read >= 1024:
                    rcved = client.recv(1024)
                    http_body += rcved
                    remaining_to_read -= len(rcved)
                else:
                    rcved = client.recv(remaining_to_read)
                    http_body += rcved
                    remaining_to_read -= len(rcved)

                server.send(rcved)

        self.print_debug("receveid client data")
        request.add_body(http_body)
        return request

    def get_server_response(self, client, server, request, do_not_send=False):
        response = HTTPResponse(self.uuid)
        http_header = b""
        http_body = b""
        raw_response = b""

        self.print_debug("reading from server")

        # read until end of response HTTP headers
        while (server_data := server.recv(2048)):
            http_header += server_data
            # sometimes client disconnect before getting the response
            if not do_not_send:
                try:
                    client.send(server_data)
                except IOError as e:
                    self.print_debug(e)

            if b"\r\n\r\n" in http_header:
                break

        end_of_header = http_header.index(b"\r\n\r\n")
        http_body = http_header[end_of_header+4:]
        http_header = http_header[:end_of_header+4]

        response.add_headers(http_header)
        response.set_response_code(http_header)

        self.print_debug(f"received server headers : {response.status_code}")

        self.print_debug(f"reading server body")

        # using it to know how much to read
        if "Content-Length" in response.headers:
            remaining_to_read = int(response.headers['Content-Length']) - len(http_body)
            self.print_debug(f"Content-Length : {remaining_to_read}")

            while remaining_to_read != 0:
                if remaining_to_read >= 1024:
                    rcved = server.recv(1024)
                    http_body += rcved
                    remaining_to_read -= len(rcved)
                else:
                    rcved = server.recv(remaining_to_read)
                    http_body += rcved
                    remaining_to_read -= len(rcved)
                if not do_not_send:
                    try:
                        client.send(rcved)
                    except IOError as e:
                        self.print_debug(e)

            response.add_body(http_body)


        # hop by hop header, should not be forwarded by proxy but who cares
        elif "Transfer-Encoding" in response.headers:
            # we assume it's only chunked even if other are possible

            while rcved := server.recv(1024):
                http_body += rcved

                if not do_not_send:
                    try:
                        client.send(rcved)
                    except IOError as e:
                        self.print_debug(e)

                if b"\r\n\r\n" in rcved:
                    break

            decoded = self.decode_chunked(http_body)

            # maybe the content is encoded itself
            if "Content-Encoding" in response.headers:
                encoding = response.headers['Content-Encoding']

                if encoding == "gzip":
                    try:
                        decompressed_body = gzip.decompress(decoded)
                        response.add_body(decompressed_body)
                    except Exception as e:
                        self.print_danger("gzip " +  request.uri + " " +  str(e))
                        response.add_body(http_body)

                elif encoding == "br":
                    try:
                        decompressed_body = brotli.decompress(decoded)
                        response.add_body(decompressed_body)
                    except Exception as e:
                        self.print_error("br " +  request.uri + " " +  str(e))
                        response.add_body(http_body)
                # should implents other but who care
                else:
                    self.print_danger('encoding not supported ' + encoding)
                    response.add_body(decoded)
            else:
                response.add_body(decoded)

        raw_response = http_header + http_body
        self.print_debug("received server body")
        if do_not_send:
            return (response, raw_response)
        else:
            return response

    def run(self):
        TLS = False
        # for https request with a proxy, the browser first send a HTTP request
        host, _, port = self.request.path.partition(":")
        if host in ["mtalk.google.com"]:
            return (None, None)

        # acknowledge browser request
        self.request.send_response(200, "Connection established")
        self.request.end_headers()

        if host not in ["127.0.0.1"]:

            cert, key = self.cert_gen(host)

        client = self.request.connection

        TLS_header_test = client.recv(4, socket.MSG_PEEK)

        # TLS signature, very dirty
        # didn't found anyway to chekc if it was SSL or not before handshake
        if match(b"\x16\x03[\x03\x01]", TLS_header_test):
            # create the socket of the fake server with the fake certificate
            ctx_client = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx_client.load_cert_chain(cert, key)
            ctx_client.verify_mode = ssl.CERT_NONE
            ctx_client.check_hostname = False
            client_wrapped = ctx_client.wrap_socket(client, server_side=True)
            TLS = True
        else:
            client_wrapped = client

        # now, connect to the real site
        try:
            sock = socket.create_connection((host, int(port)))
        except ConnectionRefusedError:
            self.print_error(f"can't connect to {host}:{port}, connexion refused")
            return (None, None)

        sock.settimeout(self.remote_server_timeout)

        if TLS:
            ctx_server = ssl.create_default_context()
            server = ctx_server.wrap_socket(sock, server_hostname=host)
        else:
            server = sock

        self.active_connexion[self.uuid] = f"{host}:{port}"
        self.print_info(f"connected to {host}")

        request = self.get_client_request(client_wrapped, server)

        if self.interception_callback is not None and self.interception_callback(request):
                response, raw_response = self.get_server_response(client_wrapped, server, request, do_not_send=True)
                modified_response = self.interception_callback(request, response, raw_response)
                client_wrapped.send(modified_response)
        else:
            response = self.get_server_response(client_wrapped, server, request)

        self.print_debug("closing connection")
        server.close()
        client_wrapped.close()

        del self.active_connexion[self.uuid]

        return (request, response)