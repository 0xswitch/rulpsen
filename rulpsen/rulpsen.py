from .proxy import HandleTLS

import http.server
import socketserver
from OpenSSL import crypto
from rich import print
from uuid import uuid4
import os

class generateCert():

    def __init__(self):
        self.KEY_FILE = f"/home/{os.environ['USER']}/.config/rulpsen/keys/cert.key"
        self.cert_template = self.create_cert_template()
        self.ca_cert, self.ca_key = self.load_ca()
        self.keyusage = crypto.X509Extension(b"keyUsage", critical=True, value=b"Digital Signature, Key Encipherment")
        self.eku = crypto.X509Extension(b"extendedKeyUsage", critical=False, value=b"TLS Web Server Authentication")

    def load_ca(self):
        cert = f"/home/{os.environ['USER']}/.config/rulpsen/keys/CA.pem"
        key = f"/home/{os.environ['USER']}/.config/rulpsen/keys/CA.key"
        ca_cert = open(cert, "r").read()
        ca_key = open(key, "r").read()

        return (crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert),crypto.load_privatekey(crypto.FILETYPE_PEM, ca_key))

    def create_cert_template(self):
        emailAddress="dev@rulpsen.dev"
        commonName="Rulpsen dev certificate"
        countryName="FR"
        localityName="local"
        stateOrProvinceName="state"
        organizationName="Rulpsen"
        organizationUnitName="Rulpsen dev"

        # create CSR
        k = crypto.load_privatekey(crypto.FILETYPE_PEM, open(self.KEY_FILE).read())

        csr = crypto.X509Req()
        csr.set_version(2)
        csr.get_subject().C = countryName
        csr.get_subject().ST = stateOrProvinceName
        csr.get_subject().L = localityName
        csr.get_subject().O = organizationName
        csr.get_subject().OU = organizationUnitName
        csr.get_subject().CN = commonName
        csr.get_subject().emailAddress = emailAddress
        csr.set_pubkey(k)
        csr.sign(k, 'sha256')

        return csr


class RequestHandler(http.server.SimpleHTTPRequestHandler):

    def log_message(self, format, *args):
        pass

    def do_CONNECT(self):
        uuid = str(uuid4())[:6]
        request, response = HandleTLS(uuid, self.certHdl, self, self.active_connexion, verbose=False, debug=self.options["debug"], interception_callback=self.options["interception_callback"]).run()
        if self.options['callback'] is not None:
            self.options['callback'](request, response, self.active_connexion)

class Rulpsen:

    def __init__(self, port=8081) -> None:
        self.first_run()
        self.port = port
        self.active_connexion = {}

    def run(self, options):
        socketserver.TCPServer.allow_reuse_address = True
        RequestHandler.certHdl = generateCert()
        RequestHandler.options = options
        RequestHandler.active_connexion = self.active_connexion

        with socketserver.ThreadingTCPServer(("", self.port), RequestHandler) as httpd:
            print(f"Serving on port {self.port}")
            httpd.serve_forever()

    def first_run(self):
        try:
            os.makedirs(f"/home/{os.environ['USER']}/.config/rulpsen/keys")
        except FileExistsError:
            pass

        try:
            os.makedirs(f"/home/{os.environ['USER']}/.config/rulpsen/certificates/")
        except FileExistsError:
            pass

        # making a private key for the fake certificate
        if not os.path.exists(f"/home/{os.environ['USER']}/.config/rulpsen/keys/cert.key"):
            private_key = crypto.PKey()
            private_key.generate_key(type=crypto.TYPE_RSA, bits=2048)
            pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key)
            open(f"/home/{os.environ['USER']}/.config/rulpsen/keys/cert.key", "wb").write(pem)

        if not os.path.exists(f"/home/{os.environ['USER']}/.config/rulpsen/keys/CA.pem"):
            print("[red][!][/] CA certificate not found")
            exit(0)

        if not os.path.exists(f"/home/{os.environ['USER']}/.config/rulpsen/keys/CA.key"):
            print("[red][!][/] CA private key not found")
            exit(0)

