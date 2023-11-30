import email
import re
from io import StringIO
from rich import print
import re

class HTTPHeaders(dict):

    def __init__(self, raw_headers):
        super().__init__(self.parse_headers(raw_headers))

    def parse_headers(self, raw_headers):
        raw_headers = raw_headers.decode("utf-8")
        _, headers = raw_headers.split('\r\n', 1)
        message = email.message_from_file(StringIO(headers))
        headers = dict(message.items())
        return headers

    def __str__(self):
        buffer = ""
        for k,v in self.items():
            buffer += f"{k}: {v}\n"
        return buffer
    
    def __repr__(self):
        buffer = ""
        for k,v in self.items():
            buffer += f"{k}: {v}\n"
        return buffer
    
    def keys(self):
        res = list(super().keys())
        res += list(map(str.lower, res))
        return res
    
    def __contains__(self, __key) :
        return __key in self.keys() or __key.lower() in self.keys()
    
    def __getitem__(self, __key):
        try:
            return super().__getitem__(__key)
        except:
            return super().__getitem__(__key.lower())


class HTTPr:
    def __init__(self, uuid):
        self.headers = {}
        self.body = b"" 
        self.uuid = uuid

    def add_headers(self, raw_headers):
        self.headers = HTTPHeaders(raw_headers)

    def add_body(self, body):
        self.body = body

class HTTPrequest(HTTPr):

    def __init__(self, uuid):
        super().__init__(uuid)
        self.uri = None
        self.method = None
        self.version = None
    
    def extract_request_information(self, raw_http_headers):
        self.method, self.uri, self.version = raw_http_headers.decode("utf-8").split("\r\n")[0].split(" ")

    def __repr__(self) -> str:
        return f"[{self.uuid}][Req] {self.headers['Host']}: {self.method}"
    
class HTTPResponse(HTTPr):

    def __init__(self, uuid):
        super().__init__(uuid)
        self.status_code = None

    def get_response_code(self, headers):
        return int(re.findall(r"HTTP/[0-2\.]+\s(\d+)\s.*$", headers.split(b"\r\n")[0].decode("utf-8"))[0])

    def set_response_code(self, headers):
        self.status_code = self.get_response_code(headers)
    
    def __repr__(self):
        if "Content-Type" in self.headers.keys():
            return f"[{self.uuid}][Rep] {self.status_code} {self.headers['Content-Type']}"
        else:
            return f"[{self.uuid}][Rep] {self.status_code}"
