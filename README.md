# Rulpsen

Small python HTTP(S) proxy and interceptor 


```python
from rulpsen import Rulpsen
from re import sub

all_urls = []

def callback(request, response, connexion):
    print(request.uri)

def interception_callback(request, response=None, raw_response=None):

    if response is None:

        if "<pattern>" in request.uri:
            return True

    # interception
    else:
        raw_response = raw_response.replace(b"http://remote.lan/lib.jar", b"http://localhost/lib.jar")
        return raw_response

if __name__ == "__main__":
    r = Rulpsen(port=8081)
    r.run(options={"callback": callback, "interception_callback": interception_callback, "debug": False})

```
