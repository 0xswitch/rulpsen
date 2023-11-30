from rulpsen import Rulpsen
from re import findall, MULTILINE, DOTALL
from urllib.parse import *

all_urls = []

def callback(_, request, response, connexion):
    body = None

    if (content_type := response.headers.get('Content-Type')) is not None:
        if ";" in content_type:
            content_type = content_type.split(";")[0]
        if content_type in ["text/html", "application/json", "text/plain", "application/x-httpd-php"]:

            try:
                body = response.body.decode("utf-8")
            except:
                pass
    else:
        try:
            body = response.body.decode("utf-8")
        except:
            pass
    
    if body is not None:
        urls = findall(r'https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)', body, MULTILINE | DOTALL )
        for url in urls:
            url = urlparse(url)._replace(params="", query="", fragment="").geturl()
            last_part = urlparse(url).path.split("/")[-1]
            if "." in last_part:
                new_url = url.replace(last_part, "")
            else:
                new_url = url
            
            if new_url[-1] != "/":
                new_url += "/"

            if new_url not in all_urls:
                print(new_url)
                all_urls.append(new_url)



if __name__ == "__main__":
    r = Rulpsen()
    r.run(callback)
