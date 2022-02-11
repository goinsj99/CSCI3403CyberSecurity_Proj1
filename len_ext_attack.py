import http.client
import urllib.parse
import sys
import pymd5

from pymd5 import md5, padding
from urllib.parse import urlparse


def length_extension_attack(original_url):
    original_url_parsed = urlparse(original_url)
    url_query = str(original_url_parsed.query)

    split_url_query = url_query.split('&', 1)
    token = split_url_query[0][6:]
    og_query = split_url_query[1]
    og_query_bytes = str.encode(og_query)

    h = md5()
    h.update(og_query_bytes)

    original_message_length = len(og_query_bytes) + 8
    message_padding = pymd5.padding(original_message_length * 8)
    total_len = (original_message_length + len(message_padding)) * 8
    h = pymd5.md5(state=bytes.fromhex(token), count=total_len)

    suffix = '&command3=DeleteAllFiles'
    h.update(suffix.encode())
    updated_token = h.hexdigest()

    url_safe_padding = urllib.parse.quote(message_padding)

    updated_query = 'token={}&{}{}{}'.format(updated_token, og_query, url_safe_padding, suffix)

    new_url = 'https://csci3403.com/proj1/api?{}'.format(updated_query)
    return new_url


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print('Requires the URL to extend as a command line argument.')
        exit(1)
    original_url = sys.argv[1]
    # Your code to modify url goes here
    new_url = length_extension_attack(original_url)
    # The following code requests the URL and returns the response from the server
    parsed_url = urllib.parse.urlparse(new_url)
    conn = http.client.HTTPSConnection(parsed_url.hostname,
                                       parsed_url.port)
    conn.request("GET", parsed_url.path + "?" + parsed_url.query)
    print(conn.getresponse().read())