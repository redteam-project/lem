import gzip
import re
import StringIO
import os
import json
import requests
import csv

def open_from_url(location, tlsverify=True):
    response = requests.get(location, verify=tlsverify, stream=True)
    response.raise_for_status()
    if 'gzip' in response.headers.get('content-type'):
        data = decode_compressed_content(response.content)
    elif 'json' in response.headers.get('content-type') or 'text' in response.headers.get('content-type'):
        data = response.content
    return data

def open_from_file(location):
    file_content = ''
    if location.endswith(".gz"):
        with gzip.open(location, 'rb') as gzip_file_obj:
            file_content = gzip_file_obj.read()
    else:
        with open(location, 'r') as file_obj:
            file_content = file_obj.read()
    return file_content

def open_from_directory(location):
    filenames = [os.path.join(d, x)
                 for d, _, files in os.walk(location)
                 for x in files]
    return filenames

def write_to_file(location, file_content):
    _, file_extension = os.path.splitext(location)
    if file_extension == '.gzip' or file_extension == '.gz':
        with gzip.open(location, 'wb') as gzip_file_obj:
            gzip_file_obj.write(json.dumps(file_content))
    elif file_extension == '.json':
        with open(location, "w") as json_file_obj:
            json.dump(file_content, json_file_obj)
    else:
        with open(location, "w") as file_obj:
            file_obj.write(file_content)

def location_is_url(location):
    url_regex = re.compile(r'^(?:http|ftp)s?://' # http:// or https://
                           r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
                           r'localhost|' #localhost...
                           r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
                           r'(?::\d+)?' # optional port
                           r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    if url_regex.match(location):
        return True
    return False

def location_is_url_dir(location):
    url_regex = re.compile(r'^(?:http|ftp)s?://' # http:// or https://
                           r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
                           r'localhost|' #localhost...
                           r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
                           r'(?::\d+)?' # optional port
                           r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    if url_regex.match(location):
        return True
    return False

def decode_compressed_content(content):
    string_data = StringIO.StringIO(content)
    data = gzip.GzipFile(fileobj=string_data).read()
    return data
