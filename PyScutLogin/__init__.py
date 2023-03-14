# encoding:utf-8

import requests
from requests.adapters import HTTPAdapter
import re
import os
from . import DES_JS


def PyScutLogin(username: str, password: str, service: str = '') -> requests.session:
    u = username
    p = password

    url = 'https://sso.scut.edu.cn/cas/login'
    if service:
        url += '?service=' + service
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.22 Safari/537.36 SE 2.X MetaSr 1.0'}
    session = requests.session()
    session.mount('http://', HTTPAdapter(max_retries=5))
    session.mount('https://', HTTPAdapter(max_retries=5))
    r = session.get(url, headers=headers, timeout=(2, 5))

    # lt : r'value="(LT-\d+?-\w+?-cas)"'
    lt = re.findall(r'value="(LT-\d+?-\w+?-cas)"', r.text)[0]
    execution = re.findall(r'name="execution" value="(.+?)"', r.text)[0]

    u = u.strip()
    p = p.strip()

    s = u+p+lt
    rsa = DES_JS.strenc(s, "1", "2", "3")

    # POST /cas/login
    data = {
        'rsa': rsa,
        'ul': len(u),
        'pl': len(p),
        'lt': lt,
        'execution': execution,
        '_eventId': 'submit'
    }
    print('LoginData :', data)
    r = session.post(url, data=data, headers=headers, timeout=(2, 5))
    print('Cookies :', session.cookies.items())
    return session
