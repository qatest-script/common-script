import requests
import hashlib
import rsa
import base64
import json
import random
import string
import pprint

host_pc = 'https://asdx.plus'
host_m = 'https://m.asdx.plus'
domain_new = 'asdcn.me'

langs = [
    'zh-cn',
    'en'
]

pc_urls = [
    '',
    '/DeFi-Yield-Farming-Agreement',
    '/Liquidity-Mining-Services-Agreement',
    '/staking-agreement',
    '/terms-of-service',
    '/terms/copytrade'
]
h5_urls = [
    '',
    '/static/terms/DeFi-Yield-Farming-Agreement.html',
    '/static/terms/Liquidity-Mining-Services-Agreement.html',
    '/static/terms/service.html',
    '/static/terms/staking-agreement.html',
    '/app-download'
]

# 验证 pc 端
print('检查pc端')
for lang in langs:
    print('检查语言：' + lang)
    for path in pc_urls:
        url = f'{host_pc}/{lang}{path}'
        page = requests.get(url).text
        if page.find(domain_new) > 0:
            print(f'验证正常--{url}')
        else:
            print(f'没有找到--{url}')

# 验证 h5
for lang in langs:
    print('检查语言：' + lang)
    headers = {
        'cookies': f'"locale"={lang}',
        'Accept-Language': f'{lang}'
    }
    for path in h5_urls:
        url = f'{host_m}{path}'
        page = requests.get(url=url, headers=headers).text
        # if lang=='en':
        #     print(page)
        if page.find(domain_new) > 0:
            print(f'验证正常--{url}')
        else:
            print(f'!!!没有找到--{url}')

print("！！！通知后端修改 notification-server 配置,和 cookie 设置配置")
