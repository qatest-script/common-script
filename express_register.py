import requests
import hashlib
import rsa
import base64
import json
import random
import string
import pprint


class Register:
    host = 'https://test107.ascendex-sandbox.com'
    url = f'{host}/api/a/v2/auth/express-register/email'
    headers = {
        'authorization': 'LMVInPUIylpSMErb650793878eea2669',
        'cookie': 'authtoken=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6ImthaXNoaUBiaXRtYXguaW8iLCJpc0FkbWluRW1haWwiOnRydWUsImVtYWlsT3JQaG9uZSI6ImthaXNoaUBiaXRtYXguaW8iLCJpc0VtYWlsIjp0cnVlLCJ1c2VySWQiOiJ1c3Jjd3dzS0lGTW4xZVo0RmRSdGxPRDF1bm4zMnU4eSIsImlzQWRtaW4iOnRydWUsImFjY291bnRJZCI6ImNzaGN3d3NLSUZNbjFlWjRGZFJ0bE9EMXVubjMydTh5IiwibWFyZ2luQWN0SWQiOiJtYXJjd3dzS0lGTW4xZVo0RmRSdGxPRDF1bm4zMnU4eSIsImZ1dHVyZXNBY3RJZCI6ImZ1dGN3d3NLSUZNbjFlWjRGZFJ0bE9EMXVubjMydTh5IiwiaXNFbWFpbFZlcmlmaWVkIjp0cnVlLCJwYXNzd29yZFN0cmVuZ3RoIjowLCJ0d29GYWN0b3JSZXF1aXJlZCI6ZmFsc2UsInR3b0ZhY3RvclZlcmlmaWVkIjpmYWxzZSwidXNlcm5hbWUiOiIiLCJ1c2VybmFtZU9yaWdpbmFsIjoiIiwiZGF0YUZlZVRlcm1BY2NlcHRlZCI6dHJ1ZSwia3ljTGV2ZWwiOjMsImFjY291bnRUeXBlIjoiIiwiZGFpbHlXaXRoZHJhd0xpbWl0SW5CdGMiOiIxMDAuMCIsIm1heFdpdGhkcmF3YWxCdGNWYWx1ZSI6IjEwMC4wIiwidmlwIjowLCJjYW5UcmFkZSI6dHJ1ZSwiY2FuV2l0aGRyYXciOnRydWUsImFjY291bnRHcm91cCI6MCwiYXV0aG9yaXphdGlvbiI6IkxNVkluUFVJeWxwU01FcmI2NTA3OTM4NzhlZWEyNjY5IiwibWluaW5nT3V0cHV0T3B0aW9uIjoicmVndWxhciIsIm1hcmdpblRlcm1zQWNjZXB0ZWQiOjAsImxvZ2luU3VjY2Vzc2Z1bCI6dHJ1ZSwibWFyZ2luUmlza1Rlcm1zQWNjZXB0ZWQiOmZhbHNlLCJkZXZpY2VJZCI6ImYxY2ExNWNmNTgwMjNhOWI5NWFkZDhkZDQ4NDg4ZTZhIiwic2lnbmF0dXJlIjoiMWMzOGQyZjRhMzdhODg3ZWY5NTk4YjM4MWQyODc2YjMiLCJleHBpcmVUaW1lIjoxNjQ2NjE5NDk1NTg1LCJsb2dpblRpbWUiOjE2NDYzNjAyOTU1ODUsIlVJRCI6Ilg3MTQyNzk5Nzk3IiwiaXNBbnRpUGhpc2hpbmdDb2RlU2V0IjpmYWxzZSwiZnV0dXJlVGVybXNBY2NlcHRlZCI6MCwic3ViVXNlclRlcm1zQWNjZXB0ZWQiOjAsInZlcnNpb24iOjAsImFyZWFDb2RlIjoiIiwiZGlhbENvZGUiOiIiLCJwaG9uZSI6IiIsImlzQWRtaW5QaG9uZSI6ZmFsc2UsInJlZ2lzdHJhdGlvbiI6ImVtYWlsIiwibm90aWZpY2F0aW9uIjoiZW1haWwiLCJ2ZXJpZmljYXRpb24iOiJlbWFpbCIsInNob3dQaG9uZU5vdGljZSI6dHJ1ZSwic2hvd0VtYWlsTm90aWNlIjpmYWxzZSwicGhvbmVBdXRoVmVyaWZpZWQiOmZhbHNlLCJhdXRoVmVyc2lvbiI6NCwidXNlQWRtaW5Ud29GYWN0b3IiOmZhbHNlLCJpc0Jyb2tlciI6ZmFsc2UsImV4dHJhQXV0aCI6IjZlMTk1ZjQ0ZDI0MTdmNzI1YjcxOWM2Nzg4MmVkYTE3IiwiZXh0cmFUcmFkaW5nIjoiNmUxOTVmNDRkMjQxN2Y3MjViNzE5YzY3ODgyZWRhMTcifQ.gsOv6EkqvaXDhwlq2hIGH_UIeEimgdlCtN7zan4HR74;'
    }

    def get_random_str(self, len):
        return ''.join(random.sample(string.ascii_lowercase + string.digits, len))

    def encrypt_pwd(self, pwd):
        public_key = '''
                    -----BEGIN PUBLIC KEY-----
                    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkpYfNB6efBqb7uquHK9l1iwrgpBenE4u6EttJ3t+EsQJskDnChixUGqOozTaJ4DdHjPdlgIoBKl8VHfYevGvZRv5+cRcnw3mBbDmCDdUwC/lt3eeW/f9ylEU5nfZBSQ/C4UY76qqzH6eqGe/SXw8sUbwRytC0p3g1jCyc4jo7G+smVe4pKq0mGmfhlJpV+1MLSw7ye1eT8/tD5htmIcBmemjhHzUwhsC5qnqMv1iH3IWd8yu/udEQlYfNa/V6N9HPqoFAJYMYkCoRWgM0oLvV2YQekU1mzSHglXbzx39cAK17VUFgxeyEGLEWXR8MH0MOgu3/LY//Ct9yQpVg1uweQIDAQAB
                    -----END PUBLIC KEY-----
                    '''
        '''rsa加密'''
        rsa_pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(public_key.encode())
        crypto = rsa.encrypt(pwd.encode(), rsa_pubkey)
        b64str = base64.b64encode(crypto)
        return str(b64str.decode())

    def hash_pwd(self, str):
        salt = '8f684cfc8b283fadabd804167f1e0ce5'
        md5 = hashlib.md5()
        str = str.strip().lower() + salt
        md5.update(str.encode('utf8'))
        return md5.hexdigest()

    def express_register_email(self, email=''):
        print('开始注册。。。')
        if email == '':
            email = f'{self.get_random_str(4)}@bitmax.io'
        pwd = '12345678'
        headers = dict(
            language='en-us',
            cookie='locale=en-us'
        )
        body = {
            "email": email,
            "inviteCode": "",
            "deviceId": "deviceId",
            "hashedPwd": self.hash_pwd(pwd + email),
            "encryptedPwd": self.encrypt_pwd(pwd),
            # "countryCode": "SG",
            "encryptedCode": self.encrypt_pwd('654321'),
        }
        print(body)
        try:
            res = requests.post(self.url, headers=headers, json=body)
            cookies_dict = requests.utils.dict_from_cookiejar(res.cookies)
            # print(cookies_dict)
            authorization = json.loads(res.text).get('data').get('authorization')
            authtoken = cookies_dict.get('authtoken')
            print({
                'authorization': authorization,
                'cookie': 'authtoken=' + authtoken
            })
            print(f'\n注册成功。。。邮箱:{email} ，密码:{pwd}')
            return authorization, authtoken
        except Exception as e:
            print(f'注册失败。。。' + res.text)

    def set_kyc1(self, email='', country=''):
        headers = self.headers
        if email != '':
            authorization, authtoken = self.express_register_email(email)
            headers = {
                'authorization': authorization,
                'cookie': 'authtoken=' + authtoken
            }
        url = f'{self.host}/api/a/v1/auth/kyc/level1'
        body = {
            "nationality": country,
            "lastName": "d",
            "firstName": "d",
            "idType": "passport",
            "idNumber": "12345678",
            "dob": "2000-02-01"
        }
        print(headers)
        print(f'kyc1设置成功{requests.post(url=url, json=body, headers=headers).text}')

    def set_kyc3(self, email='', country=''):
        headers = self.headers
        if email != '':
            authorization, authtoken = self.express_register_email(email)
            headers = {
                'authorization': authorization,
                'cookie': 'authtoken=' + authtoken
            }
        url1 = f'{self.host}/api/a/v1/auth/kyc/level1'
        body = {
            "nationality": country,
            "lastName": "d",
            "firstName": "d",
            "idType": "passport",
            "idNumber": "12345678",
            "dob": "2000-02-01"
        }
        print(f'kyc1设置成功{requests.post(url=url1, json=body, headers=headers).text}')
        url2 = f'{self.host}/api/a/v1/auth/kyc/staging-set-kyc-level'
        body = {
            "kycLevel": 3,
            "nationality": country
        }
        print('headers:')
        print(headers)
        print(f'kyc3设置成功{requests.post(url=url2, json=body, headers=headers).text}')


if __name__ == '__main__':
    o = Register()

    index = '18'
    # email = f'yjg{index}@bitmax.io'
    email = f'tuisong308@bitmax.io'

    o.express_register_email(email)
    # o.set_kyc3(country='CN')
    # o.set_kyc1(country='CN')
