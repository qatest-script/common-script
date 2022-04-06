from http.cookiejar import Cookie
import random
import hashlib
from pprint import pprint
import base64
import time
import os
import requests
import json
import string
import hashlib
import rsa


class LoginV4:
    host = 'https://test107.ascendex-sandbox.com'
    deposit_host = '107'
    md5_salt = '8f684cfc8b283fadabd804167f1e0ce5'
    device_old = 'old_device'
    device_new = 'new_device'
    base_email = 'autologin@bitmax.io'
    base_dial_code = '+376'
    base_phone = '99999999'
    pwd = 'a12345678'
    verify_code = '654321'
    accounts = dict(
        # 只绑定手机、只绑定邮箱、邮箱+手机、邮箱+谷歌、手机+谷歌、邮箱+手机+谷歌
        phone_only=dict(
            phone='11111111',
            dialCode='+376',
            pwd='12345678'
        ),

    )
    headers = dict(
        authorization='',
        cookie=''
    )

    def hash_pwd(self, str):
        salt = self.md5_salt
        md5 = hashlib.md5()
        str = str.strip().lower() + salt
        md5.update(str.encode('utf8'))
        return md5.hexdigest()

    def encrypt_pwd(self, pwd):
        """rsa加密"""
        public_key = '''
                    -----BEGIN PUBLIC KEY-----
                    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkpYfNB6efBqb7uquHK9l1iwrgpBenE4u6EttJ3t+EsQJskDnChixUGqOozTaJ4DdHjPdlgIoBKl8VHfYevGvZRv5+cRcnw3mBbDmCDdUwC/lt3eeW/f9ylEU5nfZBSQ/C4UY76qqzH6eqGe/SXw8sUbwRytC0p3g1jCyc4jo7G+smVe4pKq0mGmfhlJpV+1MLSw7ye1eT8/tD5htmIcBmemjhHzUwhsC5qnqMv1iH3IWd8yu/udEQlYfNa/V6N9HPqoFAJYMYkCoRWgM0oLvV2YQekU1mzSHglXbzx39cAK17VUFgxeyEGLEWXR8MH0MOgu3/LY//Ct9yQpVg1uweQIDAQAB
                    -----END PUBLIC KEY-----
                    '''
        rsa_pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(public_key.encode())
        crypto = rsa.encrypt(pwd.encode(), rsa_pubkey)
        b64str = base64.b64encode(crypto)
        return str(b64str.decode())

    def get_random_str(self, len):
        return ''.join(random.sample(string.ascii_lowercase + string.digits, len))

    def express_register_email(self, email=''):
        print('开始注册一个新邮箱账号。。。')
        url = f'{self.host}/api/a/v2/auth/express-register/email'
        self.base_email = f'{self.get_random_str(4)}@bitmax.io'
        body = {
            "email": self.base_email,
            "inviteCode": "",
            "deviceId": self.device_old,
            "hashedPwd": self.hash_pwd(self.pwd + self.base_email),
            "encryptedPwd": self.encrypt_pwd(self.pwd),
            # "countryCode": "SG",
            "encryptedCode": self.encrypt_pwd(self.verify_code),
        }
        res = requests.post(url=url, json=body)
        if res.status_code == 200:
            if json.loads(res.text).get('code') == 0:
                print(f'注册成功，账号：{self.base_email}，密码：{self.pwd}')
            else:
                print(f'注册失败，账号：{self.base_email}，密码：{self.pwd}')

    def login_phone(self, account_type):
        print(f'手机登录')
        user = dict()
        url = f'{self.host}/api/a/v4/auth/login/phone'
        phone, dialCode, pwd = '11111111', '+376', 'a11111111'
        body = dict(
            deviceId=self.device_id,
            oldDeviceId=self.device_id,
            phone=phone,
            dialCode=dialCode,
            hashedPwd=self.hash_pwd(f'{pwd}{dialCode}{phone}'),
            encryptedPwd=self.encrypt_pwd(pwd)
        )
        pprint(body)
        res = requests.post(url=url, json=body, headers=self.headers)
        pprint(json.loads(res.text))
        return res

    def get_user_info(self):
        url = f'{self.host}/api/a/v1/auth/user/info'
        if self.headers == '':
            print('用户信息获取失败，请重新登录')
        res = requests.get(url=url, headers=self.headers)
        pprint(json.loads(res.text))

    def deal_headers(self, res):
        pprint(f'刷新下headers和cookie')
        authorization = dict(json.loads(res.text)).get('data').get('authorization')
        cookies_dict = requests.utils.dict_from_cookiejar(res.cookies)
        print('000000000000000000000000')
        print(cookies_dict)
        authtoken = cookies_dict.get('authtoken')
        self.headers['authorization'] = authorization
        self.headers['cookie'] = f'locale=zh-cn;authtoken={authtoken}'
        pprint(f'刷新headers和cookie完成')
        pprint(self.headers)

    def delete_device(self):
        print(f'开始删除设备')
        url = f'{self.host}/api/a/v1/auth/device/delete-all-device-staging-only'
        res = requests.delete(url, headers = self.headers)
        print(f'登录设备删除成功')


    def generate_account_and_login(self, balance=0):
        """无余额时"""
        # 单邮箱
        print('生成纯邮箱账号')
        self.express_register_email()
        # 充值
        if balance:
            self.deposit(self.base_email)
        self.login_email(balance, "只绑定邮箱", False, [],[])
        self.delete_device()
        self.login_email(balance, "只绑定邮箱", True, ['email'],[])



    def deposit(self,email):
        print(f'开始充值:{email}')
        os.system(f'')
        print(f'充值完成:{email}')

    def login_new_device(self,channels):
        url = f'{self.host}/api/a/v4/auth/login/device'
        body = dict(
            deviceId=self.device_new
        )
        for channel in channels:
            if channel == 'email':
                body['encryptedEmailCode'] = self.encrypt_pwd(self.verify_code)
            if channel == 'sms':
                body['encryptedSmsCode'] = self.encrypt_pwd(self.verify_code)
            if channel == '2fa':
                body['encrypted2FaCode'] = self.encrypt_pwd(self.verify_code)
        res = requests.post(url=url, json=body, headers=self.headers)
        loginSuccessful = dict(json.loads(res.text)).get('data').get('loginSuccessful')
        if loginSuccessful:
            print(f'登录成功')
            self.deal_headers(res)
        else:
            raise Exception(f'新备登录失败,请手动确认')

    def login_old_device(self, channel):
        url = f'{self.host}/api/a/v4/auth/login/verify-code'
        body = dict(
            encryptedCode=self.encrypt_pwd(self.verify_code),
            verifiedBy=channel[0]
        )
        res = requests.post(url=url, json=body, headers=self.headers)
        loginSuccessful = dict(json.loads(res.text)).get('data').get('loginSuccessful')
        if loginSuccessful:
            print(f'登录成功')
            self.deal_headers(res)
        else:
            raise Exception(f'老设备登录失败,请手动确认')

    def login_email(self, balance_type, account_type, is_new_device, expect_channel_priority1,expect_channel_priority2):
        url = f'{self.host}/api/a/v4/auth/login/email-or-username'
        print(f'=====开始邮箱登录--{"无余额" if balance_type==0 else "有余额"}--{account_type}--{"老设备" if is_new_device else "新设备"}--期望验证方式{expect_channel_priority1,expect_channel_priority2}=====')
        body = dict(
            deviceId=self.device_new,
            oldDeviceId=self.device_old,
            emailOrUsername=self.base_email,
            hashedPwd=self.hash_pwd(f'{self.pwd}{self.base_email}'),
            encryptedPwd=self.encrypt_pwd(self.pwd)
        )
        pprint(f'登录参数为：')
        # pprint(json.dumps(body))
        res = requests.post(url, json=body)
        self.deal_headers(res)
        pprint(json.loads(res.text))
        loginSuccessful = dict(json.loads(res.text)).get('data').get('loginSuccessful')
        verifyType_from_server = dict(json.loads(res.text)).get('data').get('verifyInstruction').get('verifyType')
        allowedVerificationMethods_from_server = dict(json.loads(res.text)).get('data').get('verifyInstruction').get('allowedVerificationMethods')
        if expect_channel_priority1 == [] and loginSuccessful:
            print(f'无需验证，登录成功')
            self.deal_headers(res)
        else:
            print(f'需要验证')
            if loginSuccessful:
                raise Exception(f'接口返回了需要验证的方式,但是loginSuccessful=1,有问题.')
            if len(allowedVerificationMethods_from_server) != 1:
                raise Exception(f'接口返回了可选择的验证方式,不符合预期,请手动检查')

            # 验证方式不可选择的时候
            if len(allowedVerificationMethods_from_server) == 1:
                channel_from_server = allowedVerificationMethods_from_server[0].get('channels')
                if channel_from_server == expect_channel_priority1:
                    print(f'接口返回的验证方式符合预期{channel_from_server}')
                    if is_new_device and verifyType_from_server=='NewDeviceLogin':
                        print(f'执行新设备认证')
                        self.login_new_device(expect_channel_priority1)
                    else:
                        print(f'执行老设备登录认证')
                        self.login_old_device(expect_channel_priority1)
                else:
                    raise Exception('预期验证方式和接口返回的验证方式不一致')
            # 验证方式可选择的时候
            else:
                channel_from_server=[]
                for method in allowedVerificationMethods_from_server:
                    channel_from_server.append(method.get('channels')[0])
                channel_expect = expect_channel_priority1.append(expect_channel_priority2[0])
                if channel_from_server != channel_expect:
                    raise Exception(f'预期验证方式和接口返回的验证方式不一致')
                random_channel = random.randint(0,1)
                channel_to_verify=channel_from_server[random_channel]
                if is_new_device and verifyType_from_server == 'NewDeviceLogin':
                    print(f'执行新设备认证')
                    self.login_new_device(verifyType_from_server)
                else:
                    print(f'执行老设备登录认证')
                    self.login_old_device(verifyType_from_server)

    def run(self):
        self.generate_account_and_login(balance=0)
        self.generate_account_and_login(balance=1)


if __name__ == '__main__':
    # 参数verifyType就是验证情景，暂时支持 NewDeviceLogin; KnownDeviceLogin; ApiKeyCreate; ApiKeyModify; PasswordModify; WalletWithdraw
    o = LoginV4()
    o.run()
