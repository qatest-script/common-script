import random
from pprint import pprint
import base64
import os
import requests
import json
import string
import hashlib
import rsa


class LoginV4:
    test_server = '107'
    ssh_name = 'jgyang'
    host = f'https://test{test_server}.ascendex-sandbox.com'
    deposit_host = test_server
    md5_salt = '8f684cfc8b283fadabd804167f1e0ce5'
    device_old = 'old_device'
    device_new = 'new_device'
    base_email = 'autologin@bitmax.io'
    base_dial_code = '+81'
    base_country = 'JP'
    base_phone = '999999999'
    pwd = 'a12345678'
    verify_code = '654321'
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

    def express_register_email(self):
        print('开始注册一个新邮箱账号。。。')
        url = f'{self.host}/api/a/v2/auth/express-register/email'
        self.base_email = f'{self.get_random_str(4)}@bitmax.io'
        body = {
            "email": self.base_email,
            "inviteCode": "",
            "deviceId": self.device_old,
            "hashedPwd": self.hash_pwd(self.pwd + self.base_email),
            "encryptedPwd": self.encrypt_pwd(self.pwd),
            "encryptedCode": self.encrypt_pwd(self.verify_code),
        }
        res = requests.post(url=url, json=body)
        if res.status_code == 200:
            if json.loads(res.text).get('code') == 0:
                print(f'注册成功，账号：{self.base_email}，密码：{self.pwd}')
                self.deal_headers(res)
            else:
                print(f'注册失败，账号：{self.base_email}，密码：{self.pwd}')

    def express_register_phonne(self):
        print('开始注册一个新手机账号。。。')
        url = f'{self.host}/api/a/v2/auth/express-register/phone'
        self.base_phone = str(random.randint(900000000, 999999999))
        body = {
            "phone": self.base_phone,
            "dialCode": self.base_dial_code,
            "inviteCode": "",
            "deviceId": self.device_old,
            "hashedPwd": self.hash_pwd(f'{self.pwd}{self.base_dial_code}{self.base_phone}'),
            "encryptedPwd": self.encrypt_pwd(self.pwd),
            "countryCode": self.base_country,
            "encryptedCode": self.encrypt_pwd(self.verify_code)
        }
        res = requests.post(url=url, json=body)
        if res.status_code == 200:
            if json.loads(res.text).get('code') == 0:
                print(f'注册成功，账号：{self.base_dial_code}--{self.base_phone}，密码：{self.pwd}')
                self.deal_headers(res)
            else:
                print(f'注册失败，账号：{self.base_dial_code}--{self.base_phone}，密码：{self.pwd}')

    def get_user_info(self):
        url = f'{self.host}/api/a/v1/auth/user/info'
        if self.headers == '':
            print('用户信息获取失败，请重新登录')
        res = requests.get(url=url, headers=self.headers)
        pprint(json.loads(res.text))

    def deal_headers(self, res):
        pprint(f'刷新下headers和cookie')
        authorization = dict(json.loads(res.text)).get('data').get('authorization')
        res_headers = res.headers.get('Set-Cookie')
        for item in res_headers.split(';'):
            if len(item) > 1000:
                authtoken = item.split(',')[1]
        self.headers['authorization'] = authorization
        self.headers['cookie'] = f'locale=zh-cn;{authtoken}'
        pprint(f'刷新headers和cookie完成')

    def delete_device(self):
        print(f'开始删除设备')
        url = f'{self.host}/api/a/v1/auth/device/delete-all-device-staging-only'
        res = requests.delete(url, headers=self.headers)
        print(f'登录设备删除成功')

    def deposit(self, email=base_email):
        print(f'开始充值:{email}')
        # file_info = f'ssh gdmops@localhost /home/gdmops/current/exchange/examples/bin/add-staging-balance -e staging -i 1 -b 10.6.1.102:9092 -o order-request-payme -r AddBalance -g {account_group} -t {email_or_account_id}:{asset}={amount}'
        cmd = f'ssh -tt {self.ssh_name}@10.6.1.{self.deposit_host} "echo ssh gdmops@localhost /home/gdmops/add-balance -e {self.base_email} -a USDT -q 1000 > deposit.sh; sh deposit.sh"'
        os.system(cmd)
        print(f'充值完成:{email}')

    def login_new_device(self, channels):
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
        # pprint(f'新设备登录参数')
        # pprint(body)
        res = requests.post(url=url, json=body, headers=self.headers)
        loginSuccessful = json.loads(res.text).get('data').get('loginSuccessful')
        if loginSuccessful:
            print(f'=====登录成功=====')
            self.deal_headers(res)
        else:
            raise Exception(f'新备登录失败,请手动确认')

    def login_old_device(self, channel):
        url = f'{self.host}/api/a/v4/auth/login/verify-code'
        body = dict(
            encryptedCode=self.encrypt_pwd(self.verify_code),
            verifiedBy=channel
        )
        # pprint(f'老设备登录参数')
        # pprint(body)
        res = requests.post(url=url, json=body, headers=self.headers)
        loginSuccessful = json.loads(res.text).get('data').get('loginSuccessful')
        if loginSuccessful:
            print(f'=====登录成功=====')
            self.deal_headers(res)
        else:
            raise Exception(f'老设备登录失败,请手动确认')

    def login_email(self, balance_type, account_type, is_new_device, expect_channel_priority1,
                    expect_channel_priority2):
        url = f'{self.host}/api/a/v4/auth/login/email-or-username'
        print(
            f'=====开始邮箱{self.base_email}登录--{"无余额" if balance_type==0 else "有余额"}--{account_type}--{"新设备" if is_new_device else "老设备"}--期望验证方式{expect_channel_priority1,expect_channel_priority2}=====')
        body = dict(
            deviceId=self.get_random_str(32) if is_new_device else self.device_old,
            emailOrUsername=self.base_email,
            hashedPwd=self.hash_pwd(f'{self.pwd}{self.base_email}'),
            encryptedPwd=self.encrypt_pwd(self.pwd)
        )
        if is_new_device == False:
            body['oldDeviceId'] = self.device_new
        # pprint(f'登录参数为：')
        # pprint(json.dumps(body))
        res = requests.post(url, json=body)
        self.verify(res, balance_type, account_type, is_new_device, expect_channel_priority1,
                    expect_channel_priority2)

    def login_phone(self, balance_type, account_type, is_new_device, expect_channel_priority1,
                    expect_channel_priority2):
        url = f'{self.host}/api/a/v4/auth/login/phone'
        print(
            f'=====开始手机{self.base_phone}登录--{"无余额" if balance_type==0 else "有余额"}--{account_type}--{"新设备" if is_new_device else "老设备"}--期望验证方式{expect_channel_priority1,expect_channel_priority2}=====')
        print(f'手机登录，等一分钟。。。不然验证码间隔时间不够')
        # time.sleep(61)
        body = {
            "phone": self.base_phone,
            "dialCode": self.base_dial_code,
            "inviteCode": "",
            "deviceId": self.device_old,
            "hashedPwd": self.hash_pwd(f'{self.pwd}{self.base_dial_code}{self.base_phone}'),
            "encryptedPwd": self.encrypt_pwd(self.pwd),
            "countryCode": self.base_country,
        }
        if is_new_device == False:
            body['oldDeviceId'] = self.device_new
        # pprint(f'登录参数为：')
        # pprint(json.dumps(body))
        res = requests.post(url, json=body)
        self.verify(res, balance_type, account_type, is_new_device, expect_channel_priority1,
                    expect_channel_priority2)

    def verify(self, res, balance_type, account_type, is_new_device, expect_channel_priority1,
               expect_channel_priority2):
        self.deal_headers(res)
        # pprint(f'登录响应为:')
        # pprint(json.loads(res.text))
        loginSuccessful = dict(json.loads(res.text)).get('data').get('loginSuccessful')
        # 参数verifyType就是验证情景，暂时支持 NewDeviceLogin; KnownDeviceLogin; ApiKeyCreate; ApiKeyModify; PasswordModify; WalletWithdraw
        verifyType_from_server = dict(json.loads(res.text)).get('data').get('verifyInstruction').get('verifyType')
        allowedVerificationMethods_from_server = dict(json.loads(res.text)).get('data').get('verifyInstruction').get(
            'allowedVerificationMethods')
        if expect_channel_priority1 == [] and loginSuccessful:
            print(f'无需验证，登录成功')
            self.deal_headers(res)
        else:
            print(f'需要必选验证')
            if loginSuccessful:
                raise Exception(f'接口返回了需要验证的方式,但是loginSuccessful=1,有问题.')
            if expect_channel_priority2 == [] and len(allowedVerificationMethods_from_server) != 1:
                raise Exception(f'接口返回了可选择的验证方式,但期望是验证一个,不符合预期,请手动检查')

            # 验证方式不可选择的时候
            if len(allowedVerificationMethods_from_server) == 1:
                channel_from_server = allowedVerificationMethods_from_server[0].get('channels')
                if channel_from_server == expect_channel_priority1:
                    print(f'接口返回的验证方式符合预期:接口返回{channel_from_server},期望值:{expect_channel_priority1}')
                    if is_new_device and verifyType_from_server == 'NewDeviceLogin':
                        print(f'执行新设备认证')
                        self.login_new_device(expect_channel_priority1)
                    elif is_new_device == False and verifyType_from_server == 'KnownDeviceLogin':
                        print(f'执正常设备登录认证')
                        self.login_old_device(expect_channel_priority1[0])
                else:
                    raise Exception('预期验证方式和接口返回的验证方式不一致')
            # 验证方式可选择的时候
            else:
                print(f'需要可选验证')
                channel_from_server = []
                for method in allowedVerificationMethods_from_server:
                    channel_from_server.append(method.get('channels')[0])
                expect_channel_priority1.append(expect_channel_priority2[0])
                if channel_from_server != expect_channel_priority1:
                    raise Exception(f'预期验证方式和接口返回的验证方式不一致')
                print(
                    f'接口返回的验证方式符合预期:接口返回{allowedVerificationMethods_from_server[0].get("channels"),allowedVerificationMethods_from_server[1].get("channels")},期望值:{expect_channel_priority1[:1],expect_channel_priority2}')
                random_channel = random.randint(0, 1)
                channel_to_verify = channel_from_server[random_channel]
                if is_new_device and verifyType_from_server == 'NewDeviceLogin':
                    print(f'执行新设备认证')
                    self.login_new_device(channel_to_verify)
                else:
                    print(f'执行老设备登录认证')
                    self.login_old_device(channel_to_verify)

    def bind_phone(self):
        print(f'开始绑定手机')
        url = f'{self.host}/api/a/v1/auth/sms/binding-phone'
        self.base_phone = str(random.randint(900000000, 999999999))
        code = self.encrypt_pwd(self.verify_code)
        body = dict(
            dialCode=self.base_dial_code,
            areaCode=self.base_country,
            phone=self.base_phone,
            encrypted2FaCode=code,
            encryptedSmsCode=code,
            encryptedEmailCode=code
        )
        res = requests.post(url=url, headers=self.headers, json=body)
        if json.loads(res.text).get('data').get('phone') == self.base_phone:
            print(f'完成绑定手机')
            self.deal_headers(res)
        else:
            raise Exception('操作失败')

    def unbind_phone(self):
        print(f'开始解绑手机')
        url = f'{self.host}/api/a/v2/auth/unbinding/phone-unbinding-verify'
        code = self.encrypt_pwd(self.verify_code)
        body = dict(
            encrypted2FaCode=code,
            encryptedSmsCode=code,
            encryptedEmailCode=code
        )
        res = requests.post(url=url, headers=self.headers, json=body)
        if json.loads(res.text).get('code') == 0:
            print(f'完成解绑手机')
        else:
            raise Exception('操作失败')

    def bind_2fa(self):
        print(f'开始绑定2fa')
        code = self.encrypt_pwd(self.verify_code)
        # url = f'{self.host}/api/a/v3/auth/two-factor-gen/generate'
        # body = dict(
        #     encrypted2FaCode=code,
        #     encryptedSmsCode=code,
        #     encryptedEmailCode=code
        # )
        # res = requests.post(url=url, headers=self.headers, json=body)
        # print(res.text)
        url = f'{self.host}/api/a/v3/auth/two-factor-gen/verify'
        body = dict(
            encrypted2FaCode=code,
            encryptedSmsCode=code,
            encryptedEmailCode=code
        )
        res = requests.post(url=url, headers=self.headers, json=body)
        if json.loads(res.text).get('code') == 0:
            print(f'完成绑定2fa')
            self.deal_headers(res)
        else:
            raise Exception('操作失败')

    def unbind_2fa(self):
        print(f'开始解绑2fa')
        url = f'{self.host}/api/a/v3/auth/two-factor-removal'
        code = self.encrypt_pwd(self.verify_code)
        body = dict(
            encrypted2FaCode=code,
            encryptedSmsCode=code,
            encryptedEmailCode=code
        )
        res = requests.post(url=url, headers=self.headers, json=body)
        if json.loads(res.text).get('code') == 0:
            print(f'完成解绑2fa')
        else:
            raise Exception('操作失败')

    def unbind_email(self):
        print(f'开始解绑邮箱')
        url = f'{self.host}/api/a/v2/auth/unbinding/email-unbinding-verify'
        code = self.encrypt_pwd(self.verify_code)
        body = dict(
            encrypted2FaCode=code,
            encryptedSmsCode=code,
            encryptedEmailCode=code
        )
        res = requests.post(url=url, headers=self.headers, json=body)
        if json.loads(res.text).get('code') == 0:
            print(f'完成解绑邮箱')
        else:
            raise Exception('操作失败')

    def generate_account_balance0_and_login(self, balance=0):
        """主要生成各种组合且没有余额的账号，来进行登录验证"""
        self.express_register_email()

        # 无余额--只绑定邮箱--新设备
        self.delete_device()
        self.login_email(balance, "只绑定邮箱", True, ['email'], [])

        # 无余额--只绑定邮箱--老设备
        self.login_email(balance, "只绑定邮箱", False, [], [])

        # 无余额--邮箱+手机--新设备
        self.delete_device()
        self.bind_phone()
        self.login_email(balance, "邮箱+手机", True, ['email'], [])

        # 无余额--邮箱+手机--老设备
        self.login_email(balance, "邮箱+手机", False, [], [])

        # 无余额--邮箱+手机+谷歌--新设备
        self.delete_device()
        self.bind_2fa()
        self.login_email(balance, "邮箱+手机+谷歌", True, ['sms', 'email', '2fa'], [])

        # 无余额--邮箱+手机+谷歌--老设备
        self.login_email(balance, "邮箱+手机+谷歌", False, ['2fa'], ['sms'])

        # 无余额--邮箱+谷歌--新设备
        self.express_register_email()
        self.bind_2fa()
        self.delete_device()
        self.login_email(balance, "邮箱+手机+谷歌", True, ['email', '2fa'], [])

        # 无余额--邮箱+谷歌--老设备
        self.login_email(balance, "邮箱+手机+谷歌", False, ['2fa'], [])

        # 无余额--手机--新设备
        self.express_register_phonne()
        self.delete_device()
        self.login_phone(balance, "只绑定手机", True, [], [])

        # 无余额--手机--老设备
        self.login_phone(balance, "只绑定手机", False, [], [])

        # 无余额--手机+谷歌--新设备
        self.delete_device()
        self.bind_2fa()
        self.login_phone(balance, "手机+谷歌", True, ['2fa'], [])

        # 无余额--手机+谷歌--老设备
        self.login_phone(balance, "手机+谷歌", False, ['2fa'], [])

    def generate_account_balance1_and_login(self, balance=1):
        """主要生成各种组合且有余额的账号，来进行登录验证"""
        self.express_register_email()
        self.deposit(self.base_email)

        # 有余额--只绑定邮箱--新设备
        self.delete_device()
        self.login_email(balance, "只绑定邮箱", True, ['email'], [])

        # 有余额--只绑定邮箱--老设备
        self.login_email(balance, "只绑定邮箱", False, [], [])

        # 有余额--邮箱+手机--新设备
        self.delete_device()
        self.bind_phone()
        self.login_email(balance, "邮箱+手机", True, ['sms', 'email'], [])

        # 有余额--邮箱+手机--老设备
        self.login_email(balance, "邮箱+手机", False, ['sms'], [])

        # 有余额--邮箱+手机+谷歌--新设备
        self.delete_device()
        self.bind_2fa()
        self.login_email(balance, "邮箱+手机+谷歌", True, ['sms', 'email', '2fa'], [])

        # 有余额--邮箱+手机+谷歌--老设备
        self.login_email(balance, "邮箱+手机+谷歌", False, ['2fa'], ['sms'])

        # 有余额--邮箱+谷歌--新设备
        self.express_register_email()
        self.deposit()
        self.bind_2fa()
        self.delete_device()
        self.login_email(balance, "邮箱+手机+谷歌", True, ['email', '2fa'], [])

        # 有余额--邮箱+谷歌--老设备
        self.login_email(balance, "邮箱+手机+谷歌", False, ['2fa'], [])

        # 有余额--手机--新设备
        self.express_register_email()
        self.deposit()
        self.bind_phone()
        self.delete_device()
        self.unbind_email()
        self.login_phone(balance, "只绑定手机", True, ['sms'], [])

        # 有余额--手机--老设备
        self.login_phone(balance, "只绑定手机", False, ['sms'], [])

        # 有余额--手机+谷歌--新设备
        self.delete_device()
        self.bind_2fa()
        self.login_phone(balance, "手机+谷歌", True, ['sms', '2fa'], [])

        # 有余额--手机+谷歌--老设备
        self.login_phone(balance, "手机+谷歌", False, ['2fa'], ['sms'])

    def run(self, test_server='107', ssh_name='jgyang'):
        """主入口"""
        self.test_server = test_server
        self.ssh_name = ssh_name

        print('开始测试无余额的情况')
        # 先测无余额
        self.generate_account_balance0_and_login()

        # 再测有余额
        print(f'开始测试有余额的情况')
        self.generate_account_balance1_and_login()


if __name__ == '__main__':
    """需要提供被测环境地址和ssh用户名（用于充值，且这个用户可以在本地连上被测服务器）"""
    o = LoginV4()
    o.run(test_server='107', ssh_name='jgyang')

