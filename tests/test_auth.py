# tests/test_auth.py

import unittest
import time
from app.rba.auth_utils import AuthUtils

class TestAuthUtils(unittest.TestCase):
    def test_generate_totp_secret(self):
        # 测试生成 TOTP 秘钥是否返回有效字符串
        secret = AuthUtils.generate_totp_secret()
        self.assertIsInstance(secret, str, "TOTP 秘钥应为字符串")
        self.assertTrue(len(secret) > 0, "生成的 TOTP 秘钥不应为空")

    def test_get_and_verify_totp_token(self):
        # 测试令牌生成和验证流程
        secret = AuthUtils.generate_totp_secret()
        token = AuthUtils.get_totp_token(secret)
        # 立即验证生成的令牌，应该返回 True
        self.assertTrue(AuthUtils.verify_totp(token, secret), "应能验证当前生成的 TOTP 令牌")

    def test_verify_invalid_totp_token(self):
        # 测试一个错误令牌是否会验证失败
        secret = AuthUtils.generate_totp_secret()
        # 生成一个正确令牌后，构造一个错误令牌（例如在正确令牌上加1）
        correct_token = AuthUtils.get_totp_token(secret)
        invalid_token = str((int(correct_token) + 1) % 1000000).zfill(6)
        self.assertFalse(AuthUtils.verify_totp(invalid_token, secret), "错误的 TOTP 令牌应验证失败")

    def test_totp_token_time_window(self):
        # 测试 TOTP 令牌在有效时间窗口内有效，过期后验证失败
        secret = AuthUtils.generate_totp_secret()
        token = AuthUtils.get_totp_token(secret)
        # 立即验证应为 True
        self.assertTrue(AuthUtils.verify_totp(token, secret), "当前 TOTP 令牌应在有效时间窗口内")
        # 休眠超过有效窗口（例如 60 秒，取决于 TOTP 时间间隔，一般为30秒）
        time.sleep(31)
        self.assertFalse(AuthUtils.verify_totp(token, secret), "过期的 TOTP 令牌应验证失败")

if __name__ == '__main__':
    unittest.main()
