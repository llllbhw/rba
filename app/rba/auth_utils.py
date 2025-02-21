# app/rba/auth_utils.py

import pyotp
import logging

LOG = logging.getLogger(__name__)

class AuthUtils:
    @staticmethod
    def generate_totp_secret():
        """
        生成一个新的 TOTP 秘钥，用于后续生成和验证 TOTP 令牌。
        返回一个 Base32 格式的字符串，建议将此秘钥安全存储在用户记录中。
        """
        secret = pyotp.random_base32()
        LOG.debug("生成 TOTP 秘钥: %s", secret)
        return secret

    @staticmethod
    def get_totp_token(secret):
        """
        根据给定的 TOTP 秘钥生成当前有效的 TOTP 令牌。
        :param secret: 用户的 TOTP 秘钥（Base32 格式）
        :return: 当前 TOTP 令牌（通常为 6 位数字字符串）
        """
        totp = pyotp.TOTP(secret)
        token = totp.now()
        LOG.debug("生成的 TOTP 令牌: %s", token)
        return token

    @staticmethod
    def verify_totp(token, secret):
        """
        验证用户输入的 TOTP 令牌是否有效。
        :param token: 用户输入的 TOTP 令牌
        :param secret: 用户存储的 TOTP 秘钥
        :return: 如果令牌有效则返回 True，否则返回 False
        """
        totp = pyotp.TOTP(secret)
        is_valid = totp.verify(token, valid_window=1)  # 允许 ±1 个时间窗口的误差
        if is_valid:
            LOG.debug("TOTP 令牌 %s 验证成功。", token)
        else:
            LOG.debug("TOTP 令牌 %s 验证失败。", token)
        return is_valid
