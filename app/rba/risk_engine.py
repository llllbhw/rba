# app/rba/risk_engine.py

import logging
import secrets
import uuid
from ipaddress import ip_address, ip_network

#from oslo_serialization import jsonutils

# 假设配置数据在运行时以字典形式传入
# 示例配置中需要包含：features（例如 ['ip', 'rtt', 'ua']）、malicious_ip_list_path、各项权重等
# 历史数据的持久化操作由 driver 提供，driver 应该提供 get_entries()、get_entries_by_user(user_id) 等接口

LOG = logging.getLogger(__name__)


class RiskEngine:
    def __init__(self, config, driver):
        """
        :param config: 字典形式的配置，例如：
           {
              'features': ['ip', 'rtt', 'ua'],
              'ip_weight': 0.4,
              'device_weight': 0.3,
              'behavior_weight': 0.3,
              'reject_threshold': 0.9,
              'request_threshold': 0.7,
              'malicious_ip_list_path': '/path/to/malicious_ips.txt',
              // 其他配置……
           }
        :param driver: 历史数据存储接口（例如数据库访问类），需提供：
            - get_entries(): 返回所有历史记录，格式：[ (user_id, features_dict), ... ]
            - get_entries_by_user(user_id): 返回该用户的所有历史记录（列表，每个元素为 features 字典）
        """
        self.config = config
        self.driver = driver

        # 系数字典，用于各特征及其子特征的加权（例如 ip 可能包含 asn、cc 等）
        self.coefficients = {}
        self._init_coefficients()

        # 历史数据：全局统计和每个用户的统计
        self.total_history = {}
        self.users_history = {}
        self._load_histories()

        # 加载恶意 IP 网段列表（如有配置）
        self.malicious_networks = None
        self._load_malicious_networks()

        # 针对特定特征（例如 IP）指定风险因子计算函数
        self.p_A_given_xk = {
            'ip': self.p_A_given_ip,
        }

    def _load_malicious_networks(self):
        """加载恶意 IP 列表文件，文件中每行为网段（可包含注释）。"""
        path = self.config.get('malicious_ip_list_path')
        if not path:
            return
        networks = []
        try:
            with open(path, 'r') as f:
                for line in f:
                    try:
                        # 过滤注释和空白字符，取第一项为网段
                        network = ip_network(line.split('#')[0].split()[0])
                        networks.append(network)
                    except Exception:
                        continue
        except Exception as e:
            LOG.debug("加载恶意 IP 列表失败：%s", e)
        self.malicious_networks = networks

    def _init_coefficients(self):
        """
        根据配置中的 features 初始化各特征及其子特征的权重系数。
        这里以 ip、rtt、ua 举例，可根据实际情况扩展。
        """
        for feature in self.config.get('features', []):
            if feature == 'ip':
                ip_features = [feature]
                # 示例：如果配置中指定了其他 ip 相关信息，则加入 asn、cc 等
                if self.config.get('maxmind_asn_db_path'):
                    ip_features.append('asn')
                if self.config.get('maxmind_cc_db_path'):
                    ip_features.append('cc')
                ip_coefficients = self.coefficients.setdefault(feature, {})
                if 'cc' in ip_features and 'asn' in ip_features:
                    ip_coefficients.setdefault(feature, 0.6)
                    ip_coefficients.setdefault('asn', 0.3)
                    ip_coefficients.setdefault('cc', 0.1)
                elif 'asn' in ip_features:
                    ip_coefficients.setdefault(feature, 0.6)
                    ip_coefficients.setdefault('asn', 0.4)
                elif 'cc' in ip_features:
                    ip_coefficients.setdefault(feature, 0.6)
                    ip_coefficients.setdefault('cc', 0.4)
                else:
                    ip_coefficients.setdefault(feature, 1.0)
            elif feature == 'rtt':
                self.coefficients.setdefault(feature, {}).setdefault(feature, 1.0)
            elif feature == 'ua':
                self.coefficients.setdefault(feature, {}).setdefault(feature, 0.5387)
                self.coefficients[feature].setdefault('bv', 0.2680)
                self.coefficients[feature].setdefault('osv', 0.1882)
                self.coefficients[feature].setdefault('df', 0.0051)

    def _load_histories(self):
        """从持久化存储中加载历史登录记录，并构建全局与用户统计数据。"""
        self.total_history = {}
        self.users_history = {}
        data = self.driver.get_entries()
        for user_id, features in data:
            self._add_features(user_id, features)

    def _add_features(self, user_id, features):
        """将一次成功登录的特征数据添加到内存统计中。"""
        user_history = self.users_history.setdefault(user_id, {})
        user_history.setdefault('count', 0)
        user_history['count'] += 1

        for feature, value in features.items():
            user_features = user_history.setdefault(feature, {})
            user_features[value] = user_features.get(value, 0) + 1

            total_features = self.total_history.setdefault(feature, {})
            total_features[value] = total_features.get(value, 0) + 1

    def get_user_entries(self, user_id):
        """获取指定用户的所有历史登录特征数据。"""
        return self.driver.get_entries_by_user(user_id)

    def calculate_risk(self, user_id, features):
        """
        根据用户历史和当前登录时采集的特征，计算风险分数。
        采用多个概率因子的乘积进行加权：
            - 针对某一特征，先计算特殊风险因子（例如 ip 是否在恶意网络中）
            - 计算全局和用户历史中该特征的出现概率，并取比值
            - 综合各特征后，再根据用户整体登录频率归一化

        :param user_id: 用户唯一标识
        :param features: 当前登录采集的环境数据字典
        :return: 风险分数（数值越高风险越大）
        """
        score = 1.0
        user_history = self.users_history.get(user_id, {})
        entries = self.get_user_entries(user_id)
        total_entries = self.driver.get_entries()  # 所有历史数据

        for k in self.config.get('features', []):
            # 1. 对于 ip 等特征，先计算额外风险因子
            factor = self.p_A_given_xk.get(k, lambda x: 1.0)(features.get(k, ''))
            score *= factor

            # 2. 分别计算全局和该用户本地特征出现的概率（使用平滑处理）
            p_xk = self.p_linear(features, k, total_entries, self.total_history, smoothing=True)
            p_linear = self.p_linear(features, k, entries, user_history, smoothing=False)
            score *= p_xk / (4.0 if p_linear == 0.0 else p_linear)

        # 3. 引入用户整体登录比例（假设所有用户同等可能）
        total_count = self._count_total_L()
        user_count = self._count_user_L(user_id)
        p_u_given_L = (user_count / float(total_count)) if total_count else 1.0
        p_u_given_A = 1.0 / (len(self.users_history) or 1)
        score *= (p_u_given_A / p_u_given_L) if p_u_given_L != 0 else 0.0

        LOG.debug("Risk score for user %s: %s", user_id, score)
        return score

    def p_linear(self, x, k, entries, history, smoothing=True):
        """
        对某一特征 k，通过各子特征进行线性加权计算出现概率。
        :param x: 当前登录特征数据
        :param k: 主特征
        :param entries: 历史记录列表（每个记录为字典）
        :param history: 全局或用户历史统计字典
        :param smoothing: 是否对零出现值进行平滑处理
        :return: 线性加权后的概率值
        """
        p_total = 0.0
        # 对于主特征 k 下的各子特征（如 ip 可能有 asn、cc 等），累加各自概率
        for l in self.coefficients.get(k, {}).keys():
            sub_history = self.feature_value_history(entries, (l, x.get(l, '')))
            p_k = self.p_k(x, l, l, sub_history, history, smoothing)
            p_total += self.coefficients[k][l] * p_k
            # 仅对第一个子特征进行平滑处理
            smoothing = False
        return p_total

    def p_k(self, x, k, l, sub_history, history, smoothing=True):
        """
        计算主特征及其子特征联合出现的概率乘积。
        """
        p_x_hk = self.p(x, k, sub_history, smoothing)
        p_hk = self.p(x, l, history, smoothing)
        return p_x_hk * p_hk

    def p(self, x, k, history, smoothing=True):
        """
        计算特征 k 在给定历史中出现的概率。
        :param x: 当前特征数据
        :param k: 特征名称
        :param history: 统计字典
        :param smoothing: 是否进行平滑处理
        """
        k_in_history = history.get(k, {})
        c_xk = k_in_history.get(x.get(k, ''), 0)
        c_k = sum(k_in_history.values())
        if smoothing or c_xk == 0:
            M_hk = self.M_hk(k, history)
        else:
            M_hk = 0
        return self.p_0(c_xk, c_k, M_hk, smoothing)

    def M_hk(self, k, history):
        """
        用于平滑处理：返回在历史中该特征未见值的数目。
        简单实现：返回当前统计中该特征的不同取值个数；至少返回 1
        """
        return len(history.get(k, {})) or 1

    def p_0(self, c, N, M, smoothing=True):
        """
        基本概率计算函数。
        :param c: 某特征值出现次数
        :param N: 某特征的总出现次数
        :param M: 平滑处理的未见值总数
        :param smoothing: 是否平滑
        """
        if c > 0:
            return (c / N) * (1 - (M / float(N + M)))
        else:
            return 1.0 / (N + M) if smoothing else 0.0

    def feature_value_history(self, entries, feature_value):
        """
        根据传入的特征及其值过滤历史记录，并统计各特征出现次数。
        :param entries: 历史记录列表，每条记录为字典
        :param feature_value: 元组 (特征名称, 期望值)
        :return: 统计字典
        """
        history = {}
        for entry in entries:
            if entry.get(feature_value[0]) == feature_value[1]:
                for feature, value in entry.items():
                    feature_history = history.setdefault(feature, {})
                    feature_history[value] = feature_history.get(value, 0) + 1
        return history

    def _count_total_L(self):
        """统计所有用户的登录次数总和。"""
        return sum(user.get('count', 0) for user in self.users_history.values())

    def _count_user_L(self, user_id):
        """统计指定用户的登录次数。"""
        return self.users_history.get(user_id, {}).get('count', 0)
