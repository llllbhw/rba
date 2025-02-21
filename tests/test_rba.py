import secrets
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.twofactor.hotp import HOTP
from cryptography.hazmat.primitives.twofactor import InvalidToken

from ipaddress import ip_address
from ipaddress import ip_network

from keystone.common import manager
from keystone.common import password_hashing as hasher
from keystone.common import provider_api
from keystone import exception
from keystone.i18n import _

from keystone_rba_plugin import conf

from oslo_log import log
from oslo_serialization import base64
from oslo_serialization import jsonutils

CONF = conf.CONF
LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs


class RBAManager(manager.Manager):
    """Default pivot point for the rba backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
dynamically calls the backend.

    """

    driver_namespace = 'keystone.rba'
    _provides_api = 'rba_api'

    def __init__(self):
        driver_name = CONF.rba.driver
        if driver_name is not None:
            self.driver = manager.load_driver(
                self.driver_namespace,
                driver_name)
        self.messenger = CONF.rba.messenger
        if self.messenger is not None:
            self.messenger = manager.load_driver(
                self.driver_namespace,
                self.messenger
            )
        self.init_coefficients()
        self.load_histories()
        self.load_malicious_networks()
        self.p_A_given_xk = {
            'ip': self.p_A_given_ip,
        }
        self.lai = {'attempt': [],
                    'p_x': [],
                    'p_x_u_L': [],
                    'p_A': [],
                    'p_L': [],
                    'risk_score': []}


    def load_malicious_networks(self):#加载恶意网络列表
        self.malicious_networks = None
        if CONF.rba.malicious_ip_list_path is None:
            return
        networks = []
        try:
            with open(CONF.rba.malicious_ip_list_path, 'r') as f:
                for line in f:
                    try:
                        network = ip_network(line.split('#')[0].split()[0])
                        networks.append(network)
                    except Exception:
                        continue
        except Exception as e:
            LOG.debug(e)
        self.malicious_networks = networks

    def init_histories(self):
        self.total_history = {}
        self.users_history = {}

    def load_histories(self):
        self.init_histories()
        data = self.driver.get_entries()
        for entry in data:
            self._add_features(entry[0], entry[1])

    def get_user_entries(self, user_id):
        return self.driver.get_features_list_by_user(user_id)

    def init_coefficients(self):
        self.coefficients = {}
        for feature in CONF.rba.features:
            if feature == 'ip':
                ip_features = [feature]
                if CONF.rba.maxmind_asn_db_path is not None:
                    ip_features.append('asn')
                if CONF.rba.maxmind_asn_db_path is not None:
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
            if feature == 'rtt':
                self.coefficients.setdefault(
                    feature, {}).setdefault(feature, 1.0)
            if feature == 'ua':
                self.coefficients.setdefault(
                    feature, {}).setdefault(feature, 0.5386653840551359)
                self.coefficients.setdefault(
                    feature, {}).setdefault('bv', 0.2680451498625666)
                self.coefficients.setdefault(
                    feature, {}).setdefault('osv', 0.18818295100109536)
                self.coefficients.setdefault(
                    feature, {}).setdefault('df', 0.0051065150812021525)

    def _add_features(self, user_id, features):
        user_history = self.users_history.setdefault(user_id, {})
        user_history.setdefault('count', 0)
        user_history['count'] += 1
        for feature, value in features.items():
            user_features = user_history.setdefault(feature, {})
            user_features.setdefault(value, 0)
            self.users_history[user_id][feature][value] += 1
            total_features = self.total_history.setdefault(feature, {})
            total_features.setdefault(value, 0)
            self.total_history[feature][value] += 1

    def add_features(self, user_id, features, confidence_score):
        """Adds a new entry using the driver in compliance with
the configured max_user_history_size.

        If no history is to be created, all existing entries will be deleted.

        Otherwise, if the max_user_history_size will be exceeded on another
        successful recording, it will delete as much of the oldest
        persisted entries and keeps track of changes to apply on
        the in memory lookup histories without the need to retrieving
        the whole history.

        :param str user_id: unique user identitier.
        :param dict features: environmental values collected during
        an authentication attempt.
        :param float confidence_score: risk score calculated for the features
        """

        # In case max_user_history_size is 0, flush all histories and return
        # as no entry can be persisted and circumvents the endless
        # grow of in memory histories.
        if (CONF.rba.max_user_history_size == 0):
            self.driver.clear_entries()
            self.init_histories()
            return
        counter = 0
        if CONF.rba.max_user_history_size is not None:
            counter = (self.driver.count_entries_by_user(user_id) + 1 -
                       CONF.rba.max_user_history_size)
        list_to_remove = []
        if counter > 0:
            list_to_remove += self.driver.delete_oldest_n_entries_by_user(
                user_id, counter)
        self.driver.create_entry(user_id, features, confidence_score)
        # In case max_user_history_size has not been reached yet,
        # would list_to_remove be empty and the loop is skipped.
        try:
            for user_id_to_remove, features_to_remove in list_to_remove:
                self._subtract_features(user_id_to_remove, features_to_remove)
            self._add_features(user_id, features)
        except AssertionError:
            self.load_histories()

    def _subtract_features(self, user_id, features):
        try:
            self.users_history[user_id]['count'] -= 1
            for feature, value in features.items():
                self._dict_subtract(self.users_history[user_id],
                                    feature, value)
                if len(self.users_history[user_id]) == 1:
                    del self.users_history[user_id]
                self._dict_subtract(self.total_history,
                                    feature, value)
        except KeyError:
            raise AssertionError('Inconsistancy in history.')
        try:
            if self.users_history[user_id]['count'] <= 0:
                raise AssertionError('Inconsistancy in history.')
        except KeyError:
            pass

    def _dict_subtract(self, dictionary, feature, value):
        try:
            dictionary[feature][value] -= 1
            if dictionary[feature][value] == 0:
                del dictionary[feature][value]
            if len(dictionary[feature]) == 0:
                del dictionary[feature]
        except KeyError:
            raise AssertionError('Inconsistancy in dictionary.')

    def _filter_features(self, features):
        filtered_values = {}
        for key in CONF.rba.features:
            filtered_values[key] = features.get(
                key, '')
        return filtered_values

    def _hash_features(self, features):
        return {k: base64.encode_as_text(hasher.hash_password(
            str(features[k]))) for k in features}

    def _sum_values(self, values):
        return sum(values.values())

    def _count_total_L(self):
        return sum(map(lambda x: x.get('count'),
                       self.users_history.values()))

    def _count_user_L(self, user_id):
        return self.users_history.get(user_id, {}).get('count', 0)

    def authenticate(self, user_id, features=None, passcode=None):
        identity_manager = PROVIDERS.identity_api
        user_dict = identity_manager.get_user(user_id)
        identity_manager.assert_user_enabled(user_id, user_dict)
        if not user_dict:
            raise AssertionError(_('Invalid user.'))
        if passcode is not None:
            credentials = self.get_credentials(user_id)
            if not credentials:
                raise AssertionError(_('Passcode but no credentials.'))
            self.delete_credentials_by_user(user_id)
            for credential in credentials:
                ref = self.verify_passcode(passcode, credential)
                self.add_features(user_id,
                                  ref['features'],
                                  ref['confidence_score'])
                return
        elif features is not None:
            self.delete_credentials_by_user(user_id)
            score = self.confidence_score(user_id, features)
            LOG.debug('User: ' + user_id)
            LOG.debug('Confidence score: ' + str(score))
            if self.users_history.get(user_id, None) is None:
                self.add_features(user_id, features, score)
                return
            if score > CONF.rba.reject_threshold:
                LOG.debug('Rejection at threshold: ' +
                          str(CONF.rba.reject_threshold))
                raise AssertionError(_('User rejected.'))
            elif score > CONF.rba.request_threshold:
                code = self.create_credential(user_id, features, score)
                try:
                    return self.send_message(user_dict, code)
                except KeyError or exception.AuthPluginException:
                    self.delete_credentials_by_user(user_id)
                    LOG.debug('Message could not be sent to user:' + user_id)
                    raise exception.AuthPluginException(_('No message sent.'))
            else:
                self.add_features(user_id, features, score)
        else:
            raise AssertionError(_('No features or passcode'))

    def send_message(self, user_dict, passcode):
        contact = {'contact': user_dict[CONF.rba.contact_method]}
        response = {'contact_method': CONF.rba.contact_method}
        message = {'passcode': passcode,
                   'recipient': user_dict.get(
                       CONF.rba.recipient_designator, None
                   ) or CONF.rba.default_recipient}
        message.update(contact)
        if self.messenger is None:
            response.update(message)
        else:
            self.messenger.send_passcode(**message)
            if CONF.rba.include_contact:
                response.update(contact)
        return response

    def verify_passcode(self, passcode, credential):
        passcode = bytes(passcode, encoding='utf-8')
        ref = credential['blob']
        ref = jsonutils.loads(ref)
        key = base64.decode_as_bytes(ref['secret'])
        counter = ref['counter']
        hotp = HOTP(key, 6, hashes.SHA256())
        try:
            hotp.verify(passcode, counter)
        except InvalidToken:
            raise AssertionError(_('Invalid passcode'))
        return ref

    def create_credential(self, user_id, features, confidence_score):
        key = secrets.token_bytes(32)
        hotp = HOTP(key, 6, hashes.SHA256())
        counter = 0
        passcode = hotp.generate(counter)
        key = base64.encode_as_text(key, encoding='utf-8')
        ref = {}
        ref['id'] = uuid.uuid4().hex
        ref['user_id'] = user_id
        ref['type'] = 'rba'
        ref['blob'] = jsonutils.dumps({'features': features,
                                       'confidence_score': confidence_score,
                                       'secret': key,
                                       'counter': counter})
        ref = PROVIDERS.credential_api.create_credential(ref['id'], ref)
        return str(passcode, encoding='utf-8')

    def get_credentials(self, user_id):
        return PROVIDERS.credential_api.list_credentials_for_user(
            user_id, type='rba')

    def delete_credentials_by_user(self, user_id):
        credentials = self.get_credentials(user_id)
        for credential in credentials:
            PROVIDERS.credential_api.delete_credential(credential['id'])

    def feature_value_history(self, entries, feature_value):
        """Filters a list of features dictionaries by the occurrence
        of a value for a feature.
        """
        history = {}
        for entry in entries:
            if entry.get(feature_value[0]) == feature_value[1]:
                for feature, value in entry.items():
                    feature_history = history.setdefault(feature, {})
                    feature_history.setdefault(value, 0)
                    history[feature][value] += 1
        return history

    def p_A_given_ip(self, x):
        if self.malicious_networks is None:
            if CONF.rba.malicious_ip_list_path is not None:
                self.load_malicious_networks()
            else:
                return 1.0
        try:
            ip = ip_address(x)
            c = 0.1
        except Exception:
            return 1.0
        for network in self.malicious_networks:
            if ip in network:
                c = 1.0
                break
        p = self.p_0(c * 100, 100, 1)
        return p

    def p_xk(self, xk, k):
        # World level global likelihood
        c = sum(self.total_history.get(k, {}).values())
        c_xk = self.total_history.get(k, {}).get(xk, 0)
        p = self.p_0(c_xk, c, 1)
        return p

    def p_xk_given_u_L(self, xk, k, user_id):
        # Local likelihood for successful logins by user with feature value xk.
        c = sum(self.users_history.get(user_id, {}).get(k, {}).values())
        c_xk = self.users_history.get(user_id, {}).get(k, {}).get(xk, 0)
        p = self.p_0(c_xk, c, 1)
        return p

    def p_u_given_A(self):
        # Assuming all users are equally likely
        c = len(self.users_history)
        p = 0.0 if c == 0 else 1.0 / c
        return p

    def p_u_given_L(self, user_id):
        """Assuming the proportion of all legitimate logins belonging
        to the user.
        """
        c_L = self._count_total_L()
        c_u_L = self._count_user_L(user_id)
        p = 1.0 if c_L == 0 else 0.0 if c_u_L == 0.0 else c_u_L / c_L
        return p

    def confidence_score(self, user_id, x):
        """Calculation of the users confidence score of a current login
        attempts feature values x as estimation of the risk considering
        successful login feature value sets in the past history.
        """
        score = 1.0
        user_history = self.users_history.get(user_id, {})
        entries = self.get_user_entries(user_id)
        total_entries = list(map(lambda x: x[1], self.driver.get_entries()))
        for k in CONF.rba.features:
            score *= self.p_A_given_xk.get(k, (lambda xk: 1.0))(x.get(k, ''))
            # p_xk = self.p(x, k, self.total_history)
            p_xk = self.p_linear(x, k, total_entries, self.total_history, smoothing=True)
            p_linear = self.p_linear(x, k, entries, user_history, smoothing=False)
            score *= p_xk / (4 if p_linear == 0.0 else p_linear)
        p_u_given_L = self.p_u_given_L(user_id)
        p_u_given_A = self.p_u_given_A()
        score *= (0.0 if p_u_given_L == 0.0 else p_u_given_A / p_u_given_L)
        return score

    def p_linear(self, x, k, entries, history, smoothing=True):
        p = 0.0
        for l in self.coefficients.get(k, {}).keys():
            x_hl = x.get(l, '')
            sub_history = self.feature_value_history(entries, (l, x_hl))
            p_k = self.p_k(x, l, l, sub_history, history, smoothing)
            p += self.coefficients[k][l] * p_k
            smoothing = False
        return p

    def p_k(self, x, k, l, sub_history, history, smoothing=True):
        vals_p_x_hk = {}
        vals_p_hk = {}
        # Likelihood of feature is in history of subfeature
        p_x_hk = self.p(x, k, sub_history, smoothing, vals_p_x_hk)
        # Calculate likelihood of subfeature
        p_hk = self.p(x, l, history, smoothing, vals_p_hk)
        p = p_x_hk * p_hk
        return p

    def M_hk(self, k, history=None, vals={}):
        """Calculate unseen features for smoothing.
        """
        if history is None:
            history = self.total_history
        for feature in CONF.rba.features:
            i = 0
            subfeatures = list(self.coefficients.get(feature, {}).keys())
            for subfeature in subfeatures:
                if i > len(subfeatures) - 2:
                    break
                if k == subfeature:
                    next_subfeature = subfeatures[i + 1]
                    c_sub = len(history.get(next_subfeature, {}))
                    c_next = self.M_hk(next_subfeature, history, vals)
                    return c_sub + c_next
                i += 1
        return 1

    def p(self, x, k, history, smoothing=True, vals={}):
        k_in_history = history.get(k, {})
        c_xk = k_in_history.get(x.get(k, ''), 0)
        c_k = sum(k_in_history.values())
        p = 1.0
        if smoothing or c_xk == 0:
            M_hk = self.M_hk(k, history=history)
        else:
            M_hk = 0
        p *= self.p_0(c_xk, c_k, M_hk, smoothing)
        return p

    def p_0(self, c, N, M, smoothing=True):
        if c > 0:
            return 1 * c / N * (1 - (M / (N + M)))
        else:
            return 1 / (N + M) if smoothing else 0.0

