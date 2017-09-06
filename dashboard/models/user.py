"""User class that governs maniuplation of session['userdata']"""
import http.client
import json
import logging
import requests
import time

from config import OIDCConfig
from models import alert


logger = logging.getLogger(__name__)


class DotDict(dict):
    """return a dict.item notation for dict()'s"""

    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

    def __init__(self, dct):
        for key, value in dct.items():
            if hasattr(value, 'keys'):
                value = DotDict(value)
            self[key] = value


class Mozillians(object):
    """Operations governing Mozillians."""
    def __init__(self, app_config=None):
        self.app_config = app_config

    @property
    def api_key(self):
        if self.app_config is not None:
            return self.app_config.MOZILLIANS_API_KEY

    @property
    def api_url(self):
        if self.app_config is not None:
            return self.app_config.MOZILLIANS_API_URL

    def _has_avatar(self, email):
        if self.api_url is not None:
            try:
                mozillians_response = requests.get(self.api_url, headers=self.headers,
                                                   params=self.params, timeout=5)
                if mozillians_response.status_code is not 200:
                    return None
                response = mozillians_response.json()
                return response
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                return None
        else:
            return None

    def _is_only_one_avatar(self, response):
        # Check if only single resource gets returned and it's valid
        avatars = response.get('results', -1)

        if len(avatars) == 1:
            self.user_url = avatars[0].get('_url')
            return True
        else:
            self.user_url = None
            return False

    def _get_image_url(self):
        # Finally fetch user public avatar and make sure  we have a valid fallback
        try:
            response = requests.get(self.user_url, headers=self.headers, timeout=5).json()
            if response['photo']['privacy'] == 'Public':
                return response['photo']['value']
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            return None

    def avatar(self, email):
        self.headers = {'X-API-KEY': self.api_key}
        self.params = {'email': email}

        response = self._has_avatar(email)

        if response:
            self._is_only_one_avatar(response)
            avatar_url = self._get_image_url()
        else:
            avatar_url = None

        return avatar_url

class AuthZero(object):
    def __init__(self):
        self.default_headers = {
            'content-type': "application/json"
        }
        self.oidc_config = OIDCConfig()
        self.client_id = self.oidc_config.OIDC_CLIENT_ID
        self.client_secret = self.oidc_config.OIDC_CLIENT_SECRET

        self.access_token = None
        self.access_token_scope = None
        self.access_token_valid_until = 0

        self.conn = http.client.HTTPSConnection(self.oidc_config.OIDC_DOMAIN)

    def __del__(self):
        self.client_secret = None
        self.conn.close()

    def get_user(self, user_id):
        """Return user from the auth0 API.
        user_id: string
        returns: JSON dict of the user profile
        """

        payload = DotDict(dict())
        payload_json = json.dumps(payload)
        self.conn.request("GET",
                          "/api/v2/users/{}".format(user_id),
                          payload_json,
                          self._authorize(self.default_headers))
        res = self.conn.getresponse()
        self._check_http_response(res)
        user = DotDict(json.loads(res.read()))

        return user

    def get_logs(self, email):
        payload = DotDict(dict())
        payload_json = json.dumps(payload)
        self.conn.request("GET",
                          "/api/v2/logs?per_page=100&search={}".format(email),
                          payload_json,
                          self._authorize(self.default_headers))
        res = self.conn.getresponse()
        self._check_http_response(res)
        return json.loads(res.read())

    def get_access_token(self):
        """
        Returns a JSON object containing an OAuth access_token.
        This is also stored in this class other functions to use.
        """
        payload = DotDict(dict())
        payload.client_id = self.client_id
        payload.client_secret = self.client_secret
        payload.audience = "https://{}/api/v2/".format(self.oidc_config.OIDC_DOMAIN)
        payload.grant_type = "client_credentials"
        payload_json = json.dumps(payload)

        self.conn.request("POST", "/oauth/token", payload_json, self.default_headers)
        res = self.conn.getresponse()
        self._check_http_response(res)

        access_token = DotDict(json.loads(res.read()))
        # Validation
        if ('access_token' not in access_token.keys()):
            raise Exception('InvalidAccessToken', access_token)
        self.access_token = access_token.access_token
        self.access_token_valid_until = time.time() + access_token.expires_in
        self.access_token_scope = access_token.scope

        return access_token

    def _authorize(self, headers):
        if not self.access_token:
            raise Exception('InvalidAccessToken')
        if self.access_token_valid_until < time.time():
            raise Exception('InvalidAccessToken', 'The access token has expired')

        local_headers = {}
        local_headers.update(headers)
        local_headers['Authorization'] = 'Bearer {}'.format(self.access_token)

        return local_headers

    def _check_http_response(self, response):
        """Check that we got a 2XX response from the server, else bail out"""
        if (response.status >= 300) or (response.status < 200):
            self.logger.debug("_check_http_response() HTTP communication failed: {} {}".format(
                response.status, response.reason, response.read()
                )
            )
            raise Exception('HTTPCommunicationFailed', (response.status, response.reason))

class User(object):
    def __init__(self, session, app_config):
        """Constructor takes user session."""
        self.userinfo = session.get('userinfo', None)
        self.app_config = app_config

    def apps(self, app_list):
        """Return a list of the apps a user is allowed to see in dashboard."""
        authorized_apps = {
            'apps': []
        }

        for app in app_list['apps']:
            if self._is_valid_yaml(app):
                if self._is_authorized(app):
                    authorized_apps['apps'].append(app)
        return authorized_apps.get('apps', [])

    @property
    def avatar(self):
        m = Mozillians(self.app_config)
        return m.avatar(self.userinfo.get('email'))

    def group_membership(self):
        """Return list of group membership if user is asserted from ldap."""
        if 'groups' in self.userinfo.keys() and len(self.userinfo['groups']) > 0:
            return self.userinfo['groups']
        else:
            # This could mean a user is authing with non-ldap
            return []

    @property
    def first_name(self):
        """Return user first_name."""
        try:
            return self.userinfo['given_name']
        except KeyError:
            return None

    @property
    def last_name(self):
        """Return user last_name."""
        try:
            return self.userinfo['family_name']
        except KeyError:
            return None

    def user_identifiers(self):
        """Construct a list of potential user identifiers to match on."""
        return [self.userinfo['email'], self.userinfo['user_id']]

    @property
    def authzero_profile(self):
        a = AuthZero()
        a.get_access_token()
        return a.get_user(self.userinfo['user_id'])

    @property
    def authzero_logs(self):
        a = AuthZero()
        a.get_access_token()
        return a.get_logs(self.userinfo['emails'][0]['value'])

    @property
    def frequently_used(self):
        logs = self.authzero_logs

        used_apps = []

        for entry in logs:
            used_apps.append(entry.get('client_id'))

    @property
    def alerts(self):
        alerts = alert.Alert().find(user_id=self.userinfo['user_id'])
        return alerts

    def acknowledge_alert(self, alert_id):
        a = alert.Alert()

        """ Future home of the code that pushes an alert back to MozDef """
        logger.info('An alert was acked for {uid}.'.format(uid=self.userinfo['user_id']))
        return a.destroy(alert_id=alert_id, user_id=self.userinfo['user_id'])

    def _is_authorized(self, app):
        if app['application']['display'] == 'False':
            return False
        elif not app['application']['display']:
            return False
        elif 'everyone' in app['application']['authorized_groups']:
            return True
        elif set(app['application']['authorized_groups']) & set(self.group_membership()):
            return True
        elif set(app['application']['authorized_users']) & set(self.user_identifiers()):
            return True
        else:
            return False

    def _is_valid_yaml(self, app):
        """If an app doesn't have the required fields skip it."""
        try:
            app['application']['display']
            app['application']['authorized_groups']
            app['application']['authorized_users']
            return True
        except Exception:
            return False
