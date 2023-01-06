""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from requests import request
from time import time, ctime
from datetime import datetime
from connectors.core.connector import get_logger, ConnectorError
from .constant import *
from connectors.core.utils import update_connnector_config

logger = get_logger('microsoft-sentinel')

CONFIG_SUPPORTS_TOKEN = True


class MicrosoftAuth:

    def __init__(self, config):
        self.client_id = config.get("client_id")
        self.client_secret = config.get("client_secret")
        self.verify_ssl = config.get('verify_ssl')
        self.scope = "https://management.azure.com/user_impersonation offline_access user.read"
        self.host = config.get("resource")
        if self.host[:7] == "http://":
            self.host = self.host.replace('http://', 'https://')
        elif self.host[:8] == "https://":
            self.host = "{0}".format(self.host)
        else:
            self.host = "https://{0}".format(self.host)
        tenant_id = config.get('tenant_id')
        self.auth_url = 'https://login.microsoftonline.com/{0}'.format(tenant_id)
        self.auth_type = config.get("auth_type")
        self.token_url = "https://login.microsoftonline.com/{0}/oauth2/v2.0/token".format(tenant_id)
        self.refresh_token = ""
        self.code = config.get("code")
        if not config.get("redirect_uri"):
            self.redirect_url = DEFAULT_REDIRECT_URL
        else:
            self.redirect_url = config.get("redirect_uri")

    def convert_ts_epoch(self, ts):
        datetime_object = datetime.strptime(ctime(ts), "%a %b %d %H:%M:%S %Y")
        return datetime_object.timestamp()

    def generate_token(self, REFRESH_TOKEN_FLAG):
        try:
            resp = self.acquire_token_on_behalf_of_user(REFRESH_TOKEN_FLAG)
            ts_now = time()
            resp['expiresOn'] = (ts_now + resp['expires_in']) if resp.get("expires_in") else None
            resp['accessToken'] = resp.get("access_token")
            resp.pop("access_token")
            return resp
        except Exception as err:
            logger.error("{0}".format(err))
            raise ConnectorError("{0}".format(err))

    def validate_token(self, connector_config, connector_info):
        if CONFIG_SUPPORTS_TOKEN:
            ts_now = time()
            if not connector_config.get('accessToken'):
                logger.error('Error occurred while connecting server: Unauthorized')
                raise ConnectorError('Error occurred while connecting server: Unauthorized')
            expires = connector_config['expiresOn']
            expires_ts = self.convert_ts_epoch(expires)
            if ts_now > float(expires_ts):
                REFRESH_TOKEN_FLAG = True
                logger.info("Token expired at {0}".format(expires))
                self.refresh_token = connector_config["refresh_token"]
                token_resp = self.generate_token(REFRESH_TOKEN_FLAG)
                connector_config['accessToken'] = token_resp['accessToken']
                connector_config['expiresOn'] = token_resp['expiresOn']
                connector_config['refresh_token'] = token_resp.get('refresh_token')
                update_connnector_config(connector_info['connector_name'], connector_info['connector_version'],
                                         connector_config,
                                         connector_config['config_id'])

                return "Bearer {0}".format(connector_config.get('accessToken'))
            else:
                logger.info("Token is valid till {0}".format(expires))
                return "Bearer {0}".format(connector_config.get('accessToken'))

    def acquire_token_on_behalf_of_user(self, REFRESH_TOKEN_FLAG):
        try:
            data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "redirect_uri": self.redirect_url,
                "scope": self.scope
            }

            if not REFRESH_TOKEN_FLAG:
                data["grant_type"] = AUTHORIZATION_CODE,
                data["code"] = self.code
            else:
                data['grant_type'] = REFRESH_TOKEN,
                data['refresh_token'] = self.refresh_token

            response = request("POST", self.token_url, data=data, verify=self.verify_ssl)
            if response.status_code in [200, 204, 201]:
                return response.json()

            else:
                if response.text != "":
                    error_msg = ''
                    err_resp = response.json()
                    if err_resp and 'error' in err_resp:
                        failure_msg = err_resp.get('error_description')
                        error_msg = 'Response {0}: {1} \n Error Message: {2}'.format(response.status_code,
                                                                                     response.reason,
                                                                                     failure_msg if failure_msg else '')
                    else:
                        err_resp = response.text
                else:
                    error_msg = '{0}:{1}'.format(response.status_code, response.reason)
                raise ConnectorError(error_msg)

        except Exception as err:
            logger.error("{0}".format(err))
            raise ConnectorError("{0}".format(err))


def check(config, connector_info):
    try:
        ms = MicrosoftAuth(config)
        if CONFIG_SUPPORTS_TOKEN:
            if not 'accessToken' in config:
                token_resp = ms.generate_token(REFRESH_TOKEN_FLAG)
                config['accessToken'] = token_resp.get('accessToken')
                config['expiresOn'] = token_resp.get('expiresOn')
                config['refresh_token'] = token_resp.get('refresh_token')
                update_connnector_config(connector_info['connector_name'], connector_info['connector_version'], config,
                                         config['config_id'])
                return True
            else:
                token_resp = ms.validate_token(config, connector_info)
                return True
    except Exception as err:
        raise ConnectorError(str(err))
