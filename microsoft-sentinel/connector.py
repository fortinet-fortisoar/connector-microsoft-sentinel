"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations, _check_health
from connectors.core.utils import update_connnector_config

logger = get_logger('microsoft-sentinel')

CONFIG_SUPPORTS_TOKEN = True


class MicrosoftSentinel(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            connector_info = {"connector_name": self._info_json.get('name'),
                              "connector_version": self._info_json.get('version')}
            operation = operations.get(operation)
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)
        return operation(config, params, connector_info)

    def check_health(self, config):
        logger.info('starting health check')
        connector_info = {"connector_name": self._info_json.get('name'),
                          "connector_version": self._info_json.get('version')}
        _check_health(config, connector_info)
        logger.info('Completed health check and no errors found')

    def on_update_config(self, old_config, new_config, active):
        connector_info = {"connector_name": self._info_json.get('name'),
                          "connector_version": self._info_json.get('version')}

        if CONFIG_SUPPORTS_TOKEN:
            old_auth_code = old_config.get('code')
            new_auth_code = new_config.get('code')
            if old_auth_code != new_auth_code:
                new_config.pop('access_token', '')
            else:
                new_config['access_token'] = old_config.get('access_token')
                new_config['refresh_token'] = old_config.get('refresh_token ')
                new_config['expires_in'] = old_config.get('expires_in')
        update_connnector_config(connector_info['connector_name'], connector_info['connector_version'], new_config,
                                 new_config['config_id'])
