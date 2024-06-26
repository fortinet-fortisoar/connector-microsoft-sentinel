"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

from connectors.core.connector import get_logger, ConnectorError
import requests
from .microsoft_api_auth import *
from .constant import *
import random, uuid

logger = get_logger('microsoft-sentinel')


def api_request(method, endpoint, connector_info, config, params=None, data=None, json=None, headers={}):
    try:
        ms = MicrosoftAuth(config)
        endpoint = ms.host + endpoint
        token = ms.validate_token(config, connector_info)
        headers['Authorization'] = token
        headers['Content-Type'] = 'application/json'
        headers['consistencylevel'] = 'eventual'
        response = request(method, endpoint, headers=headers, params=params, data=data, json=json,
                           verify=ms.verify_ssl)
        if response.status_code in [200, 201, 202, 204]:
            if 'json' in str(response.headers):
                return response.json()
            else:
                return dict()
        elif response.status_code == 404:
            return {"message": "Not Found"}
        else:
            raise ConnectorError("{0}".format(response.content))
    except requests.exceptions.SSLError:
        raise ConnectorError('SSL certificate validation failed')
    except requests.exceptions.ConnectTimeout:
        raise ConnectorError('The request timed out while trying to connect to the server')
    except requests.exceptions.ReadTimeout:
        raise ConnectorError(
            'The server did not send any data in the allotted amount of time')
    except requests.exceptions.ConnectionError:
        raise ConnectorError('Invalid Credentials')
    except Exception as err:
        raise ConnectorError(str(err))


def create_endpoint(config, url, id=None):
    if id:
        endpoint = url.format(config.get('WorkspaceSubscriptionId'),
                              config.get('WorkspaceResourceGroup'),
                              config.get('WorkspaceName'),
                              id)
    else:
        endpoint = url.format(config.get('WorkspaceSubscriptionId'),
                              config.get('WorkspaceResourceGroup'),
                              config.get('WorkspaceName'))
    return endpoint


def check_payload(payload):
    updated_payload = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            nested = check_payload(value)
            if len(nested.keys()) > 0:
                updated_payload[key] = nested
        elif value:
            updated_payload[key] = value
    return updated_payload


def extract_token(skip_token):
    skip_token = skip_token.split("$skipToken=")[1]
    return skip_token


def threat_indicator_payload(params):
    threatIntelligenceTags = params.get('threatIntelligenceTags')
    threatTypes = params.get('threatTypes')
    indicatorTypes = params.get('indicatorTypes')
    labels = params.get('labels')
    pattern_type = PATTERN_TYPE.get(params.get('patternType'))
    payload = {
        'kind': 'indicator',
        'properties': {
            'confidence': params.get('confidence'),
            'description': params.get('description'),
            'displayName': params.get('displayName'),
            'threatIntelligenceTags': threatIntelligenceTags.split(",") if threatIntelligenceTags else "",
            'threatTypes': threatTypes.split(",") if threatTypes else "",
            'indicatorTypes': indicatorTypes.split(",") if indicatorTypes else "",
            'labels': labels.split(",") if labels else "",
            'patternType': pattern_type,
            'pattern': "[{0}:value = '{1}']".format(pattern_type, params.get('pattern')),
            'source': params.get('source')
        }
    }
    additional_fields = params.get('additional_fields')
    if additional_fields:
        payload['properties'].update(additional_fields)
    payload = check_payload(payload)
    return payload


def create_threat_intelligence_indicator(config, params, connector_info):
    url = THREAT_INDICATORS_API + "/createIndicator?api-version=2022-11-01"
    endpoint = create_endpoint(config, url)
    payload = threat_indicator_payload(params)
    response = api_request("POST", endpoint, connector_info, config, json=payload)
    return response


def get_all_threat_intelligence_indicators(config, params, connector_info):
    url = THREAT_INDICATORS_API + "/indicators?api-version=2022-11-01"
    endpoint = create_endpoint(config, url)
    filter = params.get('$filter')
    orderby = params.get('$orderby')
    skip_token = params.get('$skipToken')
    if skip_token:
        skip_token = extract_token(skip_token)
    payload = {
        '$filter': filter if filter else '',
        '$orderby': orderby if orderby else '',
        '$top': params.get('$top'),
        '$skipToken': skip_token
    }
    payload = {k: v for k, v in payload.items() if v is not None and v != ''}
    response = api_request("GET", endpoint, connector_info, config, params=payload)
    return response


def get_threat_intelligence_indicator(config, params, connector_info):
    url = THREAT_INDICATORS_API + "/indicators/{3}?api-version=2022-11-01"
    endpoint = create_endpoint(config, url, id=params.get('id'))
    response = api_request("GET", endpoint, connector_info, config, params={})
    return response


def update_threat_intelligence_indicator(config, params, connector_info):
    url = THREAT_INDICATORS_API + "/indicators/{3}?api-version=2022-11-01"
    endpoint = create_endpoint(config, url, id=params.get('id'))
    payload = threat_indicator_payload(params)
    response = api_request("PUT", endpoint, connector_info, config, json=payload)
    return response


def delete_threat_intelligence_indicator(config, params, connector_info):
    url = THREAT_INDICATORS_API + "/indicators/{3}?api-version=2022-11-01"
    endpoint = create_endpoint(config, url, id=params.get('id'))
    response = api_request("DELETE", endpoint, connector_info, config, params={})
    if response.get('message'):
        return response
    else:
        return {"result": "Successfully deleted the indicator {0}".format(params.get("id"))}


def get_incident_list(config, params, connector_info):
    filter_list = []
    url = INCIDENT_API + "?api-version=2022-11-01"
    endpoint = create_endpoint(config, url)
    date_time = params.get('created_datetime')
    filter = params.get('$filter')
    filter_params = {
        'createdTimeUtc': date_time,
        'status': params.get('Status'),
        'severity': params.get('Severity')
    }
    filter_params = {k: v for k, v in filter_params.items() if v is not None and v != ''}
    for item, value in filter_params.items():
        if item == 'createdTimeUtc':
            filter_list.append('properties/' + item + ' ge ' + value)
        elif item == 'status':
            filter_list.append('properties/' + item + ' eq ' + f"'{value}'")
        else:
            filter_list.append('properties/' + item + ' eq ' + f"'{value}'")
    if filter:
        filter_list.append(filter)
    filter_str = ' and '.join(filter_list)
    orderby = params.get('$orderby')
    skip_token = params.get('$skipToken')
    if skip_token:
        skip_token = extract_token(skip_token)
    payload = {
        '$filter': filter_str,
        '$orderby': orderby,
        '$top': params.get('$top'),
        '$skipToken': skip_token
    }
    payload = check_payload(payload)
    response = api_request("GET", endpoint, connector_info, config, params=payload)
    return response


def get_incident(config, params, connector_info):
    url = INCIDENT_API + "/{3}?api-version=2022-11-01"
    endpoint = create_endpoint(config, url, id=params.get('incidentId'))
    response = api_request("GET", endpoint, connector_info, config, params={})
    return response


def update_incident(config, params, connector_info):
    incident_id = {'incidentId': params.get('incidentId')}
    incident_details = get_incident(config, incident_id, connector_info)
    old_labels = incident_details.get('properties').get('labels')
    new_labels = params.get('labels').split(",") if params.get('labels') else ''
    if new_labels:
        for label in new_labels:
            old_labels.append({'labelName': label})
    url = INCIDENT_API + "/{3}?api-version=2022-11-01"
    endpoint = create_endpoint(config, url, id=params.get('incidentId'))
    payload = {
        'etag': params.get('etag'),
        'properties': {
            'description': params.get('Description'),
            'title': params.get('Title'),
            'severity': params.get('Severity'),
            'classification': params.get('classification'),
            'classificationComment': params.get('Comment'),
            'classificationReason': params.get('reason'),
            'status': params.get('Status'),
            'labels': old_labels
        }
    }
    custom_attributes = params.get('custom_attributes')
    if custom_attributes:
        payload['properties'].update(custom_attributes)
    payload = check_payload(payload)
    response = api_request("PUT", endpoint, connector_info, config, json=payload)
    return response


def get_alert_list(config, params, connector_info):
    url = INCIDENT_API + "/{3}/alerts?api-version=2022-11-01"
    endpoint = create_endpoint(config, url, id=params.get('incidentId'))
    response = api_request("POST", endpoint, connector_info, config, json={})
    return response


def get_entities_list(config, params, connector_info):
    url = INCIDENT_API + "/{3}/entities?api-version=2022-11-01"
    endpoint = create_endpoint(config, url, id=params.get('incidentId'))
    response = api_request("POST", endpoint, connector_info, config, json={})
    return response


def get_bookmarks_list(config, params, connector_info):
    url = INCIDENT_API + "/{3}/bookmarks?api-version=2022-11-01"
    endpoint = create_endpoint(config, url, id=params.get('incidentId'))
    response = api_request("POST", endpoint, connector_info, config, json={})
    return response


def create_incident_relations(config, params, connector_info):
    endpoint = create_endpoint(config, INCIDENT_RELATION_API,
                               id=params.get('incidentId')) + "/{0}?api-version=2022-11-01".format(
        params.get('relationName'))
    payload = {
        'properties': {
            'relatedResourceId': params.get('resourceId')
        }
    }
    response = api_request("PUT", endpoint, connector_info, config, json=payload)
    return response


def get_all_incident_relations(config, params, connector_info):
    url = INCIDENT_RELATION_API + "?api-version=2022-11-01"
    endpoint = create_endpoint(config, url, id=params.get('incidentId'))
    filter = params.get('$filter')
    orderby = params.get('$orderby')
    skip_token = params.get('$skipToken')
    if skip_token:
        skip_token = extract_token(skip_token)
    payload = {
        '$filter': 'properties/' + filter if filter else '',
        '$orderby': 'properties/' + orderby if orderby else '',
        '$top': params.get('$top'),
        '$skipToken': skip_token
    }
    payload = {k: v for k, v in payload.items() if v is not None and v != ''}
    response = api_request("GET", endpoint, connector_info, config, params=payload)
    return response


def get_incident_relations(config, params, connector_info):
    endpoint = create_endpoint(config, INCIDENT_RELATION_API,
                               id=params.get('incidentId')) + "/{0}?api-version=2022-11-01".format(
        params.get('relationName'))
    response = api_request("GET", endpoint, connector_info, config, params={})
    return response


def update_incident_relations(config, params, connector_info):
    endpoint = create_endpoint(config, INCIDENT_RELATION_API,
                               id=params.get('incidentId')) + "/{0}?api-version=2022-11-01".format(
        params.get('relationName'))
    payload = {
        'properties': {
            'relatedResourceId': params.get('resourceId')
        }
    }
    response = api_request("PUT", endpoint, connector_info, config, json=payload)
    return response


def delete_incident_relation(config, params, connector_info):
    endpoint = create_endpoint(config, INCIDENT_RELATION_API,
                               id=params.get('incidentId')) + "/{0}?api-version=2022-11-01".format(
        params.get('relationName'))
    response = api_request("DELETE", endpoint, connector_info, config, json={})
    if response.get('message'):
        return response
    else:
        return {"result": "Successfully deleted the incident relation \'{0}\' for specific incident \'{1}\'".format(
            params.get("relationName"), params.get('incidentId'))}


def create_incident_comment(config, params, connector_info):
    endpoint = create_endpoint(config, INCIDENT_COMMENT_API,
                               id=params.get('incidentId')) + "/{0}?api-version=2022-11-01".format(
        str(random.getrandbits(128)))
    payload = {
        'properties': {
            'message': params.get('message')
        }
    }
    response = api_request("PUT", endpoint, connector_info, config, json=payload)
    return response


def get_all_incident_comments(config, params, connector_info):
    url = INCIDENT_COMMENT_API + "?api-version=2022-11-01"
    endpoint = create_endpoint(config, url, id=params.get('incidentId'))
    filter = params.get('$filter')
    orderby = params.get('$orderby')
    skip_token = params.get('$skipToken')
    if skip_token:
        skip_token = extract_token(skip_token)
    payload = {
        '$filter': 'properties/' + filter if filter else '',
        '$orderby': 'properties/' + orderby if orderby else '',
        '$top': params.get('$top'),
        '$skipToken': skip_token
    }
    payload = {k: v for k, v in payload.items() if v is not None and v != ''}
    response = api_request("GET", endpoint, connector_info, config, params=payload)
    return response


def get_incident_comment(config, params, connector_info):
    endpoint = create_endpoint(config, INCIDENT_COMMENT_API,
                               id=params.get('incidentId')) + "/{0}?api-version=2022-11-01".format(
        params.get('incidentcommentId'))
    response = api_request("GET", endpoint, connector_info, config, params={})
    return response


def update_incident_comment(config, params, connector_info):
    endpoint = create_endpoint(config, INCIDENT_COMMENT_API,
                               id=params.get('incidentId')) + "/{0}?api-version=2022-11-01".format(
        params.get('incidentcommentId'))
    payload = {
        'properties': {
            'message': params.get('message')
        }
    }
    response = api_request("PUT", endpoint, connector_info, config, json=payload)
    return response


def delete_incident_comment(config, params, connector_info):
    endpoint = create_endpoint(config, INCIDENT_COMMENT_API,
                               id=params.get('incidentId')) + "/{0}?api-version=2022-11-01".format(
        params.get('incidentcommentId'))
    response = api_request("DELETE", endpoint, connector_info, config, json={})
    if response.get('message'):
        return response
    else:
        return {"result": "Successfully deleted the indicident comment {0} for a particular incident {1}".format(
            params.get("incidentcommentId"), params.get('incidentId'))}


def create_watchlist(config, params, connector_info):
    url = WATCHLIST_API + "/{3}?api-version=2022-11-01"
    endpoint = create_endpoint(config, url, id=params.get('watchlistAlias'))
    payload = {
        'etag': params.get('etag'),
        'properties': {
            'displayName': params.get('displayName'),
            'itemsSearchKey': params.get('itemsSearchKey'),
            'provider': params.get('provider'),
            'source': params.get('source'),
            'description': params.get('description')
        }
    }
    custom_attributes = params.get('custom_attributes')
    if custom_attributes:
        payload['properties'].update(custom_attributes)
    payload = check_payload(payload)
    response = api_request("PUT", endpoint, connector_info, config, json=payload)
    return response


def get_all_watchlist(config, params, connector_info):
    url = WATCHLIST_API + "?api-version=2022-11-01"
    endpoint = create_endpoint(config, url)
    skip_token = params.get('$skipToken')
    if skip_token:
        skip_token = extract_token(skip_token)
    payload = {
        '$skipToken': skip_token
    }
    payload = {k: v for k, v in payload.items() if v is not None and v != ''}
    response = api_request("GET", endpoint, connector_info, config, params=payload)
    return response


def get_watchlist(config, params, connector_info):
    url = WATCHLIST_API + "/{3}?api-version=2022-11-01"
    endpoint = create_endpoint(config, url, id=params.get('watchlistAlias'))
    response = api_request("GET", endpoint, connector_info, config, params={})
    return response


def update_watchlist(config, params, connector_info):
    url = WATCHLIST_API + "/{3}?api-version=2022-11-01"
    endpoint = create_endpoint(config, url, id=params.get('watchlistAlias'))
    payload = {
        'etag': params.get('etag'),
        'properties': {
            'displayName': params.get('displayName'),
            'itemsSearchKey': params.get('itemsSearchKey'),
            'provider': params.get('provider'),
            'source': params.get('source'),
            'description': params.get('description')
        }
    }
    custom_attributes = params.get('custom_attributes')
    if custom_attributes:
        payload['properties'].update(custom_attributes)
    payload = check_payload(payload)
    response = api_request("PUT", endpoint, connector_info, config, json=payload)
    return response


def delete_watchlist(config, params, connector_info):
    url = WATCHLIST_API + "/{3}?api-version=2022-11-01"
    endpoint = create_endpoint(config, url, id=params.get('watchlistAlias'))
    response = api_request("DELETE", endpoint, connector_info, config, json={})
    if response.get('message'):
        return response
    else:
        return {"result": "Successfully deleted the watchlist {0}".format(
            params.get("watchlistAlias"))}


def create_watchlist_item(config, params, connector_info):
    endpoint = create_endpoint(config, WATCHLIST_ITEM_API,
                               id=params.get('watchlistAlias')) + "/{0}?api-version=2022-11-01".format(
        uuid.uuid4())
    payload = {
        'etag': params.get('etag'),
        'properties': {
            'itemsKeyValue': params.get('itemsKeyValue')
        }
    }
    custom_attributes = params.get('custom_attributes')
    if custom_attributes:
        payload['properties'].update(custom_attributes)
    payload = check_payload(payload)
    response = api_request("PUT", endpoint, connector_info, config, json=payload)
    return response


def get_all_watchlist_items(config, params, connector_info):
    url = WATCHLIST_ITEM_API + "?api-version=2022-11-01"
    endpoint = create_endpoint(config, url, id=params.get('watchlistAlias'))
    skip_token = params.get('$skipToken')
    if skip_token:
        skip_token = extract_token(skip_token)
    payload = {
        '$skipToken': skip_token
    }
    payload = {k: v for k, v in payload.items() if v is not None and v != ''}
    response = api_request("GET", endpoint, connector_info, config, params=payload)
    return response


def get_watchlist_item(config, params, connector_info):
    endpoint = create_endpoint(config, WATCHLIST_ITEM_API,
                               id=params.get('watchlistAlias')) + "/{0}?api-version=2022-11-01".format(
        params.get('watchlistItemId'))
    response = api_request("GET", endpoint, connector_info, config, params={})
    return response


def update_watchlist_item(config, params, connector_info):
    endpoint = create_endpoint(config, WATCHLIST_ITEM_API,
                               id=params.get('watchlistAlias')) + "/{0}?api-version=2022-11-01".format(
        params.get('watchlistItemId'))
    payload = {
        'etag': params.get('etag'),
        'properties': {
            'itemsKeyValue': params.get('itemsKeyValue')
        }
    }
    custom_attributes = params.get('custom_attributes')
    if custom_attributes:
        payload['properties'].update(custom_attributes)
    payload = check_payload(payload)
    response = api_request("PUT", endpoint, connector_info, config, json=payload)
    return response


def delete_watchlist_item(config, params, connector_info):
    endpoint = create_endpoint(config, WATCHLIST_ITEM_API,
                               id=params.get('watchlistAlias')) + "/{0}?api-version=2022-11-01".format(
        params.get('watchlistItemId'))
    response = api_request("DELETE", endpoint, connector_info, config, json={})
    if response.get('message'):
        return response
    else:
        return {"result": "Successfully deleted the watchlist item {0}".format(
            params.get("watchlistItemId"))}


def _check_health(config, connector_info):
    try:
        if check(config, connector_info):
            incidents = get_incident_list(config, params={}, connector_info=connector_info)
            if not incidents.get('message'):
                return True
            else:
                raise ConnectorError("Invalid Credentials")
    except Exception as err:
        raise ConnectorError(str(err))


operations = {
    'create_threat_intelligence_indicator': create_threat_intelligence_indicator,
    'get_all_threat_intelligence_indicators': get_all_threat_intelligence_indicators,
    'get_threat_intelligence_indicator': get_threat_intelligence_indicator,
    'get_incident': get_incident,
    'update_threat_intelligence_indicator': update_threat_intelligence_indicator,
    'update_incident': update_incident,
    'delete_threat_intelligence_indicator': delete_threat_intelligence_indicator,
    'get_incident_list': get_incident_list,
    'get_alert_list': get_alert_list,
    'get_entities_list': get_entities_list,
    'get_bookmarks_list': get_bookmarks_list,
    'create_incident_relations': create_incident_relations,
    'get_all_incident_relations': get_all_incident_relations,
    'get_incident_relations': get_incident_relations,
    'update_incident_relations': update_incident_relations,
    'delete_incident_relation': delete_incident_relation,
    'create_incident_comment': create_incident_comment,
    'get_all_incident_comments': get_all_incident_comments,
    'get_incident_comment': get_incident_comment,
    'update_incident_comment': update_incident_comment,
    'delete_incident_comment': delete_incident_comment,
    'create_watchlist': create_watchlist,
    'get_all_watchlist': get_all_watchlist,
    'get_watchlist': get_watchlist,
    'update_watchlist': update_watchlist,
    'delete_watchlist': delete_watchlist,
    'create_watchlist_item': create_watchlist_item,
    'get_all_watchlist_items': get_all_watchlist_items,
    'get_watchlist_item': get_watchlist_item,
    'update_watchlist_item': update_watchlist_item,
    'delete_watchlist_item': delete_watchlist_item
}
