"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

REFRESH_TOKEN_FLAG = False

AUTH_USING_APP = "Without a User - Application Permission"
AUTH_BEHALF_OF_USER = "On behalf of User - Delegate Permission"
CERTIFICATE_BASED_AUTH_TYPE = "Certificate Based Authentication"

# API Version

API_VERSION = "2025-09-01"

# redirect url
DEFAULT_REDIRECT_URL = 'https://localhost/myapp'

# grant types
AUTHORIZATION_CODE = 'authorization_code'
REFRESH_TOKEN = 'refresh_token'

# endpoints
AUTH_URL = 'https://login.microsoftonline.com'
THREAT_INDICATORS_API = "/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.OperationalInsights/workspaces/{2}/providers/Microsoft.SecurityInsights/threatIntelligence/main"
INCIDENT_API = "/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.OperationalInsights/workspaces/{2}/providers/Microsoft.SecurityInsights/incidents"
INCIDENT_RELATION_API = "/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.OperationalInsights/workspaces/{2}/providers/Microsoft.SecurityInsights/incidents/{3}/relations"
INCIDENT_COMMENT_API = "/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.OperationalInsights/workspaces/{2}/providers/Microsoft.SecurityInsights/incidents/{3}/comments"
WATCHLIST_API = "/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.OperationalInsights/workspaces/{2}/providers/Microsoft.SecurityInsights/watchlists"
WATCHLIST_ITEM_API = "/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.OperationalInsights/workspaces/{2}/providers/Microsoft.SecurityInsights/watchlists/{3}/watchlistItems"

# pattern types

PATTERN_TYPE = {
    "Domain Name": "domain-name",
    "File": "file",
    "IPV4 Address": "ipv4-addr",
    "IPV6 Address": "ipv6-addr",
    "URL": "url"
}
