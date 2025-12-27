# coding: utf-8
#
# Copyright (C) 2020, Team Kodi
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Functions to interact with various web site APIs"""

from __future__ import absolute_import, unicode_literals

import json
import socket
import requests
from urllib.parse import urlencode
from pprint import pformat
from .utils import logger

try:
    import xbmc
    import xbmcgui
except ImportError:
    xbmc = None
    xbmcgui = None

try:
    from typing import Text, Optional, Union, List, Dict, Any  # pylint: disable=unused-import
    InfoType = Dict[Text, Any]  # pylint: disable=invalid-name
except ImportError:
    pass

HEADERS = {}
SERVICE_HOST = '127.0.0.1'
DNS_SETTINGS = {}

def set_headers(headers):
    # type: (Dict) -> None
    HEADERS.update(headers)

def set_dns_settings(settings):
    DNS_SETTINGS.clear()
    if settings:
        DNS_SETTINGS.update(settings)

def _direct_load_info(url, params=None, default=None, resp_type='json'):
    try:
        logger.debug('Fallback to direct request for: {}'.format(url))
        r = requests.get(url, params=params, headers=HEADERS, timeout=30)
        if r.status_code >= 400:
            logger.debug('Direct request returned error: {}'.format(r.status_code))
            return default
        if resp_type == 'json':
            return r.json()
        return r.text
    except Exception as e:
        logger.debug('Direct request failed: {}'.format(e))
        return default

def load_info(url, params=None, default=None, resp_type='json', verboselog=False):
    # type: (Text, Dict, Text, Text, bool) -> Optional[Text]
    """
    Load info from external api via background service

    :param url: API endpoint URL
    :param params: URL query params
    :default: object to return if there is an error
    :resp_type: what to return to the calling function
    :return: API response or default on error
    """
    logger.debug('Calling URL "{}" via Service'.format(url))
    if HEADERS:
        logger.debug(str(HEADERS))

    try:
        # Get port dynamically from Window Property
        service_port = 56790 # Default fallback
        if xbmcgui:
            port_str = xbmcgui.Window(10000).getProperty('TMDB_TV_OPTIMIZATION_SERVICE_PORT')
            if port_str:
                service_port = int(port_str)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(35) # Slightly longer than service timeout
        sock.connect((SERVICE_HOST, service_port))
        
        # Construct Protocol V2 Payload
        requests_list = [{
            'url': url,
            'params': params,
            'headers': HEADERS or {}
        }]
            
        request_data = {
            'requests': requests_list,
            'dns_settings': DNS_SETTINGS
        }
        
        sock.sendall(json.dumps(request_data).encode('utf-8'))
        
        # Read response
        response_data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response_data += chunk
            
        sock.close()
        
        if not response_data:
            logger.debug('Service returned empty response')
            return default
            
        result = json.loads(response_data.decode('utf-8'))
        
        # Result is a list because we sent a list of requests (even if just one)
        if isinstance(result, list) and len(result) > 0:
            res = result[0]
        else:
            res = result

        if 'error' in res:
            logger.debug('Service error: {}'.format(res['error']))
            return default
            
        if res['status'] >= 400:
            logger.debug('Remote site returned error code: {}'.format(res['status']))
            return default

        if resp_type.lower() == 'json':
            if res['json'] is not None:
                resp = res['json']
            else:
                logger.debug('Service returned no JSON')
                resp = default
        else:
            resp = res['text']

    except Exception as e:
        logger.debug('Failed to communicate with service: {}'.format(e))
        return _direct_load_info(url, params, default, resp_type)

    if verboselog:
        logger.debug('the api response:\n{}'.format(pformat(resp)))
    return resp


def load_info_batch(requests_list, default=None, resp_type='json', verboselog=False):
    """
    Load info from external api via background service in batch
    
    :param requests_list: List of dicts with 'url', 'params'
    :return: List of API responses
    """
    logger.debug('Calling Batch Requests ({}) via Service'.format(len(requests_list)))
    
    try:
        # Get port dynamically from Window Property
        service_port = 56790 # Default fallback
        if xbmcgui:
            port_str = xbmcgui.Window(10000).getProperty('TMDB_TV_OPTIMIZATION_SERVICE_PORT')
            if port_str:
                service_port = int(port_str)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(60) # Longer timeout for batch
        sock.connect((SERVICE_HOST, service_port))
        
        # Prepare payload
        final_requests = []
        for req in requests_list:
            r = {
                'url': req['url'],
                'params': req.get('params'),
                'headers': HEADERS or {}
            }
            final_requests.append(r)
            
        request_data = {
            'requests': final_requests,
            'dns_settings': DNS_SETTINGS
        }
        
        sock.sendall(json.dumps(request_data).encode('utf-8'))
        
        # Read response
        response_data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response_data += chunk
            
        sock.close()
        
        if not response_data:
            return _direct_batch_fallback(requests_list, default, resp_type)
            
        results = json.loads(response_data.decode('utf-8'))
        
        final_results = []
        if isinstance(results, list):
            for res in results:
                if 'error' in res or res['status'] >= 400:
                    final_results.append(default)
                    continue
                    
                if resp_type.lower() == 'json':
                    final_results.append(res.get('json', default))
                else:
                    final_results.append(res.get('text', default))
        else:
            # Should be list, but fallback
            return _direct_batch_fallback(requests_list, default, resp_type)
            
        return final_results

    except Exception as e:
        logger.debug('Failed to communicate with service for batch: {}'.format(e))
        return _direct_batch_fallback(requests_list, default, resp_type)

def _direct_batch_fallback(requests_list, default, resp_type):
    results = []
    for req in requests_list:
        res = _direct_load_info(req['url'], req.get('params'), default, resp_type)
        results.append(res)
    return results

