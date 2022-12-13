"""IAMAuth class.

/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
"""

import requests
import time

from requests.auth import AuthBase

###############################################################
# 12/12/22 : Fixing IAM token handling logic, because of
#            refreshToken life-time reduction from 30d to 3d
#
# IAMAuth handler class is used as external authentication for request python lib
#
# Each time a HTTP call to the IBM Cloud functions service is done the __call__
# method of this class is called. The caller expects to get a valid AUTH-Token as result
#
# AUTH-TOKEN  is requested from IBM IAM service using the __requestToken() method which
#             is providing the iamApiKey as input and gets an valid access-token with a
#             life-time ( currently 1 hour). As long as the access-token is not expired
#             the last retrieved value is still used.
#             On __isTokenExpired  a new access-token is requested using the api-key.
#
#    Comment: refresh token usage is removed with the fix of 12/12/22
######################################################################

class AuthHandlerException(Exception):
    def __init__(self, response):
        self.response = response

class IAMAuth(AuthBase):

    def __init__(self, authKey, endpoint):
        self.authKey = authKey
        self.endpoint = endpoint
        self.tokenInfo = {}

    def __call__(self, r):
        r.headers['Authorization'] = 'Bearer {}'.format(self.__getToken())
        return r

    def __getToken(self):
        ## if not already an access-token is retrieved or the current one is expired, get a new one using the iamApiKey
        if 'expires_in' not in self.tokenInfo or self.__isTokenExpired():
            response = self.__requestToken()
            if response.ok and 'access_token' in response.json():
                self.tokenInfo = response.json()
                return self.tokenInfo['access_token']
            else:
                raise AuthHandlerException(response)
        else:
            return self.tokenInfo['access_token']

    def __requestToken(self):
        headers = {
            'Content-type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic Yng6Yng='
        }
        payload = {
            'grant_type': 'urn:ibm:params:oauth:grant-type:apikey',
            'apikey': self.authKey
        }

        return self.__sendRequest(payload, headers)

    def __isTokenExpired(self):
        if 'expires_in' not in self.tokenInfo or 'expiration' not in self.tokenInfo:
            return True

        fractionOfTtl = 0.8
        timeToLive = self.tokenInfo['expires_in']
        expireTime = self.tokenInfo['expiration']
        currentTime = int(time.time())
        refreshTime = expireTime - (timeToLive * (1.0 - fractionOfTtl))

        return refreshTime < currentTime

    def __sendRequest(self, payload, headers):
        response = requests.post(self.endpoint, data=payload, headers=headers)
        return response
