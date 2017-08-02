--[[
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.

***************************************************************************
Copyright (C) 2017 ZmartZone IAM
All rights reserved.

For further information please contact:
 
     ZmartZone IAM
     info@zmartzone.eu
     http://www.zmartzone.eu

DISCLAIMER OF WARRANTIES:

THE SOFTWARE PROVIDED HEREUNDER IS PROVIDED ON AN "AS IS" BASIS, WITHOUT
ANY WARRANTIES OR REPRESENTATIONS EXPRESS, IMPLIED OR STATUTORY; INCLUDING,
WITHOUT LIMITATION, WARRANTIES OF QUALITY, PERFORMANCE, NONINFRINGEMENT,
MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  NOR ARE THERE ANY
WARRANTIES CREATED BY A COURSE OR DEALING, COURSE OF PERFORMANCE OR TRADE
USAGE.  FURTHERMORE, THERE ARE NO WARRANTIES THAT THE SOFTWARE WILL MEET
YOUR NEEDS OR BE FREE FROM ERRORS, OR THAT THE OPERATION OF THE SOFTWARE
WILL BE UNINTERRUPTED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

@Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
--]]

local require = require
local cjson   = require "cjson"
local http    = require "resty.http"
local ipairs  = ipairs
local pairs   = pairs
local type    = type
local ngx     = ngx

local xacml_pep = {
  _VERSION = "0.1.0"
}
xacml_pep.__index = xacml_pep

-- set value in server-wide cache if available
local function xacml_pep_cache_set(type, key, value, exp)
  local dict = ngx.shared[type]
  if dict then
    local success, err, forcible = dict:set(key, value, exp)
    ngx.log(ngx.DEBUG, "cache set: success=", success, " err=", err, " forcible=", forcible)
  end
end

-- retrieve value from server-wide cache if available
local function xacml_pep_cache_get(type, key)
  local dict = ngx.shared[type]
  local value
  local flags
  if dict then
    value, flags = dict:get(key)
    if value then ngx.log(ngx.DEBUG, "cache hit: type=", type) end
  end
  return value
end

-- parse the JSON result from a call to the OP
local function xacml_pep_parse_json_response(response)

  local err
  local res

  -- check the response from the OP
  if response.status ~= 200 then
    err = "response indicates failure, status="..response.status..", body="..response.body
  else
    -- decode the response and extract the JSON object
    res = cjson.decode(response.body)

    if not res then
      err = "JSON decoding failed"
    end
  end

  return res, err
end

-- make a call to the PDP endpoint
local function xacml_pep_call_pdp_endpoint(opts, endpoint, body, auth)

  ngx.log(ngx.DEBUG, "request body for PDP endpoint call: ", body)

  local headers = {
      ["Content-Type"] = "application/xacml+json",
      ["Accept"] = "application/xacml+json"
  }

  headers.Authorization = "Basic "..ngx.encode_base64( opts.pdp_user..":"..opts.pdp_passwd)
  ngx.log(ngx.DEBUG,"client_secret_basic: authorization header '"..headers.Authorization.."'")

  local httpc = http.new()
  local res, err = httpc:request_uri(endpoint, {
    method = "POST",
    body = body,
    headers = headers,
    ssl_verify = (opts.ssl_verify ~= "no")
  })
  if not res then
    err = "accessing PDP endpoint ("..endpoint..") failed: "..err
    ngx.log(ngx.ERR, err)
    return nil, err
  end

  ngx.log(ngx.DEBUG, "PDP endpoint response: ", res.body)

  return xacml_pep_parse_json_response(res);
end

-- assemble subject/action/resource cache key
local function xaml_pep_get_cache_key(subject, action, resource)
  input = (subject or "") .. (action or "") .. (resource or "")
  return ngx.sha1_bin(input)
end

-- main routine for obtaining a PDP decision
function xacml_pep.pdp_decision(opts, subject, action, resource)

  -- get a key that uniquely identifies this request in the decision cache
  key = xaml_pep_get_cache_key(subject, action, resource)

  -- see if we've previously cached the introspection result for this request
  local json
  local v = xacml_pep_cache_get("decision", key)
  if not v then

    table = { Request = {
              
        AccessSubject = {
          Attribute = { {
            AttributeId = "urn:oasis:names:tc:xacml:1.0:subject:subject-id",
            Value = subject
          } }
        },
        
        Action = {
          Attribute = { {
            AttributeId = "urn:oasis:names:tc:xacml:1.0:action:action-id",
            Value = action
          } }
        },

        Resource = {
          Attribute = { {
            AttributeId = "urn:oasis:names:tc:xacml:1.0:resource:resource-id",
            Value = resource
          } }
        }
        
    } }
    
    -- call the PDP endpoint
    body = cjson.encode(table)
    json, err = xacml_pep_call_pdp_endpoint(opts, opts.pdp_endpoint, body, nil)
    
    -- cache the results
    if json then
        ttl = opts.ttl or 300
        ngx.log(ngx.DEBUG, "cache token ttl: "..ttl)
        xacml_pep_cache_set("decision", key, cjson.encode(json), ttl)
    end

  else
    json = cjson.decode(v)
  end

  if not json or json.Response.Status.StatusCode.Value ~= "urn:oasis:names:tc:xacml:1.0:status:ok" or json.Response.Decision ~= "Permit" then
    return nil, "Denied"
  end

  return json, err
end

return xacml_pep
