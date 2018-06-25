# lua-resty-xacml-pep

**lua-resty-xacml-pep** is a library for [NGINX](http://nginx.org/) implementing the
[XACML](http://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html) **Policy Enforcement Point** functionality
using the [REST](http://docs.oasis-open.org/xacml/xacml-rest/v1.0/cs02/xacml-rest-v1.0-cs02.pdf) and
[JSON](http://docs.oasis-open.org/xacml/xacml-json-http/v1.0/cs01/xacml-json-http-v1.0-cs01.pdf) Profiles of XACML 3.0.

It can be used as a reverse proxy authorizing incoming requests in front of an origin server so that
the origin server/services can be protected with the XACML Attribute Based Access Control (ABAC) without
implementing XACML on the server or in the application itself.

## Dependencies

**lua-resty-xacml-pep** depends on the following packages:

- [NGINX](http://nginx.org/) and [`ngx_devel_kit`](https://github.com/simpl/ngx_devel_kit)
- [Lua](http://www.lua.org/) or [LuaJIT](http://luajit.org/luajit.html)
- [`lua-nginx-module`](https://github.com/openresty/lua-nginx-module)
- [`lua-cjson`](http://www.kyne.com.au/~mark/software/lua-cjson.php)
- [`lua-resty-string`](https://github.com/openresty/lua-resty-string)

The dependencies above come automatically with [OpenResty](http://openresty.org/). You will need
to install one extra pure-Lua dependency that implements HTTP client functions:

- [`lua-resty-http`](https://github.com/pintsized/lua-resty-http)

## Installation

Copy `xacml_pep.lua` somewhere in your `lua_package_path` under a directory named `resty`.
If you are using [OpenResty](http://openresty.org/), the default location would be `/usr/local/openresty/lualib/resty`.

## Sample Configuration

```
events {
  worker_connections 128;
}

http {

  lua_package_path '~/lua/?.lua;;';

  resolver 8.8.8.8;

  lua_ssl_trusted_certificate /opt/local/etc/openssl/cert.pem;
  lua_ssl_verify_depth 5;

  -- cache for PDP decisions
  lua_shared_dict decision 1m;
  
  server {
    listen 8080;

    location / {

      access_by_lua '

          -- PDP configuration
          local opts = {
             pdp_endpoint="https://localhost:8643/asm-pdp/authorize",
             pdp_user="pdp-user",
             pdp_passwd="my_secret",
             ssl_verify = "no",
          }

          -- typically you'd get the input parameters to the PDP call
          -- from the current context, such as the authenticated "subject",
          -- the "action" and the current "resource" that is being accessed
          local res, err = require("resty.xacml_pep").pdp_decision(opts, "hans", "GET", "https://www.example.com")
          
          if err then
            ngx.status = 403
            ngx.say(err)
            ngx.exit(ngx.HTTP_FORBIDDEN)
          end
          
          -- at this point the user is authorized and content can be served, e.g.:
          local cjson = require "cjson"
          ngx.header.content_type = "text/json"          
          ngx.say(cjson.encode(res))
          ngx.exit(ngx.OK)
      ';
    }
  }
}
```

## Support

See the Wiki pages with Frequently Asked Questions at:  
  https://github.com/zmartzone/lua-resty-xacml-pep/wiki  
For commercial support and consultancy you can contact:  
  [info@zmartzone.eu](mailto:info@zmartzone.eu)  

Any questions/issues should go to issues tracker.

Disclaimer
----------

*See the DISCLAIMER file in this directory. For commercial support
you can contact [ZmartZone IAM](https://www.zmartzone.eu) as described above.*
