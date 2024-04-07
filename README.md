Almost totally rewriten version of https://github.com/lexelby/nginx-radius with<br>
configuration inspired by https://github.com/timchengx/nginx-http-radius-module.

Build:

1. Get nginx source:

```
$ make getsrc && make src
```

2. Build source:

```
$ make build_all
```

3. Local run:

```
$ make run
```

4. Local debug:

```
$ make gdb
```

5. Configuration:

Sample config file: `conf/nginx.conf`:

```
# Main directive to add a Radius server.
# Can be several "radius_server" directives.
radius_server "radius_server_1" {
    # Radius server URL
    url "127.0.0.1:1812";

    # Radius server shared secret
    secret "secret";

    # NAS identifier, optional
    nas_identifier "nas-identifier";

    # Timeout for Radius auth requests, optional, default: 5s
    auth_timeout   5s;

    # Retries count for Radius auth requests, optional, default: 3
    auth_retries   3;

    # Timeout for Radius health requests, optional, default: 5s
    health_timeout 5s;

    # Retries count for Radius health requests, optional, default: 1
    health_retries 1;

    # Radius auth/health requests queue size, optional, default: 10
    # Effectively, the number of concurrent requests that can be
    # processed without retrying.
    queue_size     10;
}

# Location directive to select Radius server.
# Can be several "radius_servers" directives per location.
radius_servers "radius_server_1";

# Location directive to enable module and make auth request.
auth_radius              "realm" | off;
radius_auth              "realm" | off;

# Location directive to enable module and make health request.
radius_health            ["user"] ["passwd"];
```

6. Installation (optional):

```
$ make install
```
