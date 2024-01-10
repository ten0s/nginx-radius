
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
# Address, secret and nas-identifier of radius server.
# Can be several servers.
radius_server       127.0.0.1:1812 "secret" ["nas-identifier"];

# Timeout for radius auth requests.
radius_auth_timeout      5s;

# Retries count for radius auth requests.
radius_auth_retries      3;

# Timeout for radius health requests.
radius_auth_timeout      5s;

# Retries count for radius health requests.
radius_auth_retries      1;

# Location directive to enable module and make auth request.
auth_radius         "realm" | off;

# Location directive to enable module and make health request.
auth_radius_health  "user" ["passwd"];
```

6. Installation (optional):

```
$ make install
```
