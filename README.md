
Build:

1. Get nginx source:
    make getsrc && make src

2. Build source:
    make build_all

3. Installation:
    make install

4. Configuration:

    Sample config file: conf/nginx.conf

    radius_server       127.0.0.1:1812 "secret" "nas-identifier";
        - Address, secret and nas-identifier of radius server. Can be several servers.

    radius_timeout      5s;
        - Timeout for radius requests.

    radius_retries      3;
        - Attempts count for radius requests.

    auth_radius     "realm" | off;
        - Location directive for enable module.
