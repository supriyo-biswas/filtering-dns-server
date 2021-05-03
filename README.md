# filtering-dns-server

A stub resolver DNS server using [dnspython](https://github.com/rthalley/dnspython)
and [socketserver](https://docs.python.org/3/library/socketserver.html) for the
purpose of blocking malware, parental control, or blocking ads.

Being a stub resolver, it needs to be configured with a DNS server to which queries
would be forwarded to, if the domain is blacklisted. By default, it uses the same
DNS servers as would be used by the system it's installed on.

It also implements ratelimiting and refuses to answer DNS queries should a
potentially problematic query be made, such as ANY.

## Usage

The server requires Python3 and Redis to run. These instructions are for Ubuntu 20.04
although it can be run on any distribution.

* Install the dependencies:

```bash
sudo apt install virtualenv python3 python3-dev redis-server
```

* Configure Redis to use a Unix domain socket. If you don't need Redis for anything
else, you can also disable it from using TCP ports. The command below does both of
these things mentioned above:

```bash
sudo sed -ri 's/^bind /#&/;s/^(port ).*$/\10/;s/^# (unixsocket)/\1/;s/^(unixsocketperm )[0-9]+/\1777/' /etc/redis/redis.conf
```

* Clone and enter into the repository directory:

```bash
git clone https://github.com/supriyo-biswas/filtering-dns-server
cd filtering-dns-server
```

* Create a virtualenv for this project, and install the dependencies:

```bash
virtualenv -p python3 venv
. venv/bin/activate
pip install -r requirements.txt
```

* Add the cap_net_bind_service capability so that it can be run on port 53.

```bash
sudo setcap cap_net_bind_service=+ep venv/bin/python3
```

* Run the server:

```bash
./venv/bin/python3 server.py
```

## Configuration

You can run the server with a JSON configuration file, as follows:

```
./venv/bin/python server.py /path/to/config.json
```

The following settings can be configured. All of these have reasonable
defaults.

```js
{
  // The DNS server to which we should send queries to
  "nameservers": ["1.1.1.1", "1.0.0.1"],
  // Any websites to blacklist. Blocking 'example.com' also blocks
  // 'www.example.com', 'foo.example.com' and so on. You can also block entire
  // TLDs by specifying the TLD name, for example, 'cn'.
  "blacklist": ["example.com", "cn"],
  // A whitelist. Whitelisting 'example.com' also whitelists 'www.example.com'
  "whitelist": ["foo.example.com"],
  // Path to the redis socket file.
  "redis_socket_file": "/tmp/redis.sock",
  // Ratelimits (per second) to place on IPs querying the DNS server.
  "ratelimits": {"limit": 10, "limit_burst": 2, "enabled": true},
  // The port on which the server will be run. Helpful for development.
  "port": 5454
}
```

## License

[MIT](https://opensource.org/licenses/MIT)
