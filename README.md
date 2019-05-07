# alexproxy
Aptly named `alexproxy`, this is my asynchronous HTTP(s) proxy
written in Golang.

Most of the server part is copied and modified from the Golang httputil package.

## Introduction
> In need of a fast and simple HTTP(s) proxy?<br>
> Look no further, alexproxy is the solution for you!

### Features
- CIDR-based IP access control
- Monitoring via netdata module [go_expvar](https://docs.netdata.cloud/collectors/python.d.plugin/go_expvar/)
- Tight systemd integration by implementing [sd_notify(3)](https://manpages.debian.org/jessie/libsystemd-dev/sd_notify.3.en.html)
- Supports both regular HTTP proxying and HTTPS proxying by implementing the HTTP CONNECT method
- Supports `HTTP_PROXY` / `HTTPS_PROXY` environment variables so you can proxy while you proxy
- Easy to use: just run `alexproxy -listen :8080` and you're up and running!
- Runs on Windows, Linux, macOS and more!

## Usage
```
Usage of alexproxy:
  -cidrfile string
        Path to file containing newline-separated CIDR prefixes that are allowed access, 0.0.0.0/0 / ::/0 is allowed if not specified
  -direct-cidrfile string
        Path to file containing newline-separated CIDR prefixes that are allowed access to direct endpoint, 127.0.0.0/8 / ::1/128 is allowed if not specified
  -debug
        Enable debug logging
  -h    Show this help menu
  -help
        Show this help menu
  -listen string
        Listen address in the format of <ip>:<port>
  -timeout string
        Request timeout (default "30s")
  -version
        Print version and exit
```

## Direct endpoints
#### GET | HEAD `/debug/status`
Returns 200 OK.

#### GET `/debug/vars`
See [golang.org/pkg/expvar](https://golang.org/pkg/expvar/). Additionally exports `proxyRequests`, which is a counter of requests currently being handled.

## Building
Requires the Golang runtime (and GNU Make if you want to make your life easier).

Run `make` to build, or if you're not on Linux, have a look at the
commands in the Makefile.
