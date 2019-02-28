# Another HTTP Server Benchmark Test 

Small http server benchmark tool powered by libcurl library (https://curl.haxx.se/libcurl/)

There are plenty number of tools with same functionality but they have some disadvantages:

* [ab](https://httpd.apache.org/docs/2.4/programs/ab.html) and [wrk](https://github.com/wg/wrk) lack http2 support
* [h2load](https://nghttp2.org/documentation/h2load.1.html) has no non keep alive mode
* go based tools [hey](https://github.com/rakyll/hey), [vegeta](https://github.com/tsenart/vegeta) has non deterministic thread-process usage

# Usage
```sh
Usage: ahsbt [option...] url
Options:
  --requests       overall requests count (default: 2)
  --connections    concurrent connections count per single thread (default: 2)
  --threads        concurrent threads count (default: 2)
  --noreuse        forbid reuse connection (default: false)
  --insecure       disable SSL peer and host verification (default: false)
  --fastopen       enable TCP Fast Open (default: false)
  --tcpnagle       enable TCP Nagle (default: false)
  --verbose        verbose information will be sent to stderr (default: false)
  --http           enforce http version (default: none)
                   1      - HTTP 1.0
                   1.1    - HTTP 1.1
                   2      - HTTP 2
                   2tls   - HTTP 2 for HTTPS, HTTP 1.1 for HTTP
                   2prior - HTTP 2 without HTTP/1.1 Upgrade
Examples:
  ./ahsbt --threads=4 --requests=10000 http://example.com/
```

### Build

```sh
mkdir cmake-build
cd cmake-build
cmake ..
make
```
