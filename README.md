# Zeek TSV HTTP Plugin

A Zeek plugin to POST logs over HTTP. The logs are posted in native
[TSV ASCII format](https://docs.zeek.org/en/stable/scripts/base/frameworks/logging/writers/ascii.zeek.html). The plugin uses HTTP chunked encoding to first post
the Zeek log header then it streams log lines as HTTP chunks as they
become available.

If the connection closes or resets, the plugin attempts to reconnect
and transmit data where it left off.


## Building and Installing

The plugin is known to work with with Zeek versions 3.0.0 and newer.

### Building


1. Ensure that you have libcurl present on your system (plugin has
been primarily developped/tested against libcurl 7.54, but other
versions should work too).

1. Build the plugin using the following commands:

    ```sh
    $ ./configure
    $ make
    ```

The configure uses `zeek-config` to determine the path to your Zeek
distribution. If for some reason that is not present you can pass path
via the `--zeek-dist` argument to `configure`.


### Installing

**From source:** If you've built the plugin yourself following the steps above, `make
install` will install the plugin. (Of course, this requires building
the plugin locally to the Zeek host it will run on).


**From binary release:** If you're installing a binary release of the plugin (such as
`Zeek_TsvHttp-0.4.tar.gz`), then do the following after copying the
package on to the Zeek host:

```sh
$ sudo mkdir -p $(zeek-config --plugin_dir)
$ cd $(zeek-config --plugin_dir)
$ sudo tar oxzf path/to/plugin/Zeek_TsvHttp-0.5.tar.gz
```


To verify the installation, run `zeek -N Zeek::TsvHttp` and you will
see the same output as below if the installation was successful.

```sh
$ zeek -N Zeek::TsvHttp
Zeek::TsvHttp - Plugin to POST Zeek logs via HTTP (dynamic, version 0.5)
```

### Install with `zkg`

To be documented.


## Configure and Run

Add the following to the end of your `local.zeek` file:

```
@load Zeek/TsvHttp

# Set this to the URL of your HTTP endpoint
redef LogTsvHttp::url = "http://localhost:9867/space/default/zeek";
```

By default, all log streams will be sent.

You can redefine the `exclude_logs` and `send_logs` variables
for finer-grained selection of streams to send.

For example, to send only the `conn` and `dns` logs:


```
redef LogTsvHttp::send_logs = set(Conn::LOG, DNS::LOG);
```


or to send all but the `loaded_scripts` log:
```
redef LogTsvHttp::exclude_logs = set(LoadedScripts::LOG);
```

#### Sending logs to different endpoints

The `LogTsvHttp::url` endpoint can be overridden on a per-log basis
by instantiating a `Log::Filter` and passing the URL in its
configuration table. For example:

```
@load Zeek/TsvHttp

# Set this to the URL of your HTTP endpoint
redef LogTsvHttp::url = "http://localhost:9867/some/endpoint";

event zeek_init() &priority=-10
{
    # handles HTTP
    local http_filter: Log::Filter = [
        $name = tsv-http",
        $writer = Log::WRITER_TSVHTTP,
        $path = "http",
        $config = table(["url"] = "http://localhost:9877/other/endpoint")
    ];
    Log::add_filter(HTTP::LOG, http_filter);

    # handles DNS
    local dns_filter: Log::Filter = [
        $name = "tsv-dns",
        $writer = Log::WRITER_TSVHTTP,
        $path = "dns",
        $config = table(["url"] = "http://localhost:9887/and/another/endpoint")
    ];
    Log::add_filter(DNS::LOG, dns_filter);
}
```
