# Zeek ZsonHttp

A Zeek plugin to POST logs over HTTP. The logs are posted in native
TSV Ascii format. The plugin uses HTTP chunked encoding to first post
the zeek log header then it streams log lines as http chunks as they
become available.

If the connection closes or resets, the plugin attempts to reconnect
and transmit data where it left off.


## Building and Installing

The plugin is known to work with with Zeek versions 2.6.4 and
3.0.0. It should work with certain earlier versions but these have not
been tested so far.

### Building


1. Ensure that you have libcurl present on your system (plugin has
been primarily developped/tested against libcurl 7.54, but other
versions should work too).

1. Build the plugin using the following commands:

    ```sh
    $ ./configure
    $ make
    ```

The configure uses `bro-config` to determine the path to your bro
distribution. If for some reason that is not present you can pass path
via the `--bro-dist` argument to `configure`.


### Installing

**From source:** If you've built the plugin yourself following the steps above, `make
install` will install the plugin. (Of course, this requires building
the plugin locally to the Zeek host it will run on).


**From binary release:** If you're installing a binary release of the plugin (such as
`Zeek_ZsonHttp-0.3.tar.gz`), then do the following after copying the
package on to the Zeek host:

```sh
$ sudo mkdir -p $(bro-config --plugin_dir)
$ cd $(bro-config --plugin_dir)
$ sudo tar oxzf path/to/plugin/Zeek_ZsonHttp-0.3.tar.gz
```


To verify the installation, run `bro -N Zeek::ZsonHttp` and you will
see the same output as below if the installation was succesful.

    ```sh
    $ bro -N Zeek::ZsonHttp
    Zeek::ZsonHttp - Plugin to POST Zeek logs via HTTP (dynamic, version 0.3)
    ```

### Install with `bro-pkg`

To be documented.


## Configure and Run



Add the following to the end of your `local.bro` file:

```
@load Zeek/ZsonHttp

# Set this to the URL of your HTTP endpoint
redef LogZsonHttp::url = "http://localhost:9867/space/default/zeek";
```

By default, all log streams will be sent.

You can redefine the `exclude_logs` and `send_logs` variables
for finer-grained selection of streams to send.

For example, to send only the `conn` and `dns` logs:


```
redef LogZsonHttp::send_logs = set(Conn::LOG, DNS::LOG);
```


or to send all but the `loaded_scripts` log:
```
redef LogZsonHttp::exclude_logs = set(LoadedScripts::LOG);
```
