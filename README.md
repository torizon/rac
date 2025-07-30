# RAC - Remote Access Client for Torizon OS

Starts a remote session, allowing a user to connect to a device using ssh.

RAC will receive allowed keys from the server and update an `authorized_keys` file.

RAC will periodically check the server to ensure the session is still
valid and the public keys are still authorized.

RAC will try to recover from errors and reconnect.

## CI Docker Image

The CI jobs for this app run on Github Actions, which is currently blocked by `musl.cc`. Therefore, we currently do not build the docker image for CI, on CI. If you change the `Dockerfile-ci` file, you will need to manually build and push the new image to docker and update the image reference in the github actions yaml definitions.

## Usage

Compile with `cargo build --release`, or to cross compile to arm: `cargo build --target aarch64-unknown-linux-musl --release`. You will need the arm musl linker installed. 

1. Edit client.toml
   
2. Create a remote session on app.torizon.io
   
3. Run RAC.

   You can run `rac` using `cargo run`, or build a binary with `cargo build --release` and uploading that binary to a device. `client.toml` also needs to be uploaded and the values in that file need to point to the right paths. See the `client-aktualizr.toml` example.

4. Connect to the device using ssh.
    

## Configuration

RAC is configured using TOML. The config file can be specified using the `CONFIG_FILE` environment variable.

There are two main sections that a RAC config file requires: 

* `torizon` configures how RAC should connect to the Torizon Platform API
* `device` configures how the SSH session will be established, and sets up where device-specific files (like key material) will be stored

### `torizon`: Torizon Platform API Connection

RAC connects to the Torizon Platform remote access service API through the Torizon device gateway, using mutual TLS. The config file needs to specify the server URL to connect to (the URL of the device gateway), the path where the server's certificate is located, and the path where the client's certifiecate and private are located. In Torizon OS, the default device gateway cert is provided in the root filesystem image at `/usr/lib/sota/root.crt`. The client cert and key are placed in `/var/sota/import` at provisioning time.

This configuration should work for a default Torizon OS image:

```
[torizon]
url = "https://dgw.torizon.io/ras/"
director_url = "https://dgw.torizon.io/director/"
server_cert_path = "/usr/lib/sota/root.crt"
client_cert_path = "/var/sota/import/client.pem"
client_key_path = "/var/sota/import/pkey.pem"
```

### `device`: General device configuration

The `device` section of the config file has three configurable values:

* `unprivileged_user_group` allows you to set a user and group to drop privileges to after RAC is loaded. RAC generally needs to run as root initially, to be able to access the device's x.509 certificate for connecting to the Torizon API. However, after that there is no need for root privileges anymore, so it is a best practice to drop privileges down to a less-privileged user. This value is of the form `user:group`, e.g. `torizon:torizon`
* `ssh_private_key_path` configures the location the private key the device will use to open up its tunnel to the server. If the file does not yet exist, a new key will be created (and saved for re-use). This option is mandatory. If `unprivileged_user_group` is set, this file must be owned by the unprivileged user.
* `local_tuf_repo_path` configures the location where the Uptane metadata will be stored. This option is mandatory.
* `poll_timeout` configures how frequently RAC should poll the Torizon Platform API to check for a remote session. It defaults to 3 seconds.
* `validation_poll_timeout` configures how frequently RAC should validate the active SSH session to ensure it remains valid. It defaults to 60 seconds.

This configuration should work for a default Torizon OS image:


```
[device]
ssh_private_key_path = "/home/torizon/run/rac/device-key-01.sec"
local_tuf_repo_path = "/var/run/rac/uptane-repo"
unprivileged_user_group = "torizon:torizon"
poll_timeout = { secs = 60, nanos = 0 }`
```


### RAC Session Modes

RAC can run using three different session modes, which can be configured in `client.toml`. The valid modes are `spawned_sshd`, `embedded`, and `target_host`. Only one of the three modes can be configured.

```
[device.session.spawned_sshd]
sshd_path = "/usr/sbin/sshd"
config_dir = "/home/torizon/run/rac"
```

### Spawned SSHD

For each Remote Access Client session received from the server, a new sshd instance will be spawned to accept remote sessions.

This is the recommended mode for most use cases.

The sshd process will be configured to only accept the public keys allowed by the server, and will be configured to run with the `StrictModes yes` option. If you're writing your own config file here, this is the easiest place to get something wrong. Make sure that the modes of your authorized_keys file, host key, and the directory that contains them are set correctly.

The user will still need to login with a valid username (for example `torizon`). `root` access is not allowed.

Example config for the spawned_sshd mode:

```
[device.session.spawned_sshd]
sshd_path = "/usr/sbin/sshd"
config_dir = "/home/torizon/run/rac"
```

All values except `config_dir` are optional. If `host_key_path` is not provided, a new key will be created in `config_dir` and reused as long as that file exists.

The process running RAC must have write access to `config_dir`.

### Embedded Pseudo Terminal (PTY)

For each Remote Access Client session received from the server, RAC will open a pty using the configured shell and provide that terminal directly to the user. This means no external process is spawned, and no temporary files are created.

However, it does have some drawbacks, which is why we don't yet recommend it as the default option:

* Only ed25519 SSH keys are supported
* The only functionality provided is the PTY: other SSH features like scp/sftp, port forwarding, and so on will not work

This can be configured using:

```
[device.session.embedded]
server_key_path = "/home/torizon/run/rac/embedded-key.sec"
shell = "/bin/bash"
```

If `server_key_path` is not set, a new key will be generated for each session. `shell` is optional and the default is shown above.

A new server host key will be created if `server_key_path` does not exist.

### D-Bus events

RAC will listen to D-Bus messages on `io.torizon.TznService1` that control RAC's internal state. RAC will poll for new remote sessions and validate current ones based off the messages received in this bus. Withi Torizon OS, these messages come from the [`tzn-mqtt`](https://github.com/torizon/tzn-mqtt/) application which relays MQTT messages from Torizon Platform to the local D-Bus session in the interface specified above.

In the absence of messages on the bus, RAC will continue to poll the Torizon Platform through HTTPS.

### Target Host

For each new remote session, RAC will forward the TCP connection as is to a target `(host, port)` pair. The target is usually an existing sshd or http server.

RAC will save the authorized keys received from the server into the configured `authorized_keys` file, but the target host will perform all the necessary authentication steps.

This mode is not recommended, as the default configuration of the sshd on devices is often not hardened for exposure to the internet. Use at your own risk.

This can be configured in `client.toml` using:

```
[device.session.target_host]
host_port = "127.0.0.1:22"
authorized_keys_path = "/home/torizon/.ssh/authorized-keys2" 
```

All values are optional and the defaults are shown above.



