# RAC - Remote Access Client

Starts a remote session, allowing a user to connect to a device using ssh.

RAC will receive allowed keys from the server and update an `authorized_keys` file.

RAC will periodically check the server to ensure the session is still
valid and the public keys are still authorized.

RAC will try to recover from errors and reconnect.

## Usage

Compile with `cargo build --release`, or to cross compile to arm: `cargo build --target aarch64-unknown-linux-musl --release`. You will need the arm musl linker installed. 

1. Edit client.toml
   
2. Create a remote session in RAS
   
   We don't have a frontend for RAS yet, so you need to be connected to our vpn. Then use [ras-client.rb](https://gitlab.com/torizon-platform/ras/-/blob/master/ras-client.rb).
   
   `export RS_HOST=ras.internal.pilot.torizon.io`
   `export DEVICE_ID=<your device uuid>`
   `./ras-client.rb create <path to your public key>`

3. Run RAC.

   You can run `rac` using `cargo run`, or build a binary with `cargo build --release` and uploading that binary to a device. `client.toml` also needs to be uploaded and the values in that file need to point to the right paths. See the `client-aktualizr.toml` example.

4. Connect to the device using ssh.

   Once RAC is running and the session is established, you can connect to the device using ssh.

    `./ras-client.rb show` will show the port you need to use to connect to your device: `ssh torizon@ras.pilot.torizon.io -p <session port>` 
    

## Different Session Modes

RAC can run using three different session modes, which can be configured in `client.toml`.

The `device.session` section in the config file must have only one of the following session types. For example, to configure a target host session, the following `device` section could be used:

```
[device]
ssh_private_key_path = "./device-key-01.sec"

[device.session.target_host]
host_port = "127.0.0.1:22"
```

### Target Host

For each new remote session, RAC will forward the TCP connection as is to a target `(host, port)` pair. The target is usually an existing sshd or http server.

RAC will save the authorized keys received from the server into the configured `authorized_keys` file, but the target host will perform all the necessary authentication steps.

This can be configured in `client.toml` using:

```
[device.session.target_host]
host_port = "127.0.0.1:22"
authorized_keys_path = "/home/torizon/.ssh/authorized-keys2" 
```

All values are optional and the defaults are shown above.

### Embedded Pseudo Terminal (PTY)

For each remote session, RAC will open a pty using the configured shell and provide that terminal directly to the user. 

RAC will handle the authentication using the public keys received from the server.

RAC will not forward the connection to a remote host or process, instead it will setup the PTY and offer it to the user.

This mode is self contained and does not rely on a remote server.

This can be configured using:

```
[device.session.embedded]
server_key_path = "/home/torizon/.embedded-key.sec"
shell = "/usr/bin/bash"
```

If `server_key_path` is not set, a new key will be generated for each session. `shell` is optional and the default is shown above.

A new server host key will be created if `server_key_path` does not exist.

### Spawned SSHD

For each remote session, a new sshd instance will be spawned to accept
the ssh connection.

The sshd instance will be configured according to the metadata
supplied by the server. The sshd will be configured to only accept the
public keys allowed by the server.

The user will still to login with a valid username (for example `torizon`). `root` access is not allowed.

This can be enabled using:

```
[device.session.spanwed_sshd]
sshd_path = "/usr/bin/sshd"
config_dir = "/run/rac"
```

All values are optional and the defaults are shown above.

The process running RAC must have write access to `config_dir`.
