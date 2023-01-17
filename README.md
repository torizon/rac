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
    




