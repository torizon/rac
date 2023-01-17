Needs to be build on an aarch64 machine.

../ci/build-client.sh
docker build . -f client.Dockerfile -t simaom/rac-arm:latest-rs
docker push simaom/ras-client-arm:latest-rs

Then the client-compose file can be used to start ras-client on a device
