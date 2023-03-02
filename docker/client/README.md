../ci/build-client.sh
docker buildx build . --push -f client.Dockerfile -t simaom/rac-aarch64:latest

Then the `rac-docker-compose.yml` file can be used to start rac on a device
