# Quilibrium Docker Instructions

## WARNING

> [!WARNING]
> The Quilibrium docker container requires host configuration changes.

There are extreme buffering requirements, especially during sync, and these in turn require `sysctl`
configuration changes that unfortunately are not supported by Docker. But if these changes are made on
the host machine, then luckily containers seem to automatically have the larger buffers.

The buffer related `sysctl` settings are `net.core.rmem_max` and `net.core.wmem_max` and they both
should be set to `600,000,000` bytes. This value allows pre-buffering of the entire maximum payload
for sync.

You can tell that the buffer size is not large enough by noticing this log entry at beginning when 
Quilibrium starts, a few lines below the large logo:
> failed to sufficiently increase receive buffer size (was: 208 kiB, wanted: 2048 kiB, got: 416 kiB).
> See https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes for details.

To read the currently set values:
```shell
sysctl -n net.core.rmem_max
sysctl -n net.core.wmem_max
```

To set new values, this is not a persistent change:
```shell
sudo sysctl -w net.core.rmem_max=600000000
sudo sysctl -w net.core.wmem_max=600000000
```

To persistently set the new values add a configuration file named `20-quilibrium.conf` to
`/etc/sysctl.d/`. The file content should be:
```
# Quilibrium buffering requirements, especially during sync.
# The value could be as low as 26214400, but everything would be slower.

net.core.rmem_max = 600000000
net.core.wmem_max = 600000000
```


## Build

In the repository root folder, where the [Dockerfile](Dockerfile) file is, build the docker image:
```shell
docker build --build-arg GIT_COMMIT=$(git log -1 --format=%h) -t quilibrium -t quilibrium:1.2.15 .
```

Use latest version instead of `1.2.15`.


## Run

You can run Quilibrium on the same machine where you built the image, from the same repository root
folder where [docker-compose.yml](docker-compose.yml) is.

You can also copy `docker-compose.yml` to a new folder on a server and run it there. In this case you
have to have a way to push your image to a Docker image repo and then pull that image on the server.
Github offers such an image repo and a way to push and pull images using special authentication
tokens. See
[Working with the Container registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).

Run Quilibrium in a container:
```shell
docker compose up -d
```

A `.config/` subfolder will be created under the current folder, this is mapped inside the container.
Make sure you backup `config.yml` and `keys.yml`.


### Resource management
To ensure that your client performs optimally within a specific resource configuration, you can specify
resource limits and reservations in the node configuration as illustrated below. 

This configuration helps in deploying the client with controlled resource usage, such as CPU and memory,
to avoid overconsumption of resources in your environment.

The [docker-compose.yml](docker-compose.yml) file already specifies resources following the currently
recommended hardware requirements.

```yaml
services:
  node:
    # Some other configuration sections here
    deploy:
      resources:
        limits:
          cpus: '4'  # Maximum CPU count that the container can use
          memory: 16G  # Maximum memory that the container can use
        reservations:
          cpus: '2'  # CPU count that the container initially requests
          memory: 8G  # Memory that the container initially request
```


### Customizing docker-compose.yml

If you want to change certain parameters in [docker-compose.yml](docker-compose.yml) it is better not
to edit the file directly as new versions pushed through git would overwrite your changes. A more
flexible solution is to create another file called `docker-compose.override.yml` right next to it
and specifying the necessary overriding changes there.

For example:
```yaml
services:
  node:
    image: ghcr.io/mscurtescu/ceremonyclient
    restart: on-failure:7
```

The above will override the image name and also the restart policy.

To check if your overrides are being picked up run the following command:
```shell
docker compose config
```

This will output the merged and canonical compose file that will be used to run the container(s).


## Interact with a running container

Drop into a shell inside a running container:
```shell
docker compose exec -it node sh
```

Watch the logs:
```shell
docker compose logs
```

Get the Peer ID:
```shell
docker compose exec node go run ./... -peer-id
```

Get the token balance:
```shell
docker compose exec node go run ./... -balance
```

Run the DB console:
```shell
docker compose exec node go run ./... -db-console
```
