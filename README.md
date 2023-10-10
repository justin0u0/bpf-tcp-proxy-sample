# bpf-tcp-proxy-sample

First replace the proxy host IP address in the `docker-compose.yml` file:

```yaml
proxy:
  command:
    - "--remote"
    - "{host}:8080"
```

Second, start the server and the proxy:

```bash
make
docker-compose up -d --build server proxy
```

Test the proxy:

```bash
nc -t {host} 8081
```

To disable BPF, remove the `--bpf` flag from the proxy command in the `docker-compose.yml` file.
