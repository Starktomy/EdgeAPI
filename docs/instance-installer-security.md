# Local instance installer

`edge-instance-installer` now requires an explicitly configured, nonempty
`EDGE_DB_PASSWORD`. It no longer assumes `123456`; `-v` redacts the password.
`EDGE_DB_HOST` and `EDGE_DB_NAME` remain optional and default to `127.0.0.1` and
`edges`. Supply credentials through a protected environment, rather than command
arguments or shell history. For an interactive shell:

```bash
read -rs EDGE_DB_PASSWORD
export EDGE_DB_PASSWORD
export EDGE_ALLOW_LOOPBACK_RPC=true
edge-instance-installer
unset EDGE_DB_PASSWORD
```

The standalone installer binds API and REST listeners to `127.0.0.1`. Its local
RPC clients require `EDGE_ALLOW_LOOPBACK_RPC=true`; this permits literal loopback
addresses and does not permit remote HTTP endpoints. Keep the setting in the
service environment when using these local endpoints. Configure verified TLS
before connecting external nodes. Admin's browser endpoint still needs a TLS
proxy or configured HTTPS before exposing it to users.

Generated credentials, database YAML, configuration backups and the initial
`password.txt` use atomic replacement, file mode `0600` and parent directory mode
`0700`. Existing secret file modes tighten when rewritten. Symbolic-link targets
and symbolic-link configuration directories are rejected; replace those layouts
with private regular files/directories before installation or configuration
recovery. Backups under `/etc/edge-api` remain best effort when the service user
cannot write there.

The installer creates and starts local services. The verification tests only
exercise configuration parsing, private temporary files and explicitly supplied
disposable MySQL databases; they do not execute a live installation.
