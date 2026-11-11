# API authentication migration

These changes require a coordinated rollout. They do not make an existing
installation's legacy tokens or captured credentials disappear automatically.

## Preparation

- Back up the configuration and database. Update the API's schema through the
  normal `edge-api upgrade` procedure before new administrator password writes.
  `edgeAdmins.password` must support 255 characters. The updated embedded schema
  widens that column and removes its obsolete password index. This patch has not
  executed that migration on any database.
- Deploy `EdgeCommon/pkg/rpcauth` with the API, Node and Admin builds. The shared
  package and its consumers must be released together.
- Provision API HTTPS certificates with the right hostname/IP SAN. Clients
  verify system roots and optionally add a private CA from `EDGE_RPC_CA_FILE`.
  Local HTTP RPC can be enabled with `EDGE_ALLOW_LOOPBACK_RPC=true` for literal
  loopback addresses (`127.0.0.0/8` or `::1`) only; DNS names, including
  `localhost`, do not qualify. Remote HTTP requires the explicit temporary
  `EDGE_ALLOW_PLAINTEXT_RPC=true` compatibility override.

## RPC protocol rollout

1. If existing clients still emit CFB tokens, start the upgraded API with
   `EDGE_ALLOW_LEGACY_RPC_TOKENS=true` only for the migration period. This flag
   retains the old protocol's integrity weakness; timestamps merely limit its
   validity window. Keep API access restricted while it is enabled.
2. Upgrade Admin, Node and any other RPC consumers. Clients call
   `rpcauth.Sign(secret, nodeID, role, userID)` and pass the returned token directly
   in `token` metadata, without another Base64 layer. Tokens bind version,
   audience `edge-api`, node ID, role, account ID, issuance/expiry and a random
   nonce. Lifetime is two minutes with 30 seconds of clock allowance. Keep clocks
   synchronized. Node command streams authenticate when established and recheck
   their original credential and enabled-node identity against the database
   every 30 seconds. Secret/role changes, removal or a disabled node end the
   session. A failed lookup or a revalidation taking over five seconds also
   stops session processing. Handshake expiry alone does not interrupt a
   session whose authoritative credential remains valid. Revalidation occurs
   within 30 seconds and has a five-second lookup deadline; offline-status
   cleanup has its own five-second deadline before the RPC handler returns.
3. Remove `EDGE_ALLOW_LEGACY_RPC_TOKENS` after every consumer has upgraded. New
   installations reject CFB tokens by default. Remove the plaintext flag after
   endpoints use verified HTTPS. The Node client reconnects after stream errors
   with fresh signed metadata. Other custom streaming consumers must implement
   their own equivalent revalidation or reconnect policy.

Server authorization now permits only the machine's own role plus the explicit
Admin-to-API installation delegation. Node or cluster credentials cannot claim
Admin/API roles. Credential lookups read current database state on each new call,
so token revocation has no permanent process-local credential cache.

## Administrator passwords

Admin login sends `Password = "raw-v1:" + rawPassword` over verified transport.
Password bytes, including spaces or a literal `raw-v1:`, are preserved. New
passwords use Argon2id with a random salt, 19 MiB memory, two iterations and one
lane. The verifier rejects unsupported formats and excessive parameters and
bounds concurrent password work.

A correct raw login against an MD5 record upgrades it using a conditional write;
a concurrent password change wins. Legacy clients sending an unprefixed MD5
digest work only while the record remains MD5. They stop working once that
account migrates. Upgrade all Admin clients before users log in with raw-v1;
rollback to an old API also requires planning for the migrated hashes. User
portal password storage is unchanged. Existing weak-password list queries only
recognize legacy MD5 entries, not Argon2id hashes.

## Access keys and permission changes

Access keys and bearer tokens must identify exactly one user or administrator.
Historical mixed keys cannot be exchanged. Review existing mixed key/token
records and revoke compromised credentials using the installation's normal
operational process; this patch does not mutate existing records.

Administrator management requires a live super administrator; self profile and
password changes remain available. Signed Admin service credentials retain the
installation/login/session functions. User principals cannot read node/cluster
secrets. Header, WebSocket and Web references enforce tenant ownership, and users
cannot create local filesystem roots. Check workflows that previously relied on
sharing another tenant's configuration by numeric ID.

## Validation

The changes include signature/expiry/claim parsing, real TLS certificate checks,
RPC authorization, task response ownership/cancellation, and password migration
regressions. DAO tests use an in-memory SQL driver, not an installation database.
No deployment or live database mutation was performed during implementation.
