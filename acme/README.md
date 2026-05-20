# acme.sh + BIND nsupdate

This directory holds the per-deploy TSIG key used by the acme.sh sidecar
to satisfy the DNS-01 challenge against BIND.

## File layout

- `tsig.key` — the TSIG key, in BIND/nsupdate format. **Gitignored.** Place
  it here yourself; don't commit it. The acme container bind-mounts it
  read-only.

## TSIG key format

`tsig.key` should be a BIND keyfile, e.g.:

```
key "acme-honeycow." {
    algorithm hmac-sha256;
    secret "<base64 secret>";
};
```

acme.sh's `dns_nsupdate` hook reads this file directly and uses it with
`nsupdate -k`.

## BIND-side prep (do this on the master before issuing)

In the honeycow.net zone definition on the primary nameserver (`ns1.example.net`):

```
key "acme-honeycow." {
    algorithm hmac-sha256;
    secret "<base64 secret>";
};

zone "honeycow.net" {
    type primary;
    file "zones/db.honeycow.net";
    notify explicit;
    also-notify { /* ns2, ns3 */ };
    update-policy {
        grant acme-honeycow. name _acme-challenge.honeycow.net. TXT;
    };
};
```

The `update-policy` is scoped to the single label `_acme-challenge` and the
single record type `TXT`. The key can do nothing else.

Generate the key with:

```
tsig-keygen -a hmac-sha256 acme-honeycow.
```

Put the resulting `key` block both in `named.conf` (master) and as the
content of `acme/tsig.key` on the honeycow VPS.
