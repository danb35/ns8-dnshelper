# Data and privacy

dnshelper has no telemetry, and nothing is sent to its author.

## What goes where

| Data | Where it goes | When |
|---|---|---|
| API credentials | The DNS host you choose, to authenticate. Some hosts' secrets are only used to sign requests and are not transmitted | Whenever dnshelper talks to that host |
| Zone names and DNS records (names, types, values, TTLs) | The same DNS host | When you, or a module your access rules allow, read or change records. The host also sees your server's IP address |
| DNS queries for one name and type | The zone's authoritative name servers, asked directly by the node; the node's own resolver is asked for their names and addresses | When you choose **Check propagation** on the Records page |
| Snapshots: a full copy of a zone's records, with who changed what and when | Kept on the node, in files only the module can read | Before every change made through dnshelper, and when you take one |
| Zones, access rules, credentials, snapshots, settings, and which module wrote which record | Your backup destination, encrypted by NS8 | If you have configured backups |
| A zone or snapshot exported as a zone file | Your browser, as a download | When you choose **Export** or **Download** |
| Audit log: calling module, zone, record names and types, first 80 characters of values. Never credentials | NS8's log server, and any syslog server or Cloud Log Manager you forward logs to | On every change, and every call by another module |

For PowerDNS and RFC 2136, the "DNS host" is the server you name, which may be your own.
How a DNS host handles this data is governed by that host's own terms.

## How credentials are stored

Credentials are kept on the node in files only the module can read (mode 0600). They are not
encrypted there, and they are not stored in Redis. Use a token limited to the zones dnshelper
manages, so that you can revoke it without affecting anything else.

Modules on your cluster can read or change records only as their access role and access rules
allow. They can never read credentials. Cloning or moving dnshelper copies its data, credentials
included, to the new instance.

## Removing data

Deleting a credential removes it from the node, but older backups still contain it, and the
token stays valid until you revoke it at your DNS host. Removing a zone leaves its records at
the DNS host, and deletes its snapshots and its record of which module wrote which record from
the node (older backups still contain them).

Snapshots are deleted when a zone has more than the number set on the Settings page (50 by
default) or when they are older than the age set there (90 days by default); the latest snapshot
of a zone is kept. A zone that dnshelper stops managing because the PowerDNS module dropped it
keeps its snapshots until they reach that age. Deleting a snapshot on the Records page removes it
at once.
