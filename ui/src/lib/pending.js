//
// Copyright (C) 2026 dnshelper contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Pending changes of the Records page: changes the administrator collects
// before sending them as one apply-changes. A change is
//   { kind: "add", new }        a record to add
//   { kind: "edit", old, new }  a record replaced by another
//   { kind: "delete", old }     a record to remove
// "old" is a record as get-records returned it. See DESIGN.md, Records
// editor: Staged changes and bulk operations.

// apply-changes takes at most this many records in each of its lists
export const MAX_PER_LIST = 100;

/** What identifies an existing record: name, type and value. */
export function recordKey(r) {
  return `${r.name}|${r.type}|${r.data}`;
}

// The old record as apply-changes must find it: without the TTL, since a DNS
// host may store a different one from the one asked for.
function bare(r) {
  return { name: r.name, type: r.type, data: r.data };
}

/**
 * The key of a record in the owner index (list-owners): as the backend's
 * _rec_key, host names without case or final dot.
 */
export function ownerKey(r) {
  let data = r.data || "";
  if (["CNAME", "NS", "PTR", "MX", "SRV"].includes(r.type)) {
    data = data.toLowerCase().replace(/\.$/, "");
  }
  return [(r.name || "").toLowerCase(), r.type, data].join("|");
}

/** The keys of the existing records a list of changes touches. */
export function touchedKeys(changes) {
  const keys = {};
  for (const c of changes) {
    if (c.old) {
      keys[recordKey(c.old)] = c.kind;
    }
  }
  return keys;
}

/** The apply-changes lists for some changes. */
export function changeset(changes) {
  const remove = [];
  const add = [];
  for (const c of changes) {
    if (c.old) {
      remove.push(bare(c.old));
    }
    if (c.new) {
      add.push(c.new);
    }
  }
  return { remove, add };
}

/**
 * Split changes into groups that each fit one apply-changes. An edit stays
 * whole, so its removal and addition are always planned together.
 */
export function groups(changes, max = MAX_PER_LIST) {
  const out = [];
  let cur = [];
  let removes = 0;
  let adds = 0;
  for (const c of changes) {
    const r = c.old ? 1 : 0;
    const a = c.new ? 1 : 0;
    if (cur.length && (removes + r > max || adds + a > max)) {
      out.push(cur);
      cur = [];
      removes = 0;
      adds = 0;
    }
    cur.push(c);
    removes += r;
    adds += a;
  }
  if (cur.length) {
    out.push(cur);
  }
  return out;
}

/** A shell-style pattern (* and ?) matching a whole record name. */
export function nameMatcher(pattern) {
  const p = (pattern || "").trim().toLowerCase() || "*";
  const re = new RegExp(
    "^" +
      p
        .split("")
        .map((ch) =>
          ch === "*" ? ".*" : ch === "?" ? "." : ch.replace(/[.+^${}()|[\]\\]/g, "\\$&")
        )
        .join("") +
      "$"
  );
  return (name) => re.test((name || "").toLowerCase());
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * The edits a find and replace in record values makes.
 * opts: { find, replace, type ("" for any), name (pattern), matchCase }.
 * Records whose value does not change are left out.
 */
export function findReplace(records, opts) {
  if (!opts.find) {
    return [];
  }
  const re = new RegExp(escapeRegExp(opts.find), opts.matchCase ? "g" : "gi");
  const nameOk = nameMatcher(opts.name);
  const out = [];
  for (const r of records) {
    if (opts.type && r.type !== opts.type) {
      continue;
    }
    if (!nameOk(r.name)) {
      continue;
    }
    const data = r.data.replace(re, () => opts.replace || "");
    if (data !== r.data) {
      const next = { name: r.name, type: r.type, data };
      if (r.ttl) {
        next.ttl = r.ttl;
      }
      out.push({ kind: "edit", old: r, new: next });
    }
  }
  return out;
}

/** The edits that give records a new TTL; records that have it already are left out. */
export function setTtl(records, ttl) {
  return records
    .filter((r) => r.ttl !== ttl)
    .map((r) => ({
      kind: "edit",
      old: r,
      new: { name: r.name, type: r.type, data: r.data, ttl },
    }));
}

/**
 * Add changes to the pending list. A change to a record that already has a
 * pending change is skipped. Returns { pending, added, skipped }.
 */
export function stage(pending, changes) {
  const taken = touchedKeys(pending);
  const out = pending.slice();
  let added = 0;
  let skipped = 0;
  for (const c of changes) {
    if (c.old && taken[recordKey(c.old)]) {
      skipped++;
      continue;
    }
    if (c.old) {
      taken[recordKey(c.old)] = c.kind;
    }
    out.push(c);
    added++;
  }
  return { pending: out, added, skipped };
}
