//
// Copyright (C) 2026 dnshelper contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Reverse DNS for the Records page: the PTR name of an address, the managed
// reverse zone it falls in, and the host name it should point to. See
// DESIGN.md, Records editor: Linked PTR records.

/** The eight 16-bit groups of an IPv6 address, or null. */
export function expandIPv6(address) {
  let s = (address || "").trim().toLowerCase();
  let tail = [];
  // an IPv4 tail (::ffff:192.0.2.1) is two groups
  const v4 = s.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    const o = v4[2].split(".").map(Number);
    if (o.some((x) => x > 255)) {
      return null;
    }
    tail = [
      ((o[0] << 8) | o[1]).toString(16),
      ((o[2] << 8) | o[3]).toString(16),
    ];
    s = v4[1].endsWith("::") ? v4[1] : v4[1].slice(0, -1);
  }
  const halves = s.split("::");
  if (halves.length > 2) {
    return null;
  }
  const part = (h) => (h ? h.split(":") : []);
  const head = part(halves[0]);
  const rest = halves.length === 2 ? part(halves[1]) : [];
  const given = head.length + rest.length + tail.length;
  if (halves.length === 1 ? given !== 8 : given > 7) {
    return null;
  }
  const groups = head
    .concat(Array(8 - given).fill("0"))
    .concat(rest)
    .concat(tail);
  if (groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) {
    return null;
  }
  return groups.map((g) => g.padStart(4, "0"));
}

/** The PTR owner name of an address, without final dot, or "". */
export function reverseName(type, address) {
  const a = (address || "").trim();
  if (type === "A") {
    const o = a.split(".");
    if (
      o.length !== 4 ||
      o.some((x) => !/^\d{1,3}$/.test(x) || Number(x) > 255)
    ) {
      return "";
    }
    return o.map(Number).reverse().join(".") + ".in-addr.arpa";
  }
  if (type === "AAAA") {
    const groups = expandIPv6(a);
    if (!groups) {
      return "";
    }
    return groups.join("").split("").reverse().join(".") + ".ip6.arpa";
  }
  return "";
}

/** The longest of zones that contains name, or "". */
export function zoneOf(name, zones) {
  let best = "";
  for (const z of zones) {
    if ((name === z || name.endsWith("." + z)) && z.length > best.length) {
      best = z;
    }
  }
  return best;
}

/** name relative to zone, "@" for the apex. */
export function relativeTo(name, zone) {
  return name === zone ? "@" : name.slice(0, -(zone.length + 1));
}

/** The absolute host name a record of zone stands for, with final dot. */
export function hostOf(name, zone) {
  return (name === "@" ? zone : `${name}.${zone}`) + ".";
}

/** Whether a PTR value points at host (compared without case or final dot). */
export function pointsTo(data, host) {
  const n = (s) => (s || "").trim().toLowerCase().replace(/\.$/, "");
  return n(data) === n(host);
}

/**
 * Where the PTR of an address record lives: { zone, name, host } or null
 * when no managed reverse zone holds it (or the name is a wildcard).
 * reverseZones: managed zone names that can hold PTR records.
 */
export function ptrTarget(record, zone, reverseZones) {
  if (!record || (record.type !== "A" && record.type !== "AAAA")) {
    return null;
  }
  if ((record.name || "").includes("*")) {
    return null;
  }
  const rev = reverseName(record.type, record.data);
  const rz = rev ? zoneOf(rev, reverseZones) : "";
  if (!rz) {
    return null;
  }
  return {
    zone: rz,
    name: relativeTo(rev, rz),
    host: hostOf(record.name, zone),
  };
}
