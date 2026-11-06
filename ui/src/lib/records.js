//
// Copyright (C) 2026 dnshelper contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Record values as form fields, per type: parse() splits a value in
// zone-file syntax (as get-records returns it) into fields, compose() builds
// the value back, validate() checks the fields. Types without a form of
// their own use one free "data" field. See DESIGN.md, Records editor: Editing.

// The fields of each type with a form, in display order.
export const FIELDS = {
  A: ["address"],
  AAAA: ["address"],
  CNAME: ["target"],
  NS: ["target"],
  PTR: ["target"],
  MX: ["preference", "exchange"],
  SRV: ["priority", "weight", "port", "target"],
  CAA: ["flags", "tag", "value"],
  TXT: ["text"],
};

export const CAA_TAGS = ["issue", "issuewild", "iodef"];

export function fieldsOf(type) {
  return FIELDS[type] || ["data"];
}

export function emptyFields(type) {
  const out = {};
  for (const f of fieldsOf(type)) {
    out[f] = "";
  }
  if (type === "CAA") {
    out.flags = "0";
    out.tag = "issue";
  }
  return out;
}

function unquote(s) {
  s = s.trim();
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) {
    return s.slice(1, -1).replace(/\\"/g, '"');
  }
  return s;
}

/** Split a value of the given type into its form fields. */
export function parse(type, data) {
  data = (data || "").trim();
  const f = data.split(/\s+/);
  switch (type) {
    case "A":
    case "AAAA":
      return { address: data };
    case "CNAME":
    case "NS":
    case "PTR":
      return { target: data };
    case "MX":
      if (f.length === 2) {
        return { preference: f[0], exchange: f[1] };
      }
      break;
    case "SRV":
      if (f.length === 4) {
        return { priority: f[0], weight: f[1], port: f[2], target: f[3] };
      }
      break;
    case "CAA": {
      const m = data.match(/^(\d+)\s+(\S+)\s+([\s\S]*)$/);
      if (m) {
        return { flags: m[1], tag: m[2], value: unquote(m[3]) };
      }
      break;
    }
    case "TXT":
      return { text: data };
    default:
      return { data };
  }
  // a value that does not fit the form: keep it as it is in the main field
  const out = emptyFields(type);
  out[fieldsOf(type)[fieldsOf(type).length - 1]] = data;
  return out;
}

// A host name as a target: made absolute when it has a dot, so that it is
// not read relative to the zone. "." (the null MX / "no service" target) and
// single labels are left alone; the helper decides about those.
function host(s) {
  s = (s || "").trim();
  if (s === "." || s.endsWith(".") || !s.includes(".")) {
    return s;
  }
  return s + ".";
}

/** Build the value in zone-file syntax from the form fields. */
export function compose(type, v) {
  switch (type) {
    case "A":
    case "AAAA":
      return v.address.trim();
    case "CNAME":
    case "NS":
    case "PTR":
      return host(v.target);
    case "MX":
      return `${v.preference.trim()} ${host(v.exchange)}`;
    case "SRV":
      return `${v.priority.trim()} ${v.weight.trim()} ${v.port.trim()} ${host(
        v.target
      )}`;
    case "CAA":
      return `${v.flags.trim()} ${v.tag.trim()} "${v.value.trim()}"`;
    case "TXT":
      return joinLines(v.text);
    default:
      return v.data.trim();
  }
}

/** A TXT value pasted over several lines (a DKIM key) is one value. */
export function joinLines(text) {
  return (text || "").replace(/\s*[\r\n]+\s*/g, "").trim();
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const LABEL = "[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?";
const HOST = new RegExp(`^(\\*\\.)?${LABEL}(\\.${LABEL})*\\.?$`);

function isIPv6(s) {
  if (!/^[0-9A-Fa-f:.]+$/.test(s) || !s.includes(":") || s.includes(":::")) {
    return false;
  }
  // a single colon may not start or end the address
  if (/^:[^:]/.test(s) || /[^:]:$/.test(s)) {
    return false;
  }
  const double = s.split("::").length - 1;
  if (double > 1) {
    return false;
  }
  const groups = s.split(":").filter((g) => g !== "");
  const last = groups[groups.length - 1] || "";
  const v4 = last.includes(".");
  if (v4 && !IPV4.test(last)) {
    return false;
  }
  const n = groups.length + (v4 ? 1 : 0);
  if (groups.some((g) => !g.includes(".") && !/^[0-9A-Fa-f]{1,4}$/.test(g))) {
    return false;
  }
  return double ? n < 8 : n === 8;
}

function isHost(s, allowRoot) {
  s = (s || "").trim();
  if (s === ".") {
    return allowRoot;
  }
  return s.length > 0 && s.length <= 254 && HOST.test(s);
}

function inRange(s, min, max) {
  s = (s || "").trim();
  if (!/^\d+$/.test(s)) {
    return false;
  }
  const n = Number(s);
  return n >= min && n <= max;
}

/**
 * Check the form fields. Returns { field: translation key } for the fields
 * that are wrong; empty when the value is usable.
 */
export function validate(type, v) {
  const err = {};
  const need = (field, ok, key) => {
    if (!(v[field] || "").trim()) {
      err[field] = "records.required";
    } else if (!ok) {
      err[field] = key;
    }
  };
  switch (type) {
    case "A":
      need("address", IPV4.test(v.address.trim()), "record_form.invalid_ipv4");
      break;
    case "AAAA":
      need("address", isIPv6(v.address.trim()), "record_form.invalid_ipv6");
      break;
    case "CNAME":
    case "NS":
    case "PTR":
      need("target", isHost(v.target, false), "record_form.invalid_host");
      break;
    case "MX":
      need("preference", inRange(v.preference, 0, 65535), "record_form.invalid_16bit");
      need("exchange", isHost(v.exchange, true), "record_form.invalid_host");
      break;
    case "SRV":
      need("priority", inRange(v.priority, 0, 65535), "record_form.invalid_16bit");
      need("weight", inRange(v.weight, 0, 65535), "record_form.invalid_16bit");
      need("port", inRange(v.port, 0, 65535), "record_form.invalid_16bit");
      need("target", isHost(v.target, true), "record_form.invalid_host");
      break;
    case "CAA":
      need("flags", inRange(v.flags, 0, 255), "record_form.invalid_flags");
      need("tag", /^[A-Za-z0-9]+$/.test(v.tag.trim()), "record_form.invalid_tag");
      need("value", !v.value.includes('"'), "record_form.invalid_caa_value");
      break;
    case "TXT": {
      const t = joinLines(v.text);
      if (!t) {
        err.text = "records.required";
      } else if (t.length >= 2 && t.startsWith('"') && t.endsWith('"')) {
        err.text = "record_form.txt_quoted";
      }
      break;
    }
    default:
      need("data", true, "");
  }
  return err;
}

/** Bytes of a TXT value (DNS limits count bytes, not characters). */
export function byteLength(s) {
  return new TextEncoder().encode(s || "").length;
}
