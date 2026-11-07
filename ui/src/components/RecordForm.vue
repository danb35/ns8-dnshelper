<!--
  Copyright (C) 2026 dnshelper contributors
  SPDX-License-Identifier: GPL-3.0-or-later

  The fields of one record: name, type, a form of its own for the value of
  each common type, and the TTL. Used by the Add and Edit dialogs of the
  Records page. The parent calls build() to get the record, or null when a
  field is wrong (the field then shows why).
-->
<template>
  <div>
    <NsTextInput
      v-model.trim="name"
      :label="$t('records.col_name')"
      :helper-text="$t('records.name_help')"
      placeholder="www"
      :invalid-message="$t(errors.name)"
      :disabled="disabled"
      ref="name"
      class="mg-bottom-md"
    />
    <cv-select
      v-model="type"
      :label="$t('records.col_type')"
      :disabled="disabled"
      class="mg-bottom-md"
    >
      <cv-select-option v-for="t in typeChoices" :key="t" :value="t">{{
        t
      }}</cv-select-option>
    </cv-select>

    <!-- the value, per type -->
    <template v-if="type === 'A' || type === 'AAAA'">
      <NsTextInput
        v-model.trim="fields.address"
        :label="$t('record_form.address')"
        :placeholder="type === 'A' ? '192.0.2.10' : '2001:db8::10'"
        :invalid-message="$t(errors.address)"
        :disabled="disabled"
        ref="address"
        class="mg-bottom-md"
      />
    </template>
    <template v-else-if="isHostType">
      <NsTextInput
        v-model.trim="fields.target"
        :label="$t('record_form.target_' + type.toLowerCase())"
        :helper-text="
          type === 'NS'
            ? $t('record_form.ns_help')
            : $t('record_form.host_help')
        "
        placeholder="host.example.net"
        :invalid-message="$t(errors.target)"
        :disabled="disabled"
        ref="target"
        class="mg-bottom-md"
      />
    </template>
    <template v-else-if="type === 'MX'">
      <div class="field-row">
        <NsTextInput
          v-model.trim="fields.preference"
          type="number"
          :label="$t('record_form.preference')"
          :helper-text="$t('record_form.preference_help')"
          placeholder="10"
          :invalid-message="$t(errors.preference)"
          :disabled="disabled"
          ref="preference"
          class="mg-bottom-md small-field"
        />
        <NsTextInput
          v-model.trim="fields.exchange"
          :label="$t('record_form.exchange')"
          :helper-text="$t('record_form.exchange_help')"
          placeholder="mail.example.net"
          :invalid-message="$t(errors.exchange)"
          :disabled="disabled"
          ref="exchange"
          class="mg-bottom-md wide-field"
        />
      </div>
    </template>
    <template v-else-if="type === 'SRV'">
      <div class="field-row">
        <NsTextInput
          v-for="f in ['priority', 'weight', 'port']"
          :key="f"
          v-model.trim="fields[f]"
          type="number"
          :label="$t('record_form.' + f)"
          :placeholder="f === 'port' ? '443' : '0'"
          :invalid-message="$t(errors[f])"
          :disabled="disabled"
          :ref="f"
          class="mg-bottom-md small-field"
        />
      </div>
      <NsTextInput
        v-model.trim="fields.target"
        :label="$t('record_form.target_srv')"
        :helper-text="$t('record_form.srv_target_help')"
        placeholder="host.example.net"
        :invalid-message="$t(errors.target)"
        :disabled="disabled"
        ref="target"
        class="mg-bottom-md"
      />
      <p class="record-hint mg-bottom-md">
        {{ $t("record_form.srv_name_hint") }}
      </p>
    </template>
    <template v-else-if="type === 'CAA'">
      <div class="field-row">
        <NsTextInput
          v-model.trim="fields.flags"
          type="number"
          :label="$t('record_form.flags')"
          :helper-text="$t('record_form.flags_help')"
          :invalid-message="$t(errors.flags)"
          :disabled="disabled"
          ref="flags"
          class="mg-bottom-md small-field"
        />
        <cv-select
          v-model="fields.tag"
          :label="$t('record_form.tag')"
          :invalid-message="$t(errors.tag)"
          :disabled="disabled"
          class="mg-bottom-md small-field"
        >
          <cv-select-option v-for="t in caaTags" :key="t" :value="t">{{
            t
          }}</cv-select-option>
        </cv-select>
      </div>
      <NsTextInput
        v-model.trim="fields.value"
        :label="$t('record_form.caa_value')"
        :helper-text="$t('record_form.caa_value_help')"
        placeholder="letsencrypt.org"
        :invalid-message="$t(errors.value)"
        :disabled="disabled"
        ref="value"
        class="mg-bottom-md"
      />
    </template>
    <template v-else-if="type === 'TXT'">
      <cv-text-area
        v-model="fields.text"
        :label="$t('record_form.text')"
        :helper-text="txtHelp"
        :invalid-message="$t(errors.text)"
        :disabled="disabled"
        :rows="4"
        ref="text"
        class="mg-bottom-md txt-area"
      />
      <NsInlineNotification
        v-if="otherSpf"
        kind="warning"
        :title="$t('record_form.second_spf_title')"
        :description="$t('record_form.second_spf', { name: name || '@' })"
        :showCloseButton="false"
      />
      <p v-else-if="txtKind" class="record-hint mg-bottom-md">
        {{ $t("record_form.hint_" + txtKind) }}
      </p>
    </template>
    <template v-else>
      <NsTextInput
        v-model.trim="fields.data"
        :label="$t('records.col_data')"
        :helper-text="$t('record_form.generic_help')"
        :invalid-message="$t(errors.data)"
        :disabled="disabled"
        ref="data"
        class="mg-bottom-md"
      />
    </template>

    <NsTextInput
      v-model.trim="ttl"
      :label="$t('records.col_ttl') + ' (' + $t('wizard.optional') + ')'"
      :helper-text="$t('records.ttl_help')"
      placeholder="3600"
      :invalid-message="$t(errors.ttl)"
      :disabled="disabled"
      ref="ttl"
      class="mg-bottom-md"
    />
  </div>
</template>

<script>
import { UtilService } from "@nethserver/ns8-ui-lib";
import {
  CAA_TAGS,
  byteLength,
  compose,
  emptyFields,
  fieldsOf,
  joinLines,
  parse,
  validate,
} from "../lib/records";

const HOST_TYPES = ["CNAME", "NS", "PTR"];

export default {
  name: "RecordForm",
  mixins: [UtilService],
  props: {
    // the record types the zone's DNS host handles, in display order
    types: { type: Array, default: () => [] },
    // the zone's records, to warn about a second SPF record
    existing: { type: Array, default: () => [] },
    // the record being edited; null to add one
    initial: { type: Object, default: null },
    disabled: { type: Boolean, default: false },
  },
  data() {
    return {
      name: "",
      type: "A",
      ttl: "",
      fields: emptyFields("A"),
      errors: { name: "", ttl: "" },
    };
  },
  computed: {
    // the record's own type stays selectable even if the list lacks it
    typeChoices() {
      const t = this.types.slice();
      if (this.initial && !t.includes(this.initial.type)) {
        t.push(this.initial.type);
      }
      return t;
    },
    draft() {
      let data = "";
      try {
        data = compose(this.type, this.fields);
      } catch (e) {
        data = "";
      }
      return { name: (this.name || "").trim().toLowerCase(), type: this.type, data };
    },
    isHostType() {
      return HOST_TYPES.includes(this.type);
    },
    // the usual tags, and the record's own if it is another one
    caaTags() {
      const tag = (this.fields.tag || "").trim();
      return tag && !CAA_TAGS.includes(tag) ? CAA_TAGS.concat([tag]) : CAA_TAGS;
    },
    txtValue() {
      return joinLines(this.fields.text);
    },
    txtKind() {
      const t = this.txtValue.toLowerCase();
      if (t.startsWith("v=spf1")) {
        return "spf";
      }
      if (t.startsWith("v=dkim1")) {
        return "dkim";
      }
      if (t.startsWith("v=dmarc1")) {
        return "dmarc";
      }
      return "";
    },
    txtHelp() {
      const bytes = byteLength(this.txtValue);
      const parts = [this.$t("record_form.txt_bytes", { bytes })];
      if (bytes > 255) {
        parts.push(this.$t("record_form.txt_long"));
      }
      if (/[\r\n]/.test(this.fields.text || "")) {
        parts.push(this.$t("record_form.txt_lines_joined"));
      }
      return parts.join(" ");
    },
    // another SPF record at the same name, besides the one being edited
    otherSpf() {
      if (this.txtKind !== "spf") {
        return false;
      }
      const name = (this.name || "@").toLowerCase();
      return this.existing.some(
        (r) =>
          r.type === "TXT" &&
          r.name.toLowerCase() === name &&
          r.data.toLowerCase().startsWith("v=spf1") &&
          !(
            this.initial &&
            r.name === this.initial.name &&
            r.type === this.initial.type &&
            r.data === this.initial.data
          )
      );
    },
  },
  watch: {
    // an error about the name (NS at @) may no longer hold
    name() {
      this.errors.name = "";
    },
    // the record as it stands, for the page (linked PTR records)
    draft: {
      handler(d) {
        this.$emit("draft", d);
      },
      immediate: true,
    },
    type(next, prev) {
      this.errors.name = "";
      // keep a host name across CNAME / NS / PTR; otherwise start over,
      // unless this is the type the record had
      if (HOST_TYPES.includes(prev) && HOST_TYPES.includes(next)) {
        return;
      }
      if (this.initial && next === this.initial.type) {
        this.fields = parse(next, this.initial.data);
      } else {
        this.fields = emptyFields(next);
      }
      this.clearFieldErrors();
    },
  },
  created() {
    this.reset();
  },
  methods: {
    /** Start from the record being edited, or from an empty form. */
    reset() {
      const r = this.initial;
      const type = r
        ? r.type
        : this.types.includes("A")
        ? "A"
        : this.types[0] || "A";
      this.name = r ? r.name : "";
      this.ttl = r && r.ttl ? String(r.ttl) : "";
      // the type watcher, if the type changes, sets the same fields again
      this.type = type;
      this.fields = r ? parse(r.type, r.data) : emptyFields(type);
      this.clearFieldErrors();
      this.errors.name = "";
      this.errors.ttl = "";
    },
    clearFieldErrors() {
      const e = { name: this.errors.name || "", ttl: this.errors.ttl || "" };
      for (const f of fieldsOf(this.type)) {
        e[f] = "";
      }
      this.errors = e;
    },
    /** The record, or null after marking the fields that are wrong. */
    build() {
      this.errors.name = "";
      this.errors.ttl = "";
      this.clearFieldErrors();
      const name = this.name.trim().toLowerCase() || "";
      if (!name || !/^[a-z0-9@_.*-]+$/.test(name)) {
        this.errors.name = "records.invalid_name";
        this.focusElement("name");
        return null;
      }
      // the backend refuses this too (forbidden); say so before saving
      if (this.type === "NS" && name === "@") {
        this.errors.name = "record_form.apex_ns";
        this.focusElement("name");
        return null;
      }
      const wrong = validate(this.type, this.fields);
      const first = fieldsOf(this.type).find((f) => wrong[f]);
      if (first) {
        this.errors = { ...this.errors, ...wrong };
        if (first !== "tag") {
          this.focusElement(first);
        }
        return null;
      }
      const record = {
        name,
        type: this.type,
        data: compose(this.type, this.fields),
      };
      if (this.ttl !== "" && this.ttl !== null) {
        const ttl = Number(this.ttl);
        if (!Number.isInteger(ttl) || ttl < 1 || ttl > 2147483647) {
          this.errors.ttl = "records.invalid_ttl";
          this.focusElement("ttl");
          return null;
        }
        record.ttl = ttl;
      }
      return record;
    },
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";

.field-row {
  display: flex;
  flex-wrap: wrap;
  gap: $spacing-05;
}

.small-field {
  flex: 0 1 9rem;
}

.wide-field {
  flex: 1 1 16rem;
}

.record-hint {
  font-size: 0.875rem;
  max-width: 40rem;
}

.txt-area ::v-deep textarea {
  font-family: "IBM Plex Mono", monospace;
  font-size: 0.875rem;
}
</style>
