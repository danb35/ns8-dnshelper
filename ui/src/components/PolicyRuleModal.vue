<!--
  Copyright (C) 2026 dnshelper contributors
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <NsModal
    size="default"
    :visible="isShown"
    :primary-button-disabled="loading"
    :isLoading="loading"
    @modal-hidden="$emit('hide')"
    @primary-click="save"
  >
    <template slot="title">{{
      isEditing ? $t("access.edit_rule") : $t("access.add_rule")
    }}</template>
    <template slot="content">
      <cv-form @submit.prevent="save">
        <div class="mg-bottom-sm">{{ $t("access.presets") }}</div>
        <div class="mg-bottom-md">
          <NsButton
            v-for="p in presets"
            :key="p.key"
            kind="tertiary"
            size="small"
            :disabled="loading"
            class="mg-right-sm"
            @click="applyPreset(p)"
          >
            {{ $t("access.preset_" + p.key) }}
          </NsButton>
        </div>
        <div class="mg-bottom-md">
          <NsComboBox
            :key="comboKey"
            :marginBottomOnOpen="true"
            v-model.trim="caller"
            :options="callerOptions"
            :title="$t('access.col_caller')"
            :label="$t('access.caller_placeholder')"
            :helper-text="$t('access.caller_help')"
            :acceptUserInput="true"
            :invalid-message="$t(error.caller)"
            :disabled="loading"
            ref="caller"
          />
        </div>
        <div class="mg-bottom-md">
          <NsComboBox
            :key="comboKey"
            :marginBottomOnOpen="true"
            v-model="zone"
            :options="zoneOptions"
            :title="$t('access.col_zone')"
            :label="$t('access.zone_placeholder')"
            :invalid-message="$t(error.zone)"
            :disabled="loading"
            ref="zone"
          />
        </div>
        <div class="mg-bottom-md">
          <NsComboBox
            :key="comboKey"
            :marginBottomOnOpen="true"
            v-model="access"
            :options="accessOptions"
            :title="$t('access.col_access')"
            :label="$t('access.access_placeholder')"
            :invalid-message="$t(error.access)"
            :disabled="loading"
            ref="access"
          />
        </div>
        <NsTextInput
          v-model.trim="names"
          :label="$t('access.col_names')"
          :helper-text="$t('access.names_help')"
          placeholder="@, *._domainkey"
          :invalid-message="$t(error.names)"
          :disabled="loading"
          ref="names"
          class="mg-bottom-md"
        />
        <NsTextInput
          v-model.trim="types"
          :label="$t('access.col_types')"
          :helper-text="$t('access.types_help')"
          placeholder="TXT, MX"
          :invalid-message="$t(error.types)"
          :disabled="loading"
          ref="types"
          class="mg-bottom-md"
        />
        <NsInlineNotification
          v-if="error.save"
          kind="error"
          :title="$t('action.set-policy')"
          :description="error.save"
          :showCloseButton="false"
        />
      </cv-form>
    </template>
    <template slot="secondary-button">{{ core.$t("common.cancel") }}</template>
    <template slot="primary-button">{{ $t("common.save") }}</template>
  </NsModal>
</template>

<script>
import { mapState } from "vuex";
import { UtilService } from "@nethserver/ns8-ui-lib";

const PRESETS = [
  {
    key: "mail",
    names:
      "@, *._domainkey, _dmarc, autoconfig, autodiscover, _autodiscover._tcp",
    types: "TXT, MX, CNAME, SRV",
    access: "write",
  },
  {
    key: "acme",
    names: "_acme-challenge, _acme-challenge.*",
    types: "TXT",
    access: "write",
  },
];

export default {
  name: "PolicyRuleModal",
  mixins: [UtilService],
  props: {
    isShown: { type: Boolean, default: false },
    isEditing: { type: Boolean, default: false },
    rule: { type: Object, default: null },
    modules: { type: Array, default: () => [] },
    zones: { type: Array, default: () => [] },
    loading: { type: Boolean, default: false },
    saveError: { type: String, default: "" },
  },
  data() {
    return {
      presets: PRESETS,
      comboKey: 0,
      extraCaller: "",
      caller: "",
      zone: "",
      access: "write",
      names: "*",
      types: "*",
      error: {
        caller: "",
        zone: "",
        access: "",
        names: "",
        types: "",
        save: "",
      },
    };
  },
  computed: {
    ...mapState(["core"]),
    callerOptions() {
      const options = this.modules.map((m) => ({
        name: "module/" + m.id,
        label: m.name ? `${m.name} (module/${m.id})` : "module/" + m.id,
        value: "module/" + m.id,
      }));
      // a pattern such as module/mail* is not an installed module, but it
      // must be in the list for the combo box to display it
      if (
        this.extraCaller &&
        !options.find((o) => o.value === this.extraCaller)
      ) {
        options.push({
          name: this.extraCaller,
          label: this.extraCaller,
          value: this.extraCaller,
        });
      }
      return options;
    },
    zoneOptions() {
      return [
        { name: "*", label: this.$t("access.all_zones"), value: "*" },
      ].concat(this.zones.map((z) => ({ name: z, label: z, value: z })));
    },
    accessOptions() {
      return ["write", "read"].map((a) => ({
        name: a,
        label: this.$t("access.access_" + a),
        value: a,
      }));
    },
  },
  watch: {
    isShown(shown) {
      if (!shown) {
        return;
      }
      this.clearErrors();
      const rule = this.rule;
      this.names = rule ? rule.names.join(", ") : "*";
      this.types = rule ? rule.types.join(", ") : "*";
      // NsComboBox shows a label only for a value it can find in its current,
      // filtered list, and keeps its filter text between uses: remount the
      // combo boxes empty, then set their values
      this.caller = "";
      this.zone = "";
      this.access = "";
      this.extraCaller = rule ? rule.caller : "";
      this.comboKey++;
      this.$nextTick(() => {
        this.caller = rule ? rule.caller : "";
        this.zone = rule ? rule.zone : "";
        this.access = rule ? rule.access : "write";
      });
    },
    saveError(text) {
      this.error.save = text;
    },
  },
  methods: {
    applyPreset(p) {
      this.names = p.names;
      this.types = p.types;
      this.access = p.access;
    },
    list(text) {
      return text
        .split(/[\s,]+/)
        .map((s) => s.trim())
        .filter((s) => s);
    },
    save() {
      this.clearErrors();
      const caller = this.caller.trim().toLowerCase();
      if (!/^module\/[a-z0-9_*?-]+$/.test(caller)) {
        this.error.caller = "access.invalid_caller";
        this.focusElement("caller");
        return;
      }
      if (!this.zone) {
        this.error.zone = "access.required";
        return;
      }
      if (!this.access) {
        this.error.access = "access.required";
        return;
      }
      const names = this.list(this.names.toLowerCase());
      if (!names.length || !names.every((n) => /^[a-z0-9@_.*?-]+$/.test(n))) {
        this.error.names = "access.invalid_names";
        this.focusElement("names");
        return;
      }
      const types = this.list(this.types.toUpperCase());
      if (!types.length || !types.every((t) => /^([A-Z0-9]+|\*)$/.test(t))) {
        this.error.types = "access.invalid_types";
        this.focusElement("types");
        return;
      }
      this.$emit("save", {
        caller,
        zone: this.zone,
        access: this.access,
        names,
        types,
      });
    },
  },
};
</script>
