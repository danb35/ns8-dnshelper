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
        <div class="mg-bottom-md presets">
          <NsButton
            v-for="p in presets"
            :key="p.key"
            kind="tertiary"
            size="small"
            :disabled="loading"
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
        <fieldset class="mg-bottom-md zones">
          <legend class="bx--label">{{ $t("access.col_zones") }}</legend>
          <NsCheckbox
            v-model="allZones"
            value="*"
            :label="$t('access.all_zones')"
            :disabled="loading"
          />
          <div class="zones-list">
            <NsCheckbox
              v-for="z in zoneChoices"
              :key="z"
              v-model="selectedZones"
              :value="z"
              :label="z"
              :disabled="loading || allZones"
            />
          </div>
          <div v-if="!error.zone" class="bx--form__helper-text">
            {{ $t("access.zones_help") }}
          </div>
          <div v-else class="bx--form-requirement zones-error">
            {{ $t(error.zone) }}
          </div>
        </fieldset>
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
    // ns8-automx: the autoconfig/autodiscover CNAMEs and the autodiscover SRV,
    // at the apex of a zone or for a mail domain below it
    key: "automx",
    names:
      "autoconfig, autoconfig.*, autodiscover, autodiscover.*, _autodiscover._tcp, _autodiscover._tcp.*",
    types: "CNAME, SRV",
    access: "write",
  },
  {
    key: "acme",
    names: "_acme-challenge, _acme-challenge.*",
    types: "TXT",
    access: "write",
  },
  {
    // a web server or a service on its own host name (SOGo, Grafana, ...) that
    // points a name of its choice at the host's FQDN
    key: "web",
    names: "*",
    types: "CNAME",
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
      allZones: false,
      selectedZones: [],
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
    // the managed zones, plus any zone the rule names that is no longer managed:
    // it stays visible, and so can be unticked, instead of being dropped silently
    zoneChoices() {
      const extra = (this.rule ? this.rule.zones : []).filter(
        (z) => z !== "*" && !this.zones.includes(z)
      );
      return this.zones.concat(extra);
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
      this.access = "";
      this.allZones = rule ? rule.zones.includes("*") : false;
      this.selectedZones = rule ? rule.zones.filter((z) => z !== "*") : [];
      this.extraCaller = rule ? rule.caller : "";
      this.comboKey++;
      this.$nextTick(() => {
        this.caller = rule ? rule.caller : "";
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
      if (!this.allZones && !this.selectedZones.length) {
        this.error.zone = "access.zones_required";
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
        zones: this.allZones ? ["*"] : this.selectedZones.slice(),
        access: this.access,
        names,
        types,
      });
    },
  },
};
</script>

<style scoped lang="scss">
// the preset buttons wrap onto more rows as presets are added: keep the same
// space between rows as between buttons
.presets {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.zones {
  border: 0;
  padding: 0;
  margin-left: 0;
  margin-right: 0;
}

// a long list of zones scrolls inside the dialog instead of stretching it
.zones-list {
  max-height: 11rem;
  overflow-y: auto;
}

.zones-error {
  display: block;
  max-height: none;
  margin-top: 0.25rem;
}
</style>
