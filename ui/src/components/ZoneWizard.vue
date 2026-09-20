<!--
  Copyright (C) 2026 dnshelper contributors
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <NsWizard
    size="default"
    :visible="isShown"
    :cancelLabel="core.$t('common.cancel')"
    :previousLabel="core.$t('common.previous')"
    :nextLabel="nextLabel"
    :isPreviousDisabled="isFirstStep || busy"
    :isNextDisabled="isNextDisabled"
    :isNextLoading="busy"
    :isLastStep="isLastStep"
    auto-hide-off
    @cancel="hide"
    @modal-hidden="hide"
    @previousStep="previousStep"
    @nextStep="nextStep"
  >
    <template slot="title">{{ $t("wizard.title") }}</template>
    <template slot="content">
      <cv-form @submit.prevent="nextStep">
        <!-- step 1: DNS host -->
        <template v-if="step == 'provider'">
          <div class="mg-bottom-md">{{ $t("wizard.provider_intro") }}</div>
          <div class="mg-bottom-md">
            <NsComboBox
              :key="comboKey"
              :marginBottomOnOpen="true"
              v-model="providerName"
              :options="providerOptions"
              :title="$t('wizard.provider')"
              :label="$t('wizard.provider_placeholder')"
              :invalid-message="$t(error.provider)"
              :disabled="busy"
              ref="provider"
            />
          </div>
          <template v-if="provider">
            <div class="mg-bottom-sm">
              <span class="label">{{ $t("wizard.record_types") }}</span>
              <cv-tag
                v-for="t in provider.types"
                :key="t"
                :label="t"
                kind="gray"
                class="mg-right-sm"
              />
            </div>
            <div v-if="provider.notes" class="mg-bottom-md note">
              {{ provider.notes }}
            </div>
            <NsToggle
              v-if="savedForProvider.length"
              v-model="useSaved"
              value="useSaved"
              :label="$t('wizard.use_saved_credential')"
              :disabled="busy"
              class="mg-bottom-md"
            >
              <template slot="text-left">{{ $t("common.no") }}</template>
              <template slot="text-right">{{ $t("common.yes") }}</template>
            </NsToggle>
            <NsComboBox
              :key="comboKey"
              :marginBottomOnOpen="true"
              v-if="useSaved && savedForProvider.length"
              v-model="credentialId"
              :options="savedOptions"
              :title="$t('wizard.saved_credential')"
              :label="$t('wizard.choose_credential')"
              :invalid-message="$t(error.credential)"
              :disabled="busy"
              ref="credential"
            />
          </template>
        </template>

        <!-- step 2: credentials -->
        <template v-else-if="step == 'credentials'">
          <NsInlineNotification
            kind="info"
            :title="$t('wizard.least_privilege_title')"
            :description="$t('wizard.least_privilege')"
            :showCloseButton="false"
          />
          <NsTextInput
            v-model.trim="credentialName"
            :label="$t('wizard.credential_name')"
            :helper-text="$t('wizard.credential_name_help')"
            :invalid-message="$t(error.credentialName)"
            :disabled="busy"
            ref="credentialName"
            class="mg-bottom-md"
          />
          <template v-for="f in provider.fields">
            <NsTextInput
              :key="f.name"
              v-model.trim="fields[f.name]"
              :type="f.secret ? 'password' : undefined"
              :label="
                f.label + (f.required ? '' : ' (' + $t('wizard.optional') + ')')
              "
              :invalid-message="$t(error['field_' + f.name])"
              :passwordHideLabel="$t('common.hide_password')"
              :passwordShowLabel="$t('common.show_password')"
              :disabled="busy"
              :ref="'field_' + f.name"
              class="mg-bottom-md"
            />
          </template>
        </template>

        <!-- step 3: the zone -->
        <template v-else-if="step == 'zone'">
          <div class="mg-bottom-md">
            <span v-if="providerZones.supported">{{
              $t("wizard.zone_intro_listed")
            }}</span>
            <span v-else>{{ $t("wizard.zone_intro_typed") }}</span>
          </div>
          <div v-if="providerZones.supported" class="mg-bottom-md">
            <NsComboBox
              :key="comboKey"
              :marginBottomOnOpen="true"
              v-model.trim="zone"
              :options="zoneOptions"
              :title="$t('wizard.zone')"
              :label="$t('wizard.zone_placeholder')"
              :acceptUserInput="true"
              :invalid-message="$t(error.zone)"
              :disabled="busy"
              ref="zone"
            />
          </div>
          <NsTextInput
            v-else
            v-model.trim="zone"
            :label="$t('wizard.zone')"
            placeholder="example.com"
            :invalid-message="$t(error.zone)"
            :disabled="busy"
            ref="zone"
            class="mg-bottom-md"
          />
          <NsInlineNotification
            v-if="error.validate"
            kind="error"
            :title="$t('wizard.cannot_validate')"
            :description="error.validate"
            :showCloseButton="false"
          />
          <div class="mg-bottom-sm">
            <NsButton
              kind="tertiary"
              size="small"
              :icon="Search20"
              :loading="discovering"
              :disabled="busy"
              @click="discover"
            >
              {{ $t("wizard.find_zones") }}
            </NsButton>
          </div>
          <NsInlineNotification
            v-if="error.discover"
            kind="error"
            :title="$t('wizard.cannot_discover')"
            :description="error.discover"
            :showCloseButton="false"
          />
          <template v-if="discovered">
            <div v-if="!suggestions.length" class="note">
              {{ $t("wizard.no_suggestions") }}
            </div>
            <template v-else>
              <div class="note mg-bottom-sm">
                {{ $t("wizard.suggestions_help") }}
              </div>
              <cv-tag
                v-for="c in suggestions"
                :key="c.zone"
                :label="c.zone"
                :kind="zone === c.zone ? 'blue' : 'gray'"
                class="mg-right-sm suggestion"
                :title="c.names.join(', ')"
                @click.native="chooseZone(c.zone)"
              />
            </template>
          </template>
        </template>

        <!-- step 4: review -->
        <template v-else-if="step == 'review'">
          <NsInlineNotification
            kind="success"
            :title="$t('wizard.validated_title', { zone })"
            :description="validatedDescription"
            :showCloseButton="false"
          />
          <cv-structured-list class="mg-bottom-md">
            <template slot="items">
              <cv-structured-list-item>
                <cv-structured-list-data>{{
                  $t("wizard.zone")
                }}</cv-structured-list-data>
                <cv-structured-list-data>{{ zone }}</cv-structured-list-data>
              </cv-structured-list-item>
              <cv-structured-list-item>
                <cv-structured-list-data>{{
                  $t("wizard.provider")
                }}</cv-structured-list-data>
                <cv-structured-list-data>{{
                  provider.label
                }}</cv-structured-list-data>
              </cv-structured-list-item>
              <cv-structured-list-item>
                <cv-structured-list-data>{{
                  $t("wizard.credential")
                }}</cv-structured-list-data>
                <cv-structured-list-data>{{
                  usedCredentialName
                }}</cv-structured-list-data>
              </cv-structured-list-item>
              <cv-structured-list-item>
                <cv-structured-list-data>{{
                  $t("wizard.capabilities")
                }}</cv-structured-list-data>
                <cv-structured-list-data>
                  <div v-for="c in capabilityRows" :key="c.key">
                    <span :class="c.ok ? 'ok' : 'missing'">{{
                      c.ok ? "✓" : "✗"
                    }}</span>
                    {{ $t("wizard.capability_" + c.key) }}
                  </div>
                </cv-structured-list-data>
              </cv-structured-list-item>
            </template>
          </cv-structured-list>
          <NsInlineNotification
            v-if="!validation.capabilities.set_records"
            kind="warning"
            :title="$t('wizard.read_only_title')"
            :description="$t('wizard.read_only')"
            :showCloseButton="false"
          />
          <div class="mg-bottom-sm">{{ $t("wizard.write_test_help") }}</div>
          <NsButton
            kind="tertiary"
            size="small"
            :icon="Checkmark20"
            :loading="testing"
            :disabled="busy || writeTest === 'passed'"
            @click="runWriteTest"
          >
            {{ $t("wizard.run_write_test") }}
          </NsButton>
          <span v-if="writeTest === 'passed'" class="ok mg-left-sm">{{
            $t("wizard.write_test_passed")
          }}</span>
          <NsInlineNotification
            v-if="error.writeTest"
            kind="error"
            :title="$t('wizard.write_test_failed')"
            :description="error.writeTest"
            :showCloseButton="false"
          />
          <NsInlineNotification
            v-if="error.save"
            kind="error"
            :title="$t('wizard.cannot_save')"
            :description="error.save"
            :showCloseButton="false"
          />
        </template>
      </cv-form>
    </template>
  </NsWizard>
</template>

<script>
import { mapState } from "vuex";
import { IconService, UtilService } from "@nethserver/ns8-ui-lib";
import DiscoverService from "../mixins/discover";

const STEPS = ["provider", "credentials", "zone", "review"];

export default {
  name: "ZoneWizard",
  mixins: [DiscoverService, IconService, UtilService],
  props: {
    isShown: { type: Boolean, default: false },
    providers: { type: Array, default: () => [] },
    credentials: { type: Array, default: () => [] },
    managedZones: { type: Array, default: () => [] },
  },
  data() {
    return {
      comboKey: 0,
      step: "provider",
      providerName: "",
      useSaved: false,
      credentialId: "",
      credentialName: "",
      fields: {},
      zone: "",
      providerZones: { supported: false, zones: [] },
      discovering: false,
      discovered: false,
      suggestions: [],
      validation: null,
      writeTest: "skipped",
      busy: false,
      testing: false,
      error: {
        provider: "",
        credential: "",
        credentialName: "",
        zone: "",
        validate: "",
        discover: "",
        writeTest: "",
        save: "",
      },
    };
  },
  computed: {
    ...mapState(["core"]),
    stepIndex() {
      return STEPS.indexOf(this.step);
    },
    isFirstStep() {
      return this.stepIndex === 0;
    },
    isLastStep() {
      return this.step === "review";
    },
    nextLabel() {
      return this.isLastStep
        ? this.$t("wizard.add_zone")
        : this.core.$t("common.next");
    },
    isNextDisabled() {
      return this.busy || (this.step === "provider" && !this.provider);
    },
    provider() {
      return this.providers.find((p) => p.name === this.providerName) || null;
    },
    providerOptions() {
      return this.providers.map((p) => ({
        name: p.name,
        label: p.label,
        value: p.name,
      }));
    },
    savedForProvider() {
      return this.credentials.filter((c) => c.provider === this.providerName);
    },
    savedOptions() {
      return this.savedForProvider.map((c) => ({
        name: c.id,
        label: c.name,
        value: c.id,
      }));
    },
    zoneOptions() {
      const managed = new Set(this.managedZones);
      return this.providerZones.zones
        .filter((z) => !managed.has(z))
        .map((z) => ({ name: z, label: z, value: z }));
    },
    usingSaved() {
      return this.useSaved && this.savedForProvider.length > 0;
    },
    usedCredentialName() {
      if (this.usingSaved) {
        const c = this.credentials.find((x) => x.id === this.credentialId);
        return c ? c.name : "";
      }
      return this.credentialName;
    },
    capabilityRows() {
      if (!this.validation) {
        return [];
      }
      const c = this.validation.capabilities;
      return [
        { key: "read", ok: c.get_records },
        { key: "append", ok: c.append_records },
        { key: "set", ok: c.set_records },
        { key: "delete", ok: c.delete_records },
        { key: "list_zones", ok: c.list_zones },
      ];
    },
    validatedDescription() {
      const method = this.validation ? this.validation.validation.method : "";
      return this.$t("wizard.validated_" + method);
    },
  },
  watch: {
    isShown(shown) {
      if (shown) {
        this.reset();
      }
    },
    providerName() {
      this.useSaved = this.savedForProvider.length > 0;
      this.credentialId = "";
      this.fields = {};
      if (this.provider) {
        for (const f of this.provider.fields) {
          this.$set(this.fields, f.name, f.default || "");
        }
        this.credentialName = this.suggestName();
      }
    },
  },
  methods: {
    reset() {
      // remount the combo boxes: they keep their filter text between uses
      this.comboKey++;
      this.step = "provider";
      this.providerName = "";
      this.useSaved = false;
      this.credentialId = "";
      this.credentialName = "";
      this.fields = {};
      this.zone = "";
      this.providerZones = { supported: false, zones: [] };
      this.discovering = false;
      this.discovered = false;
      this.suggestions = [];
      this.validation = null;
      this.writeTest = "skipped";
      this.busy = false;
      this.testing = false;
      this.clearErrors();
    },
    suggestName() {
      const taken = new Set(this.credentials.map((c) => c.name));
      let name = this.provider.label;
      for (let i = 2; taken.has(name); i++) {
        name = `${this.provider.label} ${i}`;
      }
      return name;
    },
    hide() {
      this.$emit("hide");
    },
    chooseZone(zone) {
      this.zone = zone;
      this.comboKey++; // value equals label here, so a fresh combo shows it
    },
    previousStep() {
      this.clearErrors();
      if (this.step === "zone" && this.usingSaved) {
        this.step = "provider"; // the credentials step is skipped
      } else {
        this.step = STEPS[this.stepIndex - 1];
      }
    },
    async nextStep() {
      this.clearErrors();
      if (this.busy) {
        return;
      }
      if (this.step === "provider") {
        await this.leaveProvider();
      } else if (this.step === "credentials") {
        await this.leaveCredentials();
      } else if (this.step === "zone") {
        await this.leaveZone();
      } else {
        await this.save();
      }
    },
    // the credential the wizard is working with, in the form the actions take
    credentialArgs() {
      return this.usingSaved
        ? { credential: this.credentialId }
        : { provider: this.providerName, fields: this.filledFields() };
    },
    filledFields() {
      const out = {};
      for (const [k, v] of Object.entries(this.fields)) {
        if (v !== "") {
          out[k] = v;
        }
      }
      return out;
    },
    async leaveProvider() {
      if (!this.provider) {
        this.error.provider = "wizard.required";
        return;
      }
      if (this.usingSaved) {
        if (!this.credentialId) {
          this.error.credential = "wizard.required";
          return;
        }
        if (await this.loadProviderZones()) {
          this.step = "zone";
        }
      } else {
        this.step = "credentials";
      }
    },
    async leaveCredentials() {
      if (!this.credentialName) {
        this.error.credentialName = "wizard.required";
        this.focusElement("credentialName");
        return;
      }
      for (const f of this.provider.fields) {
        if (f.required && !this.fields[f.name]) {
          this.$set(this.error, "field_" + f.name, "wizard.required");
          this.focusElement("field_" + f.name);
          return;
        }
      }
      // asking the DNS host for its zones is also the first test of the credentials
      if (await this.loadProviderZones()) {
        this.step = "zone";
      }
    },
    async loadProviderZones() {
      this.busy = true;
      try {
        this.providerZones = await this.callAction("list-provider-zones", {
          data: this.credentialArgs(),
        });
        return true;
      } catch (err) {
        const message = this.errorText(err);
        // a rejected credential belongs on the credentials step
        if (this.step === "credentials") {
          const first =
            this.provider.fields.find((f) => f.required) ||
            this.provider.fields[0];
          this.$set(this.error, "field_" + (first ? first.name : ""), message);
        } else {
          this.error.credential = message;
        }
        return false;
      } finally {
        this.busy = false;
      }
    },
    async discover() {
      this.discovering = true;
      this.error.discover = "";
      try {
        const managed = new Set(this.managedZones);
        this.suggestions = (await this.discoverZones()).filter(
          (c) => !c.managed && !managed.has(c.zone)
        );
        // when the DNS host lists its zones, only those it serves are useful
        if (this.providerZones.supported) {
          const served = new Set(this.providerZones.zones);
          this.suggestions = this.suggestions.filter((c) => served.has(c.zone));
        }
        this.discovered = true;
      } catch (err) {
        this.error.discover = this.errorText(err);
      }
      this.discovering = false;
    },
    async leaveZone() {
      const zone = this.zone.trim().toLowerCase().replace(/\.$/, "");
      if (!zone) {
        this.error.zone = "wizard.required";
        this.focusElement("zone");
        return;
      }
      if (this.managedZones.includes(zone)) {
        this.error.zone = "wizard.zone_already_managed";
        return;
      }
      this.zone = zone;
      this.busy = true;
      try {
        this.validation = await this.callAction("validate-zone", {
          data: { zone, ...this.credentialArgs() },
        });
        this.writeTest = "skipped";
        this.step = "review";
      } catch (err) {
        this.error.validate = this.errorText(err);
        this.error.zone = this.fieldError(err, "zone");
      } finally {
        this.busy = false;
      }
    },
    async runWriteTest() {
      this.testing = true;
      this.error.writeTest = "";
      try {
        const out = await this.callAction("validate-zone", {
          data: { zone: this.zone, ...this.credentialArgs(), write_test: true },
        });
        this.writeTest = out.validation.write_test;
      } catch (err) {
        this.error.writeTest = this.errorText(err);
      }
      this.testing = false;
    },
    async save() {
      this.busy = true;
      let createdId = "";
      try {
        let credentialId = this.credentialId;
        if (!this.usingSaved) {
          const out = await this.callAction("add-credential", {
            data: {
              name: this.credentialName,
              provider: this.providerName,
              fields: this.filledFields(),
            },
          });
          createdId = out.id;
          credentialId = out.id;
        }
        await this.callAction("add-zone", {
          data: { zone: this.zone, credential: credentialId },
        });
        this.$emit("added", this.zone);
        this.hide();
      } catch (err) {
        this.error.save = this.errorText(err);
        if (createdId) {
          // do not leave a credential behind that no zone uses
          try {
            await this.callAction("remove-credential", {
              data: { id: createdId },
            });
          } catch (e) {
            console.warn("cannot remove the unused credential", e);
          }
        }
      } finally {
        this.busy = false;
      }
    },
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";

.label {
  margin-right: $spacing-03;
  color: $text-02;
}

.note {
  color: $text-02;
}

.ok {
  color: $support-02;
}

.missing {
  color: $text-03;
}

.suggestion {
  cursor: pointer;
}
</style>
