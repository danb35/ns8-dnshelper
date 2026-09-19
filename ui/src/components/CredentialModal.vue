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
      $t("credentials.edit_title", { name: credential ? credential.name : "" })
    }}</template>
    <template slot="content">
      <cv-form @submit.prevent="save">
        <NsTextInput
          v-model.trim="name"
          :label="$t('wizard.credential_name')"
          :invalid-message="$t(error.name)"
          :disabled="loading"
          ref="name"
          class="mg-bottom-md"
        />
        <template v-if="provider">
          <template v-for="f in provider.fields">
            <NsTextInput
              :key="f.name"
              v-model.trim="fields[f.name]"
              :type="f.secret ? 'password' : undefined"
              :label="f.label"
              :placeholder="
                f.secret && isSet(f.name)
                  ? $t('credentials.secret_unchanged')
                  : ''
              "
              :helper-text="
                f.secret && isSet(f.name)
                  ? $t('credentials.secret_help')
                  : undefined
              "
              :invalid-message="$t(error['field_' + f.name])"
              :passwordHideLabel="$t('common.hide_password')"
              :passwordShowLabel="$t('common.show_password')"
              :disabled="loading"
              :ref="'field_' + f.name"
              class="mg-bottom-md"
            />
          </template>
        </template>
        <NsInlineNotification
          v-if="error.save"
          kind="error"
          :title="$t('action.update-credential')"
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
import DnsHelperService from "../mixins/dnshelper";

export default {
  name: "CredentialModal",
  mixins: [DnsHelperService, UtilService],
  props: {
    isShown: { type: Boolean, default: false },
    credential: { type: Object, default: null },
    providers: { type: Array, default: () => [] },
  },
  data() {
    return {
      name: "",
      fields: {},
      loading: false,
      error: { name: "", save: "" },
    };
  },
  computed: {
    ...mapState(["core"]),
    provider() {
      return this.credential
        ? this.providers.find((p) => p.name === this.credential.provider)
        : null;
    },
  },
  watch: {
    isShown(shown) {
      if (shown && this.credential) {
        this.name = this.credential.name;
        this.fields = {};
        for (const f of this.provider ? this.provider.fields : []) {
          // secrets are never sent back to the browser: blank means "keep"
          this.$set(
            this.fields,
            f.name,
            f.secret ? "" : this.credential.values[f.name] || ""
          );
        }
        this.clearErrors();
        this.loading = false;
      }
    },
  },
  methods: {
    isSet(field) {
      return this.credential.secrets_set.includes(field);
    },
    async save() {
      this.clearErrors();
      if (!this.name) {
        this.error.name = "wizard.required";
        this.focusElement("name");
        return;
      }
      this.loading = true;
      try {
        await this.callAction("update-credential", {
          data: {
            id: this.credential.id,
            name: this.name,
            fields: this.fields,
          },
        });
        this.$emit("saved");
        this.$emit("hide");
      } catch (err) {
        this.error.save = this.errorText(err);
        for (const e of err.errors || []) {
          if (e.parameter && e.parameter.startsWith("fields.")) {
            this.$set(
              this.error,
              "field_" + e.parameter.slice(7),
              this.validationText(e)
            );
          }
        }
      }
      this.loading = false;
    },
  },
};
</script>
