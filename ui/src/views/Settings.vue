<!--
  Copyright (C) 2026 dnshelper contributors
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <div>
    <cv-grid fullWidth>
      <cv-row>
        <cv-column class="page-title">
          <h2>{{ $t("settings.title") }}</h2>
        </cv-column>
      </cv-row>
      <cv-row v-if="error.load">
        <cv-column>
          <NsInlineNotification
            kind="error"
            :title="$t('action.get-configuration')"
            :description="error.load"
            :showCloseButton="false"
          />
        </cv-column>
      </cv-row>
      <cv-row>
        <cv-column>
          <cv-tile light>
            <h4 class="mg-bottom-md">{{ $t("settings.snapshots_title") }}</h4>
            <p class="mg-bottom-lg section-intro">
              {{ $t("settings.snapshots_intro") }}
            </p>
            <cv-skeleton-text
              v-if="loading.load"
              :paragraph="true"
              :line-count="4"
            />
            <cv-form v-else @submit.prevent="save">
              <NsTextInput
                v-model.trim="form.snapshot_max_count"
                type="number"
                min="1"
                max="1000"
                :label="$t('settings.max_count')"
                :helper-text="$t('settings.max_count_help')"
                :invalid-message="$t(error.snapshot_max_count)"
                :disabled="loading.save"
                ref="snapshot_max_count"
                class="mg-bottom-md narrow"
              />
              <NsTextInput
                v-model.trim="form.snapshot_max_age_days"
                type="number"
                min="1"
                max="3650"
                :label="$t('settings.max_age')"
                :helper-text="$t('settings.max_age_help')"
                :invalid-message="$t(error.snapshot_max_age_days)"
                :disabled="loading.save"
                ref="snapshot_max_age_days"
                class="mg-bottom-lg narrow"
              />
              <NsInlineNotification
                v-if="error.save"
                kind="error"
                :title="$t('action.configure-module')"
                :description="error.save"
                :showCloseButton="false"
              />
              <NsButton
                kind="primary"
                :icon="Save20"
                :loading="loading.save"
                :disabled="loading.save"
              >
                {{ $t("common.save") }}
              </NsButton>
            </cv-form>
          </cv-tile>
        </cv-column>
      </cv-row>
    </cv-grid>
  </div>
</template>

<script>
import { mapState } from "vuex";
import {
  QueryParamService,
  IconService,
  UtilService,
  PageTitleService,
} from "@nethserver/ns8-ui-lib";
import DnsHelperService from "../mixins/dnshelper";

const LIMITS = { snapshot_max_count: 1000, snapshot_max_age_days: 3650 };

export default {
  name: "Settings",
  mixins: [
    DnsHelperService,
    QueryParamService,
    IconService,
    UtilService,
    PageTitleService,
  ],
  pageTitle() {
    return this.$t("settings.title") + " - " + this.appName;
  },
  data() {
    return {
      q: { page: "settings" },
      urlCheckInterval: null,
      form: { snapshot_max_count: "", snapshot_max_age_days: "" },
      loading: { load: true, save: false },
      error: {
        load: "",
        save: "",
        snapshot_max_count: "",
        snapshot_max_age_days: "",
      },
    };
  },
  computed: {
    ...mapState(["core", "appName", "instanceName"]),
  },
  beforeRouteEnter(to, from, next) {
    next((vm) => {
      vm.watchQueryData(vm);
      vm.urlCheckInterval = vm.initUrlBindingForApp(vm, vm.q.page);
    });
  },
  beforeRouteLeave(to, from, next) {
    clearInterval(this.urlCheckInterval);
    next();
  },
  created() {
    this.load();
  },
  methods: {
    async load() {
      this.loading.load = true;
      this.error.load = "";
      try {
        const config = await this.callAction("get-configuration");
        for (const k of Object.keys(LIMITS)) {
          this.form[k] = String(config.settings[k]);
        }
      } catch (err) {
        this.error.load = this.errorText(err);
      }
      this.loading.load = false;
    },
    async save() {
      this.error.save = "";
      const data = {};
      for (const [k, max] of Object.entries(LIMITS)) {
        this.error[k] = "";
        const n = Number(this.form[k]);
        if (!Number.isInteger(n) || n < 1 || n > max) {
          this.error[k] = "settings.invalid_number";
          this.focusElement(k);
          return;
        }
        data[k] = n;
      }
      this.loading.save = true;
      try {
        await this.callAction("configure-module", { data });
      } catch (err) {
        this.error.save = this.errorText(err);
      }
      this.loading.save = false;
    },
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";

.section-intro {
  max-width: 50rem;
}

.narrow {
  max-width: 20rem;
}
</style>
