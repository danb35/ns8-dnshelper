<!--
  Copyright (C) 2026 dnshelper contributors
  SPDX-License-Identifier: GPL-3.0-or-later

  Ask the zone's authoritative name servers whether they serve a record's
  name and type as the DNS host has it (check-propagation).
-->
<template>
  <NsModal
    size="default"
    :visible="isShown"
    :primary-button-disabled="loading"
    :isLoading="loading"
    @modal-hidden="$emit('hide')"
    @primary-click="check"
  >
    <template slot="title">{{
      $t("propagation.title", { name: record ? record.name : "", type: record ? record.type : "" })
    }}</template>
    <template slot="content">
      <p class="mg-bottom-md">{{ $t("propagation.intro") }}</p>
      <cv-skeleton-text v-if="loading" :paragraph="true" :line-count="4" />
      <NsInlineNotification
        v-else-if="error"
        kind="error"
        :title="$t('propagation.failed')"
        :description="error"
        :showCloseButton="false"
      />
      <template v-else-if="result">
        <p class="mg-bottom-sm">
          <strong>{{ $t("propagation.at_host") }}</strong>
          <span class="values">{{
            result.records.length
              ? result.records.map((r) => r.data).join(", ")
              : $t("propagation.nothing")
          }}</span>
        </p>
        <p v-if="result.servers_from === 'provider'" class="note mg-bottom-sm">
          {{ $t("propagation.from_provider") }}
        </p>
        <div
          v-for="(s, i) in result.servers"
          :key="i"
          class="server mg-bottom-sm"
        >
          <div class="server-head">
            <NsTag
              :label="$t('propagation.status_' + s.status)"
              :kind="tagKind(s.status)"
            />
            <strong class="mg-left-sm">{{ s.server }}</strong>
            <span v-if="s.address" class="note mg-left-sm">{{ s.address }}</span>
          </div>
          <div class="values">
            {{
              s.status === "error"
                ? s.message
                : s.values.length
                ? s.values.join(", ")
                : $t("propagation.nothing")
            }}
          </div>
        </div>
        <p class="note mg-top-sm">{{ $t("propagation.caching") }}</p>
      </template>
    </template>
    <template slot="secondary-button">{{ $t("snapshots.close") }}</template>
    <template slot="primary-button">{{ $t("propagation.again") }}</template>
  </NsModal>
</template>

<script>
import DnsHelperService from "../mixins/dnshelper";

export default {
  name: "PropagationCheck",
  mixins: [DnsHelperService],
  props: {
    isShown: { type: Boolean, default: false },
    zone: { type: String, default: "" },
    record: { type: Object, default: null },
  },
  data() {
    return { loading: false, error: "", result: null };
  },
  watch: {
    isShown(shown) {
      if (shown) {
        this.result = null;
        this.check();
      }
    },
  },
  methods: {
    tagKind(status) {
      return { same: "green", different: "red", error: "gray" }[status];
    },
    async check() {
      if (!this.record) {
        return;
      }
      this.loading = true;
      this.error = "";
      try {
        this.result = await this.callAction("check-propagation", {
          data: { zone: this.zone, name: this.record.name, type: this.record.type },
        });
      } catch (err) {
        this.result = null;
        this.error = this.errorText(err);
      }
      this.loading = false;
    },
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";

.server {
  padding: $spacing-03 $spacing-05;
  background-color: rgba(141, 141, 141, 0.08);
}

.server-head {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
}

.values {
  font-family: "IBM Plex Mono", monospace;
  font-size: 0.875rem;
  overflow-wrap: anywhere;
  margin-left: $spacing-03;
}

.server .values {
  margin-left: 0;
  margin-top: $spacing-02;
}

.note {
  font-size: 0.875rem;
  opacity: 0.8;
}
</style>
