<!--
  Copyright (C) 2026 dnshelper contributors
  SPDX-License-Identifier: GPL-3.0-or-later

  Review and apply the Records page's pending changes. Up to 100 removals and
  100 additions go out as one apply-changes, checked first with a dry run
  (the backend's plan: CNAME conflicts, records no longer there, changes that
  turn out to be no change). More are sent in groups, one after the other;
  each group is planned on its own.
-->
<template>
  <NsModal
    size="large"
    :visible="isShown"
    :primary-button-disabled="loading.check || loading.apply || !canApply"
    :isLoading="loading.apply"
    @modal-hidden="$emit('hide')"
    @primary-click="apply"
  >
    <template slot="title">{{ $t("pending.review_title", { zone }) }}</template>
    <template slot="content">
      <cv-skeleton-text
        v-if="loading.check"
        :paragraph="true"
        :line-count="5"
      />
      <template v-else>
        <NsInlineNotification
          v-if="parts.length > 1"
          kind="warning"
          :title="$t('pending.split_title')"
          :description="$t('pending.split', { parts: parts.length })"
          :showCloseButton="false"
        />
        <p v-if="!error.check && !hasChanges" class="mg-bottom-md">
          {{ $t("pending.nothing") }}
        </p>
        <template v-if="hasChanges">
          <p class="mg-bottom-md">{{ $t("pending.review_intro") }}</p>
          <div v-for="part in ['remove', 'add']" :key="part">
            <h6 v-if="plan[part].length" class="mg-bottom-sm mg-top-md">
              {{ $t("pending.part_" + part, { count: plan[part].length }) }}
            </h6>
            <ul class="plan-list">
              <li v-for="(r, i) in plan[part]" :key="i">
                {{ r.name }} {{ r.type }} {{ r.ttl || "-" }} {{ r.data }}
              </li>
            </ul>
          </div>
        </template>
      </template>
      <NsInlineNotification
        v-if="error.check"
        kind="error"
        :title="$t('pending.check_failed')"
        :description="error.check"
        :showCloseButton="false"
      />
      <NsInlineNotification
        v-if="error.apply"
        kind="error"
        :title="$t('pending.apply_failed')"
        :description="error.apply"
        :showCloseButton="false"
      />
      <NsButton
        v-if="error.stale"
        kind="tertiary"
        size="small"
        :icon="Renew20"
        @click="$emit('reload')"
      >
        {{ $t("records.reload") }}
      </NsButton>
    </template>
    <template slot="secondary-button">{{ core.$t("common.cancel") }}</template>
    <template slot="primary-button">{{
      $t("pending.apply", { count: changes.length })
    }}</template>
  </NsModal>
</template>

<script>
import { mapState } from "vuex";
import { IconService } from "@nethserver/ns8-ui-lib";
import DnsHelperService from "../mixins/dnshelper";
import { changeset, groups } from "../lib/pending";

export default {
  name: "ReviewChanges",
  mixins: [DnsHelperService, IconService],
  props: {
    isShown: { type: Boolean, default: false },
    zone: { type: String, default: "" },
    changes: { type: Array, required: true },
  },
  data() {
    return {
      plan: { remove: [], add: [] },
      loading: { check: false, apply: false },
      error: { check: "", apply: "", stale: false },
    };
  },
  computed: {
    ...mapState(["core"]),
    parts() {
      return groups(this.changes);
    },
    hasChanges() {
      return this.plan.remove.length + this.plan.add.length > 0;
    },
    canApply() {
      return this.hasChanges && !this.error.check;
    },
  },
  watch: {
    isShown(shown) {
      if (shown) {
        this.check();
      }
    },
  },
  methods: {
    isStale(err) {
      return (
        err &&
        err.kind === "validation" &&
        err.errors.some((e) => e.error === "stale")
      );
    },
    async check() {
      this.error = { check: "", apply: "", stale: false };
      const all = changeset(this.changes);
      if (this.parts.length > 1) {
        // a dry run of one group says nothing reliable about the next, which
        // runs after it: show what was asked
        this.plan = all;
        return;
      }
      this.loading.check = true;
      try {
        const out = await this.callAction("apply-changes", {
          data: { zone: this.zone, ...all, dry_run: true },
        });
        this.plan = out.changes;
      } catch (err) {
        this.plan = all;
        this.error.check = this.errorText(err);
        this.error.stale = this.isStale(err);
      }
      this.loading.check = false;
    },
    async apply() {
      this.loading.apply = true;
      this.error.apply = "";
      this.error.stale = false;
      const parts = this.parts;
      const label = this.$t("pending.label", { count: this.changes.length });
      let done = 0;
      try {
        for (const part of parts) {
          await this.callAction("apply-changes", {
            data: { zone: this.zone, ...changeset(part), label },
          });
          done++;
        }
        this.$emit("applied", { applied: parts.flat(), complete: true });
      } catch (err) {
        this.error.apply =
          (done
            ? this.$t("pending.partly_applied", {
                done,
                parts: parts.length,
              }) + " "
            : "") + this.errorText(err);
        this.error.stale = this.isStale(err);
        // the groups that went through are no longer pending
        this.$emit("applied", {
          applied: parts.slice(0, done).flat(),
          complete: false,
        });
      }
      this.loading.apply = false;
    },
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";

.plan-list {
  font-family: "IBM Plex Mono", monospace;
  font-size: 0.875rem;
  overflow-wrap: anywhere;
}
</style>
