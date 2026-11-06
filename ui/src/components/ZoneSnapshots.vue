<!--
  Copyright (C) 2026 dnshelper contributors
  SPDX-License-Identifier: GPL-3.0-or-later

  The snapshots of one zone: list them, take one, delete one, and compare one
  with the zone to revert it (all or part of the difference), through
  apply-changes. See DESIGN.md, Records editor: Snapshots and revert.
-->
<template>
  <NsModal
    size="large"
    :visible="isShown"
    :primary-button-disabled="primaryDisabled"
    :isLoading="loading.apply"
    @modal-hidden="hide"
    @primary-click="primaryClick"
    @secondary-click="secondaryClick"
  >
    <template slot="title">{{
      view === "list"
        ? $t("snapshots.title", { zone })
        : $t("snapshots.revert_title", { time: when(diff.time) })
    }}</template>
    <template slot="content">
      <!-- list -->
      <div v-if="view === 'list'">
        <p class="mg-bottom-md">
          {{
            $t("snapshots.intro", {
              count: settings.snapshot_max_count,
              days: settings.snapshot_max_age_days,
            })
          }}
        </p>
        <cv-form class="take-row mg-bottom-md" @submit.prevent="create">
          <NsTextInput
            v-model.trim="label"
            :label="
              $t('snapshots.label') + ' (' + $t('wizard.optional') + ')'
            "
            :placeholder="$t('snapshots.label_placeholder')"
            maxlength="200"
            :disabled="loading.list || loading.create"
            class="take-label"
          />
          <NsButton
            kind="secondary"
            :icon="Add20"
            :loading="loading.create"
            :disabled="loading.list || loading.create"
          >
            {{ $t("snapshots.take") }}
          </NsButton>
        </cv-form>
        <NsInlineNotification
          v-if="error.list"
          kind="error"
          :title="$t('snapshots.cannot_load')"
          :description="error.list"
          :showCloseButton="false"
        />
        <cv-skeleton-text
          v-if="loading.list"
          :paragraph="true"
          :line-count="5"
        />
        <NsEmptyState
          v-else-if="!snapshots.length && !error.list"
          :title="$t('snapshots.none')"
        >
          <template #description>
            <div>{{ $t("snapshots.none_description") }}</div>
          </template>
        </NsEmptyState>
        <div v-else>
          <div
            v-for="s in snapshots"
            :key="s.id"
            class="snapshot mg-bottom-sm"
          >
            <div class="snapshot-head">
              <div>
                <strong>{{ when(s.time) }}</strong>
                <NsTag
                  v-if="s.kind === 'manual'"
                  :label="$t('snapshots.manual')"
                  kind="green"
                  class="mg-left-sm"
                />
                <span class="mg-left-sm">{{ describe(s) }}</span>
                <span class="muted mg-left-sm">{{
                  $t("snapshots.records", { count: s.records })
                }}</span>
              </div>
              <div class="snapshot-actions">
                <NsButton
                  kind="ghost"
                  size="small"
                  :icon="Renew20"
                  :disabled="busy"
                  @click="compare(s)"
                  >{{ $t("snapshots.compare") }}</NsButton
                >
                <NsButton
                  kind="ghost"
                  size="small"
                  :icon="TrashCan20"
                  :disabled="busy"
                  :loading="loading.delete === s.id"
                  @click="remove(s)"
                  >{{ core.$t("common.delete") }}</NsButton
                >
              </div>
            </div>
            <ul v-if="s.changes.length" class="changes">
              <li v-for="(c, i) in s.changes" :key="i">
                {{
                  $t("snapshots.change_line", {
                    time: when(c.time),
                    caller: c.caller,
                    action: c.label || c.action,
                    add: (c.add || []).length,
                    remove: (c.remove || []).length,
                  })
                }}
                <NsTag
                  v-if="c.result === 'failed'"
                  :label="$t('snapshots.failed')"
                  kind="red"
                  class="mg-left-sm"
                />
              </li>
            </ul>
          </div>
        </div>
        <NsInlineNotification
          v-if="error.action"
          kind="error"
          :title="$t('snapshots.error_title')"
          :description="error.action"
          :showCloseButton="false"
        />
      </div>
      <!-- compare and revert -->
      <div v-else>
        <cv-skeleton-text
          v-if="loading.diff"
          :paragraph="true"
          :line-count="5"
        />
        <template v-else-if="!error.diff">
          <p v-if="!rows.length" class="mg-bottom-md">
            {{ $t("snapshots.same") }}
          </p>
          <template v-else>
            <p class="mg-bottom-md">{{ $t("snapshots.revert_intro") }}</p>
            <NsInlineNotification
              v-if="hasModuleChanges"
              kind="warning"
              :title="$t('snapshots.module_changes_title')"
              :description="$t('snapshots.module_changes')"
              :showCloseButton="false"
            />
            <div v-for="part in ['remove', 'add']" :key="part">
              <h6 v-if="rowsOf(part).length" class="mg-bottom-sm mg-top-md">
                {{ $t("snapshots.part_" + part) }}
              </h6>
              <div
                v-for="row in rowsOf(part)"
                :key="row.key"
                class="diff-row"
              >
                <NsCheckbox
                  v-model="selected"
                  :value="row.key"
                  :label="row.label"
                  :disabled="loading.apply"
                />
                <NsTag
                  v-for="who in row.modules"
                  :key="who"
                  :label="$t('snapshots.changed_by', { who })"
                  kind="warm-gray"
                  class="mg-left-sm"
                />
              </div>
            </div>
          </template>
        </template>
        <NsInlineNotification
          v-if="error.diff"
          kind="error"
          :title="$t('action.diff-snapshot')"
          :description="error.diff"
          :showCloseButton="false"
        />
        <NsInlineNotification
          v-if="error.apply"
          kind="error"
          :title="$t('snapshots.revert')"
          :description="error.apply"
          :showCloseButton="false"
        />
      </div>
    </template>
    <template slot="secondary-button">{{
      view === "list" ? $t("snapshots.close") : $t("snapshots.back")
    }}</template>
    <template v-if="view === 'diff'" slot="primary-button">{{
      $t("snapshots.apply", { count: selected.length })
    }}</template>
  </NsModal>
</template>

<script>
import { mapState } from "vuex";
import { IconService, UtilService } from "@nethserver/ns8-ui-lib";
import DnsHelperService from "../mixins/dnshelper";

export default {
  name: "ZoneSnapshots",
  mixins: [DnsHelperService, IconService, UtilService],
  props: {
    isShown: { type: Boolean, default: false },
    zone: { type: String, default: "" },
  },
  data() {
    return {
      view: "list",
      snapshots: [],
      settings: { snapshot_max_count: 50, snapshot_max_age_days: 90 },
      label: "",
      diff: { id: "", time: "", remove: [], add: [] },
      selected: [],
      loading: {
        list: false,
        create: false,
        delete: "",
        diff: false,
        apply: false,
      },
      error: { list: "", action: "", diff: "", apply: "" },
    };
  },
  computed: {
    ...mapState(["core"]),
    busy() {
      return this.loading.list || this.loading.create || !!this.loading.delete;
    },
    rows() {
      const out = [];
      for (const part of ["remove", "add"]) {
        this.diff[part].forEach((item, i) => {
          const r = item.record;
          out.push({
            part,
            key: part + i,
            record: r,
            label: `${r.name} ${r.type} ${r.ttl || "-"} ${r.data}`,
            modules: item.changed_by.filter((c) => c.startsWith("module/")),
          });
        });
      }
      return out;
    },
    hasModuleChanges() {
      return this.rows.some((r) => r.modules.length);
    },
    primaryDisabled() {
      return (
        this.view !== "diff" ||
        this.loading.diff ||
        this.loading.apply ||
        !this.selected.length
      );
    },
  },
  watch: {
    isShown(shown) {
      if (shown) {
        this.view = "list";
        this.label = "";
        this.error.action = "";
        this.load();
      }
    },
  },
  methods: {
    hide() {
      this.$emit("hide");
    },
    when(iso) {
      if (!iso) {
        return "";
      }
      const d = new Date(iso);
      return isNaN(d) ? iso : d.toLocaleString();
    },
    describe(s) {
      if (s.kind === "manual") {
        return s.label || "";
      }
      return this.$t("snapshots.before", { action: s.action });
    },
    rowsOf(part) {
      return this.rows.filter((r) => r.part === part);
    },
    async load() {
      this.loading.list = true;
      this.error.list = "";
      try {
        const out = await this.callAction("list-snapshots", {
          data: { zone: this.zone },
        });
        this.snapshots = out.snapshots;
        this.settings = out.settings;
      } catch (err) {
        this.snapshots = [];
        this.error.list = this.errorText(err);
      }
      this.loading.list = false;
    },
    async create() {
      this.loading.create = true;
      this.error.action = "";
      try {
        const data = { zone: this.zone };
        if (this.label) {
          data.label = this.label;
        }
        await this.callAction("create-snapshot", { data });
        this.label = "";
        await this.load();
      } catch (err) {
        this.error.action = this.errorText(err);
      }
      this.loading.create = false;
    },
    async remove(s) {
      this.loading.delete = s.id;
      this.error.action = "";
      try {
        await this.callAction("delete-snapshot", {
          data: { zone: this.zone, id: s.id },
        });
        await this.load();
      } catch (err) {
        this.error.action = this.errorText(err);
      }
      this.loading.delete = "";
    },
    async compare(s) {
      this.view = "diff";
      this.diff = { id: s.id, time: s.time, remove: [], add: [] };
      this.selected = [];
      this.error.diff = "";
      this.error.apply = "";
      this.loading.diff = true;
      try {
        const out = await this.callAction("diff-snapshot", {
          data: { zone: this.zone, id: s.id },
        });
        this.diff = { id: s.id, time: s.time, remove: out.remove, add: out.add };
        this.selected = this.rows.map((r) => r.key);
      } catch (err) {
        this.error.diff = this.errorText(err);
      }
      this.loading.diff = false;
    },
    secondaryClick() {
      if (this.view === "diff") {
        this.view = "list";
        this.load();
      } else {
        this.hide();
      }
    },
    primaryClick() {
      if (this.view === "diff") {
        this.apply();
      }
    },
    async apply() {
      const chosen = this.rows.filter((r) => this.selected.includes(r.key));
      const pick = (part) =>
        chosen.filter((r) => r.part === part).map((r) => r.record);
      this.loading.apply = true;
      this.error.apply = "";
      try {
        await this.callAction("apply-changes", {
          data: {
            zone: this.zone,
            remove: pick("remove"),
            add: pick("add"),
            label: this.$t("snapshots.revert_label", {
              time: this.when(this.diff.time),
            }),
          },
        });
        this.$emit("changed");
        this.view = "list";
        await this.load();
      } catch (err) {
        this.error.apply = this.errorText(err);
      }
      this.loading.apply = false;
    },
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";

.take-row {
  display: flex;
  align-items: flex-end;
  gap: $spacing-05;
}

.take-label {
  flex: 1;
  max-width: 30rem;
}

.snapshot {
  padding: $spacing-03 $spacing-05;
  background-color: rgba(141, 141, 141, 0.08);
}

.snapshot-head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: $spacing-03;
}

.snapshot-actions {
  display: flex;
}

.changes {
  margin-top: $spacing-02;
  font-size: 0.875rem;
}

.muted {
  opacity: 0.7;
}

.diff-row {
  display: flex;
  align-items: center;
  font-family: "IBM Plex Mono", monospace;
  font-size: 0.875rem;
  overflow-wrap: anywhere;
}
</style>
