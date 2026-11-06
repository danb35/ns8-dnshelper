<!--
  Copyright (C) 2026 dnshelper contributors
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <div>
    <cv-grid fullWidth>
      <cv-row>
        <cv-column class="page-title">
          <h2>{{ $t("records.title") }}</h2>
        </cv-column>
      </cv-row>
      <cv-row v-if="error.load">
        <cv-column>
          <NsInlineNotification
            kind="error"
            :title="$t('records.cannot_load')"
            :description="error.load"
            :showCloseButton="false"
          />
        </cv-column>
      </cv-row>
      <cv-row v-if="notice.text">
        <cv-column>
          <NsInlineNotification
            kind="success"
            :title="notice.title"
            :description="notice.text"
            @close="notice.text = ''"
          />
        </cv-column>
      </cv-row>
      <cv-row>
        <cv-column>
          <p class="section-intro">{{ $t("records.intro") }}</p>
        </cv-column>
      </cv-row>
      <!-- no zones: nothing to look at yet -->
      <cv-row v-if="!loading.zones && !zones.length && !error.load">
        <cv-column>
          <NsEmptyState :title="$t('status.no_zones_title')">
            <template #description>
              <div>{{ $t("records.no_zones_description") }}</div>
            </template>
            <NsButton
              kind="primary"
              @click="goToAppPage(instanceName, 'zones')"
            >
              {{ $t("status.add_first_zone") }}
            </NsButton>
          </NsEmptyState>
        </cv-column>
      </cv-row>
      <template v-else>
        <cv-row>
          <cv-column :md="4" :max="4">
            <cv-select
              v-model="zone"
              :label="$t('records.zone')"
              :disabled="loading.zones || loading.records"
              class="mg-bottom-md"
              @change="loadRecords"
            >
              <cv-select-option v-for="z in zones" :key="z" :value="z">{{
                z
              }}</cv-select-option>
            </cv-select>
          </cv-column>
        </cv-row>
        <cv-row>
          <cv-column>
            <NsButton
              kind="primary"
              :icon="Add20"
              :disabled="loading.zones || loading.records || !zone"
              @click="showAdd"
              class="mg-bottom-md mg-right-sm"
            >
              {{ $t("records.add_record") }}
            </NsButton>
            <NsButton
              kind="tertiary"
              :icon="Renew20"
              :disabled="loading.zones || loading.records || !zone"
              @click="loadRecords"
              class="mg-bottom-md mg-right-sm"
            >
              {{ $t("records.refresh") }}
            </NsButton>
            <NsButton
              kind="tertiary"
              :icon="Time20"
              :disabled="loading.zones || !zone"
              @click="isSnapshotsShown = true"
              class="mg-bottom-md"
            >
              {{ $t("snapshots.button") }}
            </NsButton>
          </cv-column>
        </cv-row>
        <cv-row>
          <cv-column>
            <NsDataTable
              :allRows="rows"
              :columns="columns"
              :rawColumns="['name', 'type', 'ttl', 'data']"
              :sortable="true"
              :pageSizes="[10, 25, 50]"
              :overflow-menu="true"
              isSearchable
              :searchPlaceholder="$t('records.search')"
              :searchClearLabel="core.$t('common.clear_search')"
              :noSearchResultsLabel="core.$t('common.no_search_results')"
              :noSearchResultsDescription="
                core.$t('common.no_search_results_description')
              "
              :isLoading="loading.zones || loading.records"
              :skeletonRows="5"
              :itemsPerPageLabel="core.$t('pagination.items_per_page')"
              :rangeOfTotalItemsLabel="
                core.$t('pagination.range_of_total_items')
              "
              :ofTotalPagesLabel="core.$t('pagination.of_total_pages')"
              :backwardText="core.$t('pagination.previous_page')"
              :forwardText="core.$t('pagination.next_page')"
              :pageNumberLabel="core.$t('pagination.page_number')"
              @updatePage="page = $event"
            >
              <template slot="empty-state">
                <NsEmptyState :title="$t('records.no_records')">
                  <template #description>
                    <div>{{ $t("records.no_records_description") }}</div>
                  </template>
                </NsEmptyState>
              </template>
              <template slot="data">
                <cv-data-table-row
                  v-for="(row, i) in page"
                  :key="row.index"
                  :value="String(i)"
                >
                  <cv-data-table-cell>
                    <strong>{{ row.name }}</strong>
                  </cv-data-table-cell>
                  <cv-data-table-cell>
                    <NsTag :label="row.type" kind="blue" />
                  </cv-data-table-cell>
                  <cv-data-table-cell>{{ row.ttl || "-" }}</cv-data-table-cell>
                  <cv-data-table-cell>
                    <span class="record-data" :title="row.data">{{
                      shorten(row.data)
                    }}</span>
                  </cv-data-table-cell>
                  <cv-data-table-cell class="table-overflow-menu-cell">
                    <NsTag
                      v-if="isProtected(row)"
                      :label="$t('records.read_only')"
                      :title="$t('records.read_only_help')"
                      kind="gray"
                      class="read-only-tag"
                    />
                    <cv-overflow-menu
                      v-else
                      flip-menu
                      class="table-overflow-menu"
                    >
                      <cv-overflow-menu-item @click="showEdit(row)">
                        <NsMenuItem
                          :icon="Edit20"
                          :label="$t('records.edit')"
                        />
                      </cv-overflow-menu-item>
                      <cv-overflow-menu-item
                        danger
                        :disabled="isProtected(row)"
                        @click="showRemove(row)"
                      >
                        <NsMenuItem
                          :icon="TrashCan20"
                          :label="core.$t('common.delete')"
                        />
                      </cv-overflow-menu-item>
                    </cv-overflow-menu>
                  </cv-data-table-cell>
                </cv-data-table-row>
              </template>
            </NsDataTable>
          </cv-column>
        </cv-row>
      </template>
    </cv-grid>

    <ZoneSnapshots
      :isShown="isSnapshotsShown"
      :zone="zone"
      @hide="isSnapshotsShown = false"
      @changed="loadRecords"
    />
    <!-- add or edit a record -->
    <NsModal
      size="default"
      :visible="isFormShown"
      :primary-button-disabled="loading.save"
      :isLoading="loading.save"
      @modal-hidden="isFormShown = false"
      @primary-click="saveRecord"
    >
      <template slot="title">{{
        current
          ? $t("records.edit_title", { zone })
          : $t("records.add_title", { zone })
      }}</template>
      <template slot="content">
        <cv-form @submit.prevent="saveRecord">
          <div class="mg-bottom-md">
            {{ current ? $t("records.edit_help") : $t("records.add_help") }}
          </div>
          <RecordForm
            v-if="isFormShown"
            :key="formKey"
            ref="form"
            :types="types"
            :existing="records"
            :initial="current"
            :disabled="loading.save"
          />
          <NsInlineNotification
            v-if="error.save"
            kind="error"
            :title="
              current ? $t('action.apply-changes') : $t('action.append-records')
            "
            :description="error.save"
            :showCloseButton="false"
          />
          <NsButton
            v-if="error.stale"
            kind="tertiary"
            size="small"
            :icon="Renew20"
            @click="reloadAfterStale"
          >
            {{ $t("records.reload") }}
          </NsButton>
        </cv-form>
      </template>
      <template slot="secondary-button">{{
        core.$t("common.cancel")
      }}</template>
      <template slot="primary-button">{{
        current ? $t("common.save") : $t("records.add_record")
      }}</template>
    </NsModal>
    <!-- delete a record -->
    <NsModal
      size="default"
      kind="danger"
      :visible="isRemoveShown"
      :primary-button-disabled="loading.remove"
      :isLoading="loading.remove"
      @modal-hidden="isRemoveShown = false"
      @primary-click="removeRecord"
    >
      <template slot="title">{{ $t("records.remove_title") }}</template>
      <template slot="content">
        <p class="mg-bottom-sm">
          {{ $t("records.remove_description", { zone }) }}
        </p>
        <p v-if="current" class="mg-bottom-md record-summary">
          <strong>{{ current.name }}</strong>
          <NsTag :label="current.type" kind="blue" class="mg-left-sm" />
          <span class="record-data">{{ shorten(current.data) }}</span>
        </p>
        <p class="mg-bottom-md">{{ $t("records.remove_explanation") }}</p>
        <NsInlineNotification
          v-if="error.remove"
          kind="error"
          :title="$t('action.delete-records')"
          :description="error.remove"
          :showCloseButton="false"
        />
      </template>
      <template slot="secondary-button">{{
        core.$t("common.cancel")
      }}</template>
      <template slot="primary-button">{{ core.$t("common.delete") }}</template>
    </NsModal>
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
import ZoneSnapshots from "../components/ZoneSnapshots";
import RecordForm from "../components/RecordForm";
import Time20 from "@carbon/icons-vue/es/time/20";

const COMMON_TYPES = ["A", "AAAA", "CNAME", "MX", "SRV", "TXT", "NS", "CAA"];

export default {
  name: "Records",
  components: { ZoneSnapshots, RecordForm },
  mixins: [
    DnsHelperService,
    QueryParamService,
    IconService,
    UtilService,
    PageTitleService,
  ],
  pageTitle() {
    return this.$t("records.title") + " - " + this.appName;
  },
  data() {
    return {
      // zone: the deep link /apps/<id>?page=records&zone=example.com, which
      // the ns8-powerdns Records page opens for a zone dnshelper manages
      q: { page: "records", zone: "" },
      urlCheckInterval: null,
      zones: [],
      zoneInfo: {}, // zone -> { provider }
      providers: [],
      zone: "",
      records: [],
      page: [],
      current: null,
      isFormShown: false,
      formKey: 0,
      isRemoveShown: false,
      isSnapshotsShown: false,
      Time20,
      notice: { title: "", text: "" },
      loading: { zones: true, records: false, save: false, remove: false },
      error: {
        load: "",
        save: "",
        stale: false,
        remove: "",
      },
    };
  },
  computed: {
    ...mapState(["core", "appName", "instanceName"]),
    columns() {
      return ["name", "type", "ttl", "data"].map((c) =>
        this.$t("records.col_" + c)
      );
    },
    rows() {
      return this.records.map((r, index) => ({ ...r, index }));
    },
    // the record types the DNS host of the selected zone can handle
    types() {
      const info = this.zoneInfo[this.zone];
      const provider = info
        ? this.providers.find((p) => p.name === info.provider)
        : null;
      const supported = provider && provider.types.length ? provider.types : [];
      const ordered = COMMON_TYPES.filter((t) => supported.includes(t));
      return ordered.concat(supported.filter((t) => !COMMON_TYPES.includes(t)));
    },
  },
  watch: {
    // the link was followed while this page was already open
    "q.zone"(value) {
      const requested = this.zoneFromQuery(value);
      if (requested && requested !== this.zone) {
        this.zone = requested;
        this.loadRecords();
      }
    },
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
      this.loading.zones = true;
      this.error.load = "";
      try {
        const [config, providers] = await Promise.all([
          this.callAction("get-configuration"),
          this.callAction("list-providers"),
        ]);
        this.providers = providers.providers;
        const credProvider = {};
        for (const c of config.credentials) {
          credProvider[c.id] = c.provider;
        }
        this.zones = config.zones.map((z) => z.zone).sort();
        this.zoneInfo = {};
        for (const z of config.zones) {
          this.zoneInfo[z.zone] = { provider: credProvider[z.credential] };
        }
      } catch (err) {
        this.error.load = this.errorText(err);
      }
      this.loading.zones = false;
      if (this.zones.length) {
        const requested = this.zoneFromQuery(
          this.q.zone || this.getQueryParamsForApp().zone
        );
        if (requested) {
          this.zone = requested;
        } else if (!this.zones.includes(this.zone)) {
          // keep the zone the administrator was looking at, if it still exists
          this.zone = this.zones[0];
        }
        await this.loadRecords();
      }
    },
    // a zone named in the URL, if it is one of the managed zones
    zoneFromQuery(value) {
      const z = (value || "").trim().toLowerCase().replace(/\.$/, "");
      return this.zones.includes(z) ? z : "";
    },
    async loadRecords() {
      if (!this.zone) {
        return;
      }
      this.q.zone = this.zone;
      this.loading.records = true;
      this.error.load = "";
      try {
        const out = await this.callAction("get-records", {
          data: { zone: this.zone },
        });
        this.records = out.records.slice().sort(this.compareRecords);
      } catch (err) {
        this.records = [];
        this.error.load = this.errorText(err);
      }
      this.loading.records = false;
    },
    // the apex first, then by name and type
    compareRecords(a, b) {
      const rank = (r) => (r.name === "@" ? 0 : 1);
      return (
        rank(a) - rank(b) ||
        a.name.localeCompare(b.name) ||
        a.type.localeCompare(b.type) ||
        a.data.localeCompare(b.data)
      );
    },
    shorten(text) {
      return text && text.length > 140 ? text.slice(0, 140) + "…" : text;
    },
    // dnshelper never changes apex NS or SOA records; do not offer to
    isProtected(row) {
      return row.type === "SOA" || (row.type === "NS" && row.name === "@");
    },
    showAdd() {
      this.openForm(null);
    },
    showEdit(row) {
      // the record as get-records reported it, without the table's index
      this.openForm({ name: row.name, type: row.type, ttl: row.ttl, data: row.data });
    },
    openForm(record) {
      this.current = record;
      this.error.save = "";
      this.error.stale = false;
      this.formKey++;
      this.isFormShown = true;
    },
    async saveRecord() {
      this.error.save = "";
      this.error.stale = false;
      const record = this.$refs.form.build();
      if (!record) {
        return;
      }
      const old = this.current;
      this.loading.save = true;
      try {
        if (old) {
          // one change: the old record must still be there, or nothing is
          // done (error "stale"). No TTL: a DNS host may store a different
          // one from the one asked for.
          await this.callAction("apply-changes", {
            data: {
              zone: this.zone,
              remove: [{ name: old.name, type: old.type, data: old.data }],
              add: [record],
            },
          });
        } else {
          await this.callAction("append-records", {
            data: { zone: this.zone, records: [record] },
          });
        }
        this.isFormShown = false;
        this.notice = old
          ? {
              title: this.$t("records.edited_title"),
              text: this.$t("records.edited", {
                name: record.name,
                type: record.type,
              }),
            }
          : {
              title: this.$t("records.added_title"),
              text: this.$t("records.added", {
                name: record.name,
                type: record.type,
              }),
            };
        await this.loadRecords();
      } catch (err) {
        this.error.save = this.errorText(err);
        this.error.stale =
          err &&
          err.kind === "validation" &&
          err.errors.some((e) => e.error === "stale");
      }
      this.loading.save = false;
    },
    async reloadAfterStale() {
      this.isFormShown = false;
      await this.loadRecords();
    },
    showRemove(row) {
      this.current = row;
      this.error.remove = "";
      this.isRemoveShown = true;
    },
    async removeRecord() {
      const r = this.current;
      this.loading.remove = true;
      this.error.remove = "";
      try {
        // no TTL: a DNS host may store a different one from the one asked for
        await this.callAction("delete-records", {
          data: {
            zone: this.zone,
            records: [{ name: r.name, type: r.type, data: r.data }],
          },
        });
        this.isRemoveShown = false;
        this.notice = {
          title: this.$t("records.removed_title"),
          text: this.$t("records.removed", { name: r.name, type: r.type }),
        };
        await this.loadRecords();
      } catch (err) {
        this.error.remove = this.errorText(err);
      }
      this.loading.remove = false;
    },
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";

.section-intro {
  margin-bottom: $spacing-05;
  max-width: 50rem;
}

.record-data {
  font-family: "IBM Plex Mono", monospace;
  font-size: 0.875rem;
  overflow-wrap: anywhere;
}

.record-summary {
  padding: $spacing-03 $spacing-05;
  background-color: rgba(141, 141, 141, 0.16);
  overflow-wrap: anywhere;
}
</style>
