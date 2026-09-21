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
              class="mg-bottom-md"
            >
              {{ $t("records.refresh") }}
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
                    <cv-tag :label="row.type" kind="blue" />
                  </cv-data-table-cell>
                  <cv-data-table-cell>{{ row.ttl || "-" }}</cv-data-table-cell>
                  <cv-data-table-cell>
                    <span class="record-data" :title="row.data">{{
                      shorten(row.data)
                    }}</span>
                  </cv-data-table-cell>
                  <cv-data-table-cell class="table-overflow-menu-cell">
                    <cv-overflow-menu flip-menu class="table-overflow-menu">
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

    <!-- add a record -->
    <NsModal
      size="default"
      :visible="isAddShown"
      :primary-button-disabled="loading.add"
      :isLoading="loading.add"
      @modal-hidden="isAddShown = false"
      @primary-click="addRecord"
    >
      <template slot="title">{{ $t("records.add_title", { zone }) }}</template>
      <template slot="content">
        <cv-form @submit.prevent="addRecord">
          <div class="mg-bottom-md">{{ $t("records.add_help") }}</div>
          <NsTextInput
            v-model.trim="form.name"
            :label="$t('records.col_name')"
            :helper-text="$t('records.name_help')"
            placeholder="www"
            :invalid-message="$t(error.name)"
            :disabled="loading.add"
            ref="name"
            class="mg-bottom-md"
          />
          <cv-select
            v-model="form.type"
            :label="$t('records.col_type')"
            :disabled="loading.add"
            class="mg-bottom-md"
          >
            <cv-select-option v-for="t in types" :key="t" :value="t">{{
              t
            }}</cv-select-option>
          </cv-select>
          <NsTextInput
            v-model.trim="form.data"
            :label="$t('records.col_data')"
            :helper-text="$t('records.data_help', { example: example })"
            :placeholder="example"
            :invalid-message="$t(error.data)"
            :disabled="loading.add"
            ref="data"
            class="mg-bottom-md"
          />
          <NsTextInput
            v-model.trim="form.ttl"
            :label="$t('records.col_ttl') + ' (' + $t('wizard.optional') + ')'"
            :helper-text="$t('records.ttl_help')"
            placeholder="3600"
            :invalid-message="$t(error.ttl)"
            :disabled="loading.add"
            ref="ttl"
            class="mg-bottom-md"
          />
          <NsInlineNotification
            v-if="error.add"
            kind="error"
            :title="$t('action.append-records')"
            :description="error.add"
            :showCloseButton="false"
          />
        </cv-form>
      </template>
      <template slot="secondary-button">{{
        core.$t("common.cancel")
      }}</template>
      <template slot="primary-button">{{ $t("records.add_record") }}</template>
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
          <cv-tag :label="current.type" kind="blue" class="mg-left-sm" />
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

// what a value looks like, per record type, to show as the field's example
const EXAMPLES = {
  A: "192.0.2.10",
  AAAA: "2001:db8::10",
  CNAME: "target.example.net.",
  MX: "10 mail.example.net.",
  NS: "ns1.example.net.",
  SRV: "10 5 5060 sip.example.net.",
  TXT: "v=spf1 -all",
  CAA: '0 issue "letsencrypt.org"',
};
const COMMON_TYPES = ["A", "AAAA", "CNAME", "MX", "SRV", "TXT", "NS", "CAA"];

export default {
  name: "Records",
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
      q: { page: "records" },
      urlCheckInterval: null,
      zones: [],
      zoneInfo: {}, // zone -> { provider }
      providers: [],
      zone: "",
      records: [],
      page: [],
      current: null,
      isAddShown: false,
      isRemoveShown: false,
      form: { name: "", type: "A", data: "", ttl: "" },
      notice: { title: "", text: "" },
      loading: { zones: true, records: false, add: false, remove: false },
      error: {
        load: "",
        add: "",
        remove: "",
        name: "",
        data: "",
        ttl: "",
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
    example() {
      return EXAMPLES[this.form.type] || "";
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
        // keep the zone the administrator was looking at, if it still exists
        if (!this.zones.includes(this.zone)) {
          this.zone = this.zones[0];
        }
        await this.loadRecords();
      }
    },
    async loadRecords() {
      if (!this.zone) {
        return;
      }
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
      this.form = {
        name: "",
        type: this.types.includes("A") ? "A" : this.types[0] || "A",
        data: "",
        ttl: "",
      };
      this.clearErrors();
      this.isAddShown = true;
    },
    clearErrors() {
      this.error.add = "";
      this.error.remove = "";
      this.error.name = "";
      this.error.data = "";
      this.error.ttl = "";
    },
    async addRecord() {
      this.clearErrors();
      const name = this.form.name.trim().toLowerCase();
      if (!name || !/^[a-z0-9@_.*-]+$/.test(name)) {
        this.error.name = "records.invalid_name";
        this.focusElement("name");
        return;
      }
      const data = this.form.data.trim();
      if (!data) {
        this.error.data = "wizard.required";
        this.focusElement("data");
        return;
      }
      const record = { name, type: this.form.type, data };
      if (this.form.ttl !== "" && this.form.ttl !== null) {
        const ttl = Number(this.form.ttl);
        if (!Number.isInteger(ttl) || ttl < 1 || ttl > 2147483647) {
          this.error.ttl = "records.invalid_ttl";
          this.focusElement("ttl");
          return;
        }
        record.ttl = ttl;
      }
      this.loading.add = true;
      try {
        await this.callAction("append-records", {
          data: { zone: this.zone, records: [record] },
        });
        this.isAddShown = false;
        this.notice = {
          title: this.$t("records.added_title"),
          text: this.$t("records.added", { name, type: record.type }),
        };
        await this.loadRecords();
      } catch (err) {
        this.error.add = this.errorText(err);
      }
      this.loading.add = false;
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
