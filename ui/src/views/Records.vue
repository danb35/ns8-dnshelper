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
      <cv-row v-if="ptrWarning">
        <cv-column>
          <NsInlineNotification
            kind="warning"
            :title="$t('ptr.failed_title')"
            :description="ptrWarning"
            @close="ptrWarning = ''"
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
              :disabled="loading.zones || loading.records || !!pending.length"
              :helper-text="pending.length ? $t('pending.zone_locked') : ''"
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
              class="mg-bottom-md mg-right-sm"
            >
              {{ $t("snapshots.button") }}
            </NsButton>
            <NsButton
              kind="tertiary"
              :icon="Download20"
              :disabled="loading.zones || !zone"
              :loading="loading.export"
              @click="exportZone"
              class="mg-bottom-md mg-right-sm"
            >
              {{ $t("import.export") }}
            </NsButton>
            <NsButton
              kind="tertiary"
              :icon="CloudUpload20"
              :disabled="loading.zones || loading.records || !zone"
              @click="isImportShown = true"
              class="mg-bottom-md"
            >
              {{ $t("import.button") }}
            </NsButton>
          </cv-column>
        </cv-row>
        <cv-row v-if="pending.length">
          <cv-column>
            <PendingChanges
              :changes="pending"
              :disabled="isReviewShown"
              @review="isReviewShown = true"
              @discard="discardPending"
              @undo="undo"
            />
          </cv-column>
        </cv-row>
        <cv-row>
          <cv-column>
            <div class="view-bar mg-bottom-sm">
              <span class="view-label">{{ $t("view.types") }}</span>
              <NsButton
                v-for="t in presentTypes"
                :key="t"
                :kind="typeFilter.includes(t) ? 'primary' : 'tertiary'"
                size="small"
                class="type-chip"
                @click="toggleType(t)"
                >{{ t }}</NsButton
              >
              <NsButton
                v-if="typeFilter.length"
                kind="ghost"
                size="small"
                @click="typeFilter = []"
                >{{ $t("view.all_types") }}</NsButton
              >
              <span class="bulk-spacer"></span>
              <NsCheckbox
                v-model="fullNames"
                value="fullNames"
                :label="$t('view.full_names')"
                :formItem="false"
                class="names-check"
              />
            </div>
            <div class="bulk-bar mg-bottom-sm">
              <NsButton
                kind="ghost"
                size="small"
                :disabled="loading.records || !page.length"
                @click="selectPage"
                >{{ $t("bulk.select_page") }}</NsButton
              >
              <NsButton
                v-if="selected.length"
                kind="ghost"
                size="small"
                @click="selected = []"
                >{{
                  $t("bulk.clear_selection", { count: selected.length })
                }}</NsButton
              >
              <span class="bulk-spacer"></span>
              <NsButton
                kind="tertiary"
                size="small"
                :icon="TrashCan20"
                :disabled="!selected.length"
                @click="stageSelectedDelete"
                >{{ $t("bulk.delete_selected") }}</NsButton
              >
              <NsButton
                kind="tertiary"
                size="small"
                :icon="Time20"
                :disabled="!selected.length"
                @click="showTtl"
                >{{ $t("bulk.set_ttl") }}</NsButton
              >
              <NsButton
                kind="tertiary"
                size="small"
                :icon="Search20"
                :disabled="loading.records || !changeable.length"
                @click="isFindShown = true"
                >{{ $t("bulk.find_replace") }}</NsButton
              >
            </div>
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
                    <div class="name-cell">
                      <NsCheckbox
                        v-if="isChangeable(row)"
                        v-model="selected"
                        :value="keyOf(row)"
                        :label="row.name"
                        hideLabel
                        :formItem="false"
                        class="row-check"
                      />
                      <span v-else class="row-check-space"></span>
                      <strong
                        :class="{ 'same-name': sameAsPrevious(i) }"
                        :title="nameTitle(row)"
                        >{{ shownName(row) }}</strong
                      >
                    </div>
                  </cv-data-table-cell>
                  <cv-data-table-cell>
                    <NsTag :label="row.type" kind="blue" />
                  </cv-data-table-cell>
                  <cv-data-table-cell>{{ row.ttl || "-" }}</cv-data-table-cell>
                  <cv-data-table-cell>
                    <span class="record-data" :title="row.data">{{
                      shorten(row.data)
                    }}</span>
                    <NsTag
                      v-if="ownerOf(row)"
                      :label="$t('owners.tag', { module: ownerOf(row) })"
                      :title="$t('owners.tag_help', { module: ownerOf(row) })"
                      kind="teal"
                      class="mg-left-sm"
                    />
                    <NsTag
                      v-if="pendingKeys[keyOf(row)]"
                      :label="$t('pending.row_' + pendingKeys[keyOf(row)])"
                      :kind="pendingKeys[keyOf(row)] === 'delete' ? 'red' : 'purple'"
                      class="mg-left-sm"
                    />
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
                      v-else-if="pendingKeys[keyOf(row)]"
                      flip-menu
                      class="table-overflow-menu"
                    >
                      <cv-overflow-menu-item @click="undoRow(row)">
                        <NsMenuItem
                          :icon="Reset20"
                          :label="$t('pending.undo_row')"
                        />
                      </cv-overflow-menu-item>
                    </cv-overflow-menu>
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
    <ReviewChanges
      :isShown="isReviewShown"
      :zone="zone"
      :changes="pending"
      @hide="isReviewShown = false"
      @applied="onApplied"
      @reload="reloadFromReview"
    />
    <ImportZone
      :isShown="isImportShown"
      :zone="zone"
      @hide="isImportShown = false"
      @stage="stageFromImport"
    />
    <FindReplace
      :isShown="isFindShown"
      :records="changeable"
      :selected="selectedRecords"
      @hide="isFindShown = false"
      @stage="stageFromFind"
    />
    <!-- a new TTL for the selected records -->
    <NsModal
      size="xs"
      :visible="isTtlShown"
      @modal-hidden="isTtlShown = false"
      @primary-click="stageTtl"
    >
      <template slot="title">{{ $t("bulk.ttl_title") }}</template>
      <template slot="content">
        <cv-form @submit.prevent="stageTtl">
          <p class="mg-bottom-md">
            {{ $t("bulk.ttl_intro", { count: selected.length }) }}
          </p>
          <NsTextInput
            v-model.trim="ttlValue"
            :label="$t('records.col_ttl')"
            :helper-text="$t('records.ttl_help')"
            placeholder="300"
            :invalid-message="$t(error.ttl)"
            ref="ttlValue"
          />
        </cv-form>
      </template>
      <template slot="secondary-button">{{
        core.$t("common.cancel")
      }}</template>
      <template slot="primary-button">{{ $t("bulk.add_to_pending") }}</template>
    </NsModal>
    <!-- add or edit a record -->
    <NsModal
      size="default"
      :visible="isFormShown"
      :primary-button-disabled="loading.save"
      :isLoading="loading.save"
      @modal-hidden="isFormShown = false"
      @primary-click="saveRecord"
      @other-btn-click="stageRecord"
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
          <NsInlineNotification
            v-if="ownerOf(current)"
            kind="warning"
            :title="$t('owners.warning_title', { module: ownerOf(current) })"
            :description="$t('owners.warning', { module: ownerOf(current) })"
            :showCloseButton="false"
          />
          <RecordForm
            v-if="isFormShown"
            :key="formKey"
            ref="form"
            :types="types"
            :existing="records"
            :initial="current"
            :disabled="loading.save"
            @draft="formDraft = $event"
          />
          <div v-if="newPtr || oldPtrRemovable" class="ptr-box mg-bottom-md">
            <NsCheckbox
              v-if="newPtr && !ptrAlready"
              v-model="ptr.wanted"
              value="ptrWanted"
              :label="
                $t('ptr.set', {
                  name: newPtr.name,
                  zone: newPtr.zone,
                  host: newPtr.host,
                })
              "
              :disabled="loading.save"
            />
            <p v-if="newPtr && ptrAlready" class="ptr-note">
              {{ $t("ptr.already", { zone: newPtr.zone, host: newPtr.host }) }}
            </p>
            <p
              v-else-if="newPtr && ptr.current.length && ptr.wanted"
              class="ptr-note"
            >
              {{
                $t("ptr.replaces", {
                  values: ptr.current.map((r) => r.data).join(", "),
                })
              }}
            </p>
            <NsCheckbox
              v-if="oldPtrRemovable"
              v-model="ptrOld.wanted"
              value="ptrOldWanted"
              :label="
                $t('ptr.remove_old', {
                  name: oldPtr.name,
                  zone: oldPtr.zone,
                })
              "
              :disabled="loading.save"
            />
            <p class="ptr-note">{{ $t("ptr.separate") }}</p>
          </div>
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
      <template slot="other-button">{{ $t("bulk.to_pending") }}</template>
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
      @other-btn-click="stageDelete"
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
        <div v-if="deletePtr.records.length" class="ptr-box mg-bottom-md">
          <NsCheckbox
            v-model="deletePtr.wanted"
            value="deletePtrWanted"
            :label="
              $t('ptr.delete_too', {
                name: deletePtr.target.name,
                zone: deletePtr.target.zone,
              })
            "
            :disabled="loading.remove"
          />
          <p class="ptr-note">{{ $t("ptr.separate") }}</p>
        </div>
        <NsInlineNotification
          v-if="ownerOf(current)"
          kind="warning"
          :title="$t('owners.warning_title', { module: ownerOf(current) })"
          :description="$t('owners.warning', { module: ownerOf(current) })"
          :showCloseButton="false"
        />
        <NsInlineNotification
          v-if="error.remove"
          kind="error"
          :title="$t('action.delete-records')"
          :description="error.remove"
          :showCloseButton="false"
        />
      </template>
      <template slot="other-button">{{ $t("bulk.to_pending") }}</template>
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
import PendingChanges from "../components/PendingChanges";
import ReviewChanges from "../components/ReviewChanges";
import FindReplace from "../components/FindReplace";
import ImportZone from "../components/ImportZone";
import {
  ownerKey,
  recordKey,
  setTtl,
  stage,
  touchedKeys,
} from "../lib/pending";
import Time20 from "@carbon/icons-vue/es/time/20";
import { displayName, toUnicode } from "../lib/records";
import { pointsTo, ptrTarget } from "../lib/reverse";

function hostOfRecord(r, zone) {
  return (r.name === "@" ? zone : `${r.name}.${zone}`) + ".";
}

const COMMON_TYPES = ["A", "AAAA", "CNAME", "MX", "SRV", "TXT", "NS", "CAA"];

export default {
  name: "Records",
  components: {
    ZoneSnapshots,
    RecordForm,
    PendingChanges,
    ReviewChanges,
    FindReplace,
    ImportZone,
  },
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
      // ownerKey -> "module/<id>", for records a module wrote
      owners: {},
      page: [],
      current: null,
      isFormShown: false,
      formKey: 0,
      isRemoveShown: false,
      isSnapshotsShown: false,
      // changes collected for one apply-changes (see lib/pending.js)
      pending: [],
      // keys (recordKey) of the selected rows
      selected: [],
      // linked PTR records: the form's record as it stands, the PTR records
      // now at its reverse name, and those of the record being edited
      formDraft: null,
      ptr: { wanted: true, current: [], key: "" },
      ptrOld: { wanted: true, current: [] },
      deletePtr: { wanted: true, records: [], target: null },
      ptrWarning: "",
      // view: only these types (none: all); names in full
      typeFilter: [],
      fullNames: false,
      isReviewShown: false,
      isFindShown: false,
      isImportShown: false,
      isTtlShown: false,
      ttlValue: "",
      Time20,
      notice: { title: "", text: "" },
      loading: {
        zones: true,
        records: false,
        save: false,
        remove: false,
        export: false,
      },
      error: {
        load: "",
        save: "",
        stale: false,
        remove: "",
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
      return this.records
        .map((r, index) => ({ ...r, index }))
        .filter((r) => !this.typeFilter.length || this.typeFilter.includes(r.type));
    },
    // the record types in the zone, for the type filter
    presentTypes() {
      return [...new Set(this.records.map((r) => r.type))].sort();
    },
    // managed reverse zones whose DNS host can hold PTR records
    reverseZones() {
      return this.zones.filter((z) => {
        const info = this.zoneInfo[z];
        const p = info && this.providers.find((x) => x.name === info.provider);
        return z.endsWith(".arpa") && p && p.types.includes("PTR");
      });
    },
    newPtr() {
      return ptrTarget(this.formDraft, this.zone, this.reverseZones);
    },
    oldPtr() {
      return this.current
        ? ptrTarget(this.current, this.zone, this.reverseZones)
        : null;
    },
    // the PTR already points at the record's host: nothing to do
    ptrAlready() {
      return (
        !!this.newPtr &&
        this.ptr.current.length === 1 &&
        pointsTo(this.ptr.current[0].data, this.newPtr.host)
      );
    },
    // the old address had a PTR to the old host, at another reverse name
    oldPtrRemovable() {
      const o = this.oldPtr;
      const n = this.newPtr;
      if (!o || !this.ptrOld.current.length) {
        return false;
      }
      return !n || n.zone !== o.zone || n.name !== o.name;
    },
    pendingKeys() {
      return touchedKeys(this.pending);
    },
    // records that may be changed: not read-only, no pending change yet
    changeable() {
      return this.records.filter((r) => this.isChangeable(r));
    },
    selectedRecords() {
      const keys = new Set(this.selected);
      return this.records.filter((r) => keys.has(recordKey(r)));
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
    newPtr(t) {
      const key = t ? `${t.zone}|${t.name}` : "";
      if (key === this.ptr.key) {
        return;
      }
      this.ptr = { wanted: true, current: [], key };
      if (t) {
        clearTimeout(this.ptrTimer);
        this.ptrTimer = setTimeout(async () => {
          const found = await this.lookupPtr(t);
          if (this.ptr.key === key) {
            this.ptr.current = found;
          }
        }, 400);
      }
    },
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
      if (this.q.zone !== this.zone) {
        this.typeFilter = [];
      }
      this.q.zone = this.zone;
      this.loading.records = true;
      this.error.load = "";
      try {
        const out = await this.callAction("get-records", {
          data: { zone: this.zone },
        });
        this.records = out.records.slice().sort(this.compareRecords);
        this.loadOwners();
        // a selected record may be gone
        const keys = new Set(this.records.map(recordKey));
        this.selected = this.selected.filter((k) => keys.has(k));
      } catch (err) {
        this.records = [];
        this.error.load = this.errorText(err);
      }
      this.loading.records = false;
    },
    // which module wrote which record; the page works without it
    async loadOwners() {
      try {
        const out = await this.callAction("list-owners", {
          data: { zone: this.zone },
        });
        const owners = {};
        for (const o of out.owners) {
          owners[ownerKey(o)] = o.caller;
        }
        this.owners = owners;
      } catch (err) {
        this.owners = {};
      }
    },
    ownerOf(r) {
      const who = r ? this.owners[ownerKey(r)] : "";
      return who ? who.replace(/^module\//, "") : "";
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
    /** The PTR records at a reverse name; [] when they cannot be read. */
    async lookupPtr(t) {
      try {
        const out = await this.callAction("get-records", {
          data: { zone: t.zone, name: t.name, type: "PTR" },
        });
        return out.records;
      } catch (err) {
        return [];
      }
    },
    /** apply-changes on reverse zones; returns a warning text or "". */
    async applyPtr(plans, host) {
      const problems = [];
      for (const p of plans) {
        try {
          await this.callAction("apply-changes", {
            data: {
              zone: p.zone,
              remove: p.remove.map((r) => ({ name: r.name, type: r.type, data: r.data })),
              add: p.add,
              label: this.$t("ptr.label", { host }),
            },
          });
        } catch (err) {
          problems.push(`${p.zone}: ${this.errorText(err)}`);
        }
      }
      return problems.length
        ? this.$t("ptr.failed", { problems: problems.join(" ") })
        : "";
    },
    ptrPlans() {
      const plans = [];
      const n = this.newPtr;
      if (n && this.ptr.wanted && !this.ptrAlready) {
        plans.push({
          zone: n.zone,
          remove: this.ptr.current,
          add: [{ name: n.name, type: "PTR", data: n.host }],
        });
      }
      if (this.oldPtrRemovable && this.ptrOld.wanted) {
        const o = this.oldPtr;
        const remove = this.ptrOld.current.filter((r) => pointsTo(r.data, o.host));
        const same = plans.find((p) => p.zone === o.zone);
        if (same) {
          same.remove = same.remove.concat(remove);
        } else if (remove.length) {
          plans.push({ zone: o.zone, remove, add: [] });
        }
      }
      return plans;
    },
    toggleType(t) {
      this.typeFilter = this.typeFilter.includes(t)
        ? this.typeFilter.filter((x) => x !== t)
        : this.typeFilter.concat([t]);
    },
    shownName(row) {
      return toUnicode(displayName(row.name, this.zone, this.fullNames));
    },
    // the name as stored, when it is shown in Unicode
    nameTitle(row) {
      const raw = displayName(row.name, this.zone, this.fullNames);
      return raw !== this.shownName(row) ? raw : "";
    },
    // rows of one name read as a group: the name is dimmed after the first
    sameAsPrevious(i) {
      return i > 0 && this.page[i - 1] && this.page[i - 1].name === this.page[i].name;
    },
    keyOf(row) {
      return recordKey(row);
    },
    isChangeable(r) {
      return !this.isProtected(r) && !this.pendingKeys[recordKey(r)];
    },
    // the record as get-records reported it, without the table's index
    plain(row) {
      return { name: row.name, type: row.type, ttl: row.ttl, data: row.data };
    },
    selectPage() {
      const keys = new Set(this.selected);
      for (const row of this.page) {
        if (this.isChangeable(row)) {
          keys.add(recordKey(row));
        }
      }
      this.selected = [...keys];
    },
    /** Add changes to the pending list and say what happened. */
    stageChanges(changes) {
      const out = stage(this.pending, changes);
      this.pending = out.pending;
      const staged = new Set(changes.filter((c) => c.old).map((c) => recordKey(c.old)));
      this.selected = this.selected.filter((k) => !staged.has(k));
      this.notice = {
        title: this.$t("pending.staged_title"),
        text:
          this.$tc("pending.staged", out.added, { count: out.added }) +
          (out.skipped
            ? " " + this.$tc("pending.skipped", out.skipped, { count: out.skipped })
            : ""),
      };
    },
    undo(change) {
      this.pending = this.pending.filter((c) => c !== change);
      this.clearPendingNotice();
    },
    undoRow(row) {
      const key = recordKey(row);
      this.pending = this.pending.filter((c) => !(c.old && recordKey(c.old) === key));
      this.clearPendingNotice();
    },
    discardPending() {
      this.pending = [];
      this.clearPendingNotice();
    },
    // "n changes are pending" is wrong once the list changed
    clearPendingNotice() {
      if (this.notice.title === this.$t("pending.staged_title")) {
        this.notice = { title: "", text: "" };
      }
    },
    stageRecord() {
      this.error.save = "";
      const record = this.$refs.form.build();
      if (!record) {
        return;
      }
      const old = this.current;
      this.stageChanges([
        old ? { kind: "edit", old, new: record } : { kind: "add", new: record },
      ]);
      this.isFormShown = false;
    },
    stageDelete() {
      this.stageChanges([{ kind: "delete", old: this.plain(this.current) }]);
      this.isRemoveShown = false;
    },
    stageSelectedDelete() {
      this.stageChanges(
        this.selectedRecords.map((r) => ({ kind: "delete", old: this.plain(r) }))
      );
    },
    showTtl() {
      this.ttlValue = "";
      this.error.ttl = "";
      this.isTtlShown = true;
    },
    stageTtl() {
      const ttl = Number(this.ttlValue);
      if (!Number.isInteger(ttl) || ttl < 1 || ttl > 2147483647) {
        this.error.ttl = "records.invalid_ttl";
        this.focusElement("ttlValue");
        return;
      }
      this.stageChanges(setTtl(this.selectedRecords.map(this.plain), ttl));
      this.isTtlShown = false;
    },
    stageFromImport(changes) {
      this.stageChanges(
        changes.map((c) => (c.old ? { ...c, old: this.plain(c.old) } : c))
      );
      this.isImportShown = false;
    },
    async exportZone() {
      this.loading.export = true;
      this.error.load = "";
      try {
        const out = await this.callAction("export-zone", {
          data: { zone: this.zone },
        });
        this.downloadText(out.filename, out.text);
      } catch (err) {
        this.error.load = this.errorText(err);
      }
      this.loading.export = false;
    },
    stageFromFind(changes) {
      this.stageChanges(
        changes.map((c) => ({ ...c, old: this.plain(c.old) }))
      );
      this.isFindShown = false;
    },
    onApplied({ applied, complete }) {
      const done = new Set(applied);
      this.pending = this.pending.filter((c) => !done.has(c));
      if (complete) {
        this.isReviewShown = false;
        this.notice = {
          title: this.$t("pending.applied_title"),
          text: this.$tc("pending.applied", applied.length, {
            count: applied.length,
          }),
        };
      }
      this.loadRecords();
    },
    async reloadFromReview() {
      this.isReviewShown = false;
      await this.loadRecords();
    },
    showAdd() {
      this.openForm(null);
    },
    showEdit(row) {
      this.openForm(this.plain(row));
    },
    openForm(record) {
      this.current = record;
      this.formDraft = null;
      this.ptr = { wanted: true, current: [], key: "" };
      this.ptrOld = { wanted: true, current: [] };
      const old = record ? ptrTarget(record, this.zone, this.reverseZones) : null;
      if (old) {
        this.lookupPtr(old).then((found) => {
          if (this.current === record) {
            this.ptrOld.current = found.filter((r) => pointsTo(r.data, old.host));
          }
        });
      }
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
        const plans = this.ptrPlans();
        this.ptrWarning = plans.length
          ? await this.applyPtr(plans, hostOfRecord(record, this.zone))
          : "";
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
      this.deletePtr = { wanted: true, records: [], target: null };
      const t = ptrTarget(row, this.zone, this.reverseZones);
      if (t) {
        this.lookupPtr(t).then((found) => {
          if (this.current === row) {
            this.deletePtr = {
              wanted: true,
              records: found.filter((r) => pointsTo(r.data, t.host)),
              target: t,
            };
          }
        });
      }
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
        const dp = this.deletePtr;
        this.ptrWarning =
          dp.wanted && dp.records.length
            ? await this.applyPtr(
                [{ zone: dp.target.zone, remove: dp.records, add: [] }],
                dp.target.host
              )
            : "";
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

.view-bar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: $spacing-03;
}

.view-label {
  font-size: 0.875rem;
  margin-right: $spacing-02;
}

.type-chip {
  min-height: 2rem;
  padding-right: $spacing-05;
}

.same-name {
  opacity: 0.45;
  font-weight: normal;
}

.ptr-box {
  padding: $spacing-03 $spacing-05;
  background-color: rgba(141, 141, 141, 0.08);
}

.ptr-note {
  font-size: 0.875rem;
  margin-top: $spacing-02;
}

.bulk-bar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: $spacing-03;
}

.bulk-spacer {
  flex: 1;
}

.name-cell {
  display: flex;
  align-items: center;
  gap: $spacing-03;
}

.row-check ::v-deep .bx--checkbox-label {
  padding-left: 1rem;
}

.row-check-space {
  display: inline-block;
  width: 1rem;
}

.record-summary {
  padding: $spacing-03 $spacing-05;
  background-color: rgba(141, 141, 141, 0.16);
  overflow-wrap: anywhere;
}
</style>
