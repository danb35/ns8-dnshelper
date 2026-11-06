<!--
  Copyright (C) 2026 dnshelper contributors
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <div>
    <cv-grid fullWidth>
      <cv-row>
        <cv-column class="page-title">
          <h2>{{ $t("zones.title") }}</h2>
        </cv-column>
      </cv-row>
      <cv-row v-if="error.load">
        <cv-column>
          <NsInlineNotification
            kind="error"
            :title="$t('zones.cannot_load')"
            :description="error.load"
            :showCloseButton="false"
          />
        </cv-column>
      </cv-row>
      <cv-row v-if="notice.text">
        <cv-column>
          <NsInlineNotification
            :kind="notice.kind"
            :title="notice.title"
            :description="notice.text"
            @close="notice.text = ''"
          />
        </cv-column>
      </cv-row>
      <!-- zones -->
      <cv-row>
        <cv-column>
          <p class="section-intro">{{ $t("zones.intro") }}</p>
          <p v-if="hasAdopted" class="section-intro">
            {{ $t("zones.adopted_intro") }}
          </p>
          <NsButton
            kind="primary"
            :icon="Add20"
            :disabled="loading.load"
            @click="isWizardShown = true"
            class="mg-bottom-md mg-right-sm"
          >
            {{ $t("zones.add_zone") }}
          </NsButton>
          <NsButton
            kind="tertiary"
            :icon="Renew20"
            :disabled="loading.load || loading.sync"
            :loading="loading.sync"
            @click="syncPowerdns"
            class="mg-bottom-md"
          >
            {{ $t("zones.sync_powerdns") }}
          </NsButton>
        </cv-column>
      </cv-row>
      <cv-row>
        <cv-column>
          <NsDataTable
            :allRows="zoneRows"
            :columns="zoneColumns"
            :rawColumns="['zone', 'provider', 'credential']"
            :sortable="true"
            :pageSizes="[10, 25, 50]"
            :overflow-menu="true"
            isSearchable
            :searchPlaceholder="$t('zones.search')"
            :searchClearLabel="core.$t('common.clear_search')"
            :noSearchResultsLabel="core.$t('common.no_search_results')"
            :noSearchResultsDescription="
              core.$t('common.no_search_results_description')
            "
            :isLoading="loading.load"
            :skeletonRows="3"
            :itemsPerPageLabel="core.$t('pagination.items_per_page')"
            :rangeOfTotalItemsLabel="core.$t('pagination.range_of_total_items')"
            :ofTotalPagesLabel="core.$t('pagination.of_total_pages')"
            :backwardText="core.$t('pagination.previous_page')"
            :forwardText="core.$t('pagination.next_page')"
            :pageNumberLabel="core.$t('pagination.page_number')"
            @updatePage="zonePage = $event"
          >
            <template slot="empty-state">
              <NsEmptyState :title="$t('zones.no_zones')">
                <template #description>
                  <div>{{ $t("zones.no_zones_description") }}</div>
                </template>
              </NsEmptyState>
            </template>
            <template slot="data">
              <cv-data-table-row
                v-for="(row, i) in zonePage"
                :key="row.zone"
                :value="String(i)"
              >
                <cv-data-table-cell>
                  <strong>{{ row.zone }}</strong>
                  <NsTag
                    v-if="row.managedBy"
                    :label="$t('zones.adopted_from', { module: row.managedBy })"
                    kind="purple"
                    class="mg-left-sm"
                  />
                </cv-data-table-cell>
                <cv-data-table-cell>{{ row.providerLabel }}</cv-data-table-cell>
                <cv-data-table-cell>{{
                  row.credentialName
                }}</cv-data-table-cell>
                <cv-data-table-cell class="table-overflow-menu-cell">
                  <cv-overflow-menu flip-menu class="table-overflow-menu">
                    <cv-overflow-menu-item @click="validateZone(row)">
                      <NsMenuItem
                        :icon="Checkmark20"
                        :label="$t('zones.validate')"
                      />
                    </cv-overflow-menu-item>
                    <cv-overflow-menu-item
                      v-if="!row.managedBy"
                      @click="showChangeCredential(row)"
                    >
                      <NsMenuItem
                        :icon="Edit20"
                        :label="$t('zones.change_credential')"
                      />
                    </cv-overflow-menu-item>
                    <NsMenuDivider v-if="!row.managedBy" />
                    <cv-overflow-menu-item
                      v-if="!row.managedBy"
                      danger
                      @click="showRemoveZone(row)"
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
      <!-- credentials -->
      <cv-row>
        <cv-column class="page-subtitle">
          <h4>{{ $t("credentials.title") }}</h4>
        </cv-column>
      </cv-row>
      <cv-row>
        <cv-column>
          <p class="section-intro">{{ $t("credentials.intro") }}</p>
        </cv-column>
      </cv-row>
      <cv-row v-if="error.credential">
        <cv-column>
          <NsInlineNotification
            kind="error"
            :title="$t('credentials.cannot_delete')"
            :description="error.credential"
            :showCloseButton="false"
          />
        </cv-column>
      </cv-row>
      <cv-row>
        <cv-column>
          <NsDataTable
            :allRows="credentialRows"
            :columns="credentialColumns"
            :rawColumns="['name', 'provider', 'secrets', 'zones']"
            :sortable="true"
            :pageSizes="[10, 25, 50]"
            :overflow-menu="true"
            :isLoading="loading.load"
            :skeletonRows="2"
            :itemsPerPageLabel="core.$t('pagination.items_per_page')"
            :rangeOfTotalItemsLabel="core.$t('pagination.range_of_total_items')"
            :ofTotalPagesLabel="core.$t('pagination.of_total_pages')"
            :backwardText="core.$t('pagination.previous_page')"
            :forwardText="core.$t('pagination.next_page')"
            :pageNumberLabel="core.$t('pagination.page_number')"
            @updatePage="credentialPage = $event"
          >
            <template slot="empty-state">
              <NsEmptyState :title="$t('credentials.no_credentials')">
                <template #description>
                  <div>{{ $t("credentials.no_credentials_description") }}</div>
                </template>
              </NsEmptyState>
            </template>
            <template slot="data">
              <cv-data-table-row
                v-for="(row, i) in credentialPage"
                :key="row.id"
                :value="String(i)"
              >
                <cv-data-table-cell>
                  <strong>{{ row.name }}</strong>
                  <NsTag
                    v-if="row.managedBy"
                    :label="$t('zones.adopted_from', { module: row.managedBy })"
                    kind="purple"
                    class="mg-left-sm"
                  />
                </cv-data-table-cell>
                <cv-data-table-cell>{{ row.providerLabel }}</cv-data-table-cell>
                <cv-data-table-cell>
                  <span v-if="!row.secrets_set.length">-</span>
                  <NsTag
                    v-for="s in row.secrets_set"
                    :key="s"
                    :label="s + ': ' + $t('credentials.set')"
                    kind="green"
                  />
                </cv-data-table-cell>
                <cv-data-table-cell>
                  <span v-if="!row.zones.length">{{
                    $t("credentials.unused")
                  }}</span>
                  <span v-else>{{ row.zones.join(", ") }}</span>
                </cv-data-table-cell>
                <cv-data-table-cell class="table-overflow-menu-cell">
                  <cv-overflow-menu
                    v-if="!row.managedBy"
                    flip-menu
                    class="table-overflow-menu"
                  >
                    <cv-overflow-menu-item @click="showEditCredential(row)">
                      <NsMenuItem
                        :icon="Edit20"
                        :label="core.$t('common.edit')"
                      />
                    </cv-overflow-menu-item>
                    <NsMenuDivider />
                    <cv-overflow-menu-item
                      danger
                      :disabled="row.zones.length > 0"
                      @click="showRemoveCredential(row)"
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
    </cv-grid>

    <ZoneWizard
      :isShown="isWizardShown"
      :providers="providers"
      :credentials="manualCredentials"
      :managedZones="zones.map((z) => z.zone)"
      @hide="isWizardShown = false"
      @added="zoneAdded"
    />
    <CredentialModal
      :isShown="isEditCredentialShown"
      :credential="current"
      :providers="providers"
      @hide="isEditCredentialShown = false"
      @saved="credentialSaved"
    />
    <!-- change the credential of a zone -->
    <NsModal
      size="default"
      :visible="isChangeCredentialShown"
      :primary-button-disabled="loading.changeCredential || !newCredential"
      :isLoading="loading.changeCredential"
      @modal-hidden="isChangeCredentialShown = false"
      @primary-click="changeCredential"
    >
      <template slot="title">{{
        $t("zones.change_credential_title", {
          zone: current ? current.zone : "",
        })
      }}</template>
      <template slot="content">
        <div class="mg-bottom-md">{{ $t("zones.change_credential_help") }}</div>
        <NsComboBox
          :key="comboKey"
          :marginBottomOnOpen="true"
          v-model="newCredential"
          :options="credentialOptions"
          :title="$t('wizard.saved_credential')"
          :label="$t('wizard.choose_credential')"
          :disabled="loading.changeCredential"
        />
        <NsInlineNotification
          v-if="error.changeCredential"
          kind="error"
          :title="$t('action.update-zone')"
          :description="error.changeCredential"
          :showCloseButton="false"
        />
      </template>
      <template slot="secondary-button">{{
        core.$t("common.cancel")
      }}</template>
      <template slot="primary-button">{{ $t("common.save") }}</template>
    </NsModal>
    <!-- remove a zone -->
    <ConfirmDeleteModal
      :isShown="isRemoveZoneShown"
      :name="current ? current.zone : ''"
      :title="$t('zones.remove_zone_title')"
      :warning="core.$t('common.please_read_carefully')"
      :description="
        $t('zones.remove_zone_description', {
          zone: current ? current.zone : '',
        })
      "
      :isErrorShown="!!error.removeZone"
      :errorTitle="$t('action.remove-zone')"
      :errorDescription="error.removeZone"
      :loading="loading.removeZone"
      @hide="isRemoveZoneShown = false"
      @confirmDelete="removeZone"
    >
      <template slot="explanation">
        <p class="mg-top-sm">{{ $t("zones.remove_zone_explanation") }}</p>
        <p v-if="current && current.snapshots" class="mg-top-sm">
          <strong>{{
            $tc("zones.remove_zone_snapshots", current.snapshots, {
              count: current.snapshots,
            })
          }}</strong>
        </p>
      </template>
    </ConfirmDeleteModal>
    <!-- remove a credential -->
    <ConfirmDeleteModal
      :isShown="isRemoveCredentialShown"
      :name="current ? current.name : ''"
      :title="$t('credentials.remove_title')"
      :warning="core.$t('common.please_read_carefully')"
      :description="
        $t('credentials.remove_description', {
          name: current ? current.name : '',
        })
      "
      :isErrorShown="!!error.removeCredential"
      :errorTitle="$t('action.remove-credential')"
      :errorDescription="error.removeCredential"
      :loading="loading.removeCredential"
      @hide="isRemoveCredentialShown = false"
      @confirmDelete="removeCredential"
    />
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
import ZoneWizard from "../components/ZoneWizard";
import CredentialModal from "../components/CredentialModal";
import ConfirmDeleteModal from "../components/ConfirmDeleteModal";

export default {
  name: "Zones",
  components: { ZoneWizard, CredentialModal, ConfirmDeleteModal },
  mixins: [
    DnsHelperService,
    QueryParamService,
    IconService,
    UtilService,
    PageTitleService,
  ],
  pageTitle() {
    return this.$t("zones.title") + " - " + this.appName;
  },
  data() {
    return {
      q: { page: "zones" },
      urlCheckInterval: null,
      providers: [],
      credentials: [],
      zones: [],
      zonePage: [],
      credentialPage: [],
      current: null,
      newCredential: "",
      comboKey: 0,
      isWizardShown: false,
      isEditCredentialShown: false,
      isChangeCredentialShown: false,
      isRemoveZoneShown: false,
      isRemoveCredentialShown: false,
      notice: { kind: "success", title: "", text: "" },
      loading: {
        load: false,
        changeCredential: false,
        removeZone: false,
        removeCredential: false,
        sync: false,
      },
      error: {
        load: "",
        credential: "",
        changeCredential: "",
        removeZone: "",
        removeCredential: "",
      },
    };
  },
  computed: {
    ...mapState(["core", "appName"]),
    zoneColumns() {
      return ["zone", "provider", "credential"].map((c) =>
        this.$t("zones.col_" + c)
      );
    },
    credentialColumns() {
      return ["name", "provider", "secrets", "zones"].map((c) =>
        this.$t("credentials.col_" + c)
      );
    },
    providerLabel() {
      const labels = {};
      for (const p of this.providers) {
        labels[p.name] = p.label;
      }
      return (name) => labels[name] || name;
    },
    zoneRows() {
      return this.zones.map((z) => {
        const cred = this.credentials.find((c) => c.id === z.credential);
        return {
          zone: z.zone,
          credential: z.credential,
          snapshots: z.snapshots || 0,
          managedBy: this.moduleOf(z.managed_by),
          credentialName: cred
            ? cred.name
            : this.$t("zones.missing_credential"),
          providerLabel: cred ? this.providerLabel(cred.provider) : "-",
        };
      });
    },
    credentialRows() {
      return this.credentials.map((c) => ({
        ...c,
        managedBy: this.moduleOf(c.managed_by),
        providerLabel: this.providerLabel(c.provider),
        zones: this.zones
          .filter((z) => z.credential === c.id)
          .map((z) => z.zone),
      }));
    },
    hasAdopted() {
      return this.zones.some((z) => z.managed_by);
    },
    // credentials adopted from ns8-powerdns cannot be given to other zones
    manualCredentials() {
      return this.credentials.filter((c) => !c.managed_by);
    },
    credentialOptions() {
      return this.manualCredentials.map((c) => ({
        name: c.id,
        label: `${c.name} (${this.providerLabel(c.provider)})`,
        value: c.id,
      }));
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
      this.loading.load = true;
      this.error.load = "";
      try {
        const [providers, config] = await Promise.all([
          this.callAction("list-providers"),
          this.callAction("get-configuration"),
        ]);
        this.providers = providers.providers;
        this.credentials = config.credentials;
        this.zones = config.zones;
      } catch (err) {
        this.error.load = this.errorText(err);
      }
      this.loading.load = false;
    },
    say(kind, title, text) {
      this.notice = { kind, title, text };
    },
    // "module/powerdns1" -> "powerdns1"
    moduleOf(managedBy) {
      return managedBy ? managedBy.replace(/^module\//, "") : "";
    },
    async syncPowerdns() {
      this.loading.sync = true;
      try {
        const out = await this.callAction("sync-powerdns");
        const counts = {
          added: out.added.length + out.moved.length,
          removed: out.removed.length,
        };
        if (out.status === "multiple_primaries") {
          this.say(
            "warning",
            this.$t("zones.sync_multiple_title"),
            this.$t("zones.sync_multiple", { modules: out.modules.join(", ") })
          );
        } else if (out.status === "no_primary") {
          this.say(
            "info",
            this.$t("zones.sync_done_title"),
            this.$t("zones.sync_no_primary", counts)
          );
        } else {
          let text = this.$t("zones.sync_adopted", {
            ...counts,
            module: out.primary,
          });
          if (out.skipped.length) {
            text +=
              " " +
              this.$t("zones.sync_skipped", { zones: out.skipped.join(", ") });
          }
          this.say("success", this.$t("zones.sync_done_title"), text);
        }
        this.load();
      } catch (err) {
        this.say("error", this.$t("zones.sync_failed"), this.errorText(err));
      }
      this.loading.sync = false;
    },
    zoneAdded(zone) {
      this.say(
        "success",
        this.$t("zones.added_title"),
        this.$t("zones.added", { zone })
      );
      this.load();
    },
    async validateZone(row) {
      this.say(
        "info",
        this.$t("zones.validating_title"),
        this.$t("zones.validating", { zone: row.zone })
      );
      try {
        const out = await this.callAction("validate-zone", {
          data: { zone: row.zone },
        });
        this.say(
          "success",
          this.$t("zones.valid_title", { zone: row.zone }),
          this.$t("wizard.validated_" + out.validation.method)
        );
      } catch (err) {
        this.say(
          "error",
          this.$t("zones.invalid_title", { zone: row.zone }),
          this.errorText(err)
        );
      }
    },
    showChangeCredential(row) {
      this.current = row;
      this.newCredential = "";
      this.comboKey++; // NsComboBox keeps its filter text between uses
      this.$nextTick(() => (this.newCredential = row.credential));
      this.error.changeCredential = "";
      this.isChangeCredentialShown = true;
    },
    async changeCredential() {
      this.loading.changeCredential = true;
      this.error.changeCredential = "";
      try {
        await this.callAction("update-zone", {
          data: { zone: this.current.zone, credential: this.newCredential },
        });
        this.isChangeCredentialShown = false;
        const cred = this.credentials.find((c) => c.id === this.newCredential);
        this.say(
          "success",
          this.$t("zones.credential_changed_title"),
          this.$t("zones.credential_changed", {
            zone: this.current.zone,
            name: cred ? cred.name : this.newCredential,
          })
        );
        this.load();
      } catch (err) {
        this.error.changeCredential = this.errorText(err);
      }
      this.loading.changeCredential = false;
    },
    showRemoveZone(row) {
      this.current = row;
      this.error.removeZone = "";
      this.isRemoveZoneShown = true;
    },
    async removeZone() {
      this.loading.removeZone = true;
      this.error.removeZone = "";
      try {
        await this.callAction("remove-zone", {
          data: { zone: this.current.zone },
        });
        this.isRemoveZoneShown = false;
        this.say(
          "success",
          this.$t("zones.removed_title"),
          this.$t("zones.removed", { zone: this.current.zone })
        );
        this.load();
      } catch (err) {
        this.error.removeZone = this.errorText(err);
      }
      this.loading.removeZone = false;
    },
    credentialSaved() {
      this.say(
        "success",
        this.$t("credentials.saved_title"),
        this.$t("credentials.saved", { name: this.current.name })
      );
      this.load();
    },
    showEditCredential(row) {
      this.current = row;
      this.isEditCredentialShown = true;
    },
    showRemoveCredential(row) {
      this.current = row;
      this.error.removeCredential = "";
      this.isRemoveCredentialShown = true;
    },
    async removeCredential() {
      this.loading.removeCredential = true;
      this.error.removeCredential = "";
      try {
        await this.callAction("remove-credential", {
          data: { id: this.current.id },
        });
        this.isRemoveCredentialShown = false;
        this.say(
          "success",
          this.$t("credentials.removed_title"),
          this.$t("credentials.removed", { name: this.current.name })
        );
        this.load();
      } catch (err) {
        this.error.removeCredential = this.errorText(err);
      }
      this.loading.removeCredential = false;
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
</style>
