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
          <NsButton
            kind="primary"
            :icon="Add20"
            :disabled="loading.load"
            @click="isWizardShown = true"
            class="mg-bottom-md"
          >
            {{ $t("zones.add_zone") }}
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
                    <cv-overflow-menu-item @click="showChangeCredential(row)">
                      <NsMenuItem
                        :icon="Edit20"
                        :label="$t('zones.change_credential')"
                      />
                    </cv-overflow-menu-item>
                    <NsMenuDivider />
                    <cv-overflow-menu-item danger @click="showRemoveZone(row)">
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
                </cv-data-table-cell>
                <cv-data-table-cell>{{ row.providerLabel }}</cv-data-table-cell>
                <cv-data-table-cell>
                  <span v-if="!row.secrets_set.length">-</span>
                  <cv-tag
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
                  <cv-overflow-menu flip-menu class="table-overflow-menu">
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
      :credentials="credentials"
      :managedZones="zones.map((z) => z.zone)"
      @hide="isWizardShown = false"
      @added="zoneAdded"
    />
    <CredentialModal
      :isShown="isEditCredentialShown"
      :credential="current"
      :providers="providers"
      @hide="isEditCredentialShown = false"
      @saved="load"
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
    <NsDangerDeleteModal
      :isShown="isRemoveZoneShown"
      :name="current ? current.zone : ''"
      :title="$t('zones.remove_zone_title')"
      :warning="core.$t('common.please_read_carefully')"
      :description="
        $t('zones.remove_zone_description', {
          zone: current ? current.zone : '',
        })
      "
      :typeToConfirm="current ? current.zone : ''"
      :isErrorShown="!!error.removeZone"
      :errorTitle="$t('action.remove-zone')"
      :errorDescription="error.removeZone"
      :loading="loading.removeZone"
      @hide="isRemoveZoneShown = false"
      @confirmDelete="removeZone"
    >
      <template slot="explanation">
        <p class="mg-top-sm">{{ $t("zones.remove_zone_explanation") }}</p>
      </template>
    </NsDangerDeleteModal>
    <!-- remove a credential -->
    <NsDangerDeleteModal
      :isShown="isRemoveCredentialShown"
      :name="current ? current.name : ''"
      :title="$t('credentials.remove_title')"
      :warning="core.$t('common.please_read_carefully')"
      :description="
        $t('credentials.remove_description', {
          name: current ? current.name : '',
        })
      "
      :typeToConfirm="current ? current.name : ''"
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

export default {
  name: "Zones",
  components: { ZoneWizard, CredentialModal },
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
        providerLabel: this.providerLabel(c.provider),
        zones: this.zones
          .filter((z) => z.credential === c.id)
          .map((z) => z.zone),
      }));
    },
    credentialOptions() {
      return this.credentials.map((c) => ({
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
        this.load();
      } catch (err) {
        this.error.removeZone = this.errorText(err);
      }
      this.loading.removeZone = false;
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
