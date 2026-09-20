<!--
  Copyright (C) 2026 dnshelper contributors
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <div>
    <cv-grid fullWidth>
      <cv-row>
        <cv-column class="page-title">
          <h2>{{ $t("access.title") }}</h2>
        </cv-column>
      </cv-row>
      <cv-row v-if="error.load">
        <cv-column>
          <NsInlineNotification
            kind="error"
            :title="$t('access.cannot_load')"
            :description="error.load"
            :showCloseButton="false"
          />
        </cv-column>
      </cv-row>
      <cv-row>
        <cv-column>
          <p class="section-intro">{{ $t("access.intro") }}</p>
          <p class="section-intro">{{ $t("access.roles_help") }}</p>
          <NsCodeSnippet
            :copyTooltip="core.$t('common.copy_to_clipboard')"
            :copy-feedback="core.$t('common.copied_to_clipboard')"
            :wrap-text="true"
            hideExpandButton
            class="mg-bottom-lg"
          >
            org.nethserver.authorizations=dnshelper@cluster:dnswriter
          </NsCodeSnippet>
          <NsButton
            kind="primary"
            :icon="Add20"
            :disabled="loading.load"
            @click="showAddRule"
            class="mg-bottom-md"
          >
            {{ $t("access.add_rule") }}
          </NsButton>
        </cv-column>
      </cv-row>
      <cv-row>
        <cv-column>
          <NsDataTable
            :allRows="rows"
            :columns="columns"
            :rawColumns="['caller', 'zones', 'access', 'names', 'types']"
            :sortable="true"
            :pageSizes="[10, 25, 50]"
            :overflow-menu="true"
            :isLoading="loading.load"
            :skeletonRows="3"
            :itemsPerPageLabel="core.$t('pagination.items_per_page')"
            :rangeOfTotalItemsLabel="core.$t('pagination.range_of_total_items')"
            :ofTotalPagesLabel="core.$t('pagination.of_total_pages')"
            :backwardText="core.$t('pagination.previous_page')"
            :forwardText="core.$t('pagination.next_page')"
            :pageNumberLabel="core.$t('pagination.page_number')"
            @updatePage="page = $event"
          >
            <template slot="empty-state">
              <NsEmptyState :title="$t('access.no_rules')">
                <template #description>
                  <div>{{ $t("access.no_rules_description") }}</div>
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
                  <strong>{{ row.caller }}</strong>
                </cv-data-table-cell>
                <cv-data-table-cell>
                  <template v-if="row.zones.includes('*')">{{
                    $t("access.all_zones")
                  }}</template>
                  <div v-else v-for="z in row.zones" :key="z">{{ z }}</div>
                </cv-data-table-cell>
                <cv-data-table-cell>{{
                  $t("access.access_" + row.access)
                }}</cv-data-table-cell>
                <cv-data-table-cell>
                  <cv-tag
                    v-for="n in row.names"
                    :key="n"
                    :label="n"
                    kind="gray"
                    class="mg-right-sm"
                  />
                </cv-data-table-cell>
                <cv-data-table-cell>
                  <cv-tag
                    v-for="t in row.types"
                    :key="t"
                    :label="t === '*' ? $t('access.all_types') : t"
                    kind="blue"
                    class="mg-right-sm"
                  />
                </cv-data-table-cell>
                <cv-data-table-cell class="table-overflow-menu-cell">
                  <cv-overflow-menu flip-menu class="table-overflow-menu">
                    <cv-overflow-menu-item @click="showEditRule(row)">
                      <NsMenuItem
                        :icon="Edit20"
                        :label="core.$t('common.edit')"
                      />
                    </cv-overflow-menu-item>
                    <NsMenuDivider />
                    <cv-overflow-menu-item danger @click="showRemoveRule(row)">
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
      <cv-row>
        <cv-column class="page-subtitle">
          <h4>{{ $t("access.audit_title") }}</h4>
        </cv-column>
      </cv-row>
      <cv-row>
        <cv-column :md="4" :max="4">
          <NsSystemLogsCard
            :title="$t('status.audit_log')"
            :description="$t('status.audit_log_description')"
            :buttonLabel="core.$t('system_logs.card_button_label')"
            :router="core.$router"
            context="module"
            :moduleId="instanceName"
            searchQuery="dnshelper audit"
            light
          />
        </cv-column>
      </cv-row>
    </cv-grid>

    <PolicyRuleModal
      :isShown="isRuleShown"
      :isEditing="!!editing"
      :rule="editing"
      :modules="modules"
      :zones="zoneNames"
      :loading="loading.save"
      :saveError="error.save"
      @hide="isRuleShown = false"
      @save="saveRule"
    />
    <NsDangerDeleteModal
      :isShown="isRemoveShown"
      :name="editing ? editing.caller : ''"
      :title="$t('access.remove_title')"
      :warning="core.$t('common.please_read_carefully')"
      :description="
        $t('access.remove_description', {
          caller: editing ? editing.caller : '',
        })
      "
      :typeToConfirm="
        $t('common.type_to_confirm', { name: editing ? editing.caller : '' })
      "
      :isErrorShown="!!error.save"
      :errorTitle="$t('action.set-policy')"
      :errorDescription="error.save"
      :loading="loading.save"
      @hide="isRemoveShown = false"
      @confirmDelete="removeRule"
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
import PolicyRuleModal from "../components/PolicyRuleModal";

export default {
  name: "Access",
  components: { PolicyRuleModal },
  mixins: [
    DnsHelperService,
    QueryParamService,
    IconService,
    UtilService,
    PageTitleService,
  ],
  pageTitle() {
    return this.$t("access.title") + " - " + this.appName;
  },
  data() {
    return {
      q: { page: "access" },
      urlCheckInterval: null,
      rules: [],
      zoneNames: [],
      modules: [],
      page: [],
      editing: null,
      isRuleShown: false,
      isRemoveShown: false,
      loading: { load: false, save: false },
      error: { load: "", save: "" },
    };
  },
  computed: {
    ...mapState(["core", "instanceName", "appName"]),
    columns() {
      return ["caller", "zones", "access", "names", "types"].map((c) =>
        this.$t("access.col_" + c)
      );
    },
    rows() {
      return this.rules.map((r, index) => ({ ...r, index }));
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
    this.loadModules();
  },
  methods: {
    async load() {
      this.loading.load = true;
      this.error.load = "";
      try {
        const [policy, config] = await Promise.all([
          this.callAction("get-policy"),
          this.callAction("get-configuration"),
        ]);
        this.rules = policy.rules;
        this.zoneNames = config.zones.map((z) => z.zone);
      } catch (err) {
        this.error.load = this.errorText(err);
      }
      this.loading.load = false;
    },
    // only to suggest caller names: a failure just leaves the field free-text
    async loadModules() {
      try {
        const installed = await this.callAction("list-installed-modules", {
          cluster: true,
        });
        this.modules = []
          .concat(...Object.values(installed))
          .filter((m) => m.id !== this.instanceName)
          .sort((a, b) => a.id.localeCompare(b.id))
          .map((m) => ({ id: m.id, name: m.ui_name || "" }));
      } catch (err) {
        console.warn("cannot list the installed modules", err);
      }
    },
    showAddRule() {
      this.editing = null;
      this.error.save = "";
      this.isRuleShown = true;
    },
    showEditRule(row) {
      this.editing = row;
      this.error.save = "";
      this.isRuleShown = true;
    },
    showRemoveRule(row) {
      this.editing = row;
      this.error.save = "";
      this.isRemoveShown = true;
    },
    saveRule(rule) {
      const rules = this.rules.map((r) => ({ ...r }));
      if (this.editing) {
        rules[this.editing.index] = rule;
      } else {
        rules.push(rule);
      }
      return this.setPolicy(rules, () => (this.isRuleShown = false));
    },
    removeRule() {
      const rules = this.rules.filter((r, i) => i !== this.editing.index);
      return this.setPolicy(rules, () => (this.isRemoveShown = false));
    },
    // the whole table is replaced at once: set-policy validates it as a unit
    async setPolicy(rules, done) {
      this.loading.save = true;
      this.error.save = "";
      try {
        await this.callAction("set-policy", { data: { rules } });
        done();
        await this.load();
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
  margin-bottom: $spacing-05;
  max-width: 50rem;
}
</style>
