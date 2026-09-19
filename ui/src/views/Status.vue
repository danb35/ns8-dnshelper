<!--
  Copyright (C) 2023 Nethesis S.r.l.
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("status.title") }}</h2>
      </cv-column>
    </cv-row>
    <cv-row v-if="error.getStatus">
      <cv-column>
        <NsInlineNotification
          kind="error"
          :title="$t('action.get-status')"
          :description="error.getStatus"
          :showCloseButton="false"
        />
      </cv-column>
    </cv-row>
    <cv-row v-if="error.load">
      <cv-column>
        <NsInlineNotification
          kind="error"
          :title="$t('status.cannot_load')"
          :description="error.load"
          :showCloseButton="false"
        />
      </cv-column>
    </cv-row>
    <cv-row v-if="!loading.load && !error.load && !zones.length">
      <cv-column>
        <NsInlineNotification
          kind="info"
          :title="$t('status.no_zones_title')"
          :description="$t('status.no_zones_description')"
          :showCloseButton="false"
        >
          <template #actions>
            <NsButton
              kind="ghost"
              :icon="ArrowRight20"
              @click="goToAppPage(instanceName, 'zones')"
            >
              {{ $t("status.add_first_zone") }}
            </NsButton>
          </template>
        </NsInlineNotification>
      </cv-column>
    </cv-row>
    <cv-row>
      <cv-column :md="4" :max="4">
        <NsInfoCard
          light
          :title="String(zones.length)"
          :description="$t('status.managed_zones')"
          :icon="Earth32"
          :loading="loading.load"
          class="min-height-card"
        >
          <template slot="content">
            <NsButton
              kind="ghost"
              :icon="ArrowRight20"
              :disabled="loading.load"
              @click="goToAppPage(instanceName, 'zones')"
            >
              {{ $t("status.manage_zones") }}
            </NsButton>
          </template>
        </NsInfoCard>
      </cv-column>
      <cv-column :md="4" :max="4">
        <NsInfoCard
          light
          :title="String(rules.length)"
          :description="$t('status.access_rules')"
          :icon="Rule32"
          :loading="loading.load"
          class="min-height-card"
        >
          <template slot="content">
            <NsButton
              kind="ghost"
              :icon="ArrowRight20"
              :disabled="loading.load"
              @click="goToAppPage(instanceName, 'access')"
            >
              {{ $t("status.manage_access") }}
            </NsButton>
          </template>
        </NsInfoCard>
      </cv-column>
      <cv-column :md="4" :max="4">
        <NsInfoCard
          light
          :title="status.instance || '-'"
          :description="$t('status.app_instance')"
          :icon="Application32"
          :loading="loading.getStatus"
          class="min-height-card"
        />
      </cv-column>
      <cv-column :md="4" :max="4">
        <NsInfoCard
          light
          :title="installationNodeTitle"
          :titleTooltip="installationNodeTitleTooltip"
          :description="$t('status.installation_node')"
          :icon="Chip32"
          :loading="loading.getStatus"
          class="min-height-card"
        />
      </cv-column>
      <cv-column :md="4" :max="4">
        <NsBackupCard
          :title="core.$t('backup.title')"
          :noBackupMessage="core.$t('backup.no_backup_configured')"
          :goToBackupLabel="core.$t('backup.go_to_backup')"
          :repositoryLabel="core.$t('backup.repository')"
          :statusLabel="core.$t('common.status')"
          :statusSuccessLabel="core.$t('common.success')"
          :statusNotRunLabel="core.$t('backup.backup_has_not_run_yet')"
          :statusErrorLabel="core.$t('error.error')"
          :completedLabel="core.$t('backup.completed')"
          :durationLabel="core.$t('backup.duration')"
          :totalSizeLabel="core.$t('backup.total_size')"
          :totalFileCountLabel="core.$t('backup.total_file_count')"
          :backupDisabledLabel="core.$t('common.disabled')"
          :showMoreLabel="core.$t('common.show_more')"
          :moduleId="instanceName"
          :moduleUiName="instanceLabel"
          :repositories="backupRepositories"
          :backups="backups"
          :loading="loading.listBackupRepositories || loading.listBackups"
          :coreContext="core"
          light
        />
      </cv-column>
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
      <cv-column :md="4" :max="4">
        <NsSystemLogsCard
          :title="core.$t('system_logs.card_title')"
          :description="
            core.$t('system_logs.card_description', {
              name: instanceLabel || instanceName,
            })
          "
          :buttonLabel="core.$t('system_logs.card_button_label')"
          :router="core.$router"
          context="module"
          :moduleId="instanceName"
          light
        />
      </cv-column>
    </cv-row>
  </cv-grid>
</template>

<script>
import { mapState } from "vuex";
import Earth32 from "@carbon/icons-vue/es/earth/32";
import Rule32 from "@carbon/icons-vue/es/rule/32";
import {
  QueryParamService,
  IconService,
  UtilService,
  PageTitleService,
} from "@nethserver/ns8-ui-lib";
import DnsHelperService from "../mixins/dnshelper";

export default {
  name: "Status",
  mixins: [
    DnsHelperService,
    QueryParamService,
    IconService,
    UtilService,
    PageTitleService,
  ],
  pageTitle() {
    return this.$t("status.title") + " - " + this.appName;
  },
  data() {
    return {
      Earth32,
      Rule32,
      q: {
        page: "status",
      },
      urlCheckInterval: null,
      status: {},
      zones: [],
      rules: [],
      backupRepositories: [],
      backups: [],
      loading: {
        load: false,
        getStatus: false,
        listBackupRepositories: false,
        listBackups: false,
      },
      error: {
        load: "",
        getStatus: "",
        listBackupRepositories: "",
        listBackups: "",
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "instanceLabel", "core", "appName"]),
    installationNodeTitle() {
      if (this.status && this.status.node) {
        if (this.status.node_ui_name) {
          return this.status.node_ui_name;
        } else {
          return this.$t("status.node") + " " + this.status.node;
        }
      } else {
        return "-";
      }
    },
    installationNodeTitleTooltip() {
      if (this.status && this.status.node_ui_name) {
        return this.$t("status.node") + " " + this.status.node;
      } else {
        return "";
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
    this.getStatus();
    this.listBackupRepositories();
  },
  methods: {
    async load() {
      this.loading.load = true;
      this.error.load = "";
      try {
        const [config, policy] = await Promise.all([
          this.callAction("get-configuration"),
          this.callAction("get-policy"),
        ]);
        this.zones = config.zones;
        this.rules = policy.rules;
      } catch (err) {
        this.error.load = this.errorText(err);
      }
      this.loading.load = false;
    },
    async getStatus() {
      this.loading.getStatus = true;
      this.error.getStatus = "";
      try {
        this.status = await this.callAction("get-status");
      } catch (err) {
        this.error.getStatus = this.errorText(err);
      }
      this.loading.getStatus = false;
    },
    async listBackupRepositories() {
      this.loading.listBackupRepositories = true;
      this.error.listBackupRepositories = "";
      try {
        const output = await this.callAction("list-backup-repositories", {
          cluster: true,
        });
        this.backupRepositories = output.repositories.sort(
          this.sortByProperty("name")
        );
        this.listBackups();
      } catch (err) {
        this.error.listBackupRepositories = this.errorText(err);
      }
      this.loading.listBackupRepositories = false;
    },
    async listBackups() {
      this.loading.listBackups = true;
      this.error.listBackups = "";
      try {
        const output = await this.callAction("list-backups", {
          cluster: true,
        });
        const backups = output.backups;
        backups.sort(this.sortByProperty("name"));
        // get repository name
        for (const backup of backups) {
          const repo = this.backupRepositories.find(
            (r) => r.id == backup.repository
          );
          if (repo) {
            backup.repoName = repo.name;
          }
        }
        this.backups = backups;
      } catch (err) {
        this.error.listBackups = this.errorText(err);
      }
      this.loading.listBackups = false;
    },
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";
</style>
