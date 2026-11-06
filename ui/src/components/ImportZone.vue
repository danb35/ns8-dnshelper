<!--
  Copyright (C) 2026 dnshelper contributors
  SPDX-License-Identifier: GPL-3.0-or-later

  Import a BIND-format zone file: paste it or choose a file, preview what
  would change (import-zone plans it, writes nothing), then add those changes
  to the Records page's pending changes, to review and apply there.
-->
<template>
  <NsModal
    size="large"
    :visible="isShown"
    :primary-button-disabled="loading || !text.trim()"
    :isLoading="loading"
    @modal-hidden="$emit('hide')"
    @primary-click="primary"
  >
    <template slot="title">{{ $t("import.title", { zone }) }}</template>
    <template slot="content">
      <cv-form @submit.prevent="primary">
        <p class="mg-bottom-md">{{ $t("import.intro") }}</p>
        <div class="mg-bottom-md">
          <label class="bx--btn bx--btn--tertiary bx--btn--sm file-button">
            {{ $t("import.choose_file") }}
            <input
              type="file"
              accept=".zone,.txt,.db,text/plain"
              class="file-input"
              @change="readFile"
            />
          </label>
          <span v-if="fileName" class="mg-left-sm">{{ fileName }}</span>
        </div>
        <cv-text-area
          v-model="text"
          :label="$t('import.text')"
          :placeholder="placeholder"
          :rows="10"
          :disabled="loading"
          class="mg-bottom-md zone-text"
          @input="plan = null"
        />
        <cv-radio-group
          :legend-text="$t('import.mode')"
          vertical
          class="mg-bottom-md"
        >
          <cv-radio-button
            v-model="mode"
            name="import-mode"
            value="add"
            :label="$t('import.mode_add')"
            :disabled="loading"
            @change="plan = null"
          />
          <cv-radio-button
            v-model="mode"
            name="import-mode"
            value="replace"
            :label="$t('import.mode_replace')"
            :disabled="loading"
            @change="plan = null"
          />
        </cv-radio-group>
        <NsInlineNotification
          v-if="mode === 'replace'"
          kind="warning"
          :title="$t('import.replace_title')"
          :description="$t('import.replace_warning')"
          :showCloseButton="false"
        />
        <NsInlineNotification
          v-if="error"
          kind="error"
          :title="$t('import.cannot_read')"
          :description="error"
          :showCloseButton="false"
        />
        <template v-if="plan">
          <h6 class="mg-top-md mg-bottom-sm">
            {{
              $t("import.summary", {
                parsed: plan.parsed,
                add: plan.add.length,
                remove: plan.remove.length,
              })
            }}
          </h6>
          <div v-for="part in ['remove', 'add']" :key="part">
            <p v-if="plan[part].length" class="mg-top-sm">
              <strong>{{ $t("import.part_" + part) }}</strong>
            </p>
            <ul class="preview">
              <li v-for="(r, i) in plan[part].slice(0, 30)" :key="i">
                {{ r.name }} {{ r.type }} {{ r.ttl || "-" }} {{ r.data }}
              </li>
              <li v-if="plan[part].length > 30">…</li>
            </ul>
          </div>
          <template v-if="plan.skipped.length">
            <p class="mg-top-sm">
              <strong>{{
                $t("import.skipped", { count: plan.skipped.length })
              }}</strong>
            </p>
            <ul class="preview">
              <li v-for="(s, i) in plan.skipped.slice(0, 30)" :key="i">
                {{ s.name }} {{ s.type }}: {{ s.reason }}
              </li>
              <li v-if="plan.skipped.length > 30">…</li>
            </ul>
          </template>
        </template>
      </cv-form>
    </template>
    <template slot="secondary-button">{{ core.$t("common.cancel") }}</template>
    <template slot="primary-button">{{
      plan
        ? $tc("bulk.stage", count, { count })
        : $t("import.preview")
    }}</template>
  </NsModal>
</template>

<script>
import { mapState } from "vuex";
import DnsHelperService from "../mixins/dnshelper";

export default {
  name: "ImportZone",
  mixins: [DnsHelperService],
  props: {
    isShown: { type: Boolean, default: false },
    zone: { type: String, default: "" },
  },
  data() {
    return {
      text: "",
      fileName: "",
      mode: "add",
      plan: null,
      loading: false,
      error: "",
    };
  },
  computed: {
    ...mapState(["core"]),
    count() {
      return this.plan ? this.plan.add.length + this.plan.remove.length : 0;
    },
    placeholder() {
      return "$ORIGIN " + this.zone + ".\nwww  300  IN  A  192.0.2.10";
    },
  },
  watch: {
    isShown(shown) {
      if (shown) {
        this.text = "";
        this.fileName = "";
        this.mode = "add";
        this.plan = null;
        this.error = "";
      }
    },
  },
  methods: {
    readFile(event) {
      const file = event.target.files && event.target.files[0];
      if (!file) {
        return;
      }
      this.fileName = file.name;
      const reader = new FileReader();
      reader.onload = () => {
        this.text = String(reader.result || "");
        this.plan = null;
      };
      reader.readAsText(file);
      event.target.value = "";
    },
    primary() {
      if (this.plan) {
        this.stage();
      } else {
        this.preview();
      }
    },
    async preview() {
      this.loading = true;
      this.error = "";
      try {
        this.plan = await this.callAction("import-zone", {
          data: { zone: this.zone, text: this.text, mode: this.mode },
        });
      } catch (err) {
        this.plan = null;
        this.error =
          err && err.kind === "validation"
            ? err.errors.map((e) => e.message || this.validationText(e)).join(" ")
            : this.errorText(err);
      }
      this.loading = false;
    },
    stage() {
      if (!this.count) {
        this.$emit("hide");
        return;
      }
      this.$emit("stage", [
        ...this.plan.remove.map((r) => ({ kind: "delete", old: r })),
        ...this.plan.add.map((r) => ({ kind: "add", new: r })),
      ]);
    },
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";

.file-input {
  display: none;
}

.file-button {
  cursor: pointer;
}

.zone-text ::v-deep textarea {
  font-family: "IBM Plex Mono", monospace;
  font-size: 0.875rem;
}

.preview {
  font-family: "IBM Plex Mono", monospace;
  font-size: 0.875rem;
  overflow-wrap: anywhere;
}
</style>
