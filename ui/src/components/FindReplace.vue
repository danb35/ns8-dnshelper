<!--
  Copyright (C) 2026 dnshelper contributors
  SPDX-License-Identifier: GPL-3.0-or-later

  Find and replace in record values, for the selected records or the whole
  zone, narrowed by type and a name pattern. It only adds the resulting
  edits to the pending changes; nothing is written until Review and apply.
-->
<template>
  <NsModal
    size="large"
    :visible="isShown"
    :primary-button-disabled="!matches.length"
    @modal-hidden="$emit('hide')"
    @primary-click="stage"
  >
    <template slot="title">{{ $t("bulk.find_title") }}</template>
    <template slot="content">
      <cv-form @submit.prevent="stage">
        <p class="mg-bottom-md">{{ $t("bulk.find_intro") }}</p>
        <div class="field-row">
          <NsTextInput
            v-model="find"
            :label="$t('bulk.find')"
            placeholder="old.example.net."
            class="mg-bottom-md wide-field"
            ref="find"
          />
          <NsTextInput
            v-model="replace"
            :label="$t('bulk.replace')"
            placeholder="new.example.net."
            class="mg-bottom-md wide-field"
          />
        </div>
        <div class="field-row">
          <cv-select
            v-model="type"
            :label="$t('bulk.type')"
            class="mg-bottom-md small-field"
          >
            <cv-select-option value="">{{
              $t("bulk.any_type")
            }}</cv-select-option>
            <cv-select-option v-for="t in typeChoices" :key="t" :value="t">{{
              t
            }}</cv-select-option>
          </cv-select>
          <NsTextInput
            v-model.trim="name"
            :label="$t('bulk.name_pattern')"
            :helper-text="$t('bulk.name_pattern_help')"
            placeholder="*"
            class="mg-bottom-md wide-field"
          />
        </div>
        <NsCheckbox
          v-model="matchCase"
          :label="$t('bulk.match_case')"
          value="matchCase"
        />
        <NsCheckbox
          v-if="selected.length"
          v-model="onlySelected"
          :label="$t('bulk.only_selected', { count: selected.length })"
          value="onlySelected"
        />
        <h6 class="mg-top-md mg-bottom-sm">
          {{ $tc("bulk.matches", matches.length, { count: matches.length }) }}
        </h6>
        <ul class="preview">
          <li v-for="(c, i) in matches.slice(0, 50)" :key="i">
            {{ c.old.name }} {{ c.old.type }}: {{ c.old.data }}
            <span class="arrow">→</span> {{ c.new.data }}
          </li>
          <li v-if="matches.length > 50">…</li>
        </ul>
      </cv-form>
    </template>
    <template slot="secondary-button">{{ core.$t("common.cancel") }}</template>
    <template slot="primary-button">{{
      $tc("bulk.stage", matches.length, { count: matches.length })
    }}</template>
  </NsModal>
</template>

<script>
import { mapState } from "vuex";
import { findReplace } from "../lib/pending";

export default {
  name: "FindReplace",
  props: {
    isShown: { type: Boolean, default: false },
    // the records that may be changed (not read-only, not already pending)
    records: { type: Array, required: true },
    selected: { type: Array, default: () => [] },
  },
  data() {
    return {
      find: "",
      replace: "",
      type: "",
      name: "*",
      matchCase: false,
      onlySelected: false,
    };
  },
  computed: {
    ...mapState(["core"]),
    typeChoices() {
      return [...new Set(this.records.map((r) => r.type))].sort();
    },
    scope() {
      return this.onlySelected && this.selected.length
        ? this.selected
        : this.records;
    },
    matches() {
      return findReplace(this.scope, {
        find: this.find,
        replace: this.replace,
        type: this.type,
        name: this.name,
        matchCase: this.matchCase,
      });
    },
  },
  watch: {
    isShown(shown) {
      if (shown) {
        this.onlySelected = this.selected.length > 0;
        this.$nextTick(() => this.$refs.find && this.$refs.find.focus && this.$refs.find.focus());
      }
    },
  },
  methods: {
    stage() {
      if (this.matches.length) {
        this.$emit("stage", this.matches);
      }
    },
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";

.field-row {
  display: flex;
  flex-wrap: wrap;
  gap: $spacing-05;
}

.small-field {
  flex: 0 1 12rem;
}

.wide-field {
  flex: 1 1 16rem;
}

.preview {
  font-family: "IBM Plex Mono", monospace;
  font-size: 0.875rem;
  overflow-wrap: anywhere;
}

.arrow {
  font-family: "IBM Plex Sans", sans-serif;
}
</style>
