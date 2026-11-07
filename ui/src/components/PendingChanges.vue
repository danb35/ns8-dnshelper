<!--
  Copyright (C) 2026 dnshelper contributors
  SPDX-License-Identifier: GPL-3.0-or-later

  The Records page's pending changes: what will be sent as one apply-changes,
  each with an undo, and the Review and apply / Discard all buttons.
-->
<template>
  <cv-tile class="pending" kind="standard">
    <div class="pending-head">
      <h5>
        {{ $tc("pending.title", changes.length, { count: changes.length }) }}
      </h5>
      <div>
        <NsButton
          kind="primary"
          size="small"
          :icon="Checkmark20"
          :disabled="disabled"
          @click="$emit('review')"
          class="mg-right-sm"
          >{{ $t("pending.review") }}</NsButton
        >
        <NsButton
          kind="tertiary"
          size="small"
          :icon="Close20"
          :disabled="disabled"
          @click="$emit('discard')"
          >{{ $t("pending.discard") }}</NsButton
        >
      </div>
    </div>
    <ul class="pending-list">
      <li v-for="(c, i) in shown" :key="i" class="pending-item">
        <NsTag :label="$t('pending.kind_' + c.kind)" :kind="tagKind(c.kind)" />
        <span class="record-text">
          <template v-if="c.kind === 'add'">{{ describe(c.new) }}</template>
          <template v-else-if="c.kind === 'delete'">{{
            describe(c.old)
          }}</template>
          <template v-else
            >{{ describe(c.old) }} <span class="arrow">→</span>
            {{ describe(c.new) }}</template
          >
        </span>
        <NsButton
          kind="ghost"
          size="small"
          :disabled="disabled"
          @click="$emit('undo', c)"
          >{{ $t("pending.undo") }}</NsButton
        >
      </li>
    </ul>
    <NsButton
      v-if="changes.length > limit"
      kind="ghost"
      size="small"
      @click="expanded = !expanded"
      >{{
        expanded
          ? $t("pending.show_less")
          : $t("pending.show_all", { count: changes.length })
      }}</NsButton
    >
  </cv-tile>
</template>

<script>
import { IconService } from "@nethserver/ns8-ui-lib";

export default {
  name: "PendingChanges",
  mixins: [IconService],
  props: {
    changes: { type: Array, required: true },
    disabled: { type: Boolean, default: false },
  },
  data() {
    return { expanded: false, limit: 8 };
  },
  computed: {
    shown() {
      return this.expanded ? this.changes : this.changes.slice(0, this.limit);
    },
  },
  methods: {
    describe(r) {
      const data = r.data.length > 80 ? r.data.slice(0, 80) + "…" : r.data;
      return `${r.name} ${r.type}${r.ttl ? " " + r.ttl : ""} ${data}`;
    },
    tagKind(kind) {
      return { add: "green", edit: "blue", delete: "red" }[kind];
    },
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";

.pending {
  margin-bottom: $spacing-05;
}

.pending-head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: $spacing-03;
  margin-bottom: $spacing-03;
}

.pending-item {
  display: flex;
  align-items: center;
  gap: $spacing-03;
}

.record-text {
  flex: 1;
  font-family: "IBM Plex Mono", monospace;
  font-size: 0.875rem;
  overflow-wrap: anywhere;
}

.arrow {
  font-family: "IBM Plex Sans", sans-serif;
}
</style>
