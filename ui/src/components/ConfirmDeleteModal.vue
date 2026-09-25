<!--
  NsDangerDeleteModal with the name to type set off from the sentence around
  it. The library renders its "type ... to confirm" line as plain text, so
  that line is hidden and rendered here instead; everything else (reset,
  focus, the disabled button) stays the library's.
-->
<template>
  <NsDangerDeleteModal
    v-bind="$attrs"
    v-on="$listeners"
    :name="name"
    typeToConfirm=" "
    class="confirm-delete-modal"
  >
    <template slot="explanation">
      <slot name="explanation"></slot>
      <i18n path="common.type_to_confirm" tag="div" class="type-prompt">
        <template #name
          ><span class="name-to-type">{{ name }}</span></template
        >
      </i18n>
    </template>
  </NsDangerDeleteModal>
</template>

<script>
export default {
  name: "ConfirmDeleteModal",
  inheritAttrs: false,
  props: {
    name: {
      type: String,
      required: true,
    },
  },
};
</script>

<style scoped lang="scss">
.confirm-delete-modal ::v-deep .type-to-confirm {
  display: none;
}

.type-prompt {
  margin-top: 2rem;
}

.name-to-type {
  font-family: "IBM Plex Mono", "Menlo", "Courier New", monospace;
  font-weight: 600;
  white-space: pre-wrap;
}
</style>
