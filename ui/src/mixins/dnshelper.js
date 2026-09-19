//
// Copyright (C) 2026 dnshelper contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
import to from "await-to-js";
import { TaskService, UtilService } from "@nethserver/ns8-ui-lib";

/**
 * One promise-returning call for NS8 tasks, instead of the three event
 * listeners of the usual pattern:
 *
 *   const output = await this.callAction("list-zones");
 *
 * It rejects with { kind, errors, message }:
 *   - kind "validation": the action refused the input; errors is the NS8
 *     list of { field, parameter, value, error, message? }
 *   - kind "aborted": the task failed
 *   - kind "request": the task could not even be created (network, 401...)
 * Use errorText(err) to get a translated message.
 */
export default {
  name: "DnsHelperService",
  mixins: [TaskService, UtilService],
  methods: {
    callAction(action, { data, moduleId, cluster = false, title } = {}) {
      return new Promise((resolve, reject) => {
        const eventId = this.getUuid();
        // read from the store: a host component need not map these itself
        const root = this.$store.state.core.$root;
        const events = ["completed", "aborted", "validation-failed"].map(
          (name) => `${action}-${name}-${eventId}`
        );
        const done = () => events.forEach((e) => root.$off(e));

        root.$once(events[0], (taskContext, taskResult) => {
          done();
          resolve(taskResult.output);
        });
        root.$once(events[1], (taskResult) => {
          done();
          console.error(`${action} aborted`, taskResult);
          reject({ kind: "aborted", errors: [], message: "" });
        });
        root.$once(events[2], (validationErrors) => {
          done();
          reject({ kind: "validation", errors: validationErrors, message: "" });
        });

        const task = {
          action,
          extra: {
            title: title || this.$t("action." + action),
            isNotificationHidden: true,
            eventId,
          },
        };
        if (data !== undefined) {
          task.data = data;
        }
        const request = cluster
          ? this.createClusterTaskForApp(task)
          : this.createModuleTaskForApp(
              moduleId || this.$store.state.instanceName,
              task
            );
        to(request).then(([err]) => {
          if (err) {
            done();
            reject({
              kind: "request",
              errors: [],
              message: this.getErrorMessage(err),
            });
          }
        });
      });
    },

    /** A translated, human readable message for a rejection of callAction. */
    errorText(err) {
      if (err && err.kind === "validation" && err.errors.length) {
        return err.errors.map((e) => this.validationText(e)).join(" ");
      }
      if (err && err.kind === "request") {
        return err.message;
      }
      return this.$t("error.generic_error");
    },

    validationText(e) {
      const key = "dns_error." + e.error;
      const text = this.$te(key) ? this.$t(key) : e.error;
      if (!e.message) {
        return text;
      }
      // For these the helper's own sentence explains the problem better than
      // a generic one ("a CNAME cannot exist at the zone apex")
      if (["conflict", "forbidden", "invalid_request"].includes(e.error)) {
        return e.message;
      }
      // For these the message names what was refused (a record, a zone, a credential)
      if (["not_permitted", "credential_in_use"].includes(e.error)) {
        return `${text} (${e.message})`;
      }
      return text;
    },

    /** The first validation error for a field, or "" */
    fieldError(err, field) {
      if (!err || err.kind !== "validation") {
        return "";
      }
      const e = err.errors.find(
        (x) => x.parameter === field || x.field === field
      );
      return e ? this.validationText(e) : "";
    },
  },
};
