import assert from "node:assert/strict";
import test from "node:test";
import { parseBulkEmails } from "../src/profileMembers.ts";

test("bulk member input accepts common separators, normalizes, and deduplicates", () => {
  assert.deepEqual(
    parseBulkEmails("FIRST@example.com, second@example.com\nfirst@example.com; third@example.com"),
    {
      emails: ["first@example.com", "second@example.com", "third@example.com"],
      invalid: [],
      duplicateCount: 1,
    },
  );
});

test("bulk member input reports malformed addresses without sending them", () => {
  assert.deepEqual(parseBulkEmails("valid@example.com invalid missing@domain"), {
    emails: ["valid@example.com"],
    invalid: ["invalid", "missing@domain"],
    duplicateCount: 0,
  });
});
