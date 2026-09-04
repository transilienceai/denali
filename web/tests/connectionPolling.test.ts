import assert from "node:assert/strict";
import test from "node:test";

import { waitForAcceptedOperation } from "../src/connectionPolling.ts";

const noDelay = async () => {};

test("accepted operation polling recovers from transient refresh failures", async () => {
  const states = [new Error("network"), { running: true, revision: 1 }, { running: false, revision: 2 }];
  const result = await waitForAcceptedOperation({
    fetchCurrent: async () => {
      const state = states.shift();
      if (state instanceof Error) throw state;
      return state!;
    },
    isRunning: (current) => current.running,
    isComplete: (current) => current.revision === 2,
    delay: noDelay,
    maxAttempts: 3,
    stoppedMessage: "stopped",
    timeoutMessage: "timed out",
  });

  assert.deepEqual(result, { running: false, revision: 2 });
});

test("accepted operation polling bounds consecutive refresh failures", async () => {
  await assert.rejects(
    waitForAcceptedOperation({
      fetchCurrent: async () => { throw new Error("network detail"); },
      isRunning: () => false,
      isComplete: () => false,
      delay: noDelay,
      maxAttempts: 6,
      maxConsecutiveFailures: 3,
      stoppedMessage: "stopped",
      timeoutMessage: "timed out",
    }),
    /operation was accepted.*status could not be refreshed/i,
  );
});
