export type AcceptedOperationPolling<T> = {
  fetchCurrent: () => Promise<T>;
  isRunning: (current: T) => boolean;
  isComplete: (current: T) => boolean;
  delay?: () => Promise<void>;
  maxAttempts?: number;
  maxConsecutiveFailures?: number;
  stoppedMessage: string;
  timeoutMessage: string;
};

const defaultDelay = () => new Promise<void>((resolve) => window.setTimeout(resolve, 2000));

export async function waitForAcceptedOperation<T>({
  fetchCurrent,
  isRunning,
  isComplete,
  delay = defaultDelay,
  maxAttempts = 525,
  maxConsecutiveFailures = 5,
  stoppedMessage,
  timeoutMessage,
}: AcceptedOperationPolling<T>): Promise<T> {
  let consecutiveFailures = 0;
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    await delay();
    let current: T;
    try {
      current = await fetchCurrent();
      consecutiveFailures = 0;
    } catch (error) {
      consecutiveFailures += 1;
      if (consecutiveFailures < maxConsecutiveFailures) continue;
      throw new Error(
        "The operation was accepted, but its status could not be refreshed. " +
        "Refresh the page to see the durable result.",
        { cause: error },
      );
    }
    if (isRunning(current)) continue;
    if (isComplete(current)) return current;
    throw new Error(stoppedMessage);
  }
  throw new Error(timeoutMessage);
}
