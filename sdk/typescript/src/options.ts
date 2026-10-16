/** A zero or omitted timeout leaves the operation unbounded. */
export interface OperationOptions {
  timeoutMs?: number;
  signal?: AbortSignal;
}

export function validateDuration(value: number | undefined, name: string): void {
  if (value !== undefined && (!Number.isFinite(value) || value < 0 || value > 2_147_483_647)) {
    throw new RangeError(`${name} must be between 0 and 2147483647 milliseconds`);
  }
}
