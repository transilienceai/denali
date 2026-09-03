export const MAX_BULK_INVITES = 50;

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export type ParsedBulkEmails = {
  emails: string[];
  invalid: string[];
  duplicateCount: number;
};

export function parseBulkEmails(value: string): ParsedBulkEmails {
  const candidates = value
    .split(/[\s,;]+/)
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
  const emails: string[] = [];
  const invalid: string[] = [];
  const seen = new Set<string>();
  let duplicateCount = 0;

  for (const candidate of candidates) {
    if (!EMAIL_PATTERN.test(candidate) || candidate.length > 320) {
      invalid.push(candidate);
    } else if (seen.has(candidate)) {
      duplicateCount += 1;
    } else {
      seen.add(candidate);
      emails.push(candidate);
    }
  }

  return { emails, invalid, duplicateCount };
}
