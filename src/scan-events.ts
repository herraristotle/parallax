import * as fs from 'fs';
import * as path from 'path';

export interface ScanEvent {
  ts: number;
  stage: string;
  detail?: string;
}

/**
 * Append one NDJSON line to <outputDir>/scan-events.ndjson.
 * NEVER throws — dashboard plumbing must not be able to fail a scan.
 */
export function appendScanEvent(outputDir: string, ev: ScanEvent): void {
  try {
    fs.mkdirSync(outputDir, { recursive: true });
    fs.appendFileSync(
      path.join(outputDir, 'scan-events.ndjson'),
      `${JSON.stringify(ev)}\n`,
      'utf8',
    );
  } catch {
    // best-effort telemetry; swallow (spec: phase-2 append fails → scan unaffected)
  }
}