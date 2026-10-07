import * as fs from 'fs';
import * as path from 'path';
import { randomUUID } from 'node:crypto';

export interface ProbeRecord {
  method: string;
  url: string;
  status?: number;
  cacheStatus?: string;
  latencyMs?: number;
  bodyHash?: string;
  canary?: boolean;
  reason?: string;
  error?: string;
}

/** NDJSON trace sink: one line per probe/event, flushed synchronously. */
export class TraceSink {
  readonly runId = randomUUID();
  private readonly file: string;
  private readonly startedAt = Date.now();
  private stage = 'init';
  private requests = 0;
  private errors = 0;

  constructor(file: string) {
    this.file = file;
    const dir = path.dirname(file);
    if (dir && dir !== '.') fs.mkdirSync(dir, { recursive: true });
  }

  setStage(stage: string): void {
    this.stage = stage;
    this.event('stage.start', { stage });
  }

  probe(rec: ProbeRecord): void {
    this.requests++;
    if (rec.error || rec.status === 0) this.errors++;
    this.write({ event: 'probe', stage: this.stage, ...rec });
  }

  event(name: string, data: Record<string, unknown>): void {
    this.write({ event: name, ...data });
  }

  summary(extra: Record<string, unknown> = {}): void {
    this.write({
      event: 'run.summary',
      durationMs: Date.now() - this.startedAt,
      requests: this.requests,
      errors: this.errors,
      ...extra,
    });
  }

  private write(rec: Record<string, unknown>): void {
    fs.appendFileSync(this.file, JSON.stringify({ ts: new Date().toISOString(), runId: this.runId, ...rec }) + '\n');
  }
}
