import * as fs from 'fs';
import type { ScanEvent } from './scan-events';

export interface NdjsonTailOptions {
  file: string;
  /** Poll interval ms, default 1000. */
  intervalMs?: number;
  onEvent: (ev: ScanEvent) => void;
}

export interface NdjsonTail { stop(): void; }

/**
 * Byte-offset NDJSON tail. First successful size observation primes the
 * offset (history never re-emits). Partial last lines are held back until
 * their newline lands. Unparseable lines are skipped. Never throws.
 */
export function createNdjsonTail(opts: NdjsonTailOptions): NdjsonTail {
  let offset = 0;
  let stopped = false;

  const tick = (): void => {
    if (stopped) return;
    try {
      const st = fs.statSync(opts.file);
      if (st.size <= offset) return;
      const fd = fs.openSync(opts.file, 'r');
      try {
        const len = st.size - offset;
        const buf = Buffer.alloc(len);
        const read = fs.readSync(fd, buf, 0, len, offset);
        const text = buf.subarray(0, read).toString('utf8');
        const lastNl = text.lastIndexOf('\n');
        if (lastNl === -1) return; // still partial — wait for newline
        const complete = text.slice(0, lastNl + 1);
        offset += Buffer.byteLength(complete, 'utf8');
        for (const line of complete.split('\n')) {
          if (!line.trim()) continue;
          try {
            const ev = JSON.parse(line) as ScanEvent;
            if (ev && typeof ev.stage === 'string') opts.onEvent(ev);
          } catch { /* torn/corrupt line — skip */ }
        }
      } finally {
        fs.closeSync(fd);
      }
    } catch {
      // file missing/rotated — retry next tick
    }
  };

  const timer = setInterval(tick, opts.intervalMs ?? 1000);
  try { offset = fs.statSync(opts.file).size; } catch { offset = 0; } // prime: never re-emit history
  return { stop: () => { stopped = true; clearInterval(timer); } };
}