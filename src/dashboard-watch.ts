import * as fs from 'fs';
import * as path from 'path';
import { isSafeReportId } from './dashboard-findings';

export interface ReportChangeEvent {
  type: 'report-added' | 'report-changed';
  id: string;
  ts: number;
}

export interface ReportWatcher {
  stop(): void;
}

export interface WatcherOptions {
  dir: string;
  intervalMs?: number;
  /** Files present at the first successful scan emit nothing (default true). */
  ignoreInitial?: boolean;
  onEvent: (ev: ReportChangeEvent) => void;
}

/**
 * Stat-poll watcher — deliberately not fs.watch: Windows emits duplicate/
 * lossy events there, and mtime+size deltas are enough for report files.
 */
export function createReportWatcher(opts: WatcherOptions): ReportWatcher {
  const intervalMs = opts.intervalMs ?? 1000;
  const ignoreInitial = opts.ignoreInitial !== false;
  const state = new Map<string, { mtimeMs: number; size: number }>();
  let primed = false;

  const tick = (): void => {
    let names: string[];
    try {
      names = fs.readdirSync(opts.dir);
    } catch {
      return; // dir missing — keep polling
    }
    const files = names.filter(n => n.endsWith('.json') && isSafeReportId(n.slice(0, -5)));
    const seen = new Set<string>();
    const quiet = ignoreInitial && !primed;
    for (const name of files) {
      const id = name.slice(0, -5);
      seen.add(id);
      let st: fs.Stats;
      try {
        st = fs.statSync(path.join(opts.dir, name));
      } catch {
        continue;
      }
      const prev = state.get(id);
      if (!prev) {
        state.set(id, { mtimeMs: st.mtimeMs, size: st.size });
        if (!quiet) opts.onEvent({ type: 'report-added', id, ts: Date.now() });
      } else if (prev.mtimeMs !== st.mtimeMs || prev.size !== st.size) {
        state.set(id, { mtimeMs: st.mtimeMs, size: st.size });
        if (!quiet) opts.onEvent({ type: 'report-changed', id, ts: Date.now() });
      }
    }
    for (const id of [...state.keys()]) {
      if (!seen.has(id)) state.delete(id); // deleted → silent drop
    }
    primed = true;
  };

  tick(); // prime synchronously when dir exists
  const timer = setInterval(tick, intervalMs);
  return { stop: () => clearInterval(timer) };
}