export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  module: string;
  message: string;
  data?: Record<string, unknown>;
}

export class Logger {
  private level: LogLevel;
  private module: string;
  private entries: LogEntry[] = [];

  private static LEVELS: Record<LogLevel, number> = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3,
  };

  constructor(module: string, level: LogLevel = 'info') {
    this.module = module;
    this.level = level;
  }

  private shouldLog(level: LogLevel): boolean {
    return Logger.LEVELS[level] >= Logger.LEVELS[this.level];
  }

  private log(level: LogLevel, message: string, data?: Record<string, unknown>): void {
    if (!this.shouldLog(level)) return;

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      module: this.module,
      message,
      data,
    };

    this.entries.push(entry);

    const prefix = `[${entry.timestamp}] [${level.toUpperCase()}] [${this.module}]`;
    const msg = data ? `${prefix} ${message} ${JSON.stringify(data)}` : `${prefix} ${message}`;

    if (level === 'error') {
      console.error(msg);
    } else if (level === 'warn') {
      console.warn(msg);
    } else {
      console.log(msg);
    }
  }

  debug(message: string, data?: Record<string, unknown>): void {
    this.log('debug', message, data);
  }

  info(message: string, data?: Record<string, unknown>): void {
    this.log('info', message, data);
  }

  warn(message: string, data?: Record<string, unknown>): void {
    this.log('warn', message, data);
  }

  error(message: string, data?: Record<string, unknown>): void {
    this.log('error', message, data);
  }

  stage(name: string, callback: () => Promise<void>): () => Promise<void> {
    return async () => {
      this.info(`Starting stage: ${name}`);
      const start = Date.now();
      try {
        await callback();
        const elapsed = Date.now() - start;
        this.info(`Completed stage: ${name}`, { elapsedMs: elapsed });
      } catch (err) {
        const elapsed = Date.now() - start;
        this.error(`Failed stage: ${name}`, { elapsedMs: elapsed, error: (err as Error).message });
        throw err;
      }
    };
  }

  progress(current: number, total: number, label: string): void {
    const pct = Math.round((current / total) * 100);
    this.info(`Progress: ${label}`, { current, total, percent: pct });
  }

  getEntries(): LogEntry[] {
    return [...this.entries];
  }

  setLevel(level: LogLevel): void {
    this.level = level;
  }

  toJSON(): string {
    return JSON.stringify(this.entries, null, 2);
  }
}
