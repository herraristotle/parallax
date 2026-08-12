import { describe, it, expect, vi } from 'vitest';
import { Logger } from '../logger';

describe('Logger', () => {
  it('should log at correct levels', () => {
    const logger = new Logger('test', 'debug');
    logger.debug('debug msg');
    logger.info('info msg');
    logger.warn('warn msg');
    logger.error('error msg');

    const entries = logger.getEntries();
    expect(entries.length).toBe(4);
    expect(entries[0].level).toBe('debug');
    expect(entries[1].level).toBe('info');
    expect(entries[2].level).toBe('warn');
    expect(entries[3].level).toBe('error');
  });

  it('should filter logs below configured level', () => {
    const logger = new Logger('test', 'warn');
    logger.debug('should not appear');
    logger.info('should not appear');
    logger.warn('should appear');
    logger.error('should appear');

    const entries = logger.getEntries();
    expect(entries.length).toBe(2);
    expect(entries[0].level).toBe('warn');
    expect(entries[1].level).toBe('error');
  });

  it('should include module name in entries', () => {
    const logger = new Logger('my-module');
    logger.info('test message');

    const entries = logger.getEntries();
    expect(entries[0].module).toBe('my-module');
    expect(entries[0].message).toBe('test message');
  });

  it('should include data in entries', () => {
    const logger = new Logger('test');
    logger.info('with data', { key: 'value', num: 42 });

    const entries = logger.getEntries();
    expect(entries[0].data).toEqual({ key: 'value', num: 42 });
  });

  it('should track stage timing', async () => {
    const logger = new Logger('test');
    const timedFn = logger.stage('test-stage', async () => {
      await new Promise(r => setTimeout(r, 10));
    });

    await timedFn();

    const entries = logger.getEntries();
    expect(entries.length).toBe(2);
    expect(entries[0].message).toContain('Starting stage: test-stage');
    expect(entries[1].message).toContain('Completed stage: test-stage');
    expect(entries[1].data).toHaveProperty('elapsedMs');
  });

  it('should report progress', () => {
    const logger = new Logger('test');
    logger.progress(5, 10, 'scanning');

    const entries = logger.getEntries();
    expect(entries[0].data).toEqual({ current: 5, total: 10, percent: 50 });
  });

  it('should change log level', () => {
    const logger = new Logger('test', 'info');
    logger.debug('hidden');
    logger.setLevel('debug');
    logger.debug('visible');

    const entries = logger.getEntries();
    expect(entries.length).toBe(1);
    expect(entries[0].message).toBe('visible');
  });

  it('should serialize to JSON', () => {
    const logger = new Logger('test');
    logger.info('msg');
    const json = logger.toJSON();
    const parsed = JSON.parse(json);
    expect(parsed.length).toBe(1);
  });

  it('should rethrow in stage on error', async () => {
    const logger = new Logger('test');
    const failingFn = logger.stage('fail-stage', async () => {
      throw new Error('boom');
    });

    await expect(failingFn()).rejects.toThrow('boom');
  });
});
