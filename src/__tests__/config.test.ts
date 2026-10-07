import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { ParallaxConfigLoader } from '../config';

describe('ParallaxConfigLoader', () => {
  const origEnv = { ...process.env };

  afterEach(() => {
    process.env = { ...origEnv };
    delete process.env.INTERACTSH_SERVER;
    delete process.env.INTERACTSH_DOMAIN;
    delete process.env.INTERACTSH_TOKEN;
  });

  it('should return default config when no file or env', () => {
    delete process.env.PARALLAX_TARGET;
    delete process.env.PARALLAX_COOKIE;
    delete process.env.PARALLAX_WORDLIST_TIER;
    delete process.env.PARALLAX_TIME_BUDGET;

    const config = ParallaxConfigLoader.load('/nonexistent/config.json');
    expect(config.timeBudgetMs).toBe(300000);
    expect(config.wordlistTier).toBe('fast');
    expect(config.enableTiming).toBe(true);
    expect(config.enableDiff).toBe(true);
    expect(config.enablePoison).toBe(true);
    expect(config.enableWeaponize).toBe(true);
    expect(config.outputDir).toBe('./output');
    expect(config.logLevel).toBe('info');
  });

  it('should load from JSON file', () => {
    const tmpFile = path.join(process.cwd(), '__test_config_tmp.json');
    fs.writeFileSync(tmpFile, JSON.stringify({ target: 'https://example.com', timeBudgetMs: 60000 }));
    try {
      const config = ParallaxConfigLoader.load(tmpFile);
      expect(config.target).toBe('https://example.com');
      expect(config.timeBudgetMs).toBe(60000);
    } finally {
      fs.unlinkSync(tmpFile);
    }
  });

  it('should apply env overrides', () => {
    process.env.PARALLAX_TARGET = 'https://env.example.com';
    process.env.PARALLAX_COOKIE = 'session=xyz';
    process.env.PARALLAX_WORDLIST_TIER = 'all';
    process.env.PARALLAX_TIME_BUDGET = '999';

    const config = ParallaxConfigLoader.load('/nonexistent/config.json');
    expect(config.target).toBe('https://env.example.com');
    expect(config.cookie).toBe('session=xyz');
    expect(config.wordlistTier).toBe('all');
    expect(config.timeBudgetMs).toBe(999);
  });

  it('should populate oob from INTERACTSH_* env', () => {
    process.env.INTERACTSH_SERVER = 'https://oast.example';
    process.env.INTERACTSH_DOMAIN = 'oast.example';
    process.env.INTERACTSH_TOKEN = 'tok';

    const config = ParallaxConfigLoader.load('/nonexistent/config.json');
    expect(config.oob).toEqual({ server: 'https://oast.example', domain: 'oast.example', token: 'tok' });
  });

  it('should leave oob unset when server present without domain', () => {
    process.env.INTERACTSH_SERVER = 'https://oast.example';
    delete process.env.INTERACTSH_DOMAIN;

    const config = ParallaxConfigLoader.load('/nonexistent/config.json');
    expect(config.oob).toBeUndefined();
  });

  it('should return all profiles', () => {
    const profiles = ParallaxConfigLoader.getProfiles();
    expect(profiles).toHaveProperty('fast');
    expect(profiles).toHaveProperty('full');
    expect(profiles).toHaveProperty('stealth');
    expect(profiles.fast.wordlistTier).toBe('fast');
    expect(profiles.full.wordlistTier).toBe('all');
    expect(profiles.stealth.enableDiff).toBe(false);
  });

  it('should save config to file', () => {
    const tmpFile = path.join(process.cwd(), '__test_config_save_tmp.json');
    const config = ParallaxConfigLoader.load('/nonexistent/config.json');
    try {
      ParallaxConfigLoader.save(config, tmpFile);
      const saved = JSON.parse(fs.readFileSync(tmpFile, 'utf-8'));
      expect(saved).toHaveProperty('timeBudgetMs');
      expect(saved).not.toHaveProperty('profiles');
    } finally {
      fs.unlinkSync(tmpFile);
    }
  });
});
