import * as fs from 'fs';
import * as path from 'path';
import { PipelineConfig } from './types';

export interface ParallaxConfig extends PipelineConfig {
  profiles?: Record<string, Partial<PipelineConfig>>;
  outputDir?: string;
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
  profile?: 'fast' | 'full' | 'stealth';
}

const DEFAULT_CONFIG: Partial<ParallaxConfig> = {
  timeBudgetMs: 300000,
  wordlistTier: 'fast',
  enableTiming: true,
  enableDiff: true,
  enablePoison: true,
  enableWeaponize: true,
  outputDir: './output',
  logLevel: 'info',
};

const PROFILES: Record<string, Partial<PipelineConfig>> = {
  fast: {
    wordlistTier: 'fast',
    enableTiming: false,
    enableDiff: true,
    enablePoison: true,
    enableWeaponize: true,
    timeBudgetMs: 120000,
  },
  full: {
    wordlistTier: 'all',
    enableTiming: true,
    enableDiff: true,
    enablePoison: true,
    enableWeaponize: true,
    timeBudgetMs: 600000,
  },
  stealth: {
    wordlistTier: 'fast',
    enableTiming: false,
    enableDiff: false,
    enablePoison: true,
    enableWeaponize: false,
    timeBudgetMs: 60000,
  },
};

export class ParallaxConfigLoader {
  static load(configPath?: string): ParallaxConfig {
    let fileConfig: Partial<ParallaxConfig> = {};

    if (configPath) {
      try {
        const content = fs.readFileSync(configPath, 'utf-8');
        fileConfig = JSON.parse(content);
      } catch {
        // file doesn't exist or invalid JSON, use defaults
      }
    } else {
      const defaultPath = path.join(process.cwd(), 'parallax.json');
      if (fs.existsSync(defaultPath)) {
        const content = fs.readFileSync(defaultPath, 'utf-8');
        fileConfig = JSON.parse(content);
      }
    }

    const envConfig = ParallaxConfigLoader.fromEnv();
    const merged = { ...DEFAULT_CONFIG, ...fileConfig, ...envConfig };

    // Apply profile if specified (separate from wordlistTier)
    const profileName = merged.profile || (merged.wordlistTier === 'all' ? 'full' : merged.wordlistTier === 'fast' ? 'fast' : undefined);
    if (profileName && merged.profiles && merged.profiles[profileName]) {
      Object.assign(merged, merged.profiles[profileName]);
    }

    return merged as ParallaxConfig;
  }

  static fromEnv(): Partial<ParallaxConfig> {
    const config: Partial<PipelineConfig> = {};
    if (process.env.PARALLAX_TARGET) config.target = process.env.PARALLAX_TARGET;
    if (process.env.PARALLAX_COOKIE) config.cookie = process.env.PARALLAX_COOKIE;
    if (process.env.PARALLAX_WORDLIST_TIER) config.wordlistTier = process.env.PARALLAX_WORDLIST_TIER as 'fast' | 'all';
    if (process.env.PARALLAX_TIME_BUDGET) config.timeBudgetMs = parseInt(process.env.PARALLAX_TIME_BUDGET);
    // OOB: requires both server and domain (empty = disabled; diverges from
    // oob-helper.sh, where empty server means the public pool).
    if (process.env.INTERACTSH_SERVER && process.env.INTERACTSH_DOMAIN) {
      const server = process.env.INTERACTSH_SERVER.trim();
      const domain = process.env.INTERACTSH_DOMAIN.trim();
      const token = (process.env.INTERACTSH_TOKEN || '').trim();
      if (server && domain) {
        config.oob = token ? { server, domain, token } : { server, domain };
      }
    }
    return config;
  }

  static getProfiles(): Record<string, Partial<PipelineConfig>> {
    return { ...PROFILES };
  }

  static save(config: ParallaxConfig, outputPath: string): void {
    const { profiles, ...configWithoutProfiles } = config;
    fs.writeFileSync(outputPath, JSON.stringify(configWithoutProfiles, null, 2));
  }
}
