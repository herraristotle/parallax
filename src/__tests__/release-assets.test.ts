import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

/**
 * The release asset is an npm tarball whose contents are decided by package.json
 * `files`. Every runtime file resolved via __dirname at run time must be listed
 * there, or a global install ships a CLI that cannot find its wordlists/vendor
 * asset (this is what the old pkg snapshot did silently).
 */
describe('release tarball contents', () => {
  const root = path.join(__dirname, '..', '..');
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')) as {
    bin: Record<string, string>;
    files: string[];
    dependencies: Record<string, string>;
  };

  it('lists every runtime asset in package.json files', () => {
    expect(pkg.files).toContain('wordlists/headers.txt');
    expect(pkg.files).toContain('wordlists/parameters.txt');
    expect(pkg.files).toContain('src/vendor/htmx.min.js');
    expect(pkg.files).toContain('dist');
  });

  it('those assets exist on disk', () => {
    for (const f of ['wordlists/headers.txt', 'wordlists/parameters.txt', 'src/vendor/htmx.min.js']) {
      expect(fs.existsSync(path.join(root, f))).toBe(true);
    }
  });

  it('ships a runnable bin and keeps the browser library as a runtime dependency', () => {
    expect(pkg.bin.parallax).toBe('./dist/cli.js');
    // Stage 8 lazy-loads the browser library at runtime; a devDependency would
    // omit it from the tarball. puppeteer-core is used because it bundles no
    // browser, so it reuses the one on the box.
    expect(pkg.dependencies['puppeteer-core']).toBeTruthy();
    expect(pkg.dependencies.playwright).toBeUndefined();
  });
});
