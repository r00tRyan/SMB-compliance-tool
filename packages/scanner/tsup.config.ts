import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts', 'src/cli.ts'],
  format: ['esm'],
  dts: true,
  clean: true,
  // Bundle the workspace packages so the CLI runs standalone from dist/.
  // (src/cli.ts already carries the #!/usr/bin/env node shebang.)
  noExternal: [/^@smb\//],
});
