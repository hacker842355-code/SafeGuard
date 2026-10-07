import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import JavaScriptObfuscator from 'javascript-obfuscator';
import path from 'path';
import { defineConfig, Plugin } from 'vite';

function obfuscatorPlugin(): Plugin {
  return {
    name: 'vite-plugin-javascript-obfuscator',
    enforce: 'post',
    apply: 'build', // Active ONLY in production build
    transform(code: string, id: string) {
      // Obfuscate application scripts in production build, leaving node_modules untouched
      if (/\.(jsx?|tsx?)$/.test(id) && !id.includes('node_modules')) {
        const obfuscated = JavaScriptObfuscator.obfuscate(code, {
          compact: true,
          controlFlowFlattening: true,
          controlFlowFlatteningThreshold: 0.75,
          deadCodeInjection: false,
          debugProtection: false,
          disableConsoleOutput: false,
          identifierNamesGenerator: 'hexadecimal',
          log: false,
          numbersToExpressions: true,
          renameGlobals: false,
          rotateStringArray: true,
          selfDefending: false,
          shuffleStringArray: true,
          splitStrings: true,
          splitStringsChunkLength: 10,
          stringArray: true,
          stringArrayEncoding: ['base64'],
          stringArrayThreshold: 0.8,
          transformObjectKeys: true,
          unicodeEscapeSequence: false,
        });

        return {
          code: obfuscated.getObfuscatedCode(),
          map: null,
        };
      }
      return null;
    },
  };
}

export default defineConfig(({ mode }) => {
  const isProduction = mode === 'production';

  return {
    base: './', // Relative path for Electron build
    plugins: [
      react(),
      tailwindcss(),
      ...(isProduction ? [obfuscatorPlugin()] : []),
    ],
    build: {
      sourcemap: false, // Ensure source maps are disabled in production builds
      minify: 'esbuild',
    },
    resolve: {
      alias: {
        '@': path.resolve('.'),
      },
    },
    server: {
      host: '0.0.0.0',
      port: 3000,
      allowedHosts: true,
      hmr: process.env.DISABLE_HMR !== 'true',
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
