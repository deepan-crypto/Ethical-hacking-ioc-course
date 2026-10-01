import esbuild from 'esbuild';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const outDir = path.resolve(__dirname, '../app/static/dist');
const assetsDir = path.join(outDir, 'assets');

if (!fs.existsSync(assetsDir)) {
  fs.mkdirSync(assetsDir, { recursive: true });
}

try {
  await esbuild.build({
    entryPoints: [path.join(__dirname, 'src/main.jsx')],
    bundle: true,
    outfile: path.join(assetsDir, 'index.js'),
    minify: true,
    sourcemap: false,
    format: 'esm',
    loader: { '.js': 'jsx', '.jsx': 'jsx', '.css': 'css' },
    define: {
      'process.env.NODE_ENV': '"production"'
    }
  });

  // Prepare index.html pointing to assets
  let html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf-8');
  html = html.replace(
    '<script type="module" src="/src/main.jsx"></script>',
    '<script type="module" src="/assets/index.js"></script><link rel="stylesheet" href="/assets/index.css">'
  );
  fs.writeFileSync(path.join(outDir, 'index.html'), html);

  console.log('✅ React Blue Team SOC frontend successfully built into app/static/dist!');
} catch (err) {
  console.error('❌ Build failed:', err);
  process.exit(1);
}
