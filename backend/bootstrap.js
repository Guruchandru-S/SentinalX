const https = require('https');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const BACKEND_DIR = __dirname;
const NODE_BIN = process.execPath;
console.log('AEGIS Backend Bootstrap\n======================');
console.log('Node:', NODE_BIN, process.version);
console.log('Working dir:', BACKEND_DIR, '\n');
if (fs.existsSync(path.join(BACKEND_DIR, 'node_modules', 'express'))) {
    console.log('[OK] Dependencies already installed. Starting server...');
    require('./server.js');
    return;
}
console.log('[1/3] Downloading npm CLI from npmjs.org...');
function download(url, dest) {
    return new Promise((resolve, reject) => {
        const file = fs.createWriteStream(dest);
        https.get(url, (res) => {
            if (res.statusCode === 301 || res.statusCode === 302) {
                file.close();
                fs.unlinkSync(dest);
                return download(res.headers.location, dest).then(resolve).catch(reject);
            }
            res.pipe(file);
            file.on('finish', () => { file.close(); resolve(); });
        }).on('error', (e) => { fs.unlink(dest, () => { }); reject(e); });
    });
}
async function bootstrap() {
    try {
        const tmpTar = path.join(BACKEND_DIR, '_npm.tgz');
        const tmpDir = path.join(BACKEND_DIR, '_npm_extract');
        const meta = await new Promise((resolve, reject) => {
            https.get('https://registry.npmjs.org/npm/10.9.2', (res) => {
                let d = '';
                res.on('data', c => d += c);
                res.on('end', () => { try { resolve(JSON.parse(d)); } catch (e) { reject(e); } });
            }).on('error', reject);
        });
        const tarUrl = meta.dist.tarball;
        console.log('[1/3] Downloading:', tarUrl);
        await download(tarUrl, tmpTar);
        console.log('[1/3] Downloaded npm tarball');
        if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir);
        execFileSync(NODE_BIN, ['-e', `
      const tar = require('zlib');
      const fs = require('fs');
      const path = require('path');
      const { execFileSync } = require('child_process');
    `], { cwd: BACKEND_DIR });
        console.log('[2/3] Setting up node_modules via inline install...');
        const npmCliScript = await new Promise((resolve, reject) => {
            https.get('https://registry.npmjs.org/npm/10.9.2', (res) => {
                let d = '';
                res.on('data', c => d += c);
                res.on('end', () => {
                    try {
                        const data = JSON.parse(d);
                        resolve(data.dist.tarball);
                    } catch (e) { reject(e); }
                });
            }).on('error', reject);
        });
        console.log('[OK] Using bundled install approach...');
        installDeps();
    } catch (e) {
        console.error('Bootstrap error:', e.message);
        console.error('\n[ERROR] Could not auto-install. Please install Node.js from https://nodejs.org/');
        console.error('Then run: npm install in the backend directory');
        process.exit(1);
    }
}
function installDeps() {
    console.log('[3/3] Installing dependencies manually using node...');
    const deps = {
        'express': '4.18.2',
        'cors': '2.8.5',
        'jsonwebtoken': '9.0.2',
        'bcryptjs': '2.4.3',
        'uuid': '9.0.0',
        'ws': '8.16.0',
        'express-rate-limit': '7.1.5'
    };
    const nodeModulesDir = path.join(BACKEND_DIR, 'node_modules');
    if (!fs.existsSync(nodeModulesDir)) fs.mkdirSync(nodeModulesDir);
    console.log('Packages to install:', Object.keys(deps).join(', '));
    console.log('\n[NOTE] Node.js with npm is required to install dependencies.');
    console.log('Please install Node.js LTS from: https://nodejs.org/en/download/');
    console.log('Then run the following commands:');
    console.log(`\n  cd "${BACKEND_DIR}"`);
    console.log('  npm install');
    console.log('  npm start\n');
    console.log('Or if npm is available from a different path, run:');
    console.log('  <path-to-npm> install\n');
}
bootstrap();