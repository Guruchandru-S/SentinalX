const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const tgzPath = path.join(__dirname, 'npm.tgz');
const extractDir = path.join(__dirname, 'npm_extracted');
if (!fs.existsSync(extractDir)) fs.mkdirSync(extractDir);
const compressed = fs.readFileSync(tgzPath);
zlib.gunzip(compressed, (err, buffer) => {
    if (err) { console.error('gunzip error:', err); process.exit(1); }
    console.log('Decompressed size:', buffer.length);
    let offset = 0;
    let fileCount = 0;
    while (offset < buffer.length - 512) {
        const header = buffer.slice(offset, offset + 512);
        const isZero = header.every(b => b === 0);
        if (isZero) break;
        const name = header.slice(0, 100).toString('utf8').replace(/\0/g, '').trim();
        const sizeOctal = header.slice(124, 136).toString('utf8').replace(/\0/g, '').trim();
        const size = parseInt(sizeOctal, 8) || 0;
        const typeFlag = header.slice(156, 157).toString('utf8').replace(/\0/g, '');
        offset += 512;
        if (!name) { offset += Math.ceil(size / 512) * 512; continue; }
        let relName = name.replace(/^package\//, '');
        if (!relName) { offset += Math.ceil(size / 512) * 512; continue; }
        const outPath = path.join(extractDir, relName);
        if (typeFlag === '5' || name.endsWith('/')) {
            try { fs.mkdirSync(outPath, { recursive: true }); } catch (_) { }
        } else if (typeFlag === '0' || typeFlag === '' || typeFlag === '\0') {
            const dir = path.dirname(outPath);
            try { fs.mkdirSync(dir, { recursive: true }); } catch (_) { }
            try {
                const content = buffer.slice(offset, offset + size);
                fs.writeFileSync(outPath, content);
                fileCount++;
            } catch (e) { }
        }
        offset += Math.ceil(size / 512) * 512;
    }
    console.log(`Extracted ${fileCount} files to: ${extractDir}`);
    const npmBin = path.join(extractDir, 'bin', 'npm-cli.js');
    if (fs.existsSync(npmBin)) {
        console.log('\n[SUCCESS] npm extracted!');
        console.log('npm cli path:', npmBin);
        const { execFileSync } = require('child_process');
        const node = process.execPath;
        console.log('\nRunning npm install...');
        try {
            execFileSync(node, [npmBin, 'install', '--prefix', __dirname], {
                cwd: __dirname,
                stdio: 'inherit',
                env: { ...process.env, PATH: process.env.PATH }
            });
            console.log('\n[SUCCESS] Backend dependencies installed!');
            console.log('To start the server, run:');
            console.log(`  "${node}" server.js`);
        } catch (e) {
            console.error('npm install failed:', e.message);
        }
    } else {
        console.log('npm bin not found at expected path. Files in extractDir:');
        try {
            const files = fs.readdirSync(path.join(extractDir, 'bin') || extractDir);
            console.log(files.slice(0, 10));
        } catch (e) { console.log(e.message); }
    }
});