#!/usr/bin/env node
//
// Batch key generator — one fresh BIP39 seed + Libre key per account.
// Entropy: crypto.randomBytes (Node/OpenSSL CSPRNG) -> 256-bit mnemonic by default.
// Secrets are written ONLY to the output file (chmod 600); stdout shows public keys only.
//
// Usage:
//   node generateBatch.js accounts.txt            # one account name per line
//   node generateBatch.js --n 5                    # 5 generic keys (no account names)
//   node generateBatch.js accounts.txt --out keys-2026-07.json
//   node generateBatch.js --n 5 --bits 128         # 12-word mnemonics
//
// RUN OFFLINE on a trusted machine. Back up the output file, then wipe it.

const fs = require('fs');
const { generateMnemonic, deriveLibre } = require('./keys');
const args = require('minimist')(process.argv.slice(2));

function die(msg) {
    console.error(`❌ ${msg}`);
    process.exit(1);
}

function main() {
    // Build the list of accounts (or generic slots)
    let accounts;
    const fileArg = args._[0];
    if (fileArg) {
        accounts = fs.readFileSync(fileArg, 'utf8').split('\n').map(s => s.trim()).filter(Boolean);
    } else if (args.n !== undefined) {
        const n = Number(args.n);
        if (!Number.isInteger(n) || n < 1) die(`--n must be a positive integer, got "${args.n}"`);
        accounts = Array.from({ length: n }, (_, i) => `key${i + 1}`);
    } else {
        die('Provide an accounts file or --n <count>. See header for usage.');
    }
    if (accounts.length === 0) die(`No accounts found in ${fileArg}`);

    const bits = args.bits === undefined ? 256 : Number(args.bits);
    if (bits !== 128 && bits !== 256) die(`--bits must be 128 or 256, got "${args.bits}"`);
    const out = args.out || `keys-output-${accounts.length}.json`;

    const results = accounts.map(account => {
        const mnemonic = generateMnemonic(bits);
        const { privateKey, publicKey } = deriveLibre(mnemonic);
        return { account, mnemonic, wif: privateKey, pubkey: publicKey };
    });

    // Write secrets to a locked file (0600), created exclusively so it can't clobber
    const fd = fs.openSync(out, 'wx', 0o600);
    fs.writeSync(fd, JSON.stringify(results, null, 2));
    fs.closeSync(fd);

    // stdout: public keys only — safe to copy into rotation commands
    console.log(`\nGenerated ${results.length} keys (${bits}-bit). Secrets written to ${out} (mode 600).`);
    console.log('\naccount\tnew_pubkey');
    for (const r of results) console.log(`${r.account}\t${r.pubkey}`);
    console.log('\n⚠  Back up and then securely delete the output file. Never paste it anywhere networked.');
}

main();
