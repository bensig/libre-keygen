#!/usr/bin/env node
//
// Generate a new BIP39 mnemonic and print the derived keys.
// Entropy: crypto.randomBytes (OS CSPRNG) — nothing else is mixed in, because
// nothing else a Node process can observe adds real entropy.
//
//   node generateSeed.js              # 256-bit / 24 words (default)
//   node generateSeed.js --bits 128   # 12 words
//
// RUN OFFLINE on a trusted machine.

const { generateMnemonic, deriveAll } = require('./keys');
const { printKeys } = require('./deriveAddress');

function main() {
    const args = require('minimist')(process.argv.slice(2));
    const bits = args.bits === undefined ? 256 : Number(args.bits);

    let mnemonic;
    try {
        mnemonic = generateMnemonic(bits);
    } catch (e) {
        console.error(`❌ ${e.message}`);
        process.exit(1);
    }

    console.log(`\n🔐 Generated Seed Phrase (${bits}-bit, ${mnemonic.split(' ').length} words):`);
    console.log(mnemonic);
    console.log('\n⚠️  WARNING: Save this phrase securely!');
    console.log('Anyone with access to this phrase will have access to your funds!');

    printKeys(deriveAll(mnemonic));
}

main();
