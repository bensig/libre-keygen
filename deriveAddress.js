#!/usr/bin/env node
//
// Derive Libre / Bitcoin / Ethereum / Solana keys from a BIP39 mnemonic.
// The mnemonic is read from stdin only (interactive prompt or pipe) — never from
// argv, which would leak it into shell history and `ps`.
//
//   node deriveAddress.js
//   node deriveAddress.js < mnemonic.txt

const readline = require('readline');
const { deriveAll } = require('./keys');

function readMnemonic() {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise((resolve) => {
        rl.question('Enter your seed phrase: ', (answer) => {
            rl.close();
            resolve(answer);
        });
    });
}

function printKeys(keys) {
    const { btc, eth, libre, sol } = keys;

    console.log(`\n🗽 Libre Keys:`);
    console.log(`📢 Public Key:      ${libre.publicKey}`);
    console.log(`📢 Public Key (K1): ${libre.publicKeyK1}`);
    console.log(`🔐 Private Key:     ${libre.privateKey}`);
    console.log(`🔐 Private (K1):    ${libre.privateKeyK1}\n`);

    console.log(`₿ Bitcoin Keys:`);
    console.log(`🏠 Address:     ${btc.address}`);
    console.log(`📢 Public Key:  ${btc.publicKey}`);
    console.log(`🔐 Private Key: ${btc.privateKey}\n`);

    console.log(`⟠ Ethereum Keys:`);
    console.log(`🏠 Address:     ${eth.address}`);
    console.log(`📢 Public Key:  ${eth.publicKey}`);
    console.log(`🔐 Private Key: ${eth.privateKey}\n`);

    console.log(`☀️ Solana Keys:`);
    for (const w of sol) {
        console.log(`\n--- ${w.path} ---`);
        console.log(`🏠 Address:     ${w.address}`);
        console.log(`🔐 Private Key: ${w.privateKey}`);
    }
    console.log('');
}

async function main() {
    const args = require('minimist')(process.argv.slice(2));
    if (args.mnemonic || args.seed || args.private) {
        console.error('❌ Secrets on the command line are not accepted. Run without arguments and enter the phrase at the prompt (or pipe it via stdin).');
        process.exit(1);
    }

    let keys;
    try {
        keys = deriveAll(await readMnemonic());
    } catch (e) {
        console.error(`❌ ${e.message}`);
        process.exit(1);
    }
    printKeys(keys);
}

module.exports = { printKeys };

if (require.main === module) main();
