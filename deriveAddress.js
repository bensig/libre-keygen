#!/usr/bin/env node

const bip39 = require("bip39");
const hdkey = require('hdkey');
const { keccak256 } = require("ethereum-cryptography/keccak");
const { secp256k1 } = require("ethereum-cryptography/secp256k1");
const { toHex } = require("ethereum-cryptography/utils");
const base58 = require('bs58');
const createHash = require('create-hash');
const ecc = require('eosjs-ecc');
const wif = require('wif');
const readline = require('readline');
const bech32 = require('bech32');

// Get command-line args
const args = require("minimist")(process.argv.slice(2));

// Function to derive Ethereum address from a public key
function getEthereumAddress(publicKey) {
    // For Ethereum, we need the uncompressed public key without the prefix byte
    const pubKeyWithoutPrefix = publicKey.slice(1);
    const hash = keccak256(pubKeyWithoutPrefix);
    return "0x" + toHex(hash.slice(-20));
}

// Add these new functions for Libre key formatting
function ripemd160(data) {
    return createHash('ripemd160').update(data).digest();
}

function getLibreChecksum(key, keyType) {
    const hash = ripemd160(Buffer.concat([
        key,
        Buffer.from(keyType)
    ]));
    return hash.slice(0, 4);
}

function encodeLibreKey(key, prefix, keyType) {
    const checksum = getLibreChecksum(key, keyType);
    const buffer = Buffer.concat([key, checksum]);
    return `${prefix}${base58.encode(buffer)}`;
}

function getLibreKeys(privateKey) {
    try {
        // Debug logging
        console.log('Private key type:', typeof privateKey);
        console.log('Private key:', privateKey);
        console.log('Is Buffer?', Buffer.isBuffer(privateKey));
        
        // Convert private key to WIF format first
        const wifObj = {
            version: 128,
            privateKey: privateKey,
            compressed: false
        };
        const wifPrivate = wif.encode(wifObj);
        
        // Generate public key from WIF private key using eosjs-ecc
        const publicKey = ecc.privateToPublic(wifPrivate);
        
        return { privateKey: wifPrivate, publicKey: publicKey };
    } catch (error) {
        console.error('Error in getLibreKeys:', error);
        console.error('Private key details:', {
            type: typeof privateKey,
            value: privateKey,
            isBuffer: Buffer.isBuffer(privateKey)
        });
        throw error;
    }
}

// Add function to get user input
async function promptUser() {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    return new Promise((resolve) => {
        rl.question('Enter your seed phrase: ', (answer) => {
            rl.close();
            resolve(answer.trim().toLowerCase());
        });
    });
}

// Add Bitcoin address derivation function
function getBitcoinSegwitAddress(publicKey) {
    // Get SHA256 of public key
    const sha256Hash = createHash('sha256').update(publicKey).digest();
    // Get RIPEMD160 of the SHA256
    const ripemd160Hash = createHash('ripemd160').update(sha256Hash).digest();
    
    // Convert the hash to 5-bit words for bech32 encoding
    const words = bech32.bech32.toWords(ripemd160Hash);
    // Add version byte (0x00) in front
    const versionedWords = [0x00, ...words];
    
    // Encode as bech32 address
    return bech32.bech32.encode('bc', versionedWords);
}

// Add this function near the other helper functions
function toWIF(privateKey) {
    const wifObj = {
        version: 128,
        privateKey: privateKey,
        compressed: true
    };
    return wif.encode(wifObj);
}

// Modify the main logic
async function main() {
    let mnemonic;
    
    if (args.seed) {
        // Extract just the mnemonic part after --seed=
        let mnemonic;
        if (typeof args.seed === 'string') {
            // Handle case where mnemonic is directly after equals sign (--seed=word1 word2...)
            mnemonic = args.seed + ' ' + (args._.join(' '));
        } else {
            // Handle case where mnemonic is space-separated (--seed word1 word2...)
            mnemonic = args._.join(' ');
        }
        
        mnemonic = mnemonic.trim().toLowerCase();
        
        // Debug mnemonic characters
        console.log('\nMnemonic character analysis:');
        console.log('Raw input:', mnemonic);
        console.log('After trim/lowercase:', mnemonic);
        console.log('Words:', mnemonic.split(' '));
        console.log('Word count:', mnemonic.split(' ').length);
        console.log('Characters (with codes):');
        for (let char of mnemonic) {
            console.log(`'${char}' - ${char.charCodeAt(0)}`);
        }
        
        // Validate mnemonic
        if (!bip39.validateMnemonic(mnemonic)) {
            console.error("❌ Invalid mnemonic phrase");
            // Print the word list for verification
            console.log("\nWords in mnemonic:");
            mnemonic.split(' ').forEach((word, i) => {
                console.log(`${i + 1}: "${word}"`);
            });
            process.exit(1);
        }

        console.log('\nInput mnemonic:', mnemonic);
        console.log('Is valid mnemonic:', bip39.validateMnemonic(mnemonic));
        console.log('Word count:', mnemonic.split(' ').length);
        
        // Generate entropy from mnemonic
        const entropy = bip39.mnemonicToEntropy(mnemonic);
        console.log('Entropy:', entropy);
        
        // Generate seed
        const seed = bip39.mnemonicToSeedSync(mnemonic);
        console.log('Seed:', seed.toString('hex'));
        
        // Use EOS derivation path instead of Ethereum's
        const hdwallet = hdkey.fromMasterSeed(seed);
        
        // Different derivation paths for each coin
        const eosPath = "m/44'/194'/0'/0/0";    // EOS path
        const btcPath = "m/84'/0'/0'/0/0";      // Bitcoin SegWit path (BIP84)
        const ethPath = "m/44'/60'/0'/0/0";     // Ethereum path
        
        // Derive wallets for each path
        const eosWallet = hdwallet.derive(eosPath);
        const btcWallet = hdwallet.derive(btcPath);
        const ethWallet = hdwallet.derive(ethPath);
        
        // Get keys for each cryptocurrency
        const compressedPublicKey = secp256k1.getPublicKey(btcWallet.privateKey, true);  // For Bitcoin
        const ethCompressedPublicKey = secp256k1.getPublicKey(ethWallet.privateKey, true);  // For Ethereum, now compressed
        
        const address = getEthereumAddress(secp256k1.getPublicKey(ethWallet.privateKey, false));  // Still use uncompressed for address
        const bitcoinAddress = getBitcoinSegwitAddress(compressedPublicKey);
        const LibreKeys = getLibreKeys(eosWallet.privateKey);

        console.log(`₿ Bitcoin Keys:`);
        console.log(`🏠 Address:     ${bitcoinAddress}`);
        console.log(`📢 Public Key:  ${toHex(compressedPublicKey)}`);
        console.log(`🔐 Private Key: ${toWIF(btcWallet.privateKey)}\n`);

        console.log(`⟠ Ethereum Keys:`);
        console.log(`🏠 Address:     ${address}`);
        console.log(`📢 Public Key:  0x${toHex(ethCompressedPublicKey)}`);
        console.log(`🔐 Private Key: 0x${ethWallet.privateKey.toString('hex')}\n`);

        console.log(`🗽 Libre Keys:`);
        console.log(`📢 Public Key:  ${LibreKeys.publicKey}`);
        console.log(`🔐 Private Key: ${LibreKeys.privateKey}\n`);
    } else if (args.private) {
        const privateKey = Buffer.from(args.private.replace(/^0x/, ""), "hex");
        
        // Get both compressed and uncompressed public keys for Ethereum
        const compressedPublicKey = secp256k1.getPublicKey(privateKey, true);
        const uncompressedPublicKey = secp256k1.getPublicKey(privateKey, false);
        
        // Use uncompressed key for Ethereum address
        const address = getEthereumAddress(uncompressedPublicKey);
        
        const LibreKeys = getLibreKeys(privateKey);
        
        console.log(`\n🔑 Private Key:  0x${toHex(privateKey)}`);
        console.log(`📢 Public Key:   0x${toHex(uncompressedPublicKey)}`);
        console.log(`🏠 Address:      ${address}`);
        console.log(`\nLibre Keys:`);
        console.log(`🔑 Libre Private:  ${LibreKeys.privateKey}`);
        console.log(`📢 Libre Public:   ${LibreKeys.publicKey}\n`);
    } else {
        mnemonic = await promptUser();
        // Validate mnemonic
        if (!bip39.validateMnemonic(mnemonic)) {
            console.error("❌ Invalid mnemonic phrase");
            // Print the word list for verification
            console.log("\nWords in mnemonic:");
            mnemonic.split(' ').forEach((word, i) => {
                console.log(`${i + 1}: "${word}"`);
            });
            process.exit(1);
        }

        console.log('\nInput mnemonic:', mnemonic);
        console.log('Is valid mnemonic:', bip39.validateMnemonic(mnemonic));
        console.log('Word count:', mnemonic.split(' ').length);
        
        // Generate entropy from mnemonic
        const entropy = bip39.mnemonicToEntropy(mnemonic);
        console.log('Entropy:', entropy);
        
        // Generate seed
        const seed = bip39.mnemonicToSeedSync(mnemonic);
        console.log('Seed:', seed.toString('hex'));
        
        // Use EOS derivation path instead of Ethereum's
        const hdwallet = hdkey.fromMasterSeed(seed);
        
        // Different derivation paths for each coin
        const eosPath = "m/44'/194'/0'/0/0";    // EOS path
        const btcPath = "m/84'/0'/0'/0/0";      // Bitcoin SegWit path (BIP84)
        const ethPath = "m/44'/60'/0'/0/0";     // Ethereum path
        
        // Derive wallets for each path
        const eosWallet = hdwallet.derive(eosPath);
        const btcWallet = hdwallet.derive(btcPath);
        const ethWallet = hdwallet.derive(ethPath);
        
        // Get keys for each cryptocurrency
        const compressedPublicKey = secp256k1.getPublicKey(btcWallet.privateKey, true);  // For Bitcoin
        const ethCompressedPublicKey = secp256k1.getPublicKey(ethWallet.privateKey, true);  // For Ethereum, now compressed
        
        const address = getEthereumAddress(secp256k1.getPublicKey(ethWallet.privateKey, false));  // Still use uncompressed for address
        const bitcoinAddress = getBitcoinSegwitAddress(compressedPublicKey);
        const LibreKeys = getLibreKeys(eosWallet.privateKey);

        console.log(`₿ Bitcoin Keys:`);
        console.log(`🏠 Address:     ${bitcoinAddress}`);
        console.log(`📢 Public Key:  ${toHex(compressedPublicKey)}`);
        console.log(`🔐 Private Key: ${toWIF(btcWallet.privateKey)}\n`);

        console.log(`⟠ Ethereum Keys:`);
        console.log(`🏠 Address:     ${address}`);
        console.log(`📢 Public Key:  0x${toHex(ethCompressedPublicKey)}`);
        console.log(`🔐 Private Key: 0x${ethWallet.privateKey.toString('hex')}\n`);

        console.log(`🗽 Libre Keys:`);
        console.log(`📢 Public Key:  ${LibreKeys.publicKey}`);
        console.log(`🔐 Private Key: ${LibreKeys.privateKey}\n`);
    }
}

main().catch(console.error);
