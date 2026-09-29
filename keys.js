// Shared key derivation — the ONLY place derivation paths and encodings live.
// All tools (deriveAddress, generateSeed, generateBatch) go through here so the
// same mnemonic always yields the same keys regardless of entry point.

const crypto = require('crypto');
const bip39 = require('bip39');
const hdkey = require('hdkey');
const wif = require('wif');
const bech32 = require('bech32');
const base58 = require('bs58');
const { keccak256 } = require('ethereum-cryptography/keccak');
const { secp256k1 } = require('ethereum-cryptography/secp256k1');
const { toHex } = require('ethereum-cryptography/utils');
const { PrivateKey, KeyType, Bytes } = require('@greymass/eosio');
const { derivePath } = require('ed25519-hd-key');
const { Keypair } = require('@solana/web3.js');

const PATHS = {
    libre: "m/44'/194'/0'/0/0",   // EOS/Libre (SLIP-44 194)
    btc: "m/84'/0'/0'/0/0",       // BIP84 native SegWit
    eth: "m/44'/60'/0'/0/0",
    sol: (i) => `m/44'/501'/${i}'/0'`, // Phantom/Solflare layout
};

// Canonical form: lowercase, single-spaced. Throws on invalid checksum/wordlist.
function normalizeMnemonic(input) {
    const mnemonic = String(input).trim().toLowerCase().split(/\s+/).join(' ');
    if (!bip39.validateMnemonic(mnemonic)) throw new Error('Invalid mnemonic phrase');
    return mnemonic;
}

// bits must be exactly 128 or 256; anything else is an error, never a silent default.
function generateMnemonic(bits = 256) {
    if (bits !== 128 && bits !== 256) throw new Error(`Entropy must be 128 or 256 bits, got ${bits}`);
    return bip39.entropyToMnemonic(crypto.randomBytes(bits / 8));
}

function libreKeys(privateKey) {
    const key = new PrivateKey(KeyType.K1, Bytes.from(privateKey));
    const pub = key.toPublic();
    return {
        privateKey: key.toWif(),          // legacy 5... WIF
        publicKey: pub.toLegacyString(),  // EOS...
        privateKeyK1: String(key),        // PVT_K1_...
        publicKeyK1: String(pub),         // PUB_K1_...
    };
}

function btcKeys(privateKey) {
    const pub = secp256k1.getPublicKey(privateKey, true);
    const h160 = crypto.createHash('ripemd160').update(crypto.createHash('sha256').update(pub).digest()).digest();
    return {
        address: bech32.bech32.encode('bc', [0, ...bech32.bech32.toWords(h160)]),
        publicKey: toHex(pub),
        privateKey: wif.encode({ version: 128, privateKey, compressed: true }),
    };
}

function ethKeys(privateKey) {
    const uncompressed = secp256k1.getPublicKey(privateKey, false);
    return {
        address: '0x' + toHex(keccak256(uncompressed.slice(1)).slice(-20)),
        publicKey: '0x' + toHex(secp256k1.getPublicKey(privateKey, true)),
        privateKey: '0x' + toHex(privateKey),
    };
}

function solKeys(seed, index) {
    const path = PATHS.sol(index);
    const keypair = Keypair.fromSeed(derivePath(path, seed.toString('hex')).key);
    return { path, address: keypair.publicKey.toBase58(), privateKey: base58.encode(keypair.secretKey) };
}

function deriveLibre(mnemonic) {
    const seed = bip39.mnemonicToSeedSync(normalizeMnemonic(mnemonic));
    return libreKeys(hdkey.fromMasterSeed(seed).derive(PATHS.libre).privateKey);
}

function deriveAll(mnemonic, { solAccounts = 3 } = {}) {
    const seed = bip39.mnemonicToSeedSync(normalizeMnemonic(mnemonic));
    const root = hdkey.fromMasterSeed(seed);
    return {
        libre: libreKeys(root.derive(PATHS.libre).privateKey),
        btc: btcKeys(root.derive(PATHS.btc).privateKey),
        eth: ethKeys(root.derive(PATHS.eth).privateKey),
        sol: Array.from({ length: solAccounts }, (_, i) => solKeys(seed, i)),
    };
}

module.exports = { PATHS, normalizeMnemonic, generateMnemonic, deriveLibre, deriveAll, libreKeys };
