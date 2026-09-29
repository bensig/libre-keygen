# Libre Key Generator

Command-line tools to generate BIP39 mnemonics and derive Libre, Bitcoin, Ethereum
and Solana keys from them. **Run offline on a trusted machine.**

## Installation
```bash
npm ci
```

## Usage

### Generate a new seed phrase (and show derived keys)
```bash
node generateSeed.js              # 256-bit / 24 words (default)
node generateSeed.js --bits 128   # 12 words
```
Entropy comes from `crypto.randomBytes` (OS CSPRNG).

### Derive keys from an existing seed phrase
```bash
node deriveAddress.js             # prompts for the phrase
node deriveAddress.js < phrase.txt
```
The phrase is read from stdin only. Passing it as an argument is refused, because
arguments end up in shell history and `ps`.

### Batch-generate Libre keys (public keys to stdout, secrets to a 0600 file)
```bash
node generateBatch.js accounts.txt [--out keys.json] [--bits 128]
node generateBatch.js --n 5
```

## Derivation paths

All tools share `keys.js`, so a mnemonic yields the same keys everywhere.

| Chain    | Path                    | Output                                  |
|----------|-------------------------|-----------------------------------------|
| Libre    | `m/44'/194'/0'/0/0`     | `EOS…` / `PUB_K1_…`, WIF `5…` / `PVT_K1_…` |
| Bitcoin  | `m/84'/0'/0'/0/0`       | `bc1q…` (P2WPKH), compressed WIF        |
| Ethereum | `m/44'/60'/0'/0/0`      | `0x…` address, hex private key          |
| Solana   | `m/44'/501'/{0,1,2}'/0'`| base58 address + secret key (Phantom layout) |

## Requirements

- Node.js v20 or higher

## License

MIT. See the LICENSE file for details.

## Contact

- X (Twitter): [@bensig](https://twitter.com/bensig)
