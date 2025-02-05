# Ethereum & Libre Key Generator

A command-line tool to generate Ethereum and Libre keys from a seed phrase or private key.

## Installation
```bash
npm install
```

## Usage

### 1. Generate New Seed Phrase
```bash
node generateSeed.js
```
This will generate a new random 12-word BIP39 seed phrase.

### 2. Interactive Mode
```bash
node deriveAddress.js
```

### 3. Seed Phrase Mode
```bash
node deriveAddress.js --seed="your seed phrase"
```

### 4. Private Key Mode
```bash
node deriveAddress.js --private="your private key"
```

## Output Format

The tool generates the following keys:
- Private Key (Ethereum)
- Public Key (Ethereum)
- Ethereum Address
- Libre Private Key
- Libre Public Key

## Requirements

- Node.js v20 or higher
- npm

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contact

For questions or feedback, please reach out:
- X (Twitter): [@bensig](https://twitter.com/bensig)
