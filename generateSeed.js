#!/usr/bin/env node

const bip39 = require("bip39");
const crypto = require('crypto');
const os = require('os');
const readline = require('readline');

async function collectSystemEntropy() {
    // Collect various system metrics
    const systemEntropy = Buffer.from(JSON.stringify({
        uptime: os.uptime(),
        loadavg: os.loadavg(),
        totalmem: os.totalmem(),
        freemem: os.freemem(),
        cpus: os.cpus().map(cpu => cpu.times),
        networkInterfaces: os.networkInterfaces(),
        processMemory: process.memoryUsage(),
        hrtime: process.hrtime(),
        pid: process.pid,
        timestamp: Date.now(),
        random: crypto.randomBytes(32)
    }));

    return crypto.createHash('sha256').update(systemEntropy).digest();
}

async function collectMouseEntropy() {
    console.log('\n🎲 Move your mouse and press random keys for additional entropy...');
    console.log('Press Enter when done.');
    
    return new Promise((resolve) => {
        const movements = [];
        let timeout;
        let dots = 0;
        let dataInterval;
        
        // Setup raw mode to capture input without requiring Enter
        process.stdin.setRawMode(true);
        process.stdin.resume();
        
        // Visual feedback for data collection
        const feedbackInterval = setInterval(() => {
            process.stdout.write(`\rCollecting entropy${'.'.repeat(dots)}`);
            dots = (dots + 1) % 4;
        }, 500);
        
        // Capture mouse/keyboard events
        process.stdin.on('data', (data) => {
            if (data[0] === 13) { // Enter key
                clearInterval(feedbackInterval);
                clearInterval(dataInterval);
                cleanup();
                // Apply HMAC to ensure uniform distribution
                const key = crypto.randomBytes(32);
                const hmac = crypto.createHmac('sha256', key);
                hmac.update(Buffer.from(movements.join('')));
                resolve(hmac.digest());
            } else {
                // Collect entropy from keypresses
                movements.push(data[0]); // Key code
                movements.push(Date.now());
                movements.push(process.hrtime()[1]);
                movements.push(os.freemem());
                process.stdout.write(`\rCollecting entropy: ${movements.length} data points`);
            }
        });

        function cleanup() {
            process.stdin.setRawMode(false);
            process.stdin.pause();
            clearTimeout(timeout);
            clearInterval(dataInterval);
            console.log(`\n✨ Entropy collection complete! (${movements.length} data points collected)\n`);
        }

        // Set a timeout to auto-complete after 10 seconds
        timeout = setTimeout(() => {
            clearInterval(feedbackInterval);
            clearInterval(dataInterval);
            cleanup();
            // Apply HMAC for timeout case too
            const key = crypto.randomBytes(32);
            const hmac = crypto.createHmac('sha256', key);
            hmac.update(Buffer.from(movements.join('')));
            resolve(hmac.digest());
        }, 10000);

        // Collect additional system metrics periodically
        dataInterval = setInterval(() => {
            movements.push(Date.now());
            movements.push(process.hrtime()[1]);
            movements.push(os.loadavg()[0] * 1000);
            movements.push(os.freemem());
            process.stdout.write(`\rCollecting entropy: ${movements.length} data points`);
        }, 100);
    });
}

async function generateRandomSeed() {
    // Ask user for entropy size
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    const entropyBits = await new Promise(resolve => {
        rl.question('\n🔑 Choose entropy size (type 128 or 256 bits): ', answer => {
            rl.close();
            resolve(answer.trim() === '256' ? 32 : 16); // Convert to bytes (256/8 = 32, 128/8 = 16)
        });
    });

    // Get system entropy
    const systemEntropy = await collectSystemEntropy();
    
    // Get mouse/timing/keypress entropy
    const userEntropy = await collectMouseEntropy();
    
    // Combine all entropy sources with HMAC
    const key = crypto.randomBytes(32);
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(Buffer.concat([
        systemEntropy,
        userEntropy,
        crypto.randomBytes(32)
    ]));
    
    // Get final entropy for seed (using chosen size)
    const finalEntropy = hmac.digest().slice(0, entropyBits);
    
    // Convert to mnemonic
    return bip39.entropyToMnemonic(finalEntropy);
}

async function main() {
    console.log('\n🎲 Generating secure seed phrase...');
    console.log('This will use multiple sources of entropy for maximum security.');
    
    const seed = await generateRandomSeed();
    
    console.log('\n🔐 Generated Seed Phrase:');
    console.log(seed);
    console.log('\n⚠️  WARNING: Save this phrase securely!');
    console.log('Anyone with access to this phrase will have access to your funds!\n');

    // Automatically derive address from the seed
    const { spawn } = require('child_process');
    console.log('🔄 Deriving address from seed...\n');
    
    const deriveProcess = spawn('node', ['deriveAddress.js'], {
        stdio: ['pipe', 'inherit', 'inherit']
    });
    
    // Write the seed to deriveAddress.js's stdin
    deriveProcess.stdin.write(seed + '\n');
    deriveProcess.stdin.end();

    // Wait for the process to complete
    await new Promise((resolve, reject) => {
        deriveProcess.on('close', (code) => {
            if (code === 0) {
                resolve();
            } else {
                reject(new Error(`deriveAddress.js exited with code ${code}`));
            }
        });
    });
}

main().catch(console.error); 