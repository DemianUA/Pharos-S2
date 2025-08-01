const axios = require('axios');
const ethers = require('ethers');
const dotenv = require('dotenv');
const readline = require('readline');
const fs = require('fs');
const { HttpsProxyAgent } = require('https-proxy-agent');

dotenv.config();

// Функція для парсингу діапазону з рядка "min,max"
function parseRange(rangeStr, defaultValue = [1, 1]) {
    if (!rangeStr) return defaultValue;
    
    const parts = rangeStr.split(',').map(p => parseInt(p.trim()));
    if (parts.length !== 2 || isNaN(parts[0]) || isNaN(parts[1])) {
        logger.warn(`Invalid range format: ${rangeStr}, using default: ${defaultValue}`);
        return defaultValue;
    }
    
    return [Math.min(parts[0], parts[1]), Math.max(parts[0], parts[1])];
}

// Функція для отримання випадкового числа з діапазону
function getRandomFromRange(range) {
    return Math.floor(Math.random() * (range[1] - range[0] + 1)) + range[0];
}

// Функція для отримання випадкової затримки в мілісекундах
function getRandomDelay(rangeSeconds) {
    const delayMs = getRandomFromRange(rangeSeconds) * 1000;
    return delayMs;
}

// Завантаження налаштувань з .env
function loadConfig() {
    const config = {
        retriesPerAction: parseInt(process.env.RETRIES_PER_ACTION) || 3,
        delayBetweenRetries: parseRange(process.env.DELAY_BETWEEN_RETRIES, [5, 10]),
        delayBetweenActions: parseRange(process.env.DELAY_BETWEEN_ACTIONS, [100, 200]),
        delayBetweenWallets: parseRange(process.env.DELAY_BETWEEN_WALLETS, [20, 50]),
        tipActions: parseRange(process.env.TIP_ACTIONS_WALLET, [1, 2]),
        aquaFluxActions: parseRange(process.env.AQUAFLUX_ACTIONS_WALLET, [1, 2])
    };
    
    logger.success('Configuration loaded from .env:');
    logger.info(`Retries per action: ${config.retriesPerAction}`);
    logger.info(`Tip actions: ${config.tipActions[0]}-${config.tipActions[1]}`);
    logger.info(`AquaFlux actions: ${config.aquaFluxActions[0]}-${config.aquaFluxActions[1]}`);
    logger.info(`Delay between actions: ${config.delayBetweenActions[0]}-${config.delayBetweenActions[1]}s`);
    logger.info(`Delay between wallets: ${config.delayBetweenWallets[0]}-${config.delayBetweenWallets[1]}s`);
    
    return config;
}

// Завантаження User-Agent'ів з JSON файлу
function loadUserAgents() {
    try {
        const data = fs.readFileSync('user_agents.json', 'utf8');
        const userAgents = JSON.parse(data);
        logger.success(`${Object.keys(userAgents).length} User-Agent'ів завантажено з user_agents.json`);
        return userAgents;
    } catch (error) {
        logger.error(`Помилка завантаження user_agents.json: ${error.message}`);
        return {};
    }
}

// Функція для отримання постійного User-Agent для гаманця
function getUserAgentForWallet(privateKey, userAgents) {
    const userAgent = userAgents[privateKey];
    if (!userAgent) {
        logger.warn(`User-Agent не знайдено для приватного ключа ${privateKey}, використовую дефолтний`);
        return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
    }
    logger.info(`Використовую постійний User-Agent для приватного ключа ${privateKey}`);
    return userAgent;
}

const ERC20_ABI = [
  "function balanceOf(address owner) view returns (uint256)",
  "function decimals() view returns (uint8)",
  "function approve(address spender, uint256 amount) returns (bool)",
  "function allowance(address owner, address spender) view returns (uint256)"
];

const PRIMUS_TIP_ABI = [
    "function tip((uint32,address) token, (string,string,uint256,uint256[]) recipient)"
];

const AQUAFLUX_NFT_ABI = [
    "function claimTokens()",
    "function mint(uint256 nftType, uint256 expiresAt, bytes signature)",
    "function balanceOf(address owner) view returns (uint256)"
];

async function buildFallbackProvider(rpcUrls, chainId, name) {
  const provider = new ethers.JsonRpcProvider(rpcUrls[0], { chainId, name });
  return {
    getProvider: async () => {
      for (let i = 0; i < 3; i++) {
        try {
          await provider.getBlockNumber();
          return provider;
        } catch (e) {
          if (e.code === 'UNKNOWN_ERROR' && e.error && e.error.code === -32603) {
            console.log(`${colors.yellow}[⚠] RPC busy, retrying ${i + 1}/3...${colors.reset}`);
            await new Promise(r => setTimeout(r, 2000));
            continue;
          }
          throw e;
        }
      }
      throw new Error('All RPC retries failed');
    }
  };
}

const colors = {
  reset: "\x1b[0m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
  white: "\x1b[37m",
  bold: "\x1b[1m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m"
};

const logger = {
  info: (msg) => console.log(`${colors.green}[✓] ${msg}${colors.reset}`),
  warn: (msg) => console.log(`${colors.yellow}[⚠] ${msg}${colors.reset}`),
  error: (msg) => console.log(`${colors.red}[✗] ${msg}${colors.reset}`),
  success: (msg) => console.log(`${colors.green}[✅] ${msg}${colors.reset}`),
  loading: (msg) => console.log(`${colors.cyan}[⟳] ${msg}${colors.reset}`),
  step: (msg) => console.log(`${colors.white}[➤] ${msg}${colors.reset}`),
  countdown: (msg) => process.stdout.write(`\r${colors.blue}[⏰] ${msg}${colors.reset}`),
  banner: () => {
    console.log(`${colors.cyan}${colors.bold}`);
    console.log(`---------------------------------------------`);
    console.log(`     PharosV2 Auto Bot - Crypto Travels     `);
    console.log(`---------------------------------------------${colors.reset}`);
    console.log();
  }
};

const PHAROS_CHAIN_ID = 688688;
const PHAROS_RPC_URLS = ['https://testnet.dplabs-internal.com'];

const TOKENS = {
  PHRS: '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE'
};

const AQUAFLUX_NFT_CONTRACT = '0xcc8cf44e196cab28dba2d514dc7353af0efb370e';
const AQUAFLUX_TOKENS = {
  P: '0xb5d3ca5802453cc06199b9c40c855a874946a92c',
  C: '0x4374fbec42e0d46e66b379c0a6072c910ef10b32',
  S: '0x5df839de5e5a68ffe83b89d430dc45b1c5746851',
  CS: '0xceb29754c54b4bfbf83882cb0dcef727a259d60a'
};

const PRIMUS_TIP_CONTRACT = '0xd17512b7ec12880bd94eca9d774089ff89805f02';

function loadPrivateKeys() {
  const keys = [];
  let i = 1;
  while (process.env[`PRIVATE_KEY_${i}`]) {
    const pk = process.env[`PRIVATE_KEY_${i}`];
    if (pk.startsWith('0x') && pk.length === 66) {
      keys.push(pk);
    } else {
      logger.warn(`Invalid PRIVATE_KEY_${i} in .env, skipping...`);
    }
    i++;
  }
  return keys;
}

function loadProxies() {
    try {
        const data = fs.readFileSync('proxies.txt', 'utf8');
        const proxies = data.split('\n').map(p => p.trim());
        logger.success(`${proxies.length} proxy entries loaded from proxies.txt`);
        const validProxies = proxies.filter(p => p);
        logger.info(`${validProxies.length} valid proxies found`);
        return proxies;
    } catch (error) {
        if (error.code === 'ENOENT') {
            logger.warn('proxies.txt not found. Continuing without proxies.');
        } else {
            logger.error(`Error reading proxies.txt: ${error.message}`);
        }
        return [];
    }
}

function getProxyAgentForWallet(originalIndex, proxies) {
    if (!proxies || originalIndex >= proxies.length) {
        logger.warn(`No proxy available for wallet ${originalIndex + 1}, using direct connection`);
        return null;
    }
    
    const proxy = proxies[originalIndex];
    
    if (!proxy || proxy.trim() === '') {
        logger.info(`Wallet ${originalIndex + 1}: No proxy configured, using direct connection`);
        return null;
    }
    
    logger.info(`Wallet ${originalIndex + 1}: Using proxy: ${proxy.split('@')[1] || proxy}`);
    return new HttpsProxyAgent(proxy);
}

async function aquaFluxLogin(wallet, proxyAgent, userAgent) {
  try {
    const timestamp = Date.now();
    const message = `Sign in to AquaFlux with timestamp: ${timestamp}`;
    const signature = await wallet.signMessage(message);
    const response = await axios.post('https://api.aquaflux.pro/api/v1/users/wallet-login', {
      address: wallet.address,
      message: message,
      signature: signature
    }, {
      headers: {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'en-US,en;q=0.5',
        'content-type': 'application/json',
        'user-agent': userAgent
      },
      httpsAgent: proxyAgent
    });
    
    if (response.data.status === 'success') {
      logger.success('AquaFlux login successful!');
      return response.data.data.accessToken;
    } else {
      throw new Error('Login failed: ' + JSON.stringify(response.data));
    }
  } catch (e) {
    logger.error(`AquaFlux login failed: ${e.message}`);
    throw e;
  }
}

async function claimTokens(wallet) {
  logger.step('Claiming free AquaFlux tokens (C & S)...');
  try {
    const nftContract = new ethers.Contract(AQUAFLUX_NFT_CONTRACT, AQUAFLUX_NFT_ABI, wallet);
    
    const tx = await nftContract.claimTokens({ gasLimit: 300000 });
    logger.success(`Claim tokens transaction sent! TX Hash: ${tx.hash}`);
    await tx.wait();
    logger.success('Tokens claimed successfully!');
    
    return true;
  } catch (e) {
    if (e.message.includes('already claimed')) {
        logger.warn('Tokens have already been claimed for today.');
        return true;
    }
    logger.error(`Claim tokens failed: ${e.message}`);
    throw e;
  }
}

async function craftTokens(wallet) {
  logger.step('Crafting 100 CS tokens from C and S tokens...');
  try {
    const cTokenContract = new ethers.Contract(AQUAFLUX_TOKENS.C, ERC20_ABI, wallet);
    const sTokenContract = new ethers.Contract(AQUAFLUX_TOKENS.S, ERC20_ABI, wallet);
    const csTokenContract = new ethers.Contract(AQUAFLUX_TOKENS.CS, ERC20_ABI, wallet);

    const requiredAmount = ethers.parseUnits('100', 18); 

    const cBalance = await cTokenContract.balanceOf(wallet.address);
    if (cBalance < requiredAmount) {
      throw new Error(`Insufficient C tokens. Required: 100, Available: ${ethers.formatUnits(cBalance, 18)}`);
    }

    const sBalance = await sTokenContract.balanceOf(wallet.address);
    if (sBalance < requiredAmount) {
      throw new Error(`Insufficient S tokens. Required: 100, Available: ${ethers.formatUnits(sBalance, 18)}`);
    }

    const cAllowance = await cTokenContract.allowance(wallet.address, AQUAFLUX_NFT_CONTRACT);
    if (cAllowance < requiredAmount) {
        logger.step('Approving C tokens...');
        const cApproveTx = await cTokenContract.approve(AQUAFLUX_NFT_CONTRACT, ethers.MaxUint256);
        await cApproveTx.wait();
        logger.success('C tokens approved');
    }

    const sAllowance = await sTokenContract.allowance(wallet.address, AQUAFLUX_NFT_CONTRACT);
    if(sAllowance < requiredAmount) {
        logger.step('Approving S tokens...');
        const sApproveTx = await sTokenContract.approve(AQUAFLUX_NFT_CONTRACT, ethers.MaxUint256);
        await sApproveTx.wait();
        logger.success('S tokens approved');
    }

    const csBalanceBefore = await csTokenContract.balanceOf(wallet.address);
    logger.info(`CS Token balance before crafting: ${ethers.formatUnits(csBalanceBefore, 18)}`);
    
    logger.step("Crafting CS tokens...");
    
    const CRAFT_METHOD_ID = '0x4c10b523';
    const abiCoder = ethers.AbiCoder.defaultAbiCoder();
    const encodedParams = abiCoder.encode(['uint256'], [requiredAmount]);
    const calldata = CRAFT_METHOD_ID + encodedParams.substring(2);
    
    const craftTx = await wallet.sendTransaction({
        to: AQUAFLUX_NFT_CONTRACT,
        data: calldata,
        gasLimit: 300000
    });
    
    logger.success(`Crafting transaction sent! TX Hash: ${craftTx.hash}`);
    const receipt = await craftTx.wait();
    
    if (receipt.status === 0) {
        throw new Error('Crafting transaction reverted on-chain');
    }
    
    logger.success('Crafting transaction confirmed.');

    const csBalanceAfter = await csTokenContract.balanceOf(wallet.address);
    const craftedAmount = csBalanceAfter - csBalanceBefore;
    
    logger.success(`CS Token balance after crafting: ${ethers.formatUnits(csBalanceAfter, 18)}`);
    logger.success(`Successfully crafted: ${ethers.formatUnits(craftedAmount, 18)} CS tokens`);
    
    if (craftedAmount < requiredAmount) {
        throw new Error(`Crafting incomplete. Expected 100 CS tokens, got ${ethers.formatUnits(craftedAmount, 18)}`);
    }
    
    return true;
  } catch (e) {
    logger.error(`Craft tokens failed: ${e.reason || e.message}`);
    throw e;
  }
}

async function checkTokenHolding(accessToken, proxyAgent, userAgent) {
  try {
    const response = await axios.post('https://api.aquaflux.pro/api/v1/users/check-token-holding', null, {
      headers: {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'en-US,en;q=0.5',
        'authorization': `Bearer ${accessToken}`,
        'user-agent': userAgent
      },
      httpsAgent: proxyAgent
    });
    
    if (response.data.status === 'success') {
      const isHolding = response.data.data.isHoldingToken;
      logger.success(`API Token holding check: ${isHolding ? 'YES' : 'NO'}`);
      return isHolding;
    } else {
      throw new Error('Check holding failed: ' + JSON.stringify(response.data));
    }
  } catch (e) {
    logger.error(`Check token holding failed: ${e.message}`);
    throw e;
  }
}

async function getSignature(wallet, accessToken, proxyAgent, userAgent, nftType = 0) {
  try {
    const response = await axios.post('https://api.aquaflux.pro/api/v1/users/get-signature', {
      walletAddress: wallet.address,
      requestedNftType: nftType
    }, {
      headers: {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'en-US,en;q=0.5',
        'authorization': `Bearer ${accessToken}`,
        'content-type': 'application/json',
        'user-agent': userAgent
      },
      httpsAgent: proxyAgent
    });
    
    if (response.data.status === 'success') {
      logger.success('Signature obtained successfully!');
      return response.data.data;
    } else {
      throw new Error('Get signature failed: ' + JSON.stringify(response.data));
    }
  } catch (e) {
    logger.error(`Get signature failed: ${e.message}`);
    throw e;
  }
}

async function mintNFT(wallet, signatureData) {
  logger.step('Minting AquaFlux NFT...');
  try {
    const csTokenContract = new ethers.Contract(AQUAFLUX_TOKENS.CS, ERC20_ABI, wallet);
    const requiredAmount = ethers.parseUnits('100', 18);
    
    const csBalance = await csTokenContract.balanceOf(wallet.address);
    if (csBalance < requiredAmount) {
      throw new Error(`Insufficient CS tokens. Required: 100, Available: ${ethers.formatUnits(csBalance, 18)}`);
    }
    
    const allowance = await csTokenContract.allowance(wallet.address, AQUAFLUX_NFT_CONTRACT);
    if (allowance < requiredAmount) {
        const approvalTx = await csTokenContract.approve(AQUAFLUX_NFT_CONTRACT, ethers.MaxUint256);
        await approvalTx.wait();
    }
    
    const currentTime = Math.floor(Date.now() / 1000);
    if (currentTime >= signatureData.expiresAt) {
        throw new Error(`Signature is already expired! Check your system's clock.`);
    }

    const CORRECT_METHOD_ID = '0x75e7e053';
    const abiCoder = ethers.AbiCoder.defaultAbiCoder();
    const encodedParams = abiCoder.encode(
        ['uint256', 'uint256', 'bytes'],
        [signatureData.nftType, signatureData.expiresAt, signatureData.signature]
    );
    const calldata = CORRECT_METHOD_ID + encodedParams.substring(2);

    const tx = await wallet.sendTransaction({
        to: AQUAFLUX_NFT_CONTRACT,
        data: calldata,
        gasLimit: 400000
    });
    
    logger.success(`NFT mint transaction sent! TX Hash: ${tx.hash}`);
    const receipt = await tx.wait();
    
    if (receipt.status === 0) {
        throw new Error('Transaction reverted on-chain. Check the transaction on a block explorer.');
    }
    
    logger.success('NFT minted successfully!');
    
    return true;
  } catch (e) {
    logger.error(`NFT mint failed: ${e.reason || e.message}`);
    throw e;
  }
}

async function executeAquaFluxFlow(wallet, proxyAgent, userAgent) {
  try {
    const accessToken = await aquaFluxLogin(wallet, proxyAgent, userAgent);
    await claimTokens(wallet);
    await craftTokens(wallet);
    await checkTokenHolding(accessToken, proxyAgent, userAgent);
    const signatureData = await getSignature(wallet, accessToken, proxyAgent, userAgent);
    await mintNFT(wallet, signatureData);
    
    logger.success('AquaFlux flow completed successfully!');
    return true;
  } catch (e) {
    logger.error(`AquaFlux flow failed: ${e.message}`);
    return false;
  }
}

async function sendTip(wallet, username) {
    logger.step('Starting "Send Tip" process...');
    try {
        const minAmount = ethers.parseEther('0.00001');
        const maxAmount = ethers.parseEther('0.001');
        let randomAmount = minAmount + BigInt(Math.floor(Math.random() * Number(maxAmount - minAmount + BigInt(1))));
        let amountHuman = Number(ethers.formatEther(randomAmount));
        let rounded = Math.floor(amountHuman * 10000) / 10000;
        if (rounded < 0.0001) rounded = 0.0001;
        const roundedStr = rounded.toFixed(4);
        const finalAmount = ethers.parseEther(roundedStr);
        const amountStr = ethers.formatEther(finalAmount);

        logger.step(`Preparing to tip ${amountStr} PHRS to ${username} on X...`);
        
        const tipContract = new ethers.Contract(PRIMUS_TIP_CONTRACT, PRIMUS_TIP_ABI, wallet);

        const tokenStruct = [
            1,
            '0x0000000000000000000000000000000000000000'
        ];

        const recipientStruct = [
            'x',
            username,
            finalAmount,
            []
        ];

        const tx = await tipContract.tip(tokenStruct, recipientStruct, {
            value: finalAmount
        });

        logger.success(`Tip transaction sent! TX Hash: ${tx.hash}`);
        await tx.wait();
        logger.success(`Successfully tipped ${amountStr} PHRS to ${username}!`);

    } catch (e) {
        logger.error(`Send Tip failed: ${e.message}`);
        throw e;
    }
}

async function showCountdown() {
    const now = new Date();
    const tomorrow = new Date(now);
    tomorrow.setDate(now.getDate() + 1);
    tomorrow.setHours(0, 0, 0, 0);
 
    return new Promise(resolve => {
      const interval = setInterval(() => {
        const remaining = tomorrow - new Date();
        const hours = Math.floor(remaining / (1000 * 60 * 60));
        const minutes = Math.floor((remaining % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((remaining % (1000 * 60)) / 1000);
        logger.countdown(`Next cycle in ${hours}h ${minutes}m ${seconds}s`);
        if (remaining <= 0) {
          clearInterval(interval);
          process.stdout.write('\n');
          resolve();
        }
      }, 1000);
    });
}

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function question(query) {
  return new Promise(resolve => rl.question(query, resolve));
}

// Функція для перемішування масиву (Fisher-Yates shuffle)
function shuffleArray(array) {
    const shuffled = [...array];
    for (let i = shuffled.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    return shuffled;
}

// Функція для завантаження username з twitter.txt
function loadTwitterUsernames() {
    try {
        const data = fs.readFileSync('twitter.txt', 'utf8');
        const usernames = data.split('\n').map(u => u.trim()).filter(u => u);
        if (usernames.length === 0) {
            logger.error('twitter.txt is empty. Please add at least one username.');
            process.exit(1);
        }
        logger.success(`${usernames.length} Twitter usernames loaded from twitter.txt`);
        return usernames;
    } catch (error) {
        logger.error(`Error reading twitter.txt: ${error.message}`);
        process.exit(1);
    }
}

function getRandomTwitterUsername(usernames) {
    return usernames[Math.floor(Math.random() * usernames.length)];
}

// Функція для перевірки наявності AquaFlux NFT на гаманці
async function checkAquaFluxNFT(wallet) {
    try {
        const nftContract = new ethers.Contract(AQUAFLUX_NFT_CONTRACT, [
            "function balanceOf(address owner) view returns (uint256)"
        ], wallet.provider);
        const balance = await nftContract.balanceOf(wallet.address);
        if (balance > 0n) {
            logger.success(`AquaFlux NFT вже є на гаманці ${wallet.address}, пропускаємо всі AquaFlux активності.`);
            return true;
        } else {
            logger.info(`AquaFlux NFT ще немає на гаманці ${wallet.address}, виконуємо активності.`);
            return false;
        }
    } catch (e) {
        logger.error(`Не вдалося перевірити наявність AquaFlux NFT: ${e.message}`);
        return true;
    }
}

async function selectMode() {
    console.log(`${colors.cyan}${colors.bold}Виберіть режим роботи:${colors.reset}`);
    console.log(`${colors.yellow}1${colors.reset} - Виконати всі дії по черзі (AquaFlux, чайові)`);
    console.log(`${colors.yellow}2${colors.reset} - Тільки AquaFlux (логін, клейм, крафт, мінт)`);
    console.log(`${colors.yellow}3${colors.reset} - Тільки відправка чайових у Twitter/X`);
    let mode;
    while (true) {
        const input = await question(`${colors.cyan}Введіть номер режиму: ${colors.reset}`);
        mode = parseInt(input);
        if ([1, 2, 3].includes(mode)) break;
        console.log(`${colors.red}Некоректний вибір. Спробуйте ще раз.${colors.reset}`);
    }
    return mode;
}

(async () => {
  logger.banner();
  const fallbackProvider = await buildFallbackProvider(PHAROS_RPC_URLS, PHAROS_CHAIN_ID, 'pharos');
  const provider = await fallbackProvider.getProvider();
  const privateKeys = loadPrivateKeys();
  const proxies = loadProxies();
  const userAgents = loadUserAgents();
  const config = loadConfig();
  const twitterUsernames = loadTwitterUsernames();

  logger.info(`${privateKeys.length} wallet(s) loaded from .env file.\n`);
  logger.info(`First proxy for verification: ${proxies[0] || 'None'}`);

  const mode = await selectMode();

  while (true) {
    const indexedPrivateKeys = privateKeys.map((key, index) => ({ index, key }));
    const shuffledIndexedKeys = shuffleArray(indexedPrivateKeys);

    for (const { index: originalIndex, key: privateKey } of shuffledIndexedKeys) {
      try {
        const wallet = new ethers.Wallet(privateKey, provider);
        const proxyAgent = getProxyAgentForWallet(originalIndex, proxies);
        const userAgent = getUserAgentForWallet(privateKey, userAgents);
        console.log('----------------------------------------------------------------');
        logger.success(`Processing Wallet ${originalIndex + 1}/${privateKeys.length}: ${wallet.address}`);
        logger.info(`Using User-Agent: ${userAgent.substring(0, 50)}...`);
        console.log('----------------------------------------------------------------');

        // AquaFlux
        if (mode === 1 || mode === 2) {
          const hasNFT = await checkAquaFluxNFT(wallet);
          if (hasNFT) {
            logger.info('Пропускаємо AquaFlux активності для цього гаманця, бо NFT вже є.');
          } else {
            const numberOfMints = getRandomFromRange(config.aquaFluxActions);
            if (numberOfMints > 0) {
              logger.info(`Will perform ${numberOfMints} AquaFlux mint(s) for this wallet`);
              for (let i = 0; i < numberOfMints; i++) {
                  logger.step(`Starting AquaFlux Mint #${i + 1} of ${numberOfMints}`);
                  const aquaFluxSuccess = await executeAquaFluxFlow(wallet, proxyAgent, userAgent);
                  if (!aquaFluxSuccess) {
                      logger.error(`AquaFlux Mint #${i + 1} failed. Check logs above. Stopping AquaFlux mints for this wallet.`);
                      break;
                  }
                  if (i < numberOfMints - 1) {
                      const delay = getRandomDelay(config.delayBetweenActions);
                      logger.info(`Waiting ${delay/1000}s before the next mint...`);
                      await new Promise(r => setTimeout(r, delay));
                  }
              }
            }
          }
        }

        // Tips
        if (mode === 1 || mode === 3) {
          const numberOfTips = getRandomFromRange(config.tipActions);
          if (numberOfTips > 0) {
              logger.info(`Will send ${numberOfTips} tip(s) from this wallet`);
              for (let i = 0; i < numberOfTips; i++) {
                  const randomUsername = getRandomTwitterUsername(twitterUsernames);
                  logger.step(`Executing Tip #${i + 1} of ${numberOfTips} to ${randomUsername}`);
                  let success = false;
                  for (let retry = 0; retry < config.retriesPerAction && !success; retry++) {
                      try {
                          await sendTip(wallet, randomUsername);
                          success = true;
                      } catch (e) {
                          logger.error(`Tip transaction #${i + 1} failed (attempt ${retry + 1}/${config.retriesPerAction}): ${e.message}`);
                          if (retry < config.retriesPerAction - 1) {
                              const delay = getRandomDelay(config.delayBetweenRetries);
                              logger.info(`Retrying in ${delay/1000}s...`);
                              await new Promise(r => setTimeout(r, delay));
                          }
                      }
                  }
                  if (i < numberOfTips - 1) {
                      const delay = getRandomDelay(config.delayBetweenActions);
                      logger.info(`Waiting ${delay/1000}s before the next tip...`);
                      await new Promise(r => setTimeout(r, delay));
                  }
              }
              logger.success('Send tip operations completed for this wallet!');
          }
        }

        logger.success(`All tasks finished for wallet ${wallet.address}\n`);

      } catch (err) {
        logger.error(`A critical error occurred while processing wallet ${originalIndex + 1}: ${err.message}`);
      }

      if (originalIndex < privateKeys.length - 1) {
        const delay = getRandomDelay(config.delayBetweenWallets);
        logger.info(`Waiting ${delay/1000}s before starting the next wallet...`);
        await new Promise(r => setTimeout(r, delay));
      }
    }

    logger.step('All wallets have been processed for this cycle.');
    await showCountdown();
  }
})();