// app.js — Certificate DApp (Sepolia) — CSP-safe QR (no eval / no inline QR lib)
// -----------------------------------------------------------------------------
// Contract methods used:
//  - owner()
//  - isAdmin(address)
//  - getAllAdminInfo() -> (uint256 totalAdmins, bool isCallerAdmin, bool isCallerOwner)
//  - getCertificate(string certId) -> (productName, mfgName, mfgDate, isValid)
//  - getCertificateFull(string certId)
//  - ownerOfCertificate(string certId) -> address
//  - issueCertificate(
//        string certId, string productName, string mfgName, uint256 mfgDate,
//        uint256 expDate, string location, string intendedRegion, string details, string notes)
//  - revokeCertificate(string certId)
//  - transferCertificate(string certId, address to)
//  - updateCertificateMetadata(string certId, uint256 expDate, string location,
//                              string intendedRegion, string details, string notes)
//  - addAdmin(address)
//  - removeAdmin(address)
//  - transferOwnership(address)
//
// Pages supported by this single file:
//  - manufacturer.html (issue/revoke/admin/QR)
//  - distributor.html  (transfer UI, using showStatus/showLoading from here)
//  - index.html        (optional: verify UI; listeners wired only if elements exist)
//  - analytics.html    (analytics dashboard with historical transaction data)
// -----------------------------------------------------------------------------

// ==================== CONFIG ====================
const CONTRACT_ADDRESS = "0xcca7efb406102da9d4cd2a71e8036386269585d0";
const CONTRACT_ABI = [
  { "inputs": [], "name": "owner", "outputs": [{ "internalType": "address", "name": "", "type": "address" }], "stateMutability": "view", "type": "function" },
  { "inputs": [{ "internalType": "address", "name": "account", "type": "address" }], "name": "isAdmin", "outputs": [{ "internalType": "bool", "name": "", "type": "bool" }], "stateMutability": "view", "type": "function" },
  { "inputs": [], "name": "getAllAdminInfo", "outputs": [
      { "internalType": "uint256", "name": "totalAdmins", "type": "uint256" },
      { "internalType": "bool", "name": "isCallerAdmin", "type": "bool" },
      { "internalType": "bool", "name": "isCallerOwner", "type": "bool" }
    ], "stateMutability": "view", "type": "function" },

  // Reads
  { "inputs": [{ "internalType": "string", "name": "certId", "type": "string" }], "name": "getCertificate",
    "outputs": [
      { "internalType": "string", "name": "productName", "type": "string" },
      { "internalType": "string", "name": "mfgName", "type": "string" },
      { "internalType": "uint256", "name": "mfgDate", "type": "uint256" },
      { "internalType": "bool", "name": "isValid", "type": "bool" }
    ], "stateMutability": "view", "type": "function" },

  { "inputs": [{ "internalType": "string", "name": "certId", "type": "string" }], "name": "getCertificateFull",
    "outputs": [
      { "internalType": "string", "name": "productName", "type": "string" },
      { "internalType": "string", "name": "mfgName", "type": "string" },
      { "internalType": "uint256", "name": "mfgDate", "type": "uint256" },
      { "internalType": "uint256", "name": "expDate", "type": "uint256" },
      { "internalType": "string", "name": "location", "type": "string" },
      { "internalType": "string", "name": "intendedRegion", "type": "string" },
      { "internalType": "string", "name": "details", "type": "string" },
      { "internalType": "string", "name": "notes", "type": "string" },
      { "internalType": "bool", "name": "isValid", "type": "bool" }
    ], "stateMutability": "view", "type": "function" },

  { "inputs": [{ "internalType": "string", "name": "certId", "type": "string" }], "name": "ownerOfCertificate",
    "outputs": [{ "internalType": "address", "name": "", "type": "address" }], "stateMutability": "view", "type": "function" },

  // Writes
  { "inputs": [
      { "internalType": "string", "name": "certId", "type": "string" },
      { "internalType": "string", "name": "productName", "type": "string" },
      { "internalType": "string", "name": "mfgName", "type": "string" },
      { "internalType": "uint256", "name": "mfgDate", "type": "uint256" },
      { "internalType": "uint256", "name": "expDate", "type": "uint256" },
      { "internalType": "string", "name": "location", "type": "string" },
      { "internalType": "string", "name": "intendedRegion", "type": "string" },
      { "internalType": "string", "name": "details", "type": "string" },
      { "internalType": "string", "name": "notes", "type": "string" }
    ], "name": "issueCertificate", "outputs": [], "stateMutability": "nonpayable", "type": "function" },

  { "inputs": [{ "internalType": "string", "name": "certId", "type": "string" }], "name": "revokeCertificate",
    "outputs": [], "stateMutability": "nonpayable", "type": "function" },

  { "inputs": [{ "internalType": "string", "name": "certId", "type": "string" }, { "internalType": "address", "name": "to", "type": "address" }],
    "name": "transferCertificate", "outputs": [], "stateMutability": "nonpayable", "type": "function" },

  { "inputs": [
      { "internalType": "string", "name": "certId", "type": "string" },
      { "internalType": "uint256", "name": "expDate", "type": "uint256" },
      { "internalType": "string", "name": "location", "type": "string" },
      { "internalType": "string", "name": "intendedRegion", "type": "string" },
      { "internalType": "string", "name": "details", "type": "string" },
      { "internalType": "string", "name": "notes", "type": "string" }
    ], "name": "updateCertificateMetadata", "outputs": [], "stateMutability": "nonpayable", "type": "function" },

  { "inputs": [{ "internalType": "address", "name": "newAdmin", "type": "address" }], "name": "addAdmin",
    "outputs": [], "stateMutability": "nonpayable", "type": "function" },

  { "inputs": [{ "internalType": "address", "name": "adminToRemove", "type": "address" }], "name": "removeAdmin",
    "outputs": [], "stateMutability": "nonpayable", "type": "function" },

  { "inputs": [{ "internalType": "address", "name": "newOwner", "type": "address" }], "name": "transferOwnership",
    "outputs": [], "stateMutability": "nonpayable", "type": "function" }
];

const PUBLIC_RPC_URL = "https://1rpc.io/sepolia";
const TARGET_CHAIN_ID = 11155111; // Sepolia

// ==================== GLOBAL STATE ====================
let publicProvider;
let walletProvider;
let signer;
let publicContract;
let walletContract;
let userAccount;

// ==================== QR (CSP-SAFE) ====================
// We avoid any local QR lib to satisfy strict CSP (no eval).
// Use a remote QR image service via <img>.
const QR_FALLBACK_ENDPOINT = "https://api.qrserver.com/v1/create-qr-code/"; // ?size=300x300&data=...

async function resolveQRStrategy() { return "api"; }

// Function to fetch historical transactions for analytics page
async function fetchHistoricalTransactions(eventSignature, fromBlock = 0, contractAddress = null) {
  const provider = new ethers.providers.JsonRpcProvider("https://1rpc.io/sepolia");
  // Use the specified contract address or default to the main contract
  const targetAddress = contractAddress || CONTRACT_ADDRESS;
  
  // For analytics page, use the new contract address by default
  const analyticsContractAddress = "0x3ef5915D7A3d755A3cEbA73B407ecef47545910D";
  const addressToUse = (window.location.href.includes("analytics.html")) ? 
                        analyticsContractAddress : targetAddress;
  
  const filter = {
    address: addressToUse,
    topics: [ethers.utils.id(eventSignature)],
    fromBlock: fromBlock,
    toBlock: 'latest'
  };
  
  try {
    console.log(`Fetching logs for contract: ${addressToUse}`);
    const logs = await provider.getLogs(filter);
    
    // Add timestamps to logs by fetching block information
    const logsWithTimestamps = await Promise.all(logs.map(async (log) => {
      try {
        const block = await provider.getBlock(log.blockNumber);
        log.timeStamp = block.timestamp;
        return log;
      } catch (err) {
        console.error(`Error fetching block for log:`, err);
        log.timeStamp = Math.floor(Date.now() / 1000);
        return log;
      }
    }));
    
    return logsWithTimestamps;
  } catch (error) {
    console.error(`Error fetching historical logs for ${eventSignature}:`, error);
    return [];
  }
}

// Function to fetch detailed transaction data from Etherscan API
async function fetchTransactionList(contractAddress, apiKey = '') {
  const etherscanApiUrl = 'https://api.etherscan.io/api';
  const url = `${etherscanApiUrl}?module=account&action=txlist&address=${contractAddress}&startblock=0&endblock=99999999&sort=desc&apikey=${apiKey}`;
  
  try {
    console.log(`Fetching transaction list for: ${contractAddress} with API key: ${apiKey}`);
    const response = await fetch(url);
    const data = await response.json();
    console.log("Etherscan API response:", data);
    
    if (data.status === '1') {
      return data.result;
    } else if (data.status === '0') {
      // Try direct blockchain query as fallback
      console.log("Falling back to direct blockchain query");
      return await fetchDirectTransactions(contractAddress);
    } else {
      console.error('Error fetching transaction list:', data.message);
      return [];
    }
  } catch (error) {
    console.error('Error fetching transaction list:', error);
    return [];
  }
}

// Fallback function to fetch transactions directly from blockchain
async function fetchDirectTransactions(contractAddress) {
  try {
    const provider = new ethers.providers.JsonRpcProvider("https://eth.llamarpc.com");
    const history = await provider.getHistory(contractAddress);
    console.log("Direct blockchain history:", history);
    
    // Format to match Etherscan API response format
    return history.map(tx => ({
      hash: tx.hash,
      blockNumber: tx.blockNumber,
      timeStamp: Math.floor(Date.now() / 1000), // Placeholder timestamp
      from: tx.from,
      to: tx.to,
      value: tx.value.toString(),
      gasPrice: tx.gasPrice.toString(),
      gasUsed: tx.gasLimit.toString(),
      input: tx.data
    }));
  } catch (error) {
    console.error("Error in direct blockchain query:", error);
    return [];
  }
}

// Function to decode transaction method names
function decodeMethodName(methodId) {
  // Common method IDs for our contract
  const methodMap = {
    '0xd9900ffb': 'Issue Certificate',
    '0x6a63324d': 'Transfer Certificate',
    '0xfd9c3026': 'Revoke Certificate',
    '0x70480275': 'Add Admin',
    '0x24d7806c': 'Remove Admin',
    '0xf2fde38b': 'Transfer Ownership'
  };
  
  return methodMap[methodId] || methodId;
}

// ==================== BOOT ====================
window.addEventListener('load', async () => {
  console.log('Certificate DApp initializing...');
  if (typeof ethers === 'undefined') {
    updateNetworkInfo('Ethers.js not loaded. Please include ethers v5 before app.js', 'error');
    return;
  }

  await initPublicProvider();
  wireButtons();
  wireWalletEvents();

  if (window.ethereum) {
    try {
      const accounts = await window.ethereum.request({ method: 'eth_accounts' });
      if (accounts && accounts.length > 0) await connectWallet();
    } catch (e) { console.warn('Autoconnect check failed:', e); }
  }
});

// ==================== PROVIDERS ====================
async function initPublicProvider() {
  try {
    publicProvider = new ethers.providers.JsonRpcProvider(PUBLIC_RPC_URL);
    const network = await publicProvider.getNetwork();
    publicContract = new ethers.Contract(CONTRACT_ADDRESS, CONTRACT_ABI, publicProvider);

    // Expose for other inline scripts
    window.publicProvider = publicProvider;
    window.publicContract = publicContract;

    const code = await publicProvider.getCode(CONTRACT_ADDRESS);
    if (code === '0x') {
      updateNetworkInfo('Contract not found at this address on current RPC', 'error');
      return;
    }
    updateNetworkInfo(`Connected (public) to ${network.name} (Chain ID: ${network.chainId})`, 'success');
    console.log('Public provider initialized successfully');
  } catch (err) {
    console.error('Public provider init error:', err);
    updateNetworkInfo('Error connecting to blockchain: ' + (err.message || err), 'error');
  }
}

async function connectWallet() {
  if (!window.ethereum) {
    showStatus('connectionStatus', 'MetaMask not installed. Visit metamask.io', 'error');
    return;
  }

  showLoading('issueLoading', true);
  try {
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    if (!accounts || accounts.length === 0) throw new Error('No accounts available');

    walletProvider = new ethers.providers.Web3Provider(window.ethereum);
    let network = await walletProvider.getNetwork();

    // Enforce Sepolia
    if (network.chainId !== TARGET_CHAIN_ID) {
      try {
        await window.ethereum.request({
          method: 'wallet_switchEthereumChain',
          params: [{ chainId: `0x${TARGET_CHAIN_ID.toString(16)}` }]
        });
        await sleep(600);
        walletProvider = new ethers.providers.Web3Provider(window.ethereum);
        network = await walletProvider.getNetwork();
        if (network.chainId !== TARGET_CHAIN_ID) throw new Error('Failed to switch network');
      } catch (switchError) {
        if (switchError.code === 4902) {
          showStatus('connectionStatus', 'Please add Sepolia to MetaMask first', 'error');
        } else {
          showStatus('connectionStatus', 'Please switch MetaMask to Sepolia network', 'error');
        }
        return;
      }
    }

    signer = walletProvider.getSigner();
    userAccount = await signer.getAddress();
    walletContract = new ethers.Contract(CONTRACT_ADDRESS, CONTRACT_ABI, signer);

    // Expose for other pages (e.g., distributor.html inline helper)
    window.walletProvider = walletProvider;
    window.walletContract = walletContract;
    window.signer = signer;
    window.userAccount = userAccount;

    await updateConnectionStatus();
    await checkAdminStatus(true);

    showEl('adminStatusControls', true);

    const connectBtn = document.getElementById('connectWallet');
    if (connectBtn) connectBtn.style.display = 'none';

    console.log('Wallet connected:', userAccount);
  } catch (err) {
    console.error('Wallet connect error:', err);
    showStatus('connectionStatus', 'Connection failed: ' + (err.message || err), 'error');
  } finally {
    showLoading('issueLoading', false);
  }
}

async function updateConnectionStatus() {
  if (!walletProvider || !userAccount) return;
  try {
    const network = await walletProvider.getNetwork();
    const balanceWei = await walletProvider.getBalance(userAccount);
    const eth = parseFloat(ethers.utils.formatEther(balanceWei)).toFixed(4);
    showStatus('connectionStatus', `
      <strong>Connected</strong><br>
      Account: ${shortAddr(userAccount)}<br>
      Network: ${network.name} (Chain ID: ${network.chainId})<br>
      Balance: ${eth} ETH
    `, 'success');
  } catch (err) {
    console.error('updateConnectionStatus error:', err);
  }
}

// ==================== PERMISSIONS & ADMIN ====================
async function checkAdminStatus(forceRefresh = false) {
  if (!walletContract) return;

  try {
    if (forceRefresh) showStatus('connectionStatus', 'Refreshing permissions…', 'info');

    const [totalAdminsBN, isCallerAdmin, isCallerOwner] = await walletContract.getAllAdminInfo();
    const totalAdmins = totalAdminsBN.toNumber();

    // Enable/disable Issue button based on admin
    const issueBtn = document.getElementById('issueCertBtn');
    if (issueBtn) issueBtn.disabled = !isCallerAdmin;

    // Show manufacturer controls for admins
    showEl('manufacturerControls', isCallerAdmin);

    // Owner-only admin section (only if such a container exists)
    const adminSection = document.getElementById('adminSection');
    if (adminSection) adminSection.style.display = isCallerOwner ? 'block' : 'none';

    if (isCallerOwner) {
      showStatus('connectionStatus', 'You are the owner — full access granted', 'success');
      await loadAdminList();
    } else if (isCallerAdmin) {
      showStatus('connectionStatus', 'You are an authorized manufacturer — can issue/revoke certificates', 'success');
    } else {
      showStatus('connectionStatus', 'Connected — not authorized to issue certificates', 'warning');
    }

    console.log('Admin status:', { totalAdmins, isCallerAdmin, isCallerOwner });
  } catch (err) {
    console.error('checkAdminStatus error:', err);
    showStatus('connectionStatus', 'Error checking permissions: ' + (err.message || err), 'error');
  }
}

async function loadAdminList() {
  if (!walletContract) return;
  const listEl = document.getElementById('adminList');
  try {
    const info = await walletContract.getAllAdminInfo();
    const totalAdmins = info[0].toNumber();
    const ownerAddr = await walletContract.owner();
    if (listEl) {
      listEl.innerHTML = `
        <strong>Manufacturer Information:</strong><br>
        Total Authorized Manufacturers: ${totalAdmins}<br>
        Contract Owner: ${ownerAddr}<br>
        <small>Use "Check Authorization Status" to verify specific addresses</small>
      `;
      listEl.className = 'status info';
    }
  } catch (err) {
    console.error('loadAdminList error:', err);
    if (listEl) listEl.innerHTML = '<span class="error">Error loading manufacturer info</span>';
  }
}

// ==================== ISSUE CERTIFICATE ====================
async function issueCert() {
  const certId          = byId('certificateId');
  const productName     = byId('productName');
  const manufacturer    = byId('mfgName');
  const mfgDateStr      = byId('mfgDate');
  const expDateStr      = byId('expDate');
  const location        = byId('location');
  const intendedRegion  = byId('intendedRegion');
  const details         = byId('details');
  const notes           = byId('notes');

  if (!certId || !productName || !manufacturer || !mfgDateStr) {
    showStatus('connectionStatus', 'Please fill in all required fields (*)', 'error');
    return;
  }
  if (!walletContract || !signer || !userAccount) {
    showStatus('connectionStatus', 'Please connect your wallet first', 'error');
    return;
  }

  const mfgDateTs = toUnix(mfgDateStr);
  if (!Number.isFinite(mfgDateTs) || mfgDateTs <= 0) {
    showStatus('connectionStatus', 'Invalid manufacture date', 'error');
    return;
  }
  const expDateTs = expDateStr ? toUnix(expDateStr) : 0;
  if (expDateTs && expDateTs <= mfgDateTs) {
    showStatus('connectionStatus', 'Expiry date must be after manufacture date', 'error');
    return;
  }

  try {
    showLoading('issueLoading', true);
    console.log('Issuing certificate:', certId);
    showStatus('connectionStatus', 'Preparing transaction…', 'info');

    const tx = await walletContract.issueCertificate(
      certId,
      productName,
      manufacturer,
      mfgDateTs,
      expDateTs,
      location,
      intendedRegion,
      details,
      notes
    );

    showStatus('connectionStatus', 'Transaction submitted. Waiting for confirmation…', 'info');
    const receipt = await tx.wait();
    console.log('Transaction confirmed:', receipt.transactionHash);

    // Stop spinner before generating QR so UI doesn't look stuck
    showLoading('issueLoading', false);

    showStatus(
      'connectionStatus',
      `Certificate issued successfully!<br>TX: <a target="_blank" rel="noopener" href="https://sepolia.etherscan.io/tx/${receipt.transactionHash}">${receipt.transactionHash.slice(0,10)}…</a>`,
      'success'
    );

    // Build QR payload (human-readable)
    const certData = {
      certId,
      productName,
      mfgName: manufacturer,
      mfgDate: mfgDateStr,
      expDate: expDateStr || '',
      location,
      intendedRegion,
      details,
      notes
    };
    await generateQRCode(JSON.stringify(certData), certId);

    // Clear form AFTER QR is visible
    [
      'certificateId','productName','mfgName','mfgDate','expDate',
      'location','intendedRegion','details','notes'
    ].forEach(clearField);

  } catch (err) {
    console.error('issueCert error:', err);
    let msg = err?.reason || err?.message || 'Unknown error';
    if (/user rejected/i.test(msg)) msg = 'Transaction rejected by user';
    if (/exist/i.test(msg)) msg = 'Certificate ID already exists';
    showStatus('connectionStatus', 'Failed to issue certificate: ' + msg, 'error');
  } finally {
    showLoading('issueLoading', false);
  }
}

// ==================== QR GENERATION ====================
async function generateQRCode(data, certId) {
  const canvas     = document.getElementById('qrCodeCanvas'); // optional (hidden in API mode)
  const imgFallback= document.getElementById('qrImgFallback'); // shown in API mode
  const display    = document.getElementById('qrDisplay');
  const certIdSpan = document.getElementById('generatedCertId');

  if (!display) return;

  try {
    // Show the QR container
    display.style.display = 'block';
    if (certIdSpan) certIdSpan.textContent = certId;

    // Use API-based QR (CSP-safe)
    const qrUrl = `${QR_FALLBACK_ENDPOINT}?size=300x300&data=${encodeURIComponent(data)}`;
    if (imgFallback) {
      imgFallback.src = qrUrl;
      imgFallback.style.display = 'block';
    }
    if (canvas) canvas.style.display = 'none';

    console.log('QR code generated for certificate:', certId);
  } catch (err) {
    console.error('QR generation error:', err);
    showStatus('connectionStatus', 'Failed to generate QR code: ' + (err.message || err), 'error');
  }
}

// ==================== REVOKE CERTIFICATE ====================
async function revokeCert() {
  const certId = byId('revokeCertId');
  if (!certId) {
    showStatus('connectionStatus', 'Please enter a certificate ID', 'error');
    return;
  }
  if (!walletContract || !signer || !userAccount) {
    showStatus('connectionStatus', 'Please connect your wallet first', 'error');
    return;
  }

  try {
    showLoading('revokeLoading', true);
    console.log('Revoking certificate:', certId);
    showStatus('connectionStatus', 'Preparing transaction…', 'info');

    const tx = await walletContract.revokeCertificate(certId);
    showStatus('connectionStatus', 'Transaction submitted. Waiting for confirmation…', 'info');
    const receipt = await tx.wait();
    console.log('Transaction confirmed:', receipt.transactionHash);

    showStatus(
      'connectionStatus',
      `Certificate revoked successfully!<br>TX: <a target="_blank" rel="noopener" href="https://sepolia.etherscan.io/tx/${receipt.transactionHash}">${receipt.transactionHash.slice(0,10)}…</a>`,
      'success'
    );

    clearField('revokeCertId');
  } catch (err) {
    console.error('revokeCert error:', err);
    let msg = err?.reason || err?.message || 'Unknown error';
    if (/user rejected/i.test(msg)) msg = 'Transaction rejected by user';
    if (/not exist/i.test(msg)) msg = 'Certificate ID does not exist';
    if (/not authorized/i.test(msg)) msg = 'Not authorized to revoke this certificate';
    showStatus('connectionStatus', 'Failed to revoke certificate: ' + msg, 'error');
  } finally {
    showLoading('revokeLoading', false);
  }
}

// ==================== VERIFY CERTIFICATE ====================
async function verifyCert() {
  const certId = byId('verifyCertId');
  if (!certId) {
    showStatus('verifyStatus', 'Please enter a certificate ID', 'error');
    return;
  }

  try {
    showLoading('verifyLoading', true);
    console.log('Verifying certificate:', certId);
    showStatus('verifyStatus', 'Checking certificate…', 'info');

    // Get basic certificate info
    const [productName, mfgName, mfgDateTs, isValid] = await publicContract.getCertificate(certId);
    const owner = await publicContract.ownerOfCertificate(certId);

    // Format dates for display
    const mfgDate = new Date(mfgDateTs.toNumber() * 1000).toLocaleDateString();

    // Get full certificate info
    const fullCert = await publicContract.getCertificateFull(certId);
    const expDateTs = fullCert[3].toNumber();
    const expDate = expDateTs ? new Date(expDateTs * 1000).toLocaleDateString() : 'N/A';
    const location = fullCert[4];
    const intendedRegion = fullCert[5];
    const details = fullCert[6];
    const notes = fullCert[7];

    // Build verification result
    let statusClass = isValid ? 'success' : 'error';
    let statusText = isValid ? 'Valid' : 'Revoked';

    // Check expiry
    if (isValid && expDateTs > 0 && expDateTs < (Date.now() / 1000)) {
      statusClass = 'warning';
      statusText = 'Expired';
    }

    showStatus('verifyStatus', `
      <div class="cert-result ${statusClass}">
        <h3>Certificate Status: <span class="${statusClass}">${statusText}</span></h3>
        <table class="cert-details">
          <tr><th>Certificate ID:</th><td>${certId}</td></tr>
          <tr><th>Product Name:</th><td>${productName}</td></tr>
          <tr><th>Manufacturer:</th><td>${mfgName}</td></tr>
          <tr><th>Manufacture Date:</th><td>${mfgDate}</td></tr>
          <tr><th>Expiry Date:</th><td>${expDate}</td></tr>
          <tr><th>Current Owner:</th><td>${owner}</td></tr>
          ${location ? `<tr><th>Location:</th><td>${location}</td></tr>` : ''}
          ${intendedRegion ? `<tr><th>Intended Region:</th><td>${intendedRegion}</td></tr>` : ''}
          ${details ? `<tr><th>Details:</th><td>${details}</td></tr>` : ''}
          ${notes ? `<tr><th>Notes:</th><td>${notes}</td></tr>` : ''}
        </table>
      </div>
    `, '');

    console.log('Certificate verified:', { certId, isValid, owner });
  } catch (err) {
    console.error('verifyCert error:', err);
    let msg = err?.reason || err?.message || 'Unknown error';
    if (/not exist/i.test(msg)) msg = 'Certificate ID does not exist';
    showStatus('verifyStatus', 'Failed to verify certificate: ' + msg, 'error');
  } finally {
    showLoading('verifyLoading', false);
  }
}

// ==================== TRANSFER CERTIFICATE ====================
async function transferCert() {
  const certId = byId('transferCertId');
  const toAddr = byId('transferToAddress');

  if (!certId || !toAddr) {
    showStatus('transferStatus', 'Please fill in all required fields', 'error');
    return;
  }
  if (!ethers.utils.isAddress(toAddr)) {
    showStatus('transferStatus', 'Invalid Ethereum address', 'error');
    return;
  }
  if (!walletContract || !signer || !userAccount) {
    showStatus('transferStatus', 'Please connect your wallet first', 'error');
    return;
  }

  try {
    showLoading('transferLoading', true);
    console.log('Transferring certificate:', certId, 'to:', toAddr);
    showStatus('transferStatus', 'Preparing transaction…', 'info');

    const tx = await walletContract.transferCertificate(certId, toAddr);
    showStatus('transferStatus', 'Transaction submitted. Waiting for confirmation…', 'info');
    const receipt = await tx.wait();
    console.log('Transaction confirmed:', receipt.transactionHash);

    showStatus(
      'transferStatus',
      `Certificate transferred successfully!<br>TX: <a target="_blank" rel="noopener" href="https://sepolia.etherscan.io/tx/${receipt.transactionHash}">${receipt.transactionHash.slice(0,10)}…</a>`,
      'success'
    );

    clearField('transferCertId');
    clearField('transferToAddress');
  } catch (err) {
    console.error('transferCert error:', err);
    let msg = err?.reason || err?.message || 'Unknown error';
    if (/user rejected/i.test(msg)) msg = 'Transaction rejected by user';
    if (/not exist/i.test(msg)) msg = 'Certificate ID does not exist';
    if (/not owner/i.test(msg)) msg = 'You are not the owner of this certificate';
    if (/not valid/i.test(msg)) msg = 'Certificate is not valid (revoked)';
    showStatus('transferStatus', 'Failed to transfer certificate: ' + msg, 'error');
  } finally {
    showLoading('transferLoading', false);
  }
}

// ==================== ADMIN MANAGEMENT ====================
async function checkAdminAddress() {
  const adminAddr = byId('checkAdminAddress');
  if (!adminAddr || !ethers.utils.isAddress(adminAddr)) {
    showStatus('adminStatus', 'Please enter a valid Ethereum address', 'error');
    return;
  }

  try {
    showLoading('adminLoading', true);
    console.log('Checking admin status for:', adminAddr);

    const isAdmin = await publicContract.isAdmin(adminAddr);
    const owner = await publicContract.owner();
    const isOwner = adminAddr.toLowerCase() === owner.toLowerCase();

    let statusText = 'Not authorized';
    let statusClass = 'error';

    if (isOwner) {
      statusText = 'Contract Owner (highest privileges)';
      statusClass = 'success';
    } else if (isAdmin) {
      statusText = 'Authorized Manufacturer';
      statusClass = 'success';
    }

    showStatus('adminStatus', `
      <strong>Address:</strong> ${adminAddr}<br>
      <strong>Status:</strong> <span class="${statusClass}">${statusText}</span>
    `, 'info');

    console.log('Admin check result:', { adminAddr, isAdmin, isOwner });
  } catch (err) {
    console.error('checkAdminAddress error:', err);
    showStatus('adminStatus', 'Failed to check admin status: ' + (err.message || err), 'error');
  } finally {
    showLoading('adminLoading', false);
  }
}

async function addAdmin() {
  const adminAddr = byId('newAdminAddress');
  if (!adminAddr || !ethers.utils.isAddress(adminAddr)) {
    showStatus('adminStatus', 'Please enter a valid Ethereum address', 'error');
    return;
  }
  if (!walletContract || !signer || !userAccount) {
    showStatus('adminStatus', 'Please connect your wallet first', 'error');
    return;
  }

  try {
    showLoading('adminLoading', true);
    console.log('Adding admin:', adminAddr);
    showStatus('adminStatus', 'Preparing transaction…', 'info');

    const tx = await walletContract.addAdmin(adminAddr);
    showStatus('adminStatus', 'Transaction submitted. Waiting for confirmation…', 'info');
    const receipt = await tx.wait();
    console.log('Transaction confirmed:', receipt.transactionHash);

    showStatus(
      'adminStatus',
      `Manufacturer authorized successfully!<br>TX: <a target="_blank" rel="noopener" href="https://sepolia.etherscan.io/tx/${receipt.transactionHash}">${receipt.transactionHash.slice(0,10)}…</a>`,
      'success'
    );

    clearField('newAdminAddress');
    await loadAdminList();
  } catch (err) {
    console.error('addAdmin error:', err);
    let msg = err?.reason || err?.message || 'Unknown error';
    if (/user rejected/i.test(msg)) msg = 'Transaction rejected by user';
    if (/not owner/i.test(msg)) msg = 'Only the owner can add manufacturers';
    if (/already admin/i.test(msg)) msg = 'Address is already authorized';
    showStatus('adminStatus', 'Failed to authorize manufacturer: ' + msg, 'error');
  } finally {
    showLoading('adminLoading', false);
  }
}

async function removeAdmin() {
  const adminAddr = byId('removeAdminAddress');
  if (!adminAddr || !ethers.utils.isAddress(adminAddr)) {
    showStatus('adminStatus', 'Please enter a valid Ethereum address', 'error');
    return;
  }
  if (!walletContract || !signer || !userAccount) {
    showStatus('adminStatus', 'Please connect your wallet first', 'error');
    return;
  }

  try {
    showLoading('adminLoading', true);
    console.log('Removing admin:', adminAddr);
    showStatus('adminStatus', 'Preparing transaction…', 'info');

    const tx = await walletContract.removeAdmin(adminAddr);
    showStatus('adminStatus', 'Transaction submitted. Waiting for confirmation…', 'info');
    const receipt = await tx.wait();
    console.log('Transaction confirmed:', receipt.transactionHash);

    showStatus(
      'adminStatus',
      `Manufacturer authorization revoked successfully!<br>TX: <a target="_blank" rel="noopener" href="https://sepolia.etherscan.io/tx/${receipt.transactionHash}">${receipt.transactionHash.slice(0,10)}…</a>`,
      'success'
    );

    clearField('removeAdminAddress');
    await loadAdminList();
  } catch (err) {
    console.error('removeAdmin error:', err);
    let msg = err?.reason || err?.message || 'Unknown error';
    if (/user rejected/i.test(msg)) msg = 'Transaction rejected by user';
    if (/not owner/i.test(msg)) msg = 'Only the owner can remove manufacturers';
    if (/not admin/i.test(msg)) msg = 'Address is not an authorized manufacturer';
    showStatus('adminStatus', 'Failed to revoke manufacturer authorization: ' + msg, 'error');
  } finally {
    showLoading('adminLoading', false);
  }
}

async function transferOwnership() {
  const newOwner = byId('newOwnerAddress');
  if (!newOwner || !ethers.utils.isAddress(newOwner)) {
    showStatus('adminStatus', 'Please enter a valid Ethereum address', 'error');
    return;
  }
  if (!walletContract || !signer || !userAccount) {
    showStatus('adminStatus', 'Please connect your wallet first', 'error');
    return;
  }

  // Confirm with user
  if (!confirm(`WARNING: You are about to transfer ownership to ${newOwner}.\n\nThis action is IRREVERSIBLE and will remove your owner privileges.\n\nAre you absolutely sure?`)) {
    return;
  }

  try {
    showLoading('adminLoading', true);
    console.log('Transferring ownership to:', newOwner);
    showStatus('adminStatus', 'Preparing transaction…', 'info');

    const tx = await walletContract.transferOwnership(newOwner);
    showStatus('adminStatus', 'Transaction submitted. Waiting for confirmation…', 'info');
    const receipt = await tx.wait();
    console.log('Transaction confirmed:', receipt.transactionHash);

    showStatus(
      'adminStatus',
      `Ownership transferred successfully!<br>TX: <a target="_blank" rel="noopener" href="https://sepolia.etherscan.io/tx/${receipt.transactionHash}">${receipt.transactionHash.slice(0,10)}…</a><br><strong>Note:</strong> You are no longer the owner.`,
      'success'
    );

    clearField('newOwnerAddress');
    await checkAdminStatus(true);
  } catch (err) {
    console.error('transferOwnership error:', err);
    let msg = err?.reason || err?.message || 'Unknown error';
    if (/user rejected/i.test(msg)) msg = 'Transaction rejected by user';
    if (/not owner/i.test(msg)) msg = 'Only the owner can transfer ownership';
    showStatus('adminStatus', 'Failed to transfer ownership: ' + msg, 'error');
  } finally {
    showLoading('adminLoading', false);
  }
}

// ==================== WIRE UP UI ====================
function wireButtons() {
  // Connect wallet
  const connectBtn = document.getElementById('connectWallet');
  if (connectBtn) connectBtn.addEventListener('click', connectWallet);

  // Issue certificate
  const issueBtn = document.getElementById('issueCertBtn');
  if (issueBtn) issueBtn.addEventListener('click', issueCert);

  // Revoke certificate
  const revokeBtn = document.getElementById('revokeCertBtn');
  if (revokeBtn) revokeBtn.addEventListener('click', revokeCert);

  // Verify certificate
  const verifyBtn = document.getElementById('verifyCertBtn');
  if (verifyBtn) verifyBtn.addEventListener('click', verifyCert);

  // Transfer certificate
  const transferBtn = document.getElementById('transferCertBtn');
  if (transferBtn) transferBtn.addEventListener('click', transferCert);

  // Admin management
  const checkAdminBtn = document.getElementById('checkAdminBtn');
  if (checkAdminBtn) checkAdminBtn.addEventListener('click', checkAdminAddress);

  const addAdminBtn = document.getElementById('addAdminBtn');
  if (addAdminBtn) addAdminBtn.addEventListener('click', addAdmin);

  const removeAdminBtn = document.getElementById('removeAdminBtn');
  if (removeAdminBtn) removeAdminBtn.addEventListener('click', removeAdmin);

  const transferOwnerBtn = document.getElementById('transferOwnerBtn');
  if (transferOwnerBtn) transferOwnerBtn.addEventListener('click', transferOwnership);
}

function wireWalletEvents() {
  if (!window.ethereum) return;

  window.ethereum.on('accountsChanged', async (accounts) => {
    console.log('Accounts changed:', accounts);
    if (accounts.length === 0) {
      // User disconnected wallet
      userAccount = null;
      walletProvider = null;
      signer = null;
      walletContract = null;
      showStatus('connectionStatus', 'Wallet disconnected', 'warning');
      const connectBtn = document.getElementById('connectWallet');
      if (connectBtn) connectBtn.style.display = 'block';
      showEl('adminStatusControls', false);
      showEl('manufacturerControls', false);
    } else {
      // User switched accounts
      await connectWallet();
    }
  });

  window.ethereum.on('chainChanged', async (chainIdHex) => {
    console.log('Chain changed:', chainIdHex);
    const chainId = parseInt(chainIdHex, 16);
    if (chainId !== TARGET_CHAIN_ID) {
      showStatus('connectionStatus', 'Please switch to Sepolia network', 'warning');
    } else {
      await connectWallet();
    }
  });
}

// ==================== HELPERS ====================
function byId(id) {
  const el = document.getElementById(id);
  return el ? el.value.trim() : '';
}

function clearField(id) {
  const el = document.getElementById(id);
  if (el) el.value = '';
}

function showEl(id, show) {
  const el = document.getElementById(id);
  if (el) el.style.display = show ? 'block' : 'none';
}

function showLoading(id, show) {
  const el = document.getElementById(id);
  if (el) el.style.display = show ? 'inline-block' : 'none';
}

function showStatus(id, message, type = 'info') {
  const el = document.getElementById(id);
  if (!el) return;

  el.innerHTML = message;
  el.className = 'status ' + type;
  el.style.display = 'block';
}

function updateNetworkInfo(message, type = 'info') {
  showStatus('networkInfo', message, type);
}

function shortAddr(addr) {
  return addr ? `${addr.slice(0, 6)}...${addr.slice(-4)}` : '';
}

function toUnix(dateStr) {
  if (!dateStr) return 0;
  const date = new Date(dateStr);
  return Math.floor(date.getTime() / 1000);
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ==================== BATCH REVOCATION ====================
function setupBatchRevocation() {
  const batchRevokeBtn = document.getElementById('batchRevokeCertBtn');
  const batchRevokeParams = document.getElementById('batchRevokeParams');
  const batchRevokeParamValue = document.getElementById('batchRevokeParamValue');
  const batchRevokeStatus = document.getElementById('batchRevokeStatus');
  
  if (!batchRevokeBtn || !batchRevokeParams) return;
  
  // Show/hide parameter value input based on selected parameter
  batchRevokeParams.addEventListener('change', function() {
    const paramType = this.value;
    if (paramType === 'region' || paramType === 'location') {
      batchRevokeParamValue.style.display = 'block';
      batchRevokeParamValue.placeholder = `Enter ${paramType} value`;
    } else {
      batchRevokeParamValue.style.display = 'none';
    }
  });
  
  // Handle batch revocation
  batchRevokeBtn.addEventListener('click', async function() {
    if (!window.walletContract || !window.userAccount) {
      showStatus('batchRevokeStatus', 'Please connect your wallet first', 'error');
      batchRevokeStatus.style.display = 'block';
      return;
    }
    
    const batchCertIds = document.getElementById('batchRevokeCertIds').value.trim();
    if (!batchCertIds) {
      showStatus('batchRevokeStatus', 'Please enter certificate IDs to revoke', 'error');
      batchRevokeStatus.style.display = 'block';
      return;
    }
    
    // Parse certificate IDs (comma or newline separated)
    const certIds = batchCertIds.split(/[\n,]+/).map(id => id.trim()).filter(id => id);
    if (certIds.length === 0) {
      showStatus('batchRevokeStatus', 'No valid certificate IDs found', 'error');
      batchRevokeStatus.style.display = 'block';
      return;
    }
    
    const paramType = batchRevokeParams.value;
    const paramValue = batchRevokeParamValue.value.trim();
    
    if ((paramType === 'region' || paramType === 'location') && !paramValue) {
      showStatus('batchRevokeStatus', `Please enter a ${paramType} value`, 'error');
      batchRevokeStatus.style.display = 'block';
      return;
    }
    
    try {
      showStatus('batchRevokeStatus', `Revoking ${certIds.length} certificates...`, 'info');
      batchRevokeStatus.style.display = 'block';
      
      let successCount = 0;
      let failCount = 0;
      
      for (const certId of certIds) {
        try {
          // Check if certificate meets the filter criteria
          if (paramType !== 'all') {
            const certInfo = await window.walletContract.getCertificateFull(certId);
            
            // Skip if doesn't match filter criteria
            if (paramType === 'expired' && (certInfo[3] === 0 || certInfo[3] > Math.floor(Date.now() / 1000))) {
              continue; // Skip non-expired certificates
            } else if (paramType === 'region' && certInfo[5] !== paramValue) {
              continue; // Skip if region doesn't match
            } else if (paramType === 'location' && certInfo[4] !== paramValue) {
              continue; // Skip if location doesn't match
            }
          }
          
          // Revoke the certificate
          const tx = await window.walletContract.revokeCertificate(certId);
          await tx.wait();
          successCount++;
        } catch (err) {
          console.error(`Error revoking certificate ${certId}:`, err);
          failCount++;
        }
      }
      
      // Track batch revocation in analytics
      const batchId = `batch-${Date.now()}`;
      if (window.analyticsTracker && typeof window.analyticsTracker.trackBatchRevocation === 'function') {
        window.analyticsTracker.trackBatchRevocation(batchId, paramType, successCount, failCount, userAccount);
      }
      
      if (successCount > 0) {
        showStatus('batchRevokeStatus', 
          `Successfully revoked ${successCount} certificates.${failCount > 0 ? ` Failed to revoke ${failCount} certificates.` : ''}`, 
          failCount > 0 ? 'warning' : 'success');
      } else {
        showStatus('batchRevokeStatus', 
          `No certificates were revoked. ${failCount > 0 ? `Failed to revoke ${failCount} certificates.` : 'No certificates matched the criteria.'}`, 
          'error');
      }
    } catch (err) {
      console.error('Batch revocation error:', err);
      showStatus('batchRevokeStatus', 'Error during batch revocation: ' + (err.message || err), 'error');
    }
  });
}

// ==================== EXPIRY DROPDOWN ====================
function setupExpiryDropdown() {
  // Replace date pickers with dropdown for expiry
  const expDateInput = document.getElementById('expDate');
  const metaExpDateInput = document.getElementById('metaExpDate');
  
  if (expDateInput) {
    createExpiryDropdown(expDateInput);
  }
  
  if (metaExpDateInput) {
    createExpiryDropdown(metaExpDateInput);
  }
}

function createExpiryDropdown(dateInput) {
  // Create the dropdown element
  const dropdown = document.createElement('select');
  dropdown.id = dateInput.id + 'Dropdown';
  dropdown.className = dateInput.className;
  dropdown.style.display = 'block';
  
  // Add options
  const options = [
    { value: '', text: 'Select expiry period...' },
    { value: '6m', text: '6 months from now' },
    { value: '1y', text: '1 year from now' },
    { value: '2y', text: '2 years from now' },
    { value: 'custom', text: 'Custom date...' }
  ];
  
  options.forEach(option => {
    const opt = document.createElement('option');
    opt.value = option.value;
    opt.textContent = option.text;
    dropdown.appendChild(opt);
  });
  
  // Hide the original date input
  dateInput.style.display = 'none';
  dateInput.parentNode.insertBefore(dropdown, dateInput.nextSibling);
  
  // Handle dropdown change
  dropdown.addEventListener('change', function() {
    const value = this.value;
    
    if (value === 'custom') {
      // Show the original date picker for custom date
      dateInput.style.display = 'block';
      if (dateInput._flatpickr) {
        dateInput._flatpickr.setDate('');
      }
    } else {
      // Hide the original date picker
      dateInput.style.display = 'none';
      
      // Calculate the expiry date based on selection
      let expiryDate = '';
      const now = new Date();
      
      if (value === '6m') {
        now.setMonth(now.getMonth() + 6);
        expiryDate = now.toISOString().split('T')[0];
      } else if (value === '1y') {
        now.setFullYear(now.getFullYear() + 1);
        expiryDate = now.toISOString().split('T')[0];
      } else if (value === '2y') {
        now.setFullYear(now.getFullYear() + 2);
        expiryDate = now.toISOString().split('T')[0];
      }
      
      // Set the value in the original input
      dateInput.value = expiryDate;
      if (dateInput._flatpickr) {
        dateInput._flatpickr.setDate(expiryDate);
      }
    }
  });
}

// ==================== QR CODE SCANNER ====================
function setupQRScanner() {
  // Only setup on the verification page
  const verifyForm = document.getElementById('verifyForm');
  if (!verifyForm) return;
  
  // Create QR scanner section
  const scannerSection = document.createElement('div');
  scannerSection.className = 'section';
  scannerSection.innerHTML = `
    <h2>Scan QR Code</h2>
    <p class="muted">Scan a certificate QR code with your camera or upload an image</p>
    
    <div style="display: flex; gap: 20px; flex-wrap: wrap;">
      <div style="flex: 1; min-width: 300px;">
        <button id="startScanBtn" class="admin-btn" style="width: 100%; margin-bottom: 10px;">Start Camera Scan</button>
        <video id="qrScanner" style="width: 100%; display: none; border-radius: 8px; border: 1px solid #444;"></video>
      </div>
      
      <div style="flex: 1; min-width: 300px;">
        <label for="qrFileUpload" class="check-btn" style="display: block; text-align: center; padding: 10px; margin-bottom: 10px; cursor: pointer;">
          Upload QR Code Image
        </label>
        <input type="file" id="qrFileUpload" accept="image/*" style="display: none;">
        <div id="uploadPreview" style="width: 100%; min-height: 200px; display: none; border-radius: 8px; border: 1px solid #444; overflow: hidden;">
          <img id="uploadedQRImage" style="width: 100%; height: auto;">
        </div>
      </div>
    </div>
    
    <div id="scanResult" class="status info" style="margin-top: 15px; display: none;"></div>
  `;
  
  // Insert before the verify form
  verifyForm.parentNode.insertBefore(scannerSection, verifyForm);
  
  // Load QR scanner library
  const script = document.createElement('script');
  script.src = 'https://unpkg.com/html5-qrcode@2.3.8/html5-qrcode.min.js';
  document.head.appendChild(script);
  
  script.onload = function() {
    // Setup camera scanner
    const startScanBtn = document.getElementById('startScanBtn');
    const qrScanner = document.getElementById('qrScanner');
    const scanResult = document.getElementById('scanResult');
    
    let html5QrCode;
    
    startScanBtn.addEventListener('click', function() {
      if (qrScanner.style.display === 'none') {
        // Start scanning
        qrScanner.style.display = 'block';
        startScanBtn.textContent = 'Stop Camera Scan';
        
        html5QrCode = new Html5Qrcode("qrScanner");
        html5QrCode.start(
          { facingMode: "environment" },
          { fps: 10, qrbox: { width: 250, height: 250 } },
          onScanSuccess,
          onScanFailure
        );
      } else {
        // Stop scanning
        if (html5QrCode && html5QrCode.isScanning) {
          html5QrCode.stop().then(() => {
            qrScanner.style.display = 'none';
            startScanBtn.textContent = 'Start Camera Scan';
          });
        }
      }
    });
    
    // Setup file upload scanner
    const qrFileUpload = document.getElementById('qrFileUpload');
    const uploadPreview = document.getElementById('uploadPreview');
    const uploadedQRImage = document.getElementById('uploadedQRImage');
    
    qrFileUpload.addEventListener('change', function(e) {
      if (e.target.files && e.target.files[0]) {
        const file = e.target.files[0];
        const fileReader = new FileReader();
        
        fileReader.onload = function(e) {
          uploadedQRImage.src = e.target.result;
          uploadPreview.style.display = 'block';
          
          // Decode the QR code from the image
          const html5QrCode = new Html5Qrcode("qrScanner");
          html5QrCode.scanFile(file, true)
            .then(decodedText => {
              onScanSuccess(decodedText);
            })
            .catch(err => {
              showStatus('scanResult', 'Could not decode QR code from image: ' + err, 'error');
              scanResult.style.display = 'block';
            });
        };
        
        fileReader.readAsDataURL(file);
      }
    });
    
    function onScanSuccess(decodedText) {
      // Extract certificate ID from QR code
      let certId = decodedText;
      
      // Handle URLs or other formats
      if (decodedText.includes('certId=')) {
        const urlParams = new URLSearchParams(decodedText.split('?')[1]);
        certId = urlParams.get('certId');
      }
      
      if (certId) {
        // Fill the certificate ID in the verification form
        const certIdInput = document.getElementById('certId');
        if (certIdInput) {
          certIdInput.value = certId;
          
          // Trigger verification
          const verifyBtn = document.querySelector('#verifyForm button');
          if (verifyBtn) {
            verifyBtn.click();
          }
        }
        
        showStatus('scanResult', 'QR code scanned successfully! Certificate ID: ' + certId, 'success');
        
        // Track QR scan for analytics
        if (window.analyticsTracker && typeof window.analyticsTracker.trackQRScan === 'function') {
          const scanMethod = html5QrCode ? 'camera' : 'file';
          window.analyticsTracker.trackQRScan(certId, scanMethod);
        }
      } else {
        showStatus('scanResult', 'Invalid QR code format. Could not extract certificate ID.', 'error');
      }
      
      scanResult.style.display = 'block';
      
      // Stop scanning if using camera
      if (html5QrCode && html5QrCode.isScanning) {
        html5QrCode.stop().then(() => {
          qrScanner.style.display = 'none';
          startScanBtn.textContent = 'Start Camera Scan';
        });
      }
    }
    
    function onScanFailure(error) {
      // We don't need to show errors during scanning
      console.warn(`QR scan error: ${error}`);
    }
  };
}

// ==================== BOOT ====================
window.addEventListener('load', async () => {
  console.log('Certificate DApp initializing...');
  if (typeof ethers === 'undefined') {
    updateNetworkInfo('Ethers.js not loaded. Please include ethers v5 before app.js', 'error');
    return;
  }

  await initPublicProvider();
  wireButtons();
  wireWalletEvents();
  setupBatchRevocation();
  setupExpiryDropdown();
  setupQRScanner();

  if (window.ethereum) {
    try {
      const accounts = await window.ethereum.request({ method: 'eth_accounts' });
      if (accounts && accounts.length > 0) await connectWallet();
    } catch (e) { console.warn('Autoconnect check failed:', e); }
  }
});

// ==================== PROVIDERS ====================
async function initPublicProvider() {
  try {
    publicProvider = new ethers.providers.JsonRpcProvider(PUBLIC_RPC_URL);
    const network = await publicProvider.getNetwork();
    publicContract = new ethers.Contract(CONTRACT_ADDRESS, CONTRACT_ABI, publicProvider);

    // Expose for other inline scripts
    window.publicProvider = publicProvider;
    window.publicContract = publicContract;

    const code = await publicProvider.getCode(CONTRACT_ADDRESS);
    if (code === '0x') {
      updateNetworkInfo('Contract not found at this address on current RPC', 'error');
      return;
    }
    updateNetworkInfo(`Connected (public) to ${network.name} (Chain ID: ${network.chainId})`, 'success');
    console.log('Public provider initialized successfully');
  } catch (err) {
    console.error('Public provider init error:', err);
    updateNetworkInfo('Error connecting to blockchain: ' + (err.message || err), 'error');
    
    // Try fallback RPC if primary fails
    try {
      const fallbackRpcUrl = "https://ethereum-sepolia.publicnode.com";
      console.log('Attempting fallback RPC connection:', fallbackRpcUrl);
      publicProvider = new ethers.providers.JsonRpcProvider(fallbackRpcUrl);
      const network = await publicProvider.getNetwork();
      publicContract = new ethers.Contract(CONTRACT_ADDRESS, CONTRACT_ABI, publicProvider);
      
      window.publicProvider = publicProvider;
      window.publicContract = publicContract;
      
      updateNetworkInfo(`Connected (fallback) to ${network.name} (Chain ID: ${network.chainId})`, 'success');
      console.log('Fallback provider initialized successfully');
    } catch (fallbackErr) {
      console.error('Fallback provider init error:', fallbackErr);
    }
  }
}

async function connectWallet() {
  if (!window.ethereum) {
    showStatus('connectionStatus', 'MetaMask not installed. Visit metamask.io', 'error');
    return;
  }

  showLoading('issueLoading', true);
  try {
    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    if (!accounts || accounts.length === 0) throw new Error('No accounts available');

    walletProvider = new ethers.providers.Web3Provider(window.ethereum);
    let network = await walletProvider.getNetwork();

    if (network.chainId !== TARGET_CHAIN_ID) {
      try {
        await window.ethereum.request({
          method: 'wallet_switchEthereumChain',
          params: [{ chainId: `0x${TARGET_CHAIN_ID.toString(16)}` }]
        });
        await sleep(600);
        walletProvider = new ethers.providers.Web3Provider(window.ethereum);
        network = await walletProvider.getNetwork();
        if (network.chainId !== TARGET_CHAIN_ID) throw new Error('Failed to switch network');
      } catch (switchError) {
        if (switchError.code === 4902) {
          showStatus('connectionStatus', 'Please add Sepolia to MetaMask first', 'error');
        } else {
          showStatus('connectionStatus', 'Please switch MetaMask to Sepolia network', 'error');
        }
        return;
      }
    }

    signer = walletProvider.getSigner();
    userAccount = await signer.getAddress();
    walletContract = new ethers.Contract(CONTRACT_ADDRESS, CONTRACT_ABI, signer);

    window.walletProvider = walletProvider;
    window.walletContract = walletContract;
    window.userAccount = userAccount;
    window.signer = signer;
    window.userAccount = userAccount;

    await updateConnectionStatus();
    await checkAdminStatus(true);

    showEl('adminStatusControls', true);

    const connectBtn = document.getElementById('connectWallet');
    if (connectBtn) connectBtn.style.display = 'none';

    console.log('Wallet connected:', userAccount);
  } catch (err) {
    console.error('Wallet connect error:', err);
    showStatus('connectionStatus', 'Connection failed: ' + (err.message || err), 'error');
  } finally {
    showLoading('issueLoading', false);
  }
}

async function updateConnectionStatus() {
  if (!walletProvider || !userAccount) return;
  try {
    const network = await walletProvider.getNetwork();
    const balanceWei = await walletProvider.getBalance(userAccount);
    const eth = parseFloat(ethers.utils.formatEther(balanceWei)).toFixed(4);
    showStatus('connectionStatus', `
      <strong>Connected</strong><br>
      Account: ${shortAddr(userAccount)}<br>
      Network: ${network.name} (Chain ID: ${network.chainId})<br>
      Balance: ${eth} ETH
    `, 'success');
  } catch (err) {
    console.error('updateConnectionStatus error:', err);
  }
}

// ==================== PERMISSIONS & ADMIN ====================
async function checkAdminStatus(forceRefresh = false) {
  if (!walletContract) return;

  try {
    if (forceRefresh) showStatus('connectionStatus', 'Refreshing permissions…', 'info');

    const [totalAdminsBN, isCallerAdmin, isCallerOwner] = await walletContract.getAllAdminInfo();
    const totalAdmins = totalAdminsBN.toNumber();

    const issueBtn = document.getElementById('issueCertBtn');
    if (issueBtn) issueBtn.disabled = !isCallerAdmin;

    showEl('manufacturerControls', isCallerAdmin);

    const adminSection = document.getElementById('adminSection');
    if (adminSection) adminSection.style.display = isCallerOwner ? 'block' : 'none';

    if (isCallerOwner) {
      showStatus('connectionStatus', 'You are the owner – full access granted', 'success');
      await loadAdminList();
    } else if (isCallerAdmin) {
      showStatus('connectionStatus', 'You are an authorized manufacturer – can issue/revoke certificates', 'success');
    } else {
      showStatus('connectionStatus', 'Connected – not authorized to issue certificates', 'warning');
    }

    console.log('Admin status:', { totalAdmins, isCallerAdmin, isCallerOwner });
  } catch (err) {
    console.error('checkAdminStatus error:', err);
    showStatus('connectionStatus', 'Error checking permissions: ' + (err.message || err), 'error');
  }
}

async function loadAdminList() {
  if (!walletContract) return;
  const listEl = document.getElementById('adminList');
  try {
    const info = await walletContract.getAllAdminInfo();
    const totalAdmins = info[0].toNumber();
    const ownerAddr = await walletContract.owner();
    if (listEl) {
      listEl.innerHTML = `
        <strong>Manufacturer Information:</strong><br>
        Total Authorized Manufacturers: ${totalAdmins}<br>
        Contract Owner: ${ownerAddr}<br>
        <small>Use "Check Authorization Status" to verify specific addresses</small>
      `;
      listEl.className = 'status info';
    }
  } catch (err) {
    console.error('loadAdminList error:', err);
    if (listEl) listEl.innerHTML = '<span class="error">Error loading manufacturer info</span>';
  }
}

// ==================== ISSUE CERTIFICATE ====================
async function issueCert() {
  const certId          = byId('certificateId');
  const productName     = byId('productName');
  const manufacturer    = byId('mfgName');
  const mfgDateStr      = byId('mfgDate');
  const expDateStr      = byId('expDate');
  const location        = byId('location');
  const intendedRegion  = byId('intendedRegion');
  const details         = byId('details');
  const notes           = byId('notes');

  if (!certId || !productName || !manufacturer || !mfgDateStr) {
    showStatus('connectionStatus', 'Please fill in all required fields (*)', 'error');
    return;
  }
  if (!walletContract || !signer || !userAccount) {
    showStatus('connectionStatus', 'Please connect your wallet first', 'error');
    return;
  }

  const mfgDateTs = toUnix(mfgDateStr);
  if (!Number.isFinite(mfgDateTs) || mfgDateTs <= 0) {
    showStatus('connectionStatus', 'Invalid manufacture date', 'error');
    return;
  }
  const expDateTs = expDateStr ? toUnix(expDateStr) : 0;
  if (expDateTs && expDateTs <= mfgDateTs) {
    showStatus('connectionStatus', 'Expiry date must be after manufacture date', 'error');
    return;
  }

  try {
    showLoading('issueLoading', true);
    console.log('Issuing certificate:', certId);
    showStatus('connectionStatus', 'Preparing transaction…', 'info');

    const tx = await walletContract.issueCertificate(
      certId,
      productName,
      manufacturer,
      mfgDateTs,
      expDateTs,
      location,
      intendedRegion,
      details,
      notes
    );

    showStatus('connectionStatus', 'Transaction submitted. Waiting for confirmation…', 'info');
    const receipt = await tx.wait();
    console.log('Transaction confirmed:', receipt.transactionHash);

    showLoading('issueLoading', false);

    showStatus(
      'connectionStatus',
      `Certificate issued successfully!<br>TX: <a target="_blank" rel="noopener" href="https://sepolia.etherscan.io/tx/${receipt.transactionHash}">${receipt.transactionHash.slice(0,10)}…</a>`,
      'success'
    );

    const certData = {
      certId,
      productName,
      mfgName: manufacturer,
      mfgDate: mfgDateStr,
      expDate: expDateStr || '',
      location,
      intendedRegion,
      details,
      notes
    };
    await generateQRCode(JSON.stringify(certData), certId);

    [
      'certificateId','productName','mfgName','mfgDate','expDate',
      'location','intendedRegion','details','notes'
    ].forEach(clearField);

  } catch (err) {
    console.error('issueCert error:', err);
    let msg = err?.reason || err?.message || 'Unknown error';
    if (/user rejected/i.test(msg)) msg = 'Transaction rejected by user';
    if (/exist/i.test(msg)) msg = 'Certificate ID already exists';
    showStatus('connectionStatus', 'Failed to issue certificate: ' + msg, 'error');
  } finally {
    showLoading('issueLoading', false);
  }
}

// ==================== QR GENERATION ====================
async function generateQRCode(data, certId) {
  const canvas     = document.getElementById('qrCodeCanvas');
  const imgFallback= document.getElementById('qrImgFallback');
  const display    = document.getElementById('qrDisplay');
  const certIdSpan = document.getElementById('generatedCertId');

  if (!display) {
    console.warn('qrDisplay container not found – cannot show QR.');
    return;
  }

  try {
    const strategy = await resolveQRStrategy();

    if (strategy === "api") {
      const url = `${QR_FALLBACK_ENDPOINT}?size=300x300&data=${encodeURIComponent(data)}`;
      if (imgFallback) {
        imgFallback.src = url;
        imgFallback.alt = 'QR Code';
        imgFallback.style.display = 'block';
      }
      if (canvas) canvas.style.display = 'none';
    } else if (typeof QRCode !== 'undefined' && canvas) {
      await QRCode.toCanvas(canvas, data, { width: 300, margin: 2 });
      canvas.style.display = 'block';
      if (imgFallback) imgFallback.style.display = 'none';
    } else {
      throw new Error('No QR rendering path available.');
    }

    if (certIdSpan) certIdSpan.textContent = certId;
    display.style.display = 'block';
    display.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } catch (err) {
    console.error('generateQRCode error:', err);
    showStatus('connectionStatus', 'Error generating QR: ' + (err.message || err), 'error');
  }
}

window.downloadQR = async function () {
  const canvas     = document.getElementById('qrCodeCanvas');
  const imgFallback= document.getElementById('qrImgFallback');
  const certId     = (document.getElementById('generatedCertId')?.textContent || 'certificate').replace(/\s+/g, '_');

  let href = '';
  if (canvas && canvas.style.display !== 'none' && canvas.width && canvas.height) {
    href = canvas.toDataURL();
  } else if (imgFallback && imgFallback.style.display !== 'none' && imgFallback.src) {
    href = imgFallback.src;
  }
  if (!href) return;

  const a = document.createElement('a');
  a.download = `${certId}_QRCode.png`;
  a.href = href;
  a.click();
};

window.printQR = async function () {
  const canvas     = document.getElementById('qrCodeCanvas');
  const imgFallback= document.getElementById('qrImgFallback');
  const certId     = document.getElementById('generatedCertId')?.textContent || 'Certificate';

  let imgSrc = '';
  if (canvas && canvas.style.display !== 'none' && canvas.width && canvas.height) {
    imgSrc = canvas.toDataURL();
  } else if (imgFallback && imgFallback.style.display !== 'none' && imgFallback.src) {
    imgSrc = imgFallback.src;
  }
  if (!imgSrc) return;

  const win = window.open('', '_blank');
  win.document.write(`
    <html><head><title>Print Certificate QR Code</title>
    <style>
      body { font-family: Arial, sans-serif; text-align:center; padding:20px; }
      h2 { margin-bottom: 10px; }
      p { margin: 5px 0; }
      img { margin: 20px 0; }
    </style></head>
    <body>
      <h2>Certificate QR Code</h2>
      <p><strong>Certificate ID:</strong> ${certId}</p>
      <img src="${imgSrc}" />
      <p>Scan to verify the certificate</p>
    </body></html>
  `);
  win.document.close();
  win.print();
};

// ==================== REVOKE ====================
async function revokeCert() {
  const certId = byId('revokeCertId');
  if (!certId) {
    showStatus('connectionStatus', 'Please enter a certificate ID to revoke', 'error');
    return;
  }
  if (!walletContract) {
    showStatus('connectionStatus', 'Please connect your wallet first', 'error');
    return;
  }
  try {
    showLoading('issueLoading', true);
    showStatus('connectionStatus', 'Sending revocation transaction…', 'info');
    const tx = await walletContract.revokeCertificate(certId);
    const receipt = await tx.wait();
    showStatus(
      'connectionStatus',
      `Certificate revoked!<br>TX: <a target="_blank" rel="noopener" href="https://sepolia.etherscan.io/tx/${receipt.transactionHash}">${receipt.transactionHash.slice(0,10)}…</a>`,
      'success'
    );
    clearField('revokeCertId');
  } catch (err) {
    console.error('revokeCert error:', err);
    let msg = err?.reason || err?.message || 'Unknown error';
    if (/user rejected/i.test(msg)) msg = 'Transaction rejected by user';
    if (/not exist|not found/i.test(msg)) msg = 'Certificate not found';
    showStatus('connectionStatus', 'Failed to revoke: ' + msg, 'error');
  } finally {
    showLoading('issueLoading', false);
  }
}

// ==================== ADMIN MGMT ====================
async function addNewAdmin() {
  const addr = byId('newAdminAddress');
  if (!addr || !ethers.utils.isAddress(addr)) {
    showStatus('connectionStatus', 'Please enter a valid Ethereum address', 'error');
    return;
  }
  if (!walletContract) {
    showStatus('connectionStatus', 'Connect wallet first', 'error');
    return;
  }
  try {
    showLoading('adminLoading', true);
    showStatus('connectionStatus', 'Adding manufacturer…', 'info');
    const tx = await walletContract.addAdmin(addr);
    await tx.wait();
    showStatus('connectionStatus', 'Manufacturer added successfully!', 'success');
    clearField('newAdminAddress');
    await loadAdminList();
  } catch (err) {
    console.error('addNewAdmin error:', err);
    let msg = err?.reason || err?.message || 'Unknown error';
    if (/already/i.test(msg)) msg = 'Address is already a manufacturer';
    showStatus('connectionStatus', 'Failed to add manufacturer: ' + msg, 'error');
  } finally {
    showLoading('adminLoading', false);
  }
}

async function removeAdmin() {
  const addr = byId('removeAdminAddress');
  if (!addr || !ethers.utils.isAddress(addr)) {
    showStatus('connectionStatus', 'Please enter a valid Ethereum address', 'error');
    return;
  }
  if (!walletContract) {
    showStatus('connectionStatus', 'Connect wallet first', 'error');
    return;
  }
  try {
    showLoading('adminLoading', true);
    showStatus('connectionStatus', 'Removing manufacturer…', 'info');
    const tx = await walletContract.removeAdmin(addr);
    await tx.wait();
    showStatus('connectionStatus', 'Manufacturer removed successfully!', 'success');
    clearField('removeAdminAddress');
    await loadAdminList();
  } catch (err) {
    console.error('removeAdmin error:', err);
    let msg = err?.reason || err?.message || 'Unknown error';
    if (/not/i.test(msg) && /admin/i.test(msg)) msg = 'Address is not a manufacturer';
    showStatus('connectionStatus', 'Failed to remove manufacturer: ' + msg, 'error');
  } finally {
    showLoading('adminLoading', false);
  }
}

async function checkSpecificAdmin() {
  const addr = byId('checkAdminAddress');
  const resultEl = document.getElementById('adminCheckResult');
  if (!resultEl) return;

  if (!addr || !ethers.utils.isAddress(addr)) {
    resultEl.innerHTML = '<div class="status error">Please enter a valid Ethereum address</div>';
    return;
  }

  try {
    showLoading('adminLoading', true);
    const isAdmin = await publicContract.isAdmin(addr);
    const owner = await publicContract.owner();
    const isOwner = addr.toLowerCase() === owner.toLowerCase();

    let statusText = '';
    let statusClass = '';
    if (isOwner) { statusText = 'Owner (has manufacturer rights)'; statusClass = 'success'; }
    else if (isAdmin) { statusText = 'Authorized Manufacturer'; statusClass = 'success'; }
    else { statusText = 'Not authorized as manufacturer'; statusClass = 'info'; }

    resultEl.innerHTML = `
      <div class="status ${statusClass}">
        <strong>Address:</strong> ${addr}<br>
        <strong>Status:</strong> ${statusText}<br>
        <strong>Contract Owner:</strong> ${owner}
      </div>
    `;
  } catch (err) {
    console.error('checkSpecificAdmin error:', err);
    resultEl.innerHTML = `<div class="status error">Error checking status: ${err.message || err}</div>`;
  } finally {
    showLoading('adminLoading', false);
  }
}

// ==================== OPTIONAL VERIFY UI (for index.html) ====================
async function verifyCertUI() {
  const certId = byId('verifyCertId');
  const target = 'verifyResult';
  if (!certId) {
    showStatus(target, 'Enter a certificate ID.', 'error');
    return;
  }
  if (!publicContract) {
    showStatus(target, 'Read provider not ready. Is app.js loaded?', 'error');
    return;
  }
  try {
    showStatus(target, 'Reading certificate…', 'info');
    const full = await publicContract.getCertificateFull(certId);
    const owner = await publicContract.ownerOfCertificate(certId);

    const productName    = full[0];
    const mfgName        = full[1];
    const mfgDate        = full[2];
    const expDate        = full[3];
    const location       = full[4];
    const intendedRegion = full[5];
    const details        = full[6];
    const notes          = full[7];
    const isValid        = full[8];

    if (!productName) {
      showStatus(target, 'Certificate not found on this contract.', 'error');
      return;
    }

    const badge = isValid ? '<span style="color:#00ff88">VALID</span>' : '<span style="color:#ff6b6b">REVOKED</span>';
    const expStr = expDate && expDate.toString() !== "0" ? formatDate(expDate) : '–';

    const html = `
      <div class="status ${isValid ? 'success' : 'error'}">
        <strong>Status:</strong> ${badge}<br>
        <strong>Product:</strong> ${escapeHtml(productName)}<br>
        <strong>Manufacturer:</strong> ${escapeHtml(mfgName)}<br>
        <strong>MFG Date:</strong> ${formatDate(mfgDate)}<br>
        <strong>Expiry:</strong> ${expStr}<br>
        <strong>Location:</strong> ${escapeHtml(location || '–')}<br>
        <strong>Intended Region:</strong> ${escapeHtml(intendedRegion || '–')}<br>
        <strong>Owner:</strong> ${owner ? owner : '–'}<br>
        ${details ? `<div style="margin-top:8px;"><strong>Details:</strong><br>${escapeHtml(details)}</div>` : ''}
        ${notes   ? `<div style="margin-top:8px;"><strong>Notes:</strong><br>${escapeHtml(notes)}</div>` : ''}
      </div>
    `;
    setHtml(target, html);
  } catch (err) {
    console.error('verifyCertUI error:', err);
    showStatus('verifyResult', 'Error reading: ' + (err.message || err), 'error');
  }
}

// ==================== WIRING & HELPERS ====================
function wireButtons() {
  const connectBtn = document.getElementById('connectWallet');
  if (connectBtn) connectBtn.addEventListener('click', connectWallet);

  const refreshBtn = document.getElementById('refreshAdminStatus');
  if (refreshBtn) refreshBtn.addEventListener('click', () => checkAdminStatus(true));

  const issueBtn = document.getElementById('issueCertBtn');
  if (issueBtn) issueBtn.addEventListener('click', issueCert);

  const revokeBtn = document.getElementById('revokeCertBtn');
  if (revokeBtn) revokeBtn.addEventListener('click', revokeCert);

  const addBtn = document.getElementById('addAdminBtn');
  if (addBtn) addEventListenerSafe(addBtn, 'click', addNewAdmin);

  const removeBtn = document.getElementById('removeAdminBtn');
  if (removeBtn) addEventListenerSafe(removeBtn, 'click', removeAdmin);

  const checkBtn = document.getElementById('checkAdminBtn');
  if (checkBtn) addEventListenerSafe(checkBtn, 'click', checkSpecificAdmin);

  const verifyBtn = document.getElementById('verifyBtn');
  if (verifyBtn) verifyBtn.addEventListener('click', verifyCertUI);
}

function addEventListenerSafe(el, ev, fn) {
  try { el.addEventListener(ev, fn); } catch (_) {}
}

function wireWalletEvents() {
  if (!window.ethereum) return;
  window.ethereum.on('accountsChanged', onAccountsChanged);
  window.ethereum.on('chainChanged', onChainChanged);
}

function onAccountsChanged(accounts) {
  if (!accounts || accounts.length === 0) {
    userAccount = null;
    walletContract = null;

    window.walletProvider = null;
    window.walletContract = null;
    window.signer = null;
    window.userAccount = null;

    showStatus('connectionStatus', 'Wallet disconnected. Please connect again.', 'warning');

    const connectBtn = document.getElementById('connectWallet');
    if (connectBtn) connectBtn.style.display = 'block';
    showEl('manufacturerControls', false);
    showEl('adminStatusControls', false);
  } else {
    connectWallet();
  }
}

function onChainChanged(chainId) {
  showStatus('connectionStatus', 'Network changed. Reloading…', 'info');
  setTimeout(() => window.location.reload(), 1200);
}

// --------------- Small helpers ---------------
function sleep(ms){ return new Promise(r => setTimeout(r, ms)); }

function byId(id) {
  const el = document.getElementById(id);
  return el && 'value' in el ? String(el.value).trim() : '';
}
function clearField(id) {
  const el = document.getElementById(id);
  if (el && 'value' in el) el.value = '';
}
function showEl(id, show) {
  const el = document.getElementById(id);
  if (el) el.style.display = show ? 'block' : 'none';
}
function setHtml(id, html) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = html;
}

function updateNetworkInfo(msg, type = '') {
  const el = document.getElementById('networkInfo');
  if (el) {
    el.innerHTML = '<strong>Network Status:</strong> ' + msg;
    el.className = `network-info ${type}`;
  }
}
function showStatus(elementId, msg, type = '') {
  const el = document.getElementById(elementId);
  if (el) {
    el.innerHTML = msg;
    el.className = `status ${type}`;
  }
}
function showLoading(elementId, show) {
  const el = document.getElementById(elementId);
  if (el) el.style.display = show ? 'block' : 'none';
}

function toUnix(dateStr) {
  const t = Math.floor(new Date(dateStr).getTime() / 1000);
  return Number.isFinite(t) ? t : 0;
}
function formatDate(ts) {
  const d = new Date(Number(ts) * 1000);
  if (!Number.isFinite(d.getTime())) return '–';
  return d.toLocaleDateString();
}
function shortAddr(a) {
  return a ? `${a.slice(0,6)}...${a.slice(-4)}` : '';
}
function escapeHtml(s) {
  return String(s || '')
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}

// ==================== DEBUG EXPORTS ====================
window.connectWallet = connectWallet;
window.checkAdminStatus = checkAdminStatus;
window.issueCert = issueCert;
window.revokeCert = revokeCert;
window.addNewAdmin = addNewAdmin;
window.removeAdmin = removeAdmin;
window.checkSpecificAdmin = checkSpecificAdmin;
window.verifyCertUI = verifyCertUI;

console.log('Manufacturer DApp loaded (CSP-safe QR mode).');