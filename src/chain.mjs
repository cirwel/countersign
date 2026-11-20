// Concordium testnet access. Reading needs no keys; signing reads a key file that lives outside the repo.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
    AccountAddress,
    CcdAmount,
    ConcordiumHdWallet,
    ContractAddress,
    DataBlob,
    Energy,
    Parameter,
    ReceiveName,
    Transaction,
    TransactionHash,
    buildBasicAccountSigner,
} from '@concordium/web-sdk';
import { ConcordiumGRPCNodeClient, credentials } from '@concordium/web-sdk/nodejs';

export const TESTNET_GENESIS = '4221332d34e1694168c2a0c0b3fd0f273809612cb13d000d5c2e00e85f50f796';
export const EXPLORER_TX = (hash) => `https://ccdexplorer.io/testnet/transaction/${hash}`;
const NODE_HOST = 'grpc.testnet.concordium.com';
const NODE_PORT = 20000;

let cached;
/** Returns a node client only after confirming the node is on testnet. There is no mainnet configuration in this tool. */
export async function client() {
    if (cached) return cached;
    const c = new ConcordiumGRPCNodeClient(NODE_HOST, NODE_PORT, credentials.createSsl());
    const genesis = (await c.getConsensusStatus()).genesisBlock.toString();
    if (genesis !== TESTNET_GENESIS) throw new Error(`node is not Concordium testnet (genesis ${genesis}); refusing`);
    cached = c;
    return c;
}

function keyfilePath() {
    if (process.env.COUNTERSIGN_KEYFILE) return process.env.COUNTERSIGN_KEYFILE;
    const local = path.resolve('countersign.local.json');
    if (fs.existsSync(local)) return JSON.parse(fs.readFileSync(local, 'utf8')).keyfile.replace(/^~/, os.homedir());
    return path.join(os.homedir(), '.config/countersign/testnet-account.json');
}

/** Key file: { accountAddress, seedPhrase } (identity 0, credential 0 on identity provider 0) or { accountAddress, signKey }. */
export function loadSigner() {
    const file = keyfilePath();
    if ((fs.statSync(file).mode & 0o077) !== 0) throw new Error('key file must not be readable by group or others (chmod 600)');
    const k = JSON.parse(fs.readFileSync(file, 'utf8'));
    const signKey = k.signKey ?? ConcordiumHdWallet.fromSeedPhrase(k.seedPhrase, 'Testnet').getAccountSigningKey(0, 0, 0).toString('hex');
    return { address: k.accountAddress, sender: AccountAddress.fromBase58(k.accountAddress), signer: buildBasicAccountSigner(signKey) };
}

async function signSendWait(builder, who) {
    const c = await client();
    const { nonce } = await c.getNextAccountNonce(who.sender);
    const tx = builder.addMetadata({ sender: who.sender, nonce }).build();
    const signed = await Transaction.signAndFinalize(tx, who.signer);
    const hash = await c.sendTransaction(signed);
    const { summary } = await c.waitForTransactionFinalization(hash, 180000);
    if (summary.transactionType === 'failed' || summary.rejectReason) {
        throw new Error(`transaction ${hash} was rejected: ${JSON.stringify(summary.rejectReason ?? summary, bigintSafe)}`);
    }
    return { hash: hash.toString(), summary };
}

export const bigintSafe = (_k, v) => (typeof v === 'bigint' ? v.toString() : v);

export function sendRegisterData(bytes, who = loadSigner()) {
    return signSendWait(Transaction.registerData({ data: new DataBlob(Buffer.from(bytes)) }), who);
}

/** Signs and submits an unsigned payload built by the Agent Registry MCP server. */
export function sendRegistryUpdate(built, who = loadSigner()) {
    const payload = {
        amount: CcdAmount.zero(),
        address: ContractAddress.create(built.contract_address.index, built.contract_address.subindex),
        receiveName: ReceiveName.fromString(built.receive_name),
        message: Parameter.fromHexString(built.parameter_hex),
    };
    return signSendWait(Transaction.updateContract(payload, Energy.create(built.suggested_energy ?? 30000)), who);
}

/** Finalized register-data transaction: who sent it and what bytes it carries. */
export async function readRegisterData(txHash) {
    const c = await client();
    const status = await c.getBlockItemStatus(TransactionHash.fromHexString(txHash));
    if (status.status !== 'finalized') throw new Error(`transaction ${txHash} is not finalized (${status.status})`);
    const s = status.outcome.summary;
    if (s.transactionType !== 'registerData') throw new Error(`transaction ${txHash} is ${s.transactionType}, not registerData`);
    const block = await c.getBlockInfo(status.outcome.blockHash);
    return { sender: s.sender.address ?? String(s.sender), data: Buffer.from(s.dataRegistered.data, 'hex'), blockTime: block.blockSlotTime.toISOString() };
}
