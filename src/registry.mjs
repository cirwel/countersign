// Client for Concordium's hosted Agent Registry MCP server (JSON-RPC over HTTP).
// The server defaults to mainnet, so every call here names testnet explicitly and
// refuses any response that reports another network.
export const MCP_URL = process.env.COUNTERSIGN_MCP_URL ?? 'https://agent-registry-mcp.concordium.com/mcp';
export const NETWORK = 'testnet';
export const REGISTRY = { index: 12802, subindex: 0 }; // CIS-8004 on testnet; the verifier trusts only this instance

let nextId = 1;

export async function mcp(tool, args = {}) {
    const res = await fetch(MCP_URL, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: nextId++, method: 'tools/call', params: { name: tool, arguments: { ...args, network: NETWORK } } }),
    });
    if (!res.ok) throw new Error(`registry MCP ${tool}: HTTP ${res.status}`);
    const body = await res.json();
    if (body.error) throw new Error(`registry MCP ${tool}: ${body.error.message}`);
    const text = body.result?.content?.[0]?.text;
    if (body.result?.isError) throw new Error(`registry MCP ${tool}: ${text}`);
    let value;
    try {
        value = JSON.parse(text);
    } catch {
        return text;
    }
    if (value && typeof value === 'object' && 'network' in value && value.network !== NETWORK) {
        throw new Error(`registry MCP ${tool} answered for network ${value.network}; refusing`);
    }
    return value;
}

export function assertRegistry(address) {
    if (Number(address?.index) !== REGISTRY.index || Number(address?.subindex ?? 0) !== REGISTRY.subindex) {
        throw new Error(`unexpected registry contract ${JSON.stringify(address)}; this tool trusts only <${REGISTRY.index},${REGISTRY.subindex}> on testnet`);
    }
}
