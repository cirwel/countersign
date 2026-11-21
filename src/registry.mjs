// Client for Concordium's hosted Agent Registry MCP server (JSON-RPC over HTTP).
// The server defaults to mainnet, so every call here names testnet explicitly and
// refuses any response that reports another network.
export const MCP_URL = 'https://agent-registry-mcp.concordium.com/mcp';
export const NETWORK = 'testnet';
export const TESTNET_GENESIS = '4221332d34e1694168c2a0c0b3fd0f273809612cb13d000d5c2e00e85f50f796';
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
    // Tools that answer about chain state echo the network. Pure encoders (token_address, parse_token_address, get_metadata) do not.
    const NO_NETWORK_ECHO = new Set(['token_address', 'parse_token_address', 'get_metadata']);
    if (value && typeof value === 'object') {
        if ('network' in value ? value.network !== NETWORK : !NO_NETWORK_ECHO.has(tool)) {
            throw new Error(`registry MCP ${tool} did not answer for ${NETWORK}; refusing`);
        }
    }
    return value;
}

export function assertRegistry(address) {
    if (Number(address?.index) !== REGISTRY.index || Number(address?.subindex) !== REGISTRY.subindex) {
        throw new Error(`unexpected registry contract ${JSON.stringify(address)}; this tool trusts only <${REGISTRY.index},${REGISTRY.subindex}> on testnet`);
    }
}
