# mcp-hash

Cryptographic hash & HMAC MCP.

Part of [Pipeworx](https://pipeworx.io) — an MCP gateway connecting AI agents to 1394+ live data sources.

## Tools

| Tool | Description |
|------|-------------|
| `hash` | Compute a cryptographic hash (hex digest) of text: algorithm = md5, sha1, sha256 (default), sha384, or sha512. Keyless/offline; the input is not stored or transmitted. MD5/SHA-1 are legacy (checksums only, not security). |
| `hmac` | Compute an HMAC (hex) of text with a secret key. algorithm = sha1, sha256 (default), sha384, or sha512. Keyless/offline. |

## Quick Start

Add to your MCP client (Claude Desktop, Cursor, Windsurf, etc.):

```json
{
  "mcpServers": {
    "hash": {
      "url": "https://gateway.pipeworx.io/hash/mcp"
    }
  }
}
```

Or connect to the full Pipeworx gateway for access to all 1394+ data sources:

```json
{
  "mcpServers": {
    "pipeworx": {
      "url": "https://gateway.pipeworx.io/mcp"
    }
  }
}
```

## Using with ask_pipeworx

Instead of calling tools directly, you can ask questions in plain English:

```
ask_pipeworx({ question: "your question about Hash data" })
```

The gateway picks the right tool and fills the arguments automatically.

## More

- [Docs and guides](https://pipeworx.io/docs)
- [pipeworx.io](https://pipeworx.io)

## License

MIT
