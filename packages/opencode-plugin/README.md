# @ai4x/opencode-plugin

AI4X threat intelligence agents and skills for opencode.

## Install

```bash
npm install @ai4x/opencode-plugin
```

Add the plugin to `opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": [
    "@ai4x/opencode-plugin"
  ]
}
```

Restart opencode after changing config. opencode loads plugins and config only during startup.

## Defaults

The plugin injects:

- Agent definitions from `assets/agents`.
- Skill definitions from `assets/skills`.
- Plugin source files from `assets/plugins` for packaging and reuse.
- `default_agent: "安全运营助手"`.
- `mcp.ai4x` as a remote MCP server at `http://localhost:8000/mcp`.
- `GLOBAL_INSTRUCTIONS.md` from the package assets.

The plugin does not configure a model provider or API key. Keep model/provider credentials in the user's own opencode config or environment.

## Options

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": [
    ["@ai4x/opencode-plugin", {
      "ai4xMcpUrl": "http://localhost:8000/mcp",
      "setDefaultAgent": true,
      "injectMcp": true,
      "injectInstructions": true
    }]
  ]
}
```

Available options:

- `ai4xMcpUrl`: AI4X MCP endpoint. Defaults to `http://localhost:8000/mcp`.
- `setDefaultAgent`: Set opencode's default agent to `安全运营助手`. Defaults to `true`.
- `defaultAgent`: Override the default agent name when `setDefaultAgent` is enabled.
- `injectMcp`: Inject `mcp.ai4x`. Defaults to `true`.
- `injectInstructions`: Add packaged global instructions. Defaults to `true`.

## AI4X MCP Requirement

Most packaged agents and skills expect the AI4X MCP tool to be available through `mcp.ai4x`. Start the AI4X MCP server before using analysis workflows, or configure `ai4xMcpUrl` to point at your deployment.

## Release

Publish a new version from this package directory:

```bash
npm run release -- patch
```

Supported version arguments are `patch`, `minor`, `major`, or an explicit semver version such as `0.2.0`.

Dry-run a release without publishing:

```bash
npm run release:dry-run -- patch
```

Publish with a custom npm tag or OTP:

```bash
npm run release -- 0.2.0 --tag beta
npm run release -- patch --otp 123456
```

The release script updates `package.json` and `package-lock.json`, runs `npm test`, runs `npm pack --dry-run`, then runs `npm publish --access public`.
