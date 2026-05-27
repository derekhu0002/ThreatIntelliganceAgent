---
name: create-opencode-plugin
description: create a new OpenCode plugin with custom tools and authentication providers
---

# OpenCode Plugin Development

Build custom OpenCode plugins with TypeScript to extend AI assistant functionality.

## Quick Start

### 1. Create Plugin Package

Shell

```
mkdir my-opencode-plugincd my-opencode-pluginbun init
```

### 2. Install Dependencies


JSON

```
{  "dependencies": {    "@opencode-ai/plugin": "latest",    "@opencode-ai/sdk": "latest",    "zod": "latest"  },  "devDependencies": {    "@types/node": "latest",    "typescript": "latest"  }}
```

### 3. Configure TypeScript


JSON

```
{  "extends": "@tsconfig/node22/tsconfig.json",  "compilerOptions": {    "outDir": "dist",    "module": "preserve",    "declaration": true,    "moduleResolution": "bundler"  },  "include": ["src"]}
```

### 4. Create Plugin


TypeScript

```
// src/index.tsimport { Plugin, tool } from '@opencode-ai/plugin'export const MyPlugin: Plugin = async (ctx) => {  return {    tool: {      hello: tool({        description: 'Say hello',        args: {          name: tool.schema.string().describe('Name to greet'),        },        async execute({ name }) {          return `Hello, ${name}!`        },      }),    },  }}
```

## Plugin Structure

A plugin exports a function returning an object with hooks:


TypeScript

```
import { Plugin, tool } from '@opencode-ai/plugin'export const MyPlugin: Plugin = async (ctx) => {  return {    tool: { /* custom tools */ },    auth: { /* authentication provider */ },    event: async ({ event }) => { /* event handler */ },    config: async (config) => { /* modify config */ },    'chat.message': async ({}, { message }) => { /* intercept messages */ },    'chat.params': async ({}, { temperature, options }) => { /* modify params */ },    'permission.ask': async (perm, out) => { /* handle permissions */ },    'tool.execute.before': async ({}, { args }) => { /* before hook */ },    'tool.execute.after': async ({}, { output }) => { /* after hook */ },  }}
```

## Context API (ctx)


TypeScript

```
ctx.client              // OpenCode SDK client (localhost:4096)ctx.project.id          // Project identifier (git hash or "global")ctx.project.worktree    // Git worktree rootctx.project.vcs         // Version control ("git" or undefined)ctx.directory           // Current working directoryctx.worktree            // Alias for ctx.project.worktreectx.$`command`          // Bun shell for commands
```

## Tools

Define custom tools for AI to use:


TypeScript

```
import { tool } from '@opencode-ai/plugin'tool({  description: 'Custom tool',  args: {    param: tool.schema.string().describe('Parameter'),    count: tool.schema.number().optional().describe('Optional count'),  },  async execute(args, context) {    // context: { sessionID, messageID, agent, abort }    return `Result: ${args.param}`  },})
```

## Authentication Providers

Add custom auth methods:


TypeScript

```
export const MyPlugin: Plugin = async (ctx) => {  return {    auth: {      provider: 'myservice',      loader: async (auth, provider) => ({        apiKey: 'loaded-key'      }),      methods: [{        type: 'oauth',        label: 'Connect MyService',        async authorize() {          return {            url: 'https://myservice.com/oauth/authorize',            instructions: 'Authorize access',            method: 'code',            async callback(code) {              return {                type: 'success',                access: 'token',                refresh: 'refresh',                expires: Date.now() + 3600000,              }            },          }        },      }],    },  }}
```

## Events

Handle system events:


TypeScript

```
export const MyPlugin: Plugin = async (ctx) => {  return {    event: async ({ event }) => {      console.log('Event:', event.type)    },  }}
```

**Event Types:**

- **Session:** `session.created`, `session.updated`, `session.deleted`, `session.error`, `session.idle`
- **Message:** `message.updated`, `message.removed`, `message.part.updated`, `message.part.removed`
- **File:** `file.edited`, `file.watcher.updated`
- **Permission:** `permission.updated`, `permission.replied`
- **Server:** `server.connected`
- **LSP:** `lsp.updated`, `lsp.diagnostics`
- **Command:** `command.executed`
- **TUI:** `tui.prompt.append`, `tui.command.execute`, `tui.toast.show`
- **Other:** `installation.updated`, `ide.installed`

## Hooks

### Chat Message Hook

Intercept and modify chat messages:


TypeScript

```
'chat.message': async ({}, { message, parts }) => {  console.log('Message:', message.content)}
```

### Chat Parameters Hook

Modify LLM parameters:


TypeScript

```
'chat.params': async ({}, { temperature, topP, options }) => {  temperature = 0.7  options.customParam = 'value'}
```

### Permission Hook

Control permission requests:


TypeScript

```
'permission.ask': async (permission, output) => {  if (permission.type === 'read_file') {    output.status = 'allow'  }}
```

### Tool Execution Hooks


TypeScript

```
// Before execution'tool.execute.before': async ({ tool }, { args }) => {  if (tool === 'mytool') {    args.modified = true  }}// After execution'tool.execute.after': async ({ tool }, { title, output, metadata }) => {  console.log(`Tool ${tool} completed:`, output)}
```

### Configuration Hook

Modify OpenCode configuration:


TypeScript

```
config: async (config) => {  config.myPlugin = { enabled: true }}
```

## Shell Integration

Execute commands using Bun shell:


TypeScript

```
tool({  description: 'Run git command',  args: {},  async execute() {    const result = await ctx.$`git status --porcelain`    return result.text()  },})
```

## Configuration

### Local Development


JSON

```
{  "$schema": "https://opencode.ai/config.json",  "plugin": ["file:///path/to/plugin/dist/index.js"]}
```

### Published Plugins


JSON

```
{  "plugin": ["my-plugin@1.0.0"]}
```

### Multiple Plugins


JSON

```
{  "plugin": [    "plugin-one@latest",    "plugin-two@2.0.0",    "file:///path/to/local/plugin"  ]}
```

## Naming Convention

Use `opencode-` prefix:

- `opencode-my-service`
- `opencode-custom-tools`

## Testing

### Unit Tests


TypeScript

```
// src/index.test.tsimport { describe, it, expect } from 'bun:test'import { MyPlugin } from './index'describe('MyPlugin', () => {  it('registers tools', async () => {    const mockCtx = createMockContext()    const hooks = await MyPlugin(mockCtx)    expect(hooks.tool).toBeDefined()  })})
```

### Integration Testing


Shell

```
# Link local pluginbun linkcd /path/to/projectbun link my-opencode-plugin
```

## Debugging


Shell

```
# Check plugin loadingopencode --verbose
```


TypeScript

```
// Add loggingexport const MyPlugin: Plugin = async (ctx) => {  console.log('Loading:', ctx.project.name)  // ...}
```

## Best Practices

### Error Handling


TypeScript

```
tool({  description: 'Risky operation',  async execute() {    try {      const result = await ctx.$`some-command`      return result.text()    } catch (error) {      return `Error: ${error.message}`    }  },})
```

### Type Safety


TypeScript

```
import { z } from 'zod'tool({  description: 'Typed tool',  args: {    url: tool.schema.string().url().describe('Valid URL'),    count: tool.schema.number().min(1).max(100),  },  async execute(args) {    // args.url is typed as string    // args.count is typed as number    return `Processing ${args.url}`  },})
```

### Resource Management


TypeScript

```
export const MyPlugin: Plugin = async (ctx) => {  const cleanup = setupResource()    return {    event: async ({ event }) => {      if (event.type === 'shutdown') {        await cleanup()      }    },  }}
```

## Examples

### File System Plugin


TypeScript

```
tool({  description: 'List directory',  args: {    path: tool.schema.string().describe('Directory path'),  },  async execute({ path }) {    const result = await ctx.$`ls -la ${path}`    return result.text()  },})
```

### API Integration


TypeScript

```
tool({  description: 'Fetch API data',  args: {    url: tool.schema.string().url(),    method: tool.schema.enum(['GET', 'POST']).default('GET'),  },  async execute({ url, method }) {    const response = await fetch(url, { method })    return await response.text()  },})
```

### Session Prompt (noReply)


TypeScript

```
tool({  description: 'Send context message',  async execute(args, toolCtx) {    ctx.client.session.prompt({      path: { id: toolCtx.sessionID },      body: {        noReply: true, // Prevents AI response        parts: [{ type: 'text', text: 'Progress update...' }],      },    })  },})
```

## Resources

- OpenCode Docs: [https://opencode.ai/docs](https://opencode.ai/docs)
- Plugin SDK: [https://opencode.ai/docs/sdk](https://opencode.ai/docs/sdk)
- Source: [https://gist.github.com/rstacruz/946d02757525c9a0f49b25e316fbe715](https://gist.github.com/rstacruz/946d02757525c9a0f49b25e316fbe715)