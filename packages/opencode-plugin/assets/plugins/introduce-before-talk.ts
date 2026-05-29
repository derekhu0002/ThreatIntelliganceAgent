import type { Plugin } from "@opencode-ai/plugin"

export const AutoInitPlugin: Plugin = async ({ project, client, $, directory, worktree }) => {
  return {
    event: async ({ event }) => {
      if (event.type !== "session.compacted") {
        return
      }

      // await client.session.prompt({
      //   path: { id: event.properties.sessionID },
      //   body: {
      //     parts: [
      //       {
      //         type: "text",
      //         text: "请先用中文做一个简短自我介绍，说明你的角色、你在当前工作区能提供什么帮助，并给出一个用户下一步可以直接提问的具体建议。",
      //         synthetic: true,
      //       },
      //     ],
      //   },
      // })
    }
  }
}