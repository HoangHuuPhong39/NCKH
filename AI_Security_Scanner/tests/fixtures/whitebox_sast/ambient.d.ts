declare module "openai" {
  export default class OpenAI {
    constructor(options?: Record<string, unknown>);
    chat: {
      completions: {
        create(params: Record<string, unknown>): Promise<{
          choices: Array<{ message?: { content?: string | null } }>;
        }>;
      };
    };
  }
}
