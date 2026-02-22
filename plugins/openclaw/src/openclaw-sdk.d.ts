declare module "openclaw/plugin-sdk" {
  import type { TSchema } from "@sinclair/typebox";

  type OpenClawPluginConfigSchema = {
    safeParse?: (value: unknown) => {
      success: boolean;
      data?: unknown;
      error?: { issues?: Array<{ message: string }> };
    };
  };

  type OpenClawPluginToolOptions = {
    name?: string;
    names?: string[];
    optional?: boolean;
  };

  type OpenClawPluginToolContext = {
    config: any;
    sessionKey?: string;
    sandboxed?: boolean;
  };

  type AgentTool = {
    name: string;
    description: string;
    parameters: TSchema;
    execute(toolCallId: string, params: Record<string, unknown>): Promise<{
      content: { type: string; text: string }[];
      details?: unknown;
    }>;
  };

  type OpenClawPluginToolFactory = (
    ctx: OpenClawPluginToolContext,
  ) => AgentTool | AgentTool[] | null | undefined;

  type OpenClawPluginService = {
    id: string;
    start(): Promise<void>;
    stop(): Promise<void>;
  };

  type PluginCommandContext = {
    senderId?: string;
    channel: string;
    isAuthorizedSender: boolean;
    args?: string;
    commandBody: string;
    config: any;
  };

  type PluginCommandResult = {
    text?: string;
    mediaUrl?: string;
    mediaUrls?: string[];
    isError?: boolean;
    channelData?: Record<string, unknown>;
  };

  type OpenClawPluginCommandDefinition = {
    name: string;
    description: string;
    acceptsArgs?: boolean;
    requireAuth?: boolean;
    handler: (ctx: PluginCommandContext) => PluginCommandResult | Promise<PluginCommandResult>;
  };

  type OpenClawPluginApi = {
    id: string;
    name: string;
    version?: string;
    description?: string;
    source: string;
    config: any;
    pluginConfig?: Record<string, unknown>;
    runtime: any;
    logger: {
      info(msg: string): void;
      warn(msg: string): void;
      error(msg: string): void;
    };
    registerTool: (
      tool: AgentTool | OpenClawPluginToolFactory,
      opts?: OpenClawPluginToolOptions,
    ) => void;
    registerCli: (
      registrar: (ctx: { program: any }) => void,
      opts?: { commands?: string[] },
    ) => void;
    registerCommand: (command: OpenClawPluginCommandDefinition) => void;
    registerService: (service: OpenClawPluginService) => void;
    registerHook: (events: string | string[], handler: (...args: any[]) => any, opts?: any) => void;
    on: (hookName: string, handler: (...args: any[]) => any, opts?: { priority?: number }) => void;
    resolvePath: (input: string) => string;
  };

  function emptyPluginConfigSchema(): OpenClawPluginConfigSchema;

  export type {
    OpenClawPluginApi,
    OpenClawPluginConfigSchema,
    OpenClawPluginToolOptions,
    OpenClawPluginToolFactory,
    OpenClawPluginToolContext,
    OpenClawPluginService,
    AgentTool,
  };
  export { emptyPluginConfigSchema };
}
