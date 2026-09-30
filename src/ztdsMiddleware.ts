/**
 * ZTDS (Zero-Trust Data Sanitization) Middleware for FastMCP
 * Conforms to IETF Standards Track: draft-sibiryakov-ztds-protocol-00
 * https://datatracker.ietf.org/doc/draft-sibiryakov-ztds-protocol/
 *
 * Core Protocol Invariants:
 * 1. Zero External Egress Prior to Sanitization
 * 2. Deterministic Reversible Tokenization
 * 3. Ephemeral In-Memory Reference Purge
 * 4. ReDoS-Resistant Pattern Scanning
 * 5. Single-Pass O(N) Restoration (Zero Token Cascading)
 */

import crypto from "node:crypto";

export interface ZTDSContext {
  [key: string]: unknown;
  sessionId?: string;
  unmask?: (val: unknown) => unknown;
}

export interface ZTDSMetadata {
  sessionId: string;
  standard: string;
  zeroEgress: boolean;
}

export interface ZTDSOptions {
  autoZeroize?: boolean;
  enabledEntities?: string[];
  sanitizeInputs?: boolean;
  sanitizeOutputs?: boolean;
  useCryptoTokens?: boolean;
}

export const ZTDS_PATTERNS: Record<string, RegExp> = {
  API_SECRET:
    /\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{20,}|ghp_[a-zA-Z0-9]{20,}|eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,})\b/g,
  CREDIT_CARD: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
  EMAIL:
    /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}/g,
  IBAN: /\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]?){0,16}\b/g,
  IPV4: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  PHONE:
    /(?:(?:\+?1\s*(?:[.-]\s*)?)?(?:\(\s*([2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9])\s*\)|([2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9]))\s*(?:[.-]\s*)?)?([2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8]{2})\s*(?:[.-]\s*)?([0-9]{4})\b/g,
  SSN: /\b\d{3}-\d{2}-\d{4}\b/g,
};

export const TOKEN_PATTERN = /\[([A-Z_]+)_TOKEN_([a-zA-Z0-9_-]+)\]/g;

export type ZTDSToolResult<T> = { _ztds: ZTDSMetadata } & (T extends string
  ? { content: [{ text: string; type: "text" }] }
  : T);

export class ZTDSFastMCPMiddleware {
  public autoZeroize: boolean;
  public enabledEntities: string[];
  public sanitizeInputs: boolean;
  public sanitizeOutputs: boolean;
  public useCryptoTokens: boolean;
  private _entityMaps: Map<string, Map<string, string>> = new Map();
  private _sessionMaps: Map<string, Map<string, string>> = new Map();

  public constructor(options: ZTDSOptions = {}) {
    this.autoZeroize = options.autoZeroize !== false;
    this.enabledEntities =
      options.enabledEntities || Object.keys(ZTDS_PATTERNS);
    this.sanitizeInputs = options.sanitizeInputs !== false;
    this.sanitizeOutputs = options.sanitizeOutputs !== false;
    this.useCryptoTokens = options.useCryptoTokens !== false;
  }

  public restoreObject(val: unknown, sessionId: string): unknown {
    if (typeof val === "string") {
      return this.restoreText(val, sessionId);
    }
    if (Array.isArray(val)) {
      return val.map((item) => this.restoreObject(item, sessionId));
    }
    if (val !== null && typeof val === "object") {
      const result: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(val)) {
        result[k] = this.restoreObject(v, sessionId);
      }
      return result;
    }
    return val;
  }

  public restoreText(text: string, sessionId: string): string {
    if (typeof text !== "string") {
      return text;
    }
    const tokenMap = this._sessionMaps.get(sessionId);
    if (!tokenMap || tokenMap.size === 0) {
      return text;
    }

    return text.replace(TOKEN_PATTERN, (match) => {
      return tokenMap.get(match) || match;
    });
  }

  public sanitizeObject(val: unknown, sessionId: string): unknown {
    if (typeof val === "string") {
      return this.sanitizeText(val, sessionId).sanitized;
    }
    if (Array.isArray(val)) {
      return val.map((item) => this.sanitizeObject(item, sessionId));
    }
    if (val !== null && typeof val === "object") {
      const result: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(val)) {
        result[k] = this.sanitizeObject(v, sessionId);
      }
      return result;
    }
    return val;
  }

  public sanitizeText(
    text: string,
    sessionId: string,
  ): { sanitized: string; tokenMap: Record<string, string> } {
    if (typeof text !== "string") {
      return { sanitized: text, tokenMap: {} };
    }

    if (!this._sessionMaps.has(sessionId)) {
      this._sessionMaps.set(sessionId, new Map());
      this._entityMaps.set(sessionId, new Map());
    }

    const tokenMap = this._sessionMaps.get(sessionId)!;
    const entityMap = this._entityMaps.get(sessionId)!;
    let sanitized = text;

    for (const entityType of this.enabledEntities) {
      const pattern = ZTDS_PATTERNS[entityType];
      if (!pattern) {
        continue;
      }

      if (entityType === "EMAIL" && !sanitized.includes("@")) {
        continue;
      }

      const regex = new RegExp(pattern.source, "g");
      sanitized = sanitized.replace(regex, (match) => {
        if (entityMap.has(match)) {
          return entityMap.get(match)!;
        }

        const token = this._generateToken(entityType, tokenMap);
        tokenMap.set(token, match);
        entityMap.set(match, token);
        return token;
      });
    }

    const exportedMap: Record<string, string> = {};
    for (const [k, v] of tokenMap.entries()) {
      exportedMap[k] = v;
    }
    return { sanitized, tokenMap: exportedMap };
  }

  public wrapTool<TArgs, TResult extends Record<string, unknown> | string>(
    _toolName: string,
    handler: (args: TArgs, context: ZTDSContext) => Promise<TResult>,
  ): (args: TArgs, context?: ZTDSContext) => Promise<ZTDSToolResult<TResult>> {
    return async (
      args: TArgs,
      context?: ZTDSContext,
    ): Promise<ZTDSToolResult<TResult>> => {
      const sessionId =
        context?.sessionId ||
        `mcp-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;

      const enrichedContext: ZTDSContext = {
        ...context,
        sessionId,
        unmask: (val: unknown) => this.restoreObject(val, sessionId),
      };

      try {
        let processedArgs = args;
        if (this.sanitizeInputs && args !== undefined && args !== null) {
          processedArgs = this.sanitizeObject(args, sessionId) as TArgs;
        }

        const rawResult = await handler(processedArgs, enrichedContext);

        let finalResult: unknown = rawResult;
        if (
          this.sanitizeOutputs &&
          rawResult !== undefined &&
          rawResult !== null
        ) {
          if (typeof rawResult === "string") {
            finalResult = this.sanitizeText(rawResult, sessionId).sanitized;
          } else if (
            typeof rawResult === "object" &&
            Array.isArray((rawResult as { content?: unknown[] }).content)
          ) {
            const mcpObj = rawResult as {
              content: Array<{
                [key: string]: unknown;
                text?: string;
                type?: string;
              }>;
            };
            finalResult = {
              ...mcpObj,
              content: mcpObj.content.map((block) => {
                if (
                  block &&
                  block.type === "text" &&
                  typeof block.text === "string"
                ) {
                  return {
                    ...block,
                    text: this.sanitizeText(block.text, sessionId).sanitized,
                  };
                }
                return block;
              }),
            };
          } else {
            finalResult = this.sanitizeObject(rawResult, sessionId);
          }
        }

        const ztdsMeta: ZTDSMetadata = {
          sessionId,
          standard: "IETF draft-sibiryakov-ztds-protocol-00",
          zeroEgress: true,
        };

        if (typeof finalResult === "string") {
          return {
            _ztds: ztdsMeta,
            content: [{ text: finalResult, type: "text" }],
          } as unknown as ZTDSToolResult<TResult>;
        }

        if (
          finalResult !== null &&
          typeof finalResult === "object" &&
          !Array.isArray(finalResult)
        ) {
          return {
            ...finalResult,
            _ztds: ztdsMeta,
          } as unknown as ZTDSToolResult<TResult>;
        }

        return {
          _ztds: ztdsMeta,
          result: finalResult,
        } as unknown as ZTDSToolResult<TResult>;
      } finally {
        if (this.autoZeroize) {
          this.zeroizeSession(sessionId);
        }
      }
    };
  }

  public zeroizeSession(sessionId: string): void {
    if (this._sessionMaps.has(sessionId)) {
      this._sessionMaps.get(sessionId)!.clear();
      this._sessionMaps.delete(sessionId);
    }
    if (this._entityMaps.has(sessionId)) {
      this._entityMaps.get(sessionId)!.clear();
      this._entityMaps.delete(sessionId);
    }
  }

  private _generateToken(
    entityType: string,
    tokenMap: Map<string, string>,
  ): string {
    if (this.useCryptoTokens) {
      for (let i = 0; i < 100; i++) {
        const hex = crypto.randomBytes(4).toString("hex");
        const candidate = `[${entityType}_TOKEN_${hex}]`;
        if (!tokenMap.has(candidate)) {
          return candidate;
        }
      }
    }

    let count = 0;
    for (const k of tokenMap.keys()) {
      if (k.startsWith(`[${entityType}_TOKEN_`)) {
        count++;
      }
    }
    return `[${entityType}_TOKEN_${count + 1}]`;
  }
}
