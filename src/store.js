// Agent state: the proof_tx seen-set (PROOF_REUSED detection) plus an
// idempotency cache of task_id -> response body (task IDs are idempotency
// keys; the platform may retry a delivery — PROTOCOL.md §1).
//
// Interface (all methods may be sync or async; the core awaits them):
//   hasSeen(proofTx)            -> boolean
//   addSeen(proofTx)            -> void
//   getResponse(taskId)         -> string | undefined   (raw response body)
//   putResponse(taskId, body)   -> void
//
// MemoryStore: tests and the Worker fallback (state lost on restart — for
//   the Worker this degrades PROOF_REUSED detection across restarts; use
//   KVStore in production, see NOTES.md).
// FileStore: Node persistence to a JSON file (default ./data/seen.json).
// KVStore: Cloudflare KV binding (env.SEEN_KV).

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

const MAX_CACHED_RESPONSES = 500;

export class MemoryStore {
  constructor() {
    this.seen = new Set();
    this.responses = new Map();
  }
  hasSeen(proofTx) {
    return this.seen.has(proofTx);
  }
  addSeen(proofTx) {
    this.seen.add(proofTx);
  }
  getResponse(taskId) {
    return this.responses.get(taskId);
  }
  putResponse(taskId, body) {
    this.responses.set(taskId, body);
    if (this.responses.size > MAX_CACHED_RESPONSES) {
      // Evict oldest insertions (Map preserves insertion order).
      const oldest = this.responses.keys().next().value;
      this.responses.delete(oldest);
    }
  }
}

export class FileStore extends MemoryStore {
  constructor(filePath) {
    super();
    this.filePath = filePath;
    if (existsSync(filePath)) {
      try {
        const data = JSON.parse(readFileSync(filePath, "utf8"));
        for (const tx of data.seen ?? []) this.seen.add(tx);
        for (const [k, v] of Object.entries(data.responses ?? {})) {
          this.responses.set(k, v);
        }
      } catch {
        // Corrupt state file: start fresh rather than crash. Losing the
        // seen-set only degrades PROOF_REUSED detection until it rebuilds.
        console.error(`[store] ignoring unreadable state file: ${filePath}`);
      }
    }
  }
  _persist() {
    mkdirSync(dirname(this.filePath), { recursive: true });
    writeFileSync(
      this.filePath,
      JSON.stringify({
        seen: [...this.seen],
        responses: Object.fromEntries(this.responses),
      }),
    );
  }
  addSeen(proofTx) {
    super.addSeen(proofTx);
    this._persist();
  }
  putResponse(taskId, body) {
    super.putResponse(taskId, body);
    this._persist();
  }
}

export class KVStore {
  constructor(kv) {
    if (!kv) throw new Error("KVStore needs a KV namespace binding");
    this.kv = kv;
  }
  async hasSeen(proofTx) {
    return (await this.kv.get(`seen:${proofTx}`)) !== null;
  }
  async addSeen(proofTx) {
    await this.kv.put(`seen:${proofTx}`, "1");
  }
  async getResponse(taskId) {
    return (await this.kv.get(`resp:${taskId}`)) ?? undefined;
  }
  async putResponse(taskId, body) {
    await this.kv.put(`resp:${taskId}`, body);
  }
}
