// Groth16 proving for the gatekeeper circuit — pluggable implementations
// behind one interface:
//
//   prover.prove(circuitInput) -> { proof, publicSignals }
//     circuitInput:  { inputName: decimalString, ... } (includes salt)
//     proof:         snarkjs Groth16 proof object
//     publicSignals: array of 13 decimal strings, output-then-public order
//
// CliProver (Node, local + any VPS): shells out to the snarkjs CLI.
//   This is the measured-fast path on the research VM (~1.3 s per proof).
//   NOTE: snarkjs's in-process groth16.fullProve HUNG on that VM (>3 min,
//   killed), which is why the Node path must NOT use the library in-process.
//
// SnarkjsProver (Cloudflare Worker): in-process snarkjs. Proving inside a
//   Worker is UNVERIFIED for this circuit — see NOTES.md (CPU-time limits,
//   artifact size, ffjavascript threading). It exists so the Worker entry can
//   be wired today and swapped if practice mode shows it cannot keep up;
//   the core never knows which prover it holds.

import * as snarkjs from "snarkjs";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export class CliProver {
  constructor({ wasmPath, zkeyPath, snarkjsBin = "snarkjs", timeoutMs = 45_000 } = {}) {
    if (!wasmPath || !zkeyPath) {
      throw new Error("CliProver needs wasmPath and zkeyPath");
    }
    this.wasmPath = wasmPath;
    this.zkeyPath = zkeyPath;
    this.snarkjsBin = snarkjsBin;
    this.timeoutMs = timeoutMs;
  }

  async prove(circuitInput) {
    const dir = await mkdtemp(join(tmpdir(), "gk-proof-"));
    const inputPath = join(dir, "input.json");
    const proofPath = join(dir, "proof.json");
    const publicPath = join(dir, "public.json");
    try {
      await writeFile(inputPath, JSON.stringify(circuitInput));
      await execFileAsync(
        this.snarkjsBin,
        [
          "groth16",
          "fullprove",
          inputPath,
          this.wasmPath,
          this.zkeyPath,
          proofPath,
          publicPath,
        ],
        { timeout: this.timeoutMs, maxBuffer: 16 * 1024 * 1024 },
      );
      const [proofRaw, publicRaw] = await Promise.all([
        readFile(proofPath, "utf8"),
        readFile(publicPath, "utf8"),
      ]);
      return { proof: JSON.parse(proofRaw), publicSignals: JSON.parse(publicRaw) };
    } finally {
      await rm(dir, { recursive: true, force: true }).catch(() => {});
    }
  }
}

export class SnarkjsProver {
  /**
   * @param wasm  Uint8Array | ArrayBuffer of gatekeeper.wasm
   * @param zkey  Uint8Array | ArrayBuffer of gatekeeper_final.zkey
   */
  constructor({ wasm, zkey } = {}) {
    if (!wasm || !zkey) {
      throw new Error(
        "SnarkjsProver needs the circuit artifacts as bytes (wasm, zkey). " +
          "In a Worker, supply them from the deployment's blob imports — see NOTES.md.",
      );
    }
    // Normalize to Uint8Array: Cloudflare data-module imports hand us an
    // ArrayBuffer, and snarkjs's FastFile layer rejects a bare ArrayBuffer
    // ("Invalid FastFile type: undefined", found live 2026-11-15).
    this.wasm = wasm instanceof ArrayBuffer ? new Uint8Array(wasm) : wasm;
    this.zkey = zkey instanceof ArrayBuffer ? new Uint8Array(zkey) : zkey;
  }

  async prove(circuitInput) {
    // snarkjs is imported statically at the top of this module: a dynamic
    // import("snarkjs") is NOT inlined by the Worker bundler and fails at
    // runtime inside Cloudflare Workers (found live 2026-11-15 via a debug
    // deployment — the static import bundles and runs in both runtimes).
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInput,
      this.wasm,
      this.zkey,
    );
    return { proof, publicSignals };
  }
}

/**
 * Pick a prover for the current runtime.
 *   runtime "node"   -> CliProver (needs wasmPath/zkeyPath file paths)
 *   runtime "worker" -> SnarkjsProver (needs wasm/zkey bytes)
 */
export function createProver(runtime, opts = {}) {
  if (runtime === "worker") return new SnarkjsProver(opts);
  return new CliProver(opts);
}
