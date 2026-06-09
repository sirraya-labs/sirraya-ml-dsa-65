/* tslint:disable */
/* eslint-disable */

export function create_did(public_key_hex: string): string;

export function extract_pk_from_did(did: string): string;

export function generate_keypair(): string;

export function jcs_canonicalize_proof_config(vc_json: string): string;

export function jcs_canonicalize_unsigned_vc(vc_json: string): string;

export function sign(secret_key_hex: string, message: string): string;

export function sign_vc_proof(secret_key_hex: string, canonical_vc: string, canonical_proof: string): string;

export function verify(public_key_hex: string, message: string, signature_hex: string): boolean;

export function verify_vc_proof(public_key_hex: string, canonical_vc: string, canonical_proof: string, signature_hex: string): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly create_did: (a: number, b: number) => [number, number];
    readonly extract_pk_from_did: (a: number, b: number) => [number, number];
    readonly generate_keypair: () => [number, number];
    readonly jcs_canonicalize_proof_config: (a: number, b: number) => [number, number];
    readonly jcs_canonicalize_unsigned_vc: (a: number, b: number) => [number, number];
    readonly sign: (a: number, b: number, c: number, d: number) => [number, number];
    readonly sign_vc_proof: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
    readonly verify: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
    readonly verify_vc_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
