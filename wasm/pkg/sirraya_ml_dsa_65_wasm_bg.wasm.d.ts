/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const create_did: (a: number, b: number) => [number, number];
export const extract_pk_from_did: (a: number, b: number) => [number, number];
export const generate_keypair: () => [number, number];
export const jcs_canonicalize_proof_config: (a: number, b: number) => [number, number];
export const jcs_canonicalize_unsigned_vc: (a: number, b: number) => [number, number];
export const sign: (a: number, b: number, c: number, d: number) => [number, number];
export const sign_vc_proof: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
export const verify: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
export const verify_vc_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => number;
export const __wbindgen_exn_store: (a: number) => void;
export const __externref_table_alloc: () => number;
export const __wbindgen_externrefs: WebAssembly.Table;
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __wbindgen_start: () => void;
