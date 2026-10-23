/**
 * Canonical CBOR encoder for Atlas signed objects.
 *
 * Rules (must match `alp-grid-core::canon` byte for byte):
 * - maps keep insertion order (declaration order of the spec), text keys;
 * - integers in shortest form (number or bigint), floats are refused;
 * - Uint8Array -> byte string; string -> text string; null -> null; boolean -> true/false;
 * - arrays -> definite-length arrays.
 */

export type CborValue = null | boolean | number | bigint | string | Uint8Array | CborValue[] | { [key: string]: CborValue };

function head(major: number, len: number | bigint, out: number[]): void {
  const m = major << 5;
  const n = typeof len === "bigint" ? len : BigInt(len);
  if (n < 24n) out.push(m | Number(n));
  else if (n < 0x100n) out.push(m | 24, Number(n));
  else if (n < 0x10000n) out.push(m | 25, Number(n >> 8n), Number(n & 0xffn));
  else if (n < 0x1_0000_0000n) out.push(m | 26, Number(n >> 24n) & 0xff, Number(n >> 16n) & 0xff, Number(n >> 8n) & 0xff, Number(n & 0xffn));
  else {
    out.push(m | 27);
    for (let i = 7; i >= 0; i--) out.push(Number((n >> BigInt(i * 8)) & 0xffn));
  }
}

function encodeInto(v: CborValue, out: number[]): void {
  if (v === null) {
    out.push(0xf6);
  } else if (v === true) {
    out.push(0xf5);
  } else if (v === false) {
    out.push(0xf4);
  } else if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new Error("floats are not allowed in signed objects");
    if (v < 0) {
      head(1, -1 - v, out);
    } else head(0, v, out);
  } else if (typeof v === "bigint") {
    if (v < 0n) head(1, -1n - v, out);
    else head(0, v, out);
  } else if (typeof v === "string") {
    const bytes = new TextEncoder().encode(v);
    head(3, bytes.length, out);
    for (const b of bytes) out.push(b);
  } else if (v instanceof Uint8Array) {
    head(2, v.length, out);
    for (const b of v) out.push(b);
  } else if (Array.isArray(v)) {
    head(4, v.length, out);
    for (const x of v) encodeInto(x, out);
  } else if (typeof v === "object") {
    const keys = Object.keys(v);
    head(5, keys.length, out);
    for (const k of keys) {
      encodeInto(k, out);
      encodeInto(v[k], out);
    }
  } else {
    throw new Error(`cannot encode ${typeof v}`);
  }
}

export function encode(v: CborValue): Uint8Array {
  const out: number[] = [];
  encodeInto(v, out);
  return new Uint8Array(out);
}
