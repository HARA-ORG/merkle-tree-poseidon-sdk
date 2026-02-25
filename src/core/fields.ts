import { createHash } from "crypto";

export type FieldElement = bigint;

export const CredentialType = {
    TEXT: 0n,
    EMAIL: 1n,
    NUMBER: 2n,
    DATE: 3n,
    ATTACHMENT: 4n,
    LONG_TEXT: 5n,
} as const;

export interface CredentialField {
    key: FieldElement;    // Numeric label identifier
    typ: FieldElement;    // CredentialType value
    value: FieldElement;  // The credential value
}

export function stringToField(input: string): FieldElement {
    const BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    const bytes = Buffer.from(input, "utf8");
    if (bytes.length <= 30) {
        return BigInt("0x" + bytes.toString("hex")) % BN254_PRIME;
    }
    const digest = createHash("sha256").update(bytes).digest();
    digest[0] &= 0x1f; // 253-bit truncation
    return BigInt("0x" + digest.toString("hex")) % BN254_PRIME;
}

export function dateToField(dateStr: string): FieldElement {
    const clean = dateStr.replace(/-/g, "");
    if (!/^\d{8}$/.test(clean)) throw new Error(`Invalid date: ${dateStr}`);
    return BigInt(clean);
}
