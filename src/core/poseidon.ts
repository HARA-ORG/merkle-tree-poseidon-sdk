import { buildPoseidon } from "circomlibjs";

export type FieldElement = bigint;

class PoseidonHasher {
    private poseidon: any = null;
    private F: any = null;

    async init() {
        if (!this.poseidon) {
            this.poseidon = await buildPoseidon();
            this.F = this.poseidon.F;
        }
    }

    hash(inputs: FieldElement[]): FieldElement {
        if (!this.poseidon) throw new Error("Call init() first");
        return this.F.toObject(this.poseidon(inputs.map((x) => this.F.e(x)))) as bigint;
    }
}

export const poseidonHasher = new PoseidonHasher();
