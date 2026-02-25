import { poseidonHasher, FieldElement } from "./poseidon";

const TREE_DEPTH = 8;
const TREE_SIZE = 2 ** TREE_DEPTH; // 256

export class MerkleTree {
    private leaves: FieldElement[] = [];
    private zeroLeaf!: FieldElement;
    private layers: FieldElement[][] = [];

    constructor() { }

    async init(zeroInputs: FieldElement[] = [0n, 0n, 0n, 0n]) {
        await poseidonHasher.init();
        this.zeroLeaf = poseidonHasher.hash(zeroInputs);
        this.leaves = new Array(TREE_SIZE).fill(this.zeroLeaf);
    }

    setLeaf(index: number, leaf: FieldElement) {
        if (index < 0 || index >= TREE_SIZE) throw new Error("Index out of bounds");
        this.leaves[index] = leaf;
        this.layers = []; // invalidate cache
    }

    build() {
        this.layers = [this.leaves.slice()];
        let current = this.leaves.slice();

        for (let d = 0; d < TREE_DEPTH; d++) {
            const next: FieldElement[] = [];
            for (let i = 0; i < current.length; i += 2) {
                next.push(poseidonHasher.hash([current[i], current[i + 1]]));
            }
            this.layers.push(next);
            current = next;
        }
        return current[0];
    }

    get root(): FieldElement {
        if (this.layers.length === 0) this.build();
        return this.layers[TREE_DEPTH][0];
    }

    generateProof(index: number): { pathElements: FieldElement[]; pathIndices: number[] } {
        if (this.layers.length === 0) this.build();

        const pathElements: FieldElement[] = [];
        const pathIndices: number[] = [];
        let cur = index;

        for (let d = 0; d < TREE_DEPTH; d++) {
            const isRight = cur % 2 === 1;
            pathIndices.push(isRight ? 1 : 0);
            pathElements.push(this.layers[d][isRight ? cur - 1 : cur + 1]);
            cur = Math.floor(cur / 2);
        }

        return { pathElements, pathIndices };
    }
}
