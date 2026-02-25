import { MerkleTree } from "../core/tree";
import { poseidonHasher } from "../core/poseidon";
import {
    stringToField,
    dateToField,
    CredentialType,
    FieldElement
} from "../core/fields";

export interface UserField {
    label: string;
    type: "text" | "email" | "number" | "date" | "attachment" | "long_text";
    value: string | number | bigint;
    required?: boolean;
}

export interface SDKProofInput {
    key: string;
    typ: string;
    value: string;
    salt: string;
    pathElements: string[];
    pathIndices: number[];
    identitySecret: string;
    credentialRoot: string;
    publicCommitment: string;
    threshold: string;
    expectedValueHash: string;
}

export class ZkIdentitySDK {
    private tree: MerkleTree;
    private fields: UserField[];
    private salt: FieldElement | null = null;

    constructor(fields: UserField[]) {
        this.fields = fields;
        this.tree = new MerkleTree();
    }

    /**
     * Encodes a user-friendly field value into a BN254 field element.
     */
    private encodeValue(type: string, value: any): FieldElement {
        if (typeof value === "bigint") return value;
        if (typeof value === "number") return BigInt(value);

        switch (type) {
            case "date":
                return dateToField(value);
            case "number":
                return BigInt(value);
            default:
                return stringToField(value);
        }
    }

    /**
     * Builds the Merkle Tree using the provided salt.
     * Indices are auto-generated based on the order in the constructor.
     */
    async build(salt: FieldElement): Promise<FieldElement> {
        this.salt = salt;
        await this.tree.init();

        for (let i = 0; i < this.fields.length; i++) {
            const field = this.fields[i];
            const key = stringToField(field.label);
            const typ = CredentialType[field.type.toUpperCase() as keyof typeof CredentialType];
            const val = this.encodeValue(field.type, field.value);

            // leaf = Poseidon(key, typ, value, salt)
            const leaf = poseidonHasher.hash([key, typ, val, salt]);
            this.tree.setLeaf(i, leaf);
        }

        return this.tree.build();
    }

    get root(): FieldElement {
        return this.tree.root;
    }

    /**
     * Generates a raw Merkle proof for a specific field (by label).
     */
    async generateMerkleProof(label: string): Promise<{ pathElements: string[], pathIndices: number[] }> {
        const index = this.fields.findIndex(f => f.label === label);
        if (index === -1) throw new Error(`Field with label "${label}" not found`);

        const { pathElements, pathIndices } = this.tree.generateProof(index);
        return {
            pathElements: pathElements.map(x => x.toString()),
            pathIndices
        };
    }

    /**
     * Generates the input for a ZK proof for a specific field (by label).
     */
    async generateProofInput(params: {
        label: string;
        identitySecret: FieldElement;
        publicCommitment: FieldElement;
        threshold?: FieldElement;
    }): Promise<SDKProofInput> {
        if (this.salt === null) throw new Error("Call build(salt) first");

        const index = this.fields.findIndex(f => f.label === params.label);
        if (index === -1) throw new Error(`Field with label "${params.label}" not found`);

        const field = this.fields[index];
        const key = stringToField(field.label);
        const typ = CredentialType[field.type.toUpperCase() as keyof typeof CredentialType];
        const val = this.encodeValue(field.type, field.value);

        const { pathElements, pathIndices } = this.tree.generateProof(index);

        // Compute expectedValueHash for string/equality types
        let expectedValueHash = 0n;
        const isNumeric = field.type === "number" || field.type === "date";
        if (!isNumeric) {
            expectedValueHash = poseidonHasher.hash([val]);
        }

        return {
            key: key.toString(),
            typ: typ.toString(),
            value: val.toString(),
            salt: this.salt.toString(),
            pathElements: pathElements.map(x => x.toString()),
            pathIndices,
            identitySecret: params.identitySecret.toString(),
            credentialRoot: this.tree.root.toString(),
            publicCommitment: params.publicCommitment.toString(),
            threshold: (params.threshold ?? 0n).toString(),
            expectedValueHash: expectedValueHash.toString(),
        };
    }
}
