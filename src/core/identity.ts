import { poseidonHasher, FieldElement } from "./poseidon";

/**
 * Derives the public commitment from the identity secret.
 * publicCommitment = Poseidon(identitySecret)
 */
export async function derivePublicCommitment(identitySecret: FieldElement): Promise<FieldElement> {
    await poseidonHasher.init();
    return poseidonHasher.hash([identitySecret]);
}
