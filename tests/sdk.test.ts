import { ZkIdentitySDK } from "../src/sdk";
import { poseidonHasher } from "../src/core/poseidon";
import { createHash } from "crypto";
import { CredentialType, stringToField } from "../src/core/fields";

async function runSimulation() {
    console.log("━━━ SDK Logic Simulation (Circom Logic) ━━━\n");

    // Initialize Poseidon
    await poseidonHasher.init();

    // 1. Setup Prover state
    const identitySecret = BigInt("0x" + createHash("sha256").update("alice-secret-key").digest("hex"));
    const publicCommitment = poseidonHasher.hash([identitySecret]);

    const fields = [
        { label: "full_name", type: "text" as const, value: "Alice Wanderer" },
        { label: "email", type: "email" as const, value: "alice@example.com" },
        { label: "credit_score", type: "number" as const, value: 750 },
        { label: "Expiry Date", type: "date" as const, value: "2026-12-31" }
    ];

    const sdk = new ZkIdentitySDK(fields);
    const salt = BigInt(987654321);
    const root = await sdk.build(salt);

    console.log("Prover state initialized.");
    console.log(`Merkle Root: ${root}`);
    console.log(`Public Commitment: ${publicCommitment}\n`);

    // 2. Simulate Selective Disclosure for "credit_score" (Numeric)
    console.log("--- Simulating Numeric Disclosure (credit_score >= 700) ---");
    const threshold = 700n;
    const numericInput = await sdk.generateProofInput({
        label: "credit_score",
        identitySecret,
        publicCommitment,
        threshold
    });

    // Simulated Circuit Verification Logic
    const isVerifiedNumeric = await simulateCircuit(numericInput);
    console.log(`Simulation Result: ${isVerifiedNumeric ? "✅ PASSED" : "❌ FAILED"}\n`);

    // 3. Simulate Selective Disclosure for "email" (String Equality)
    console.log("--- Simulating String Equality Disclosure (email) ---");
    const emailInput = await sdk.generateProofInput({
        label: "email",
        identitySecret,
        publicCommitment
    });

    // Simulated Circuit Verification Logic
    const isVerifiedString = await simulateCircuit(emailInput);
    console.log(`Simulation Result: ${isVerifiedString ? "✅ PASSED" : "❌ FAILED"}\n`);

    console.log("━━━ All Simulations Complete ━━━");
}

/**
 * Simulates the SelectiveDisclosure.circom logic in TypeScript.
 */
async function simulateCircuit(input: any): Promise<boolean> {
    const {
        key,
        typ,
        value,
        salt,
        pathElements,
        pathIndices,
        identitySecret,
        credentialRoot,
        publicCommitment,
        threshold,
        expectedValueHash
    } = input;

    const bKey = BigInt(key);
    const bTyp = BigInt(typ);
    const bValue = BigInt(value);
    const bSalt = BigInt(salt);
    const bIdentitySecret = BigInt(identitySecret);
    const bCredentialRoot = BigInt(credentialRoot);
    const bPublicCommitment = BigInt(publicCommitment);
    const bThreshold = BigInt(threshold);
    const bExpectedValueHash = BigInt(expectedValueHash);

    // 1. IDENTITY BINDING
    const computedCommitment = poseidonHasher.hash([bIdentitySecret]);
    if (computedCommitment !== bPublicCommitment) {
        console.error("❌ Simulation: Identity Binding failed");
        return false;
    }

    // 2. LEAF CONSTRUCTION
    const leaf = poseidonHasher.hash([bKey, bTyp, bValue, bSalt]);

    // 3. MERKLE ROOT VERIFICATION
    let current = leaf;
    for (let i = 0; i < pathElements.length; i++) {
        const element = BigInt(pathElements[i]);
        const index = pathIndices[i];
        if (index === 0) {
            current = poseidonHasher.hash([current, element]);
        } else {
            current = poseidonHasher.hash([element, current]);
        }
    }

    if (current !== bCredentialRoot) {
        console.error("❌ Simulation: Merkle Proof failed");
        return false;
    }

    // 4. TYPE ROUTING
    const isNumeric = bTyp === 2n || bTyp === 3n; // NUMBER=2, DATE=3

    if (isNumeric) {
        // 4a. NUMERIC CHECK
        if (bValue < bThreshold) {
            console.error(`❌ Simulation: Numeric check failed (${bValue} < ${bThreshold})`);
            return false;
        }
    } else {
        // 4b. HASH EQUALITY CHECK
        const valueHash = poseidonHasher.hash([bValue]);
        if (valueHash !== bExpectedValueHash) {
            console.error("❌ Simulation: Hash equality failed");
            return false;
        }
    }

    return true;
}

runSimulation().catch(console.error);
