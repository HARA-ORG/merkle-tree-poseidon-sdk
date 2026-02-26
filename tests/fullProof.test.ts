import { ZkIdentitySDK } from "../src/sdk";
import { UserField } from "../src/sdk";
import { poseidonHasher } from "../src/core/poseidon";

async function runTest() {
    console.log("Starting Full Proof Test...");
    await poseidonHasher.init();

    const fields: UserField[] = [
        { label: "name", type: "text", value: "Alice Doe" },
        { label: "email", type: "email", value: "alice@example.com" },
        { label: "birthDate", type: "date", value: 1672531199 },
        { label: "idNumber", type: "number", value: 123456789 },
    ];

    const sdk = new ZkIdentitySDK(fields);

    // 1. Build Merkle Tree
    const salt = 987654321n;
    const root = await sdk.build(salt);
    console.log("Merkle Root built:", root.toString());

    // 2. Generate Proof Input for selective disclosure of "email"
    const identitySecret = 12345n;
    const publicCommitment = poseidonHasher.hash([identitySecret]);

    const proofInput = await sdk.generateProofInput({
        label: "email",
        identitySecret,
        publicCommitment,
    });
    console.log("Proof Input ready.");

    // 3. Setup paths to artifacts


    // 4. Generate ZK Proof
    console.log("Generating full proof...");
    const { proof, publicSignals } = await ZkIdentitySDK.generateFullProof(
        proofInput,
    );
    console.log("Proof generated successfully.");

    // 5. Verify ZK Proof
    console.log("Verifying proof...");
    const isValid = await ZkIdentitySDK.verifyProof(publicSignals, proof);

    if (isValid) {
        console.log("✅ Proof verification SUCCESSFUL!");
        process.exit(0);
    } else {
        console.error("❌ Proof verification FAILED!");
        process.exit(1);
    }
}

runTest().catch((err) => {
    console.error("Error during test:", err);
    process.exit(1);
});
