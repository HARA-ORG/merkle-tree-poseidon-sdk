import { MerkleTree } from "../src/core/tree";
import { poseidonHasher } from "../src/core/poseidon";
import { FieldElement } from "../src/core/fields";

async function runTreeTests() {
    console.log("━━━ Merkle Tree Unit Tests ━━━\n");

    // Initialize Poseidon
    await poseidonHasher.init();

    const tree = new MerkleTree();
    await tree.init();

    console.log("--- Test 1: Empty Tree Root ---");
    const emptyRoot = tree.root;
    console.log(`Empty Tree Root: ${emptyRoot}`);

    // Manual verification of empty root
    // Depth is 8, so it's 8 levels of hashing zeroLeaf
    let expectedEmptyRoot = poseidonHasher.hash([0n, 0n, 0n, 0n]);
    for (let i = 0; i < 8; i++) {
        expectedEmptyRoot = poseidonHasher.hash([expectedEmptyRoot, expectedEmptyRoot]);
    }

    if (emptyRoot === expectedEmptyRoot) {
        console.log("✅ Empty Root match expected value.\n");
    } else {
        console.error(`❌ Empty Root MISMATCH! Expected: ${expectedEmptyRoot}\n`);
        process.exit(1);
    }

    console.log("--- Test 2: Single Leaf Root ---");
    const leafIndex = 0;
    const leafValue = 123456789n;
    tree.setLeaf(leafIndex, leafValue);
    const rootWithOneLeaf = tree.root;
    console.log(`Root with one leaf at index 0: ${rootWithOneLeaf}\n`);

    console.log("--- Test 3: Proof Generation & Verification ---");
    const proof = tree.generateProof(leafIndex);
    console.log(`Generated proof for index ${leafIndex}:`);
    console.log(`Path Elements: ${proof.pathElements}`);
    console.log(`Path Indices:  ${proof.pathIndices}`);

    // Verify proof manually (simulating circuit logic)
    let current = leafValue;
    for (let i = 0; i < proof.pathElements.length; i++) {
        const element = proof.pathElements[i];
        const isRight = proof.pathIndices[i] === 1;
        if (isRight) {
            current = poseidonHasher.hash([element, current]);
        } else {
            current = poseidonHasher.hash([current, element]);
        }
    }

    if (current === rootWithOneLeaf) {
        console.log("✅ Proof verification PASSED.\n");
    } else {
        console.error(`❌ Proof verification FAILED! Result: ${current}\n`);
        process.exit(1);
    }

    console.log("--- Test 4: Multiple Leaves ---");
    const indices = [1, 5, 10, 255];
    const values = [999n, 888n, 777n, 666n];

    for (let i = 0; i < indices.length; i++) {
        tree.setLeaf(indices[i], values[i]);
    }

    const finalRoot = tree.root;
    console.log(`Final Root with multiple leaves: ${finalRoot}`);

    for (let i = 0; i < indices.length; i++) {
        const idx = indices[i];
        const val = values[i];
        const p = tree.generateProof(idx);

        let node = val;
        for (let j = 0; j < p.pathElements.length; j++) {
            const el = p.pathElements[j];
            const isR = p.pathIndices[j] === 1;
            node = isR ? poseidonHasher.hash([el, node]) : poseidonHasher.hash([node, el]);
        }

        if (node === finalRoot) {
            console.log(`✅ Proof for index ${idx} PASSED.`);
        } else {
            console.error(`❌ Proof for index ${idx} FAILED!`);
            process.exit(1);
        }
    }

    console.log("\n━━━ All Merkle Tree Tests PASSED ━━━");
}

runTreeTests().catch(e => {
    console.error(e);
    process.exit(1);
});
