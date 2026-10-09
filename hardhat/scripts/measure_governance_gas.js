// Gas for quorum-governed revocation on the Hardhat EVM.  USE_SOLCJS=1 npx hardhat run scripts/measure_governance_gas.js
const { ethers } = require("hardhat");
const fs = require("fs"), path = require("path");
const abi = ethers.AbiCoder.defaultAbiCoder();

async function regDevice(registry, deployer, i) {
  const dev = ethers.Wallet.createRandom();
  const pk = ethers.keccak256(dev.publicKey), ah = ethers.keccak256(ethers.toUtf8Bytes("fw:" + i));
  const mh = ethers.keccak256(abi.encode(["bytes32", "bytes32", "string", "address"], [pk, ah, "sensor", deployer.address]));
  await (await registry.registerDevice(pk, ah, "sensor", await dev.signMessage(ethers.getBytes(mh)), dev.address)).wait();
  return ethers.solidityPackedKeccak256(["string", "bytes32"], ["did:iot:", pk]);
}

async function main() {
  const signers = await ethers.getSigners();
  const deployer = signers[0];
  const out = [];
  for (const N of [5, 7, 9, 11, 15, 21]) {
    const q = Math.floor(N / 2) + 1;
    const registry = await (await ethers.getContractFactory("IdentityRegistry")).deploy();
    await registry.waitForDeployment();
    const voters = signers.slice(1, 1 + N);
    const gov = await (await ethers.getContractFactory("RevocationGovernance")).deploy(await registry.getAddress(), voters.map(v => v.address), q);
    const dRc = await gov.deploymentTransaction().wait();
    await (await registry.setRegistrar(await gov.getAddress(), true)).wait();
    const did = await regDevice(registry, deployer, N);
    const g = gov.connect(voters[0]);
    const prc = await (await g.propose(did, "key_compromise")).wait();
    const pid = prc.logs.map(l => { try { return gov.interface.parseLog(l); } catch { return null; } }).find(x => x && x.name === "ProposalCreated").args[0];
    const votes = [];
    for (let i = 0; i < q; i++) votes.push(Number((await (await gov.connect(voters[i]).castVote(pid, true)).wait()).gasUsed));
    const status = await registry.getStatus(did);               // expect 3 = REVOKED
    out.push({ N, quorum: q, deploy_gas: Number(dRc.gasUsed), propose_gas: Number(prc.gasUsed),
               first_vote_gas: votes[0], final_vote_gas_incl_revocation: votes[votes.length - 1],
               total_gas_to_revoke: Number(prc.gasUsed) + votes.reduce((a, b) => a + b, 0), revoked: Number(status) === 3 });
    console.log(out[out.length - 1]);
  }
  fs.writeFileSync(path.join(__dirname, "..", "..", "results", "evm_governance_gas.json"), JSON.stringify(out, null, 2));
}
main().catch(e => { console.error(e); process.exit(1); });
