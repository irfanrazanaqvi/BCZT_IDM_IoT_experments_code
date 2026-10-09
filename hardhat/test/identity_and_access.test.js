const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("IdentityRegistry + ZeroTrustAccess", function () {
  let registry, zta, deployer, oracle, device, resourceId;

  beforeEach(async function () {
    [deployer, oracle] = await ethers.getSigners();
    device = ethers.Wallet.createRandom();

    const IdentityRegistry = await ethers.getContractFactory("IdentityRegistry");
    registry = await IdentityRegistry.deploy();
    await registry.waitForDeployment();

    const ZeroTrustAccess = await ethers.getContractFactory("ZeroTrustAccess");
    zta = await ZeroTrustAccess.deploy(await registry.getAddress(), oracle.address);
    await zta.waitForDeployment();

    resourceId = ethers.id("telemetry.write");
    await (await zta.definePolicy(resourceId, 5500, 1500, 300, 10000, false, ["sensor"])).wait();
  });

  async function registerDevice() {
    const pubKeyHash = ethers.keccak256(device.publicKey);
    const attributeHash = ethers.keccak256(ethers.toUtf8Bytes("fw:2.1"));
    const messageHash = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes32", "string", "address"],
        [pubKeyHash, attributeHash, "sensor", deployer.address]
      )
    );
    const signature = await device.signMessage(ethers.getBytes(messageHash));
    const tx = await registry.registerDevice(pubKeyHash, attributeHash, "sensor", signature, device.address);
    await tx.wait();
    return ethers.solidityPackedKeccak256(["string", "bytes32"], ["did:iot:", pubKeyHash]);
  }

  it("registers a device with a valid signature", async function () {
    const did = await registerDevice();
    expect(await registry.getStatus(did)).to.equal(1); // ACTIVE
  });

  it("rejects registration with a forged signature", async function () {
    const pubKeyHash = ethers.keccak256(device.publicKey);
    const attributeHash = ethers.keccak256(ethers.toUtf8Bytes("fw:2.1"));
    const badSignature = await oracle.signMessage(ethers.getBytes(ethers.randomBytes(32)));
    await expect(
      registry.registerDevice(pubKeyHash, attributeHash, "sensor", badSignature, device.address)
    ).to.be.reverted;
  });

  it("grants ALLOW for a high, oracle-signed trust score", async function () {
    const did = await registerDevice();
    const nonce = 1;
    const trustScoreBp = 9000;
    const scoreHash = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes32", "uint16", "uint16", "uint256"],
        [did, resourceId, trustScoreBp, 500, nonce]
      )
    );
    const oracleSig = await oracle.signMessage(ethers.getBytes(scoreHash));

    const effect = await zta.evaluateAccess.staticCall(did, resourceId, "sensor", trustScoreBp, 500, oracleSig, nonce);
    expect(effect).to.equal(2); // ALLOW
  });

  it("denies a replayed nonce", async function () {
    const did = await registerDevice();
    const nonce = 42;
    const trustScoreBp = 9000;
    const scoreHash = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes32", "uint16", "uint16", "uint256"],
        [did, resourceId, trustScoreBp, 500, nonce]
      )
    );
    const oracleSig = await oracle.signMessage(ethers.getBytes(scoreHash));

    await (await zta.evaluateAccess(did, resourceId, "sensor", trustScoreBp, 500, oracleSig, nonce)).wait();
    const effect = await zta.evaluateAccess.staticCall(did, resourceId, "sensor", trustScoreBp, 500, oracleSig, nonce);
    expect(effect).to.equal(0); // DENY (replay)
  });

  it("denies access for a revoked device", async function () {
    const did = await registerDevice();
    await (await registry.revokeDevice(did, "key_rotation")).wait();

    const nonce = 7;
    const trustScoreBp = 9000;
    const scoreHash = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes32", "uint16", "uint16", "uint256"],
        [did, resourceId, trustScoreBp, 500, nonce]
      )
    );
    const oracleSig = await oracle.signMessage(ethers.getBytes(scoreHash));
    const effect = await zta.evaluateAccess.staticCall(did, resourceId, "sensor", trustScoreBp, 500, oracleSig, nonce);
    expect(effect).to.equal(0); // DENY (not active)
  });
});

describe("RevocationGovernance (quorum-governed revocation)", function () {
  let registry, gov, deployer, voters, did;
  const abi = ethers.AbiCoder.defaultAbiCoder();
  beforeEach(async function () {
    const signers = await ethers.getSigners();
    deployer = signers[0]; voters = signers.slice(1, 6);
    registry = await (await ethers.getContractFactory("IdentityRegistry")).deploy();
    gov = await (await ethers.getContractFactory("RevocationGovernance")).deploy(await registry.getAddress(), voters.map(v => v.address), 3);
    await registry.setRegistrar(await gov.getAddress(), true);
    const dev = ethers.Wallet.createRandom();
    const pk = ethers.keccak256(dev.publicKey), ah = ethers.keccak256(ethers.toUtf8Bytes("fw"));
    const mh = ethers.keccak256(abi.encode(["bytes32", "bytes32", "string", "address"], [pk, ah, "sensor", deployer.address]));
    await registry.registerDevice(pk, ah, "sensor", await dev.signMessage(ethers.getBytes(mh)), dev.address);
    did = ethers.solidityPackedKeccak256(["string", "bytes32"], ["did:iot:", pk]);
  });
  async function propose() {
    const rc = await (await gov.connect(voters[0]).propose(did, "r")).wait();
    return rc.logs.map(l => { try { return gov.interface.parseLog(l); } catch { return null; } }).find(x => x && x.name === "ProposalCreated").args[0];
  }
  it("revokes only after the quorum of approvals", async function () {
    const pid = await propose();
    await gov.connect(voters[0]).castVote(pid, true); await gov.connect(voters[1]).castVote(pid, true);
    expect(await registry.getStatus(did)).to.equal(1);   // still ACTIVE with 2 of 3
    await gov.connect(voters[2]).castVote(pid, true);
    expect(await registry.getStatus(did)).to.equal(3);   // REVOKED
  });
  it("a minority of deny votes cannot block, and q-1 approvals cannot force", async function () {
    const pid = await propose();
    await gov.connect(voters[0]).castVote(pid, false); await gov.connect(voters[1]).castVote(pid, false);
    await gov.connect(voters[2]).castVote(pid, true); await gov.connect(voters[3]).castVote(pid, true);
    expect(await registry.getStatus(did)).to.equal(1);   // 2 approvals < q=3
    await gov.connect(voters[4]).castVote(pid, true);
    expect(await registry.getStatus(did)).to.equal(3);
  });
  it("rejects non-voters and double votes", async function () {
    const pid = await propose();
    await expect(gov.connect(deployer).castVote(pid, true)).to.be.reverted;
    await gov.connect(voters[0]).castVote(pid, true);
    await expect(gov.connect(voters[0]).castVote(pid, true)).to.be.reverted;
  });
});
