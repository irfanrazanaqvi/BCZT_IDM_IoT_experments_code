const { expect } = require("chai");
const { ethers } = require("hardhat");
const abi = ethers.AbiCoder.defaultAbiCoder();

describe("IIoT extensions: anomaly gate, strict tier, batch recall", function () {
  let registry, zta, deployer, oracle, rid;
  async function reg(i) {
    const dev = ethers.Wallet.createRandom();
    const pk = ethers.keccak256(dev.publicKey), ah = ethers.keccak256(ethers.toUtf8Bytes("fw:" + i));
    const mh = ethers.keccak256(abi.encode(["bytes32", "bytes32", "string", "address"], [pk, ah, "plc", deployer.address]));
    await (await registry.registerDevice(pk, ah, "plc", await dev.signMessage(ethers.getBytes(mh)), dev.address)).wait();
    return ethers.solidityPackedKeccak256(["string", "bytes32"], ["did:iot:", pk]);
  }
  async function sig(did, T, A, n) {
    return oracle.signMessage(ethers.getBytes(ethers.keccak256(abi.encode(["bytes32","bytes32","uint16","uint16","uint256"], [did, rid, T, A, n]))));
  }
  beforeEach(async function () {
    [deployer, oracle] = await ethers.getSigners();
    registry = await (await ethers.getContractFactory("IdentityRegistry")).deploy();
    zta = await (await ethers.getContractFactory("ZeroTrustAccess")).deploy(await registry.getAddress(), oracle.address);
    rid = ethers.id("plc.setpoint.write");
    await (await zta.definePolicy(rid, 7500, 1000, 300, 2500, true, ["plc"])).wait();
  });
  it("denies a high composite score when the anomaly gate trips (mimicry)", async function () {
    const did = await reg(1);
    expect(await zta.evaluateAccess.staticCall(did, rid, "plc", 9500, 3000, await sig(did, 9500, 3000, 1), 1)).to.equal(0);
    expect(await zta.evaluateAccess.staticCall(did, rid, "plc", 9500, 1000, await sig(did, 9500, 1000, 2), 2)).to.equal(2);
  });
  it("a tampered anomaly value invalidates the oracle signature", async function () {
    const did = await reg(2);
    const good = await sig(did, 9500, 3000, 3);   // oracle attested A=3000
    expect(await zta.evaluateAccess.staticCall(did, rid, "plc", 9500, 500, good, 3)).to.equal(0); // device claims A=500
  });
  it("strict resources never step up", async function () {
    const did = await reg(3);
    expect(await zta.evaluateAccess.staticCall(did, rid, "plc", 8000, 500, await sig(did, 8000, 500, 4), 4)).to.equal(0);
  });
  it("revokeBatch revokes all known devices, skips unknown, and blocks later access", async function () {
    const dids = [await reg(10), await reg(11), await reg(12)];
    const done = await registry.revokeBatch.staticCall([...dids, ethers.id("ghost")], "firmware_recall");
    expect(done).to.equal(3);
    await (await registry.revokeBatch(dids, "firmware_recall")).wait();
    for (const d of dids) expect(await registry.getStatus(d)).to.equal(3);
    expect(await zta.evaluateAccess.staticCall(dids[0], rid, "plc", 9500, 500, await sig(dids[0], 9500, 500, 5), 5)).to.equal(0);
  });
  it("only authorised PEPs can anchor a decision-log root", async function () {
    const [, , pep, other] = await ethers.getSigners();
    await expect(zta.connect(pep).anchorDecisions(ethers.id("r"), 10)).to.be.reverted;
    await (await zta.setPEP(pep.address, true)).wait();
    await (await zta.connect(pep).anchorDecisions(ethers.id("r"), 10)).wait();
    expect(await zta.anchoredRoot(1)).to.equal(ethers.id("r"));
    await expect(zta.connect(other).anchorDecisions(ethers.id("x"), 1)).to.be.reverted;
  });
});
