const { expect } = require("chai");
const { ethers } = require("hardhat");
const abi = ethers.AbiCoder.defaultAbiCoder();

// Small seeded PRNG so the randomised run is reproducible.
function prng(seed) { let s = seed >>> 0; return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32); }

describe("Hardening and randomised invariant checks", function () {
  let registry, zta, deployer, oracle, rid;
  async function reg(i) {
    const dev = ethers.Wallet.createRandom();
    const pk = ethers.keccak256(dev.publicKey), ah = ethers.keccak256(ethers.toUtf8Bytes("fz:" + i));
    const mh = ethers.keccak256(abi.encode(["bytes32", "bytes32", "string", "address"], [pk, ah, "plc", deployer.address]));
    await (await registry.registerDevice(pk, ah, "plc", await dev.signMessage(ethers.getBytes(mh)), dev.address)).wait();
    return ethers.solidityPackedKeccak256(["string", "bytes32"], ["did:iot:", pk]);
  }
  const osig = (did, T, A, n) => oracle.signMessage(ethers.getBytes(ethers.keccak256(
    abi.encode(["bytes32", "bytes32", "uint16", "uint16", "uint256"], [did, rid, T, A, n]))));

  beforeEach(async function () {
    [deployer, oracle] = await ethers.getSigners();
    registry = await (await ethers.getContractFactory("IdentityRegistry")).deploy();
    zta = await (await ethers.getContractFactory("ZeroTrustAccess")).deploy(await registry.getAddress(), oracle.address);
    rid = ethers.id("plc.read");
    await (await zta.definePolicy(rid, 5000, 1000, 6000, 10000, false, ["plc"])).wait();
  });

  it("rejects a zero oracle address at deployment", async function () {
    const f = await ethers.getContractFactory("ZeroTrustAccess");
    await expect(f.deploy(await registry.getAddress(), ethers.ZeroAddress)).to.be.reverted;
  });

  it("rejects registration when ecrecover fails and the claimed signer is the zero address", async function () {
    const pk = ethers.id("k"), ah = ethers.id("a");
    const junk = "0x" + "11".repeat(32) + "22".repeat(32) + "05"; // v=5 -> v+27=32, ecrecover returns 0
    await expect(registry.registerDevice(pk, ah, "plc", junk, ethers.ZeroAddress)).to.be.reverted;
  });

  it("random operation sequences keep revocation terminal and nonces single-use (300 steps, 3 seeds)", async function () {
    this.timeout(300000);
    for (const seed of [1, 2, 3]) {
      const rnd = prng(seed);
      const dids = []; for (let i = 0; i < 6; i++) dids.push(await reg(seed * 100 + i));
      const status = dids.map(() => 1);          // model: 1=ACTIVE, 2=SUSPENDED, 3=REVOKED
      const used = new Set(); let nonce = seed * 1000;
      for (let step = 0; step < 100; step++) {
        const i = Math.floor(rnd() * dids.length), op = Math.floor(rnd() * 5);
        if (op === 0 && status[i] === 1) { await (await registry.suspendDevice(dids[i])).wait(); status[i] = 2; }
        else if (op === 1) { // reinstate: must succeed iff SUSPENDED, revert otherwise
          if (status[i] === 2) { await (await registry.reinstateDevice(dids[i])).wait(); status[i] = 1; }
          else await expect(registry.reinstateDevice(dids[i])).to.be.reverted;
        }
        else if (op === 2 && status[i] !== 3) { await (await registry.revokeDevice(dids[i], "fz")).wait(); status[i] = 3; }
        else { // access request with a perfect score; ALLOW (2) iff ACTIVE and (device,nonce) fresh
          nonce++; const reuse = rnd() < 0.2 && used.size;
          let key, n;
          if (reuse) { key = [...used][Math.floor(rnd() * used.size)]; [, n] = key.split(":").map(Number); } else n = nonce;
          // reuse targets the device that originally used the nonce
          const di = reuse ? Number(key.split(":")[0]) : i;
          const s = await osig(dids[di], 9500, 100, n);
          const eff = Number(await zta.evaluateAccess.staticCall(dids[di], rid, "plc", 9500, 100, s, n));
          const fresh = !used.has(di + ":" + n);
          if (status[di] === 1 && fresh) { expect(eff).to.equal(2); await (await zta.evaluateAccess(dids[di], rid, "plc", 9500, 100, s, n)).wait(); used.add(di + ":" + n); }
          else expect(eff, "inactive device or replayed nonce must not be ALLOWed").to.not.equal(2);
        }
        expect(Number(await registry.getStatus(dids[i]))).to.equal(status[i]);
      }
      for (let i = 0; i < dids.length; i++) if (status[i] === 3) await expect(registry.reinstateDevice(dids[i])).to.be.reverted;
    }
  });
});
