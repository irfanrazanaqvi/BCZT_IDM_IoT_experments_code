/**
 * simulate_devices.js
 * --------------------
 * Registers N simulated IoT devices against a running Hardhat/PoA node,
 * issues signed access requests through ZeroTrustAccess, and prints
 * measured latency + gas usage. Run `npx hardhat node` in one terminal,
 * then `npm run deploy:local` and `npm run simulate` in another.
 */
const hre = require("hardhat");
const { ethers } = hre;

const N_DEVICES = parseInt(process.env.N_DEVICES || "20", 10);

async function main() {
  const [deployer, oracle] = await ethers.getSigners();

  const IdentityRegistry = await ethers.getContractFactory("IdentityRegistry");
  const registry = await IdentityRegistry.deploy();
  await registry.waitForDeployment();

  const ZeroTrustAccess = await ethers.getContractFactory("ZeroTrustAccess");
  const zta = await ZeroTrustAccess.deploy(await registry.getAddress(), oracle.address);
  await zta.waitForDeployment();

  const resourceId = ethers.id("telemetry.write");
  await (await zta.definePolicy(resourceId, 5500, 1500, 300, 10000, false,
    ["sensor", "actuator", "gateway", "camera", "controller"])).wait();

  const devices = [];
  for (let i = 0; i < N_DEVICES; i++) {
    devices.push(ethers.Wallet.createRandom());
  }

  let totalRegGas = 0n;
  const regLatencies = [];
  for (const device of devices) {
    const pubKeyHash = ethers.keccak256(device.publicKey);
    const attributeHash = ethers.keccak256(ethers.toUtf8Bytes("fw:2.1;vendor:Acme"));
    const deviceClass = "sensor";
    const messageHash = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes32", "string", "address"],
        [pubKeyHash, attributeHash, deviceClass, deployer.address]
      )
    );
    const signature = await device.signMessage(ethers.getBytes(messageHash));

    const t0 = Date.now();
    const tx = await registry.registerDevice(pubKeyHash, attributeHash, deviceClass, signature, device.address);
    const receipt = await tx.wait();
    regLatencies.push(Date.now() - t0);
    totalRegGas += receipt.gasUsed;
  }

  const avgRegGas = totalRegGas / BigInt(N_DEVICES);
  const avgRegLatency = regLatencies.reduce((a, b) => a + b, 0) / regLatencies.length;

  console.log(`Registered ${N_DEVICES} devices`);
  console.log(`  avg gas/registration : ${avgRegGas.toString()}`);
  console.log(`  avg latency (local)  : ${avgRegLatency.toFixed(1)} ms`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
