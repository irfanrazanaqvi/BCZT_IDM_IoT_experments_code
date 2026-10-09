const hre = require("hardhat");

async function main() {
  const [deployer, oracle] = await hre.ethers.getSigners();
  console.log("Deploying with account:", deployer.address);

  const IdentityRegistry = await hre.ethers.getContractFactory("IdentityRegistry");
  const registry = await IdentityRegistry.deploy();
  await registry.waitForDeployment();
  console.log("IdentityRegistry deployed to:", await registry.getAddress());

  const ZeroTrustAccess = await hre.ethers.getContractFactory("ZeroTrustAccess");
  const zta = await ZeroTrustAccess.deploy(await registry.getAddress(), oracle.address);
  await zta.waitForDeployment();
  console.log("ZeroTrustAccess deployed to:", await zta.getAddress());

  // Example policy: telemetry.write resource, min trust 5500bp (55%),
  // 1500bp step-up margin, 300s max idle, allowed classes below.
  const resourceId = hre.ethers.id("telemetry.write");
  const tx = await zta.definePolicy(
    resourceId, 5500, 1500, 300, 10000, false,
    ["sensor", "actuator", "gateway", "camera", "controller"]
  );
  await tx.wait();
  console.log("Default policy 'telemetry.write' registered.");

  console.log(JSON.stringify({
    registry: await registry.getAddress(),
    zeroTrustAccess: await zta.getAddress(),
    oracle: oracle.address,
    resourceIdTelemetryWrite: resourceId,
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
