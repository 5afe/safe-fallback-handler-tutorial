import { ethers } from "hardhat";
import { expect } from "chai";
import { Signer, ZeroAddress } from "ethers";
import { Safe, Safe__factory, SafeProxyFactory } from "../typechain-types";
import { ERC1271FallbackHandler } from "../typechain-types/contracts/ERC1271FallbackHandler";

describe("ERC1271FallbackHandler.test", async function () {
  let deployer: Signer;
  let alice: Signer;
  let masterCopy: Safe;
  let proxyFactory: SafeProxyFactory;
  let safeFactory: Safe__factory;
  let safe: Safe;
  let exampleFallbackHandler: ERC1271FallbackHandler;
  const threshold = 1;

  const EIP712_SAFE_MESSAGE_TYPE = {
    // "SafeMessage(bytes message)"
    SafeMessage: [{ type: "bytes", name: "message" }],
  };

  // Setup signers and deploy contracts before running tests
  beforeEach(async () => {
    [deployer, alice] = await ethers.getSigners();

    safeFactory = await ethers.getContractFactory("Safe", deployer);

    // Deploy the ERC1271FallbackHandler contract
    exampleFallbackHandler = await (
      await ethers.getContractFactory("ERC1271FallbackHandler", deployer)
    ).deploy();

    masterCopy = await safeFactory.deploy();

    proxyFactory = await (
      await ethers.getContractFactory("SafeProxyFactory", deployer)
    ).deploy();

    const ownerAddresses = [await alice.getAddress()];

    const safeData = masterCopy.interface.encodeFunctionData("setup", [
      ownerAddresses,
      threshold,
      ZeroAddress,
      "0x",
      exampleFallbackHandler.target,
      ZeroAddress,
      0,
      ZeroAddress,
    ]);

    // Read the safe address by executing the static call to createProxyWithNonce function
    const safeAddress = await proxyFactory.createProxyWithNonce.staticCall(
      await masterCopy.getAddress(),
      safeData,
      0n
    );

    // Create the proxy with nonce
    await proxyFactory.createProxyWithNonce(
      await masterCopy.getAddress(),
      safeData,
      0n
    );

    if (safeAddress === ZeroAddress) {
      throw new Error("Safe address not found");
    }

    safe = await ethers.getContractAt("Safe", safeAddress);
  });

  it("should revert if called directly", async () => {
    const dataHash = ethers.keccak256("0xbaddad");
    await expect(
      exampleFallbackHandler.isValidSignature.staticCall(dataHash, "0x")
    ).to.be.reverted;
  });

  it("should revert if message was not signed", async () => {
    const validator = await ethers.getContractAt(
      "ERC1271FallbackHandler",
      safe.target
    );
    const dataHash = ethers.keccak256("0xbaddad");
    await expect(
      validator.isValidSignature.staticCall(dataHash, "0x")
    ).to.be.revertedWith("Hash not approved");
  });

  it("should revert if signature is not valid", async () => {
    const validator = await ethers.getContractAt(
      "ERC1271FallbackHandler",
      safe.target
    );
    const dataHash = ethers.keccak256("0xbaddad");
    await expect(
      validator.isValidSignature.staticCall(dataHash, "0xdeaddeaddeaddead")
    ).to.be.reverted;
  });

  it("should return magic value if enough owners signed and allow a mix different signature types", async () => {
    const validator = await ethers.getContractAt(
      "ERC1271FallbackHandler",
      safe.target
    );

    const validatorAddress = await validator.getAddress();
    const dataHash = ethers.keccak256("0xbaddad");
    const typedDataSig = {
      signer: await alice.getAddress(),
      data: await alice.signTypedData(
        {
          verifyingContract: validatorAddress,
          chainId: (await ethers.provider.getNetwork()).chainId,
        },
        EIP712_SAFE_MESSAGE_TYPE,
        { message: dataHash }
      ),
    };

    expect(
      await validator.isValidSignature.staticCall(dataHash, typedDataSig.data)
    ).to.be.eq("0x1626ba7e");
  });
});
