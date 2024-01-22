import { assert, ethers, hashMessage, Transaction, TypedDataEncoder } from "ethers";
import {
  getPublicKey,
  getEthereumAddress,
  requestKmsSignature,
  determineCorrectV,
} from "./util/aws_kms_utils";
import { KMSClient } from "@aws-sdk/client-kms";

export class AwsKmsSigner extends ethers.AbstractSigner {
  readonly kms: KMSClient;
  readonly keyId: string;
  ethereumAddress: string;

  constructor(keyId: string, kms: KMSClient, provider: ethers.Provider) {
    super(provider);
    this.keyId = keyId;
    this.kms = kms;
  }

  async getAddress(): Promise<string> {
    if (this.ethereumAddress === undefined) {
      const key = await getPublicKey(this.keyId, this.kms);
      this.ethereumAddress = getEthereumAddress(Buffer.from(key));
    }
    return Promise.resolve(this.ethereumAddress);
  }

  async _signDigest(digestString: string): Promise<string> {
    const digestBuffer = Buffer.from(ethers.getBytes(digestString));
    const sig = await requestKmsSignature(
      {
        keyId: this.keyId,
        plaintext: digestBuffer,
      },
      this.kms
    );
    const ethAddr = await this.getAddress();
    const { v } = determineCorrectV(digestBuffer, sig.r, sig.s, ethAddr);
    return ethers.Signature.from({
      v,
      r: `0x${sig.r.toString(16)}`,
      s: `0x${sig.s.toString(16)}`,
    }).serialized;
  }

  async signMessage(message: string | ethers.BytesLike): Promise<string> {
    return this._signDigest(hashMessage(message));
  }

  async signTransaction(transaction: ethers.TransactionLike): Promise<string> {
    const unsignedTx = await Transaction.from(transaction);
    const transactionSignature = await this._signDigest(
      ethers.keccak256(unsignedTx.unsignedSerialized)
    );
    unsignedTx.signature = transactionSignature;
    return unsignedTx.serialized;
  }

  connect(provider: ethers.Provider): AwsKmsSigner {
    return new AwsKmsSigner(this.keyId, this.kms, provider);
  }

  async signTypedData(
    _domain: ethers.TypedDataDomain,
    _types: Record<string, ethers.TypedDataField[]>,
    // rome-ignore lint/suspicious/noExplicitAny: <explanation>
    _value: Record<string, any>
  ): Promise<string> {
   // Populate any ENS names
   const populated = await TypedDataEncoder.resolveNames(_domain, _types, _value, async (name: string) => {
      // @TODO: this should use resolveName; addresses don't
      //        need a provider

      assert(this.provider != null, "cannot resolve ENS names without a provider", "UNSUPPORTED_OPERATION", {
          operation: "resolveName",
          info: { name }
      });

      const address = await this.provider.resolveName(name);
      assert(address != null, "unconfigured ENS name", "UNCONFIGURED_NAME", {
          value: name
      });

      return address;
    });

  return this._signDigest(TypedDataEncoder.hash(populated.domain, _types, populated.value));
  }
}
