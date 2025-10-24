// Minimal typings for the parts of 'jsrsasign' we use in the Worker
declare module "jsrsasign" {
  export class X509 {
    constructor();
    readCertPEM(pem: string): void;
    getNotBefore(): string;
    getNotAfter(): string;
    getExtSubjectAltName(...args: any[]): any;
    getExtSubjectAltName2?(): any;
  }

  export namespace KJUR {
    namespace crypto {
      class Signature {
        constructor(opts: { alg: "SHA256withRSA" | "SHA1withRSA" });
        init(key: string): void;
        updateHex(hex: string): void;
        verify(sigHex: string): boolean;
      }
    }
  }

  export function b64tohex(b64: string): string;
}
