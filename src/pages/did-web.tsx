import { AtpAgent } from "@atproto/api";
import { Secp256k1Keypair } from "@atproto/crypto";
import { createEffect, createSignal } from "solid-js";
import {} from "solid-js";
import * as ui8 from "uint8arrays";

import fileSolid from "../assets/file-solid.svg";

const DIDWeb = () => {
  const [showDebug] = createSignal(false);
  const [skipDIDFileChecks] = createSignal(false);
  const [step, setStep] = createSignal(1);

  const showError = (message: string) => {
    alert(message);
  };

  const [privateKey, setPrivateKey] = createSignal("");
  const [publicKey, setPublicKey] = createSignal("");
  const generatePrivateKey = async (event: Event) => {
    event.preventDefault();
    const keyPair = await Secp256k1Keypair.create({ exportable: true });
    const privateKeyBytes = await keyPair.export();
    const privateKeyHex = ui8.toString(privateKeyBytes, "hex");
    setPrivateKey(privateKeyHex);
  };
  const validatePrivateKey = async (event: Event) => {
    event.preventDefault();
    if (privateKey().trim() === "")
      return showError("You must specify a private key.");
    try {
      const keyPair = await Secp256k1Keypair.import(privateKey());
      setPublicKey(keyPair.did());
      setStep(step() + 1);
    } catch (error) {
      showError(`Invalid private key provided.`);
      console.log(`${error}`);
    }
  };

  const [pdsEndpoint, setPDSEndpoint] = createSignal("");
  const [domain, setDomain] = createSignal("");
  const [handle, setHandle] = createSignal("");
  const [didFileLocation, setDidFileLocation] = createSignal("");
  const [didFile, setDidFile] = createSignal("");
  const validateIdentity = async (event: Event) => {
    event.preventDefault();
    if (pdsEndpoint().trim() === "")
      return showError("You must specify the endpoint for your PDS.");
    if (domain().trim() === "") return showError("You must specify a domain.");
    if (handle().trim() === "") return showError("You must specify a handle.");
    setStep(step() + 1);
  };
  createEffect(() => {
    setDidFileLocation(`https://${domain()}/.well-known/did.json`);
    try {
      setDidFile(
        JSON.stringify(
          {
            "@context": [
              "https://www.w3.org/ns/did/v1",
              "https://w3id.org/security/multikey/v1",
              "https://w3id.org/security/suites/secp256k1-2019/v1",
            ],
            id: `did:web:${domain()}`,
            alsoKnownAs: [`at://${handle()}`],
            verificationMethod: [
              {
                id: `did:web:${domain()}#atproto`,
                type: "Multikey",
                controller: `did:web:${domain()}`,
                publicKeyMultibase: `${publicKey().split(":")[2]}`,
              },
            ],
            service: [
              {
                id: "#atproto_pds",
                type: "AtprotoPersonalDataServer",
                serviceEndpoint: `https://${new URL(pdsEndpoint()).hostname}`,
              },
            ],
          },
          null,
          "\t",
        ),
      );
    } catch (error) {}
  });

  const validateDIDFile = async (event: Event) => {
    event.preventDefault();
    if (skipDIDFileChecks() === true) return setStep(step() + 1);
    try {
      const response = await fetch(didFileLocation());
      const json = await response.json();
      const didFileMatches =
        JSON.stringify(json) == JSON.stringify(JSON.parse(didFile()));
      if (didFileMatches === false)
        return showError(
          "DID file validation failed. Check its contents and try again.",
        );
      setStep(step() + 1);
    } catch (error) {
      showError(`${error}`);
      console.log(`${error}`);
    }
  };

  const [email, setEmail] = createSignal("");
  const [password, setPassword] = createSignal("");
  const [inviteCode, setInviteCode] = createSignal("");
  const [accessJWT, setAccessJWT] = createSignal("");
  const [refreshJWT, setRefreshJWT] = createSignal("");
  const [updatedDIDFile, setUpdatedDIDFile] = createSignal("");
  const createAccount = async (event: Event) => {
    event.preventDefault();
    if (email().trim() === "") return showError("You must specify your email.");
    if (password().trim() === "")
      return showError("You must specify a password.");
    if (accessJWT() !== "" && refreshJWT() !== "") return setStep(step() + 1);
    try {
      const header = JSON.stringify({
        alg: "ES256K",
        typ: "JWT",
      });
      const headerEncoded = ui8.toString(ui8.fromString(header), "base64url");

      const payload = JSON.stringify({
        lxm: "com.atproto.server.createAccount",
        iss: `did:web:${domain()}`,
        aud: `did:web:${new URL(pdsEndpoint()).hostname}`,
        exp: Math.floor(Date.now() / 1000) + 180,
      });
      const payloadEncoded = ui8.toString(ui8.fromString(payload), "base64url");

      const headerDotPayloadEncoded = `${headerEncoded}.${payloadEncoded}`;

      const keyPair = await Secp256k1Keypair.import(privateKey());

      const signature = await keyPair.sign(
        ui8.fromString(headerDotPayloadEncoded),
      );
      const signatureEncoded = ui8.toString(signature, "base64url");

      const token = `${headerDotPayloadEncoded}.${signatureEncoded}`;

      const agent = new AtpAgent({ service: pdsEndpoint() });
      const response = await agent.com.atproto.server.createAccount(
        {
          did: `did:web:${domain()}`,
          handle: handle(),
          email: email(),
          password: password(),
          recoveryKey: `${publicKey().split(":")[2]}`,
          ...(inviteCode() !== "" ? { inviteCode: inviteCode() } : {}),
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        },
      );

      console.log(response);

      setAccessJWT(response.data.accessJwt);
      setRefreshJWT(response.data.refreshJwt);
      setStep(step() + 1);
    } catch (error) {
      showError(`${error}`);
      console.log(`${error}`);
    }
  };
  createEffect(async () => {
    if (accessJWT() === "") return;
    if (refreshJWT() === "") return;
    if (updatedDIDFile() !== "") return;
    try {
      const agent = new AtpAgent({ service: pdsEndpoint() });
      await agent.login({
        identifier: `did:web:${domain()}`,
        password: password(),
      });
      const response =
        await agent.com.atproto.identity.getRecommendedDidCredentials();
      if (!response.data.verificationMethods)
        throw new Error("Verification methods not found.");
      type VerificationMethods = {
        atproto: string;
      };
      const verificationMethods: VerificationMethods = response.data
        .verificationMethods as VerificationMethods;
      setUpdatedDIDFile(
        JSON.stringify(
          {
            "@context": [
              "https://www.w3.org/ns/did/v1",
              "https://w3id.org/security/multikey/v1",
              "https://w3id.org/security/suites/secp256k1-2019/v1",
            ],
            id: `did:web:${domain()}`,
            alsoKnownAs: [`at://${handle()}`],
            verificationMethod: [
              {
                id: `did:web:${domain()}#atproto`,
                type: "Multikey",
                controller: `did:web:${domain()}`,
                publicKeyMultibase: `${verificationMethods.atproto.split(":")[2]}`,
              },
            ],
            service: [
              {
                id: "#atproto_pds",
                type: "AtprotoPersonalDataServer",
                serviceEndpoint: `https://${new URL(pdsEndpoint()).hostname}`,
              },
            ],
          },
          null,
          "\t",
        ),
      );
    } catch (error) {
      showError(`${error}`);
      console.log(`${error}`);
    }
  });

  const validateUpdatedDIDFile = async (event: Event) => {
    event.preventDefault();
    if (skipDIDFileChecks() === true) return setStep(step() + 1);
    try {
      const response = await fetch(didFileLocation());
      const json = await response.json();
      const didFileMatches =
        JSON.stringify(json) == JSON.stringify(JSON.parse(updatedDIDFile()));
      if (didFileMatches === false)
        return showError(
          "Updated DID file validation failed. Check its contents and try again.",
        );
      setStep(step() + 1);
    } catch (error) {
      showError(`${error}`);
      console.log(`${error}`);
    }
  };

  const activateAccount = async (event: Event) => {
    event.preventDefault();
    try {
      const agent = new AtpAgent({ service: pdsEndpoint() });
      await agent.login({
        identifier: `did:web:${domain()}`,
        password: password(),
      });
      const response = await agent.com.atproto.server.activateAccount();
      if (response.success === true) {
        setStep(step() + 1);
      } else {
        throw new Error("Could not activate account.");
      }
    } catch (error) {
      showError(`${error}`);
      console.log(`${error}`);
    }
  };

  return (
    <section>
      <header>
        <h2>did:web</h2>
        <h3>setup a did:web for use on ATProto</h3>
      </header>
      <main>
        {showDebug() === true && (
          <div class="p-1 mb-2 bg-sky-100 shadow rounded text-xs overflow-clip">
            <p>Private Key: {privateKey()}</p>
            <p>Public Key: {publicKey()}</p>
            <p>PDS Endpoint: {pdsEndpoint()}</p>
            <p>Domain: {domain()}</p>
            <p>Handle: {handle()}</p>
            <p>DID File Location: {didFileLocation()}</p>
            <p>DID File: {didFile().length} bytes</p>
            <p>Email: {email()}</p>
            <p>Password: {password()}</p>
            <p>Invite Code: {inviteCode()}</p>
            <p>Access JWT: {accessJWT()}</p>
            <p>Refresh JWT: {refreshJWT()}</p>
          </div>
        )}

        {step() === 1 && (
          <div>
            <h4>{step()}. Introduction</h4>
            <p class="text-xs mb-2">
              This tool has been designed to assist in the creation of a did:web
              based account on a self hosted PDS. All operations are performed
              client side on your device, with only necessary outgoing network
              calls made to your web server to validate did.json files, and to
              the PDS to create and activate your account. No private data you
              provide is stored or shared. If you refresh this page it will
              reset the process.
            </p>
            <div class="form">
              <div class="flex">
                <div class="text-right flex-grow">
                  <button
                    class="form-button"
                    onClick={() => setStep(step() + 1)}
                  >
                    Next
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {step() === 2 && (
          <div>
            <h4>{step()}. Private Key</h4>
            <p class="text-xs mb-2">
              Generate a new hex encoded private key or specify an existing one.
              Once generated you should probably hold onto it just in case this
              process is interrupted and you need to resume it. Treat it like a
              password and don't share it with anyone.
            </p>
            <div class="form">
              <div class="form-group">
                <label for="privateKey" class="form-label">
                  Private Key
                </label>
                <input
                  type="text"
                  id="privateKey"
                  class="form-input font-mono"
                  autocorrect="off"
                  placeholder="abcd1234567890efghj1234567890kmn1234567890opqrst1234567890uvwxyz"
                  value={privateKey()}
                  onKeyUp={(e) =>
                    setPrivateKey((e.target as HTMLInputElement).value)
                  }
                />
              </div>
              <div class="flex">
                <div class="text-left flex-grow">
                  <button
                    class="form-button"
                    onClick={() => setStep(step() - 1)}
                  >
                    Back
                  </button>
                </div>
                <div class="text-right flex-grow">
                  {privateKey() === "" ? (
                    <button class="form-button" onClick={generatePrivateKey}>
                      Generate
                    </button>
                  ) : (
                    <button class="form-button" onClick={validatePrivateKey}>
                      Next
                    </button>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {step() === 3 && (
          <div>
            <h4>{step()}. Identity</h4>
            <p class="text-xs mb-2">
              Enter the details for your PDS and your new identity.
            </p>
            <div class="form">
              <div class="form-group">
                <label for="pdsEndpoint" class="form-label">
                  PDS Endpoint
                </label>
                <input
                  type="text"
                  id="pdsEndpoint"
                  class="form-input font-mono"
                  autocorrect="off"
                  placeholder="https://pds.example.com"
                  value={pdsEndpoint()}
                  onKeyUp={(e) =>
                    setPDSEndpoint((e.target as HTMLInputElement).value)
                  }
                />
              </div>
              <div class="form-group">
                <label for="domain" class="form-label">
                  Domain
                </label>
                <input
                  type="text"
                  id="domain"
                  class="form-input font-mono"
                  autocorrect="off"
                  placeholder="example.com"
                  value={domain()}
                  onKeyUp={(e) =>
                    setDomain((e.target as HTMLInputElement).value)
                  }
                />
              </div>
              <div class="form-group">
                <label for="handle" class="form-label">
                  Handle
                </label>
                <input
                  type="text"
                  id="handle"
                  class="form-input font-mono"
                  autocorrect="off"
                  placeholder="handle.pds.example.com"
                  value={handle()}
                  onKeyUp={(e) =>
                    setHandle((e.target as HTMLInputElement).value)
                  }
                />
              </div>
              <div class="flex">
                <div class="text-left flex-grow">
                  <button
                    class="form-button"
                    onClick={() => setStep(step() - 1)}
                  >
                    Back
                  </button>
                </div>
                <div class="text-right flex-grow">
                  <button class="form-button" onClick={validateIdentity}>
                    Next
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {step() === 4 && (
          <div>
            <h4>{step()}. DID File</h4>
            <p class="text-xs mb-2">
              Upload the JSON below to the did.json URL specified. You can click
              that URL to make sure it's resolving correctly before continuing.
            </p>
            <div class="form">
              <div class="form-group">
                <p class="font-xs text-sky-700 mb-1 flex opacity-50">
                  <img src={fileSolid} width="10" height="10" class="mr-2" />
                  <a target="_blank" href={didFileLocation()}>
                    {didFileLocation()}
                  </a>
                </p>
                <pre>{didFile()}</pre>
              </div>
              <div class="flex">
                <div class="text-left flex-grow">
                  <button
                    class="form-button"
                    onClick={() => setStep(step() - 1)}
                  >
                    Back
                  </button>
                </div>
                <div class="text-right flex-grow">
                  <button class="form-button" onClick={validateDIDFile}>
                    Next
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {step() === 5 && (
          <div>
            <h4>{step()}. Create Account</h4>
            <p class="text-xs mb-2">
              To create an account we'll need some extra information. For now
              use a temporary password which you can change later. It's going to
              be shown in plain text and provided to you again later in plain
              text so don't use something super secret.
            </p>
            <div class="form">
              <div class="form-group">
                <label for="email" class="form-label">
                  Email
                </label>
                <input
                  type="text"
                  id="email"
                  class="form-input font-mono"
                  autocorrect="off"
                  placeholder="hello@example.com"
                  value={email()}
                  onKeyUp={(e) =>
                    setEmail((e.target as HTMLInputElement).value)
                  }
                />
              </div>
              <div class="form-group">
                <label for="password" class="form-label">
                  Password
                </label>
                <input
                  type="text"
                  id="password"
                  class="form-input font-mono"
                  autocorrect="off"
                  placeholder="secret123"
                  value={password()}
                  onKeyUp={(e) =>
                    setPassword((e.target as HTMLInputElement).value)
                  }
                />
              </div>
              <div class="form-group">
                <label for="inviteCode" class="form-label">
                  Invite Code (if applicable)
                </label>
                <input
                  type="text"
                  id="inviteCode"
                  class="form-input font-mono"
                  autocorrect="off"
                  placeholder={`pds-example-com-djyw4-aubhs`}
                  value={inviteCode()}
                  onKeyUp={(e) =>
                    setInviteCode((e.target as HTMLInputElement).value)
                  }
                />
              </div>
              <p class="mb-2 text-xs">
                If you're using a custom domain, you'll need to create a TXT
                record with the following details. You won't be able to create
                your account with a custom domain until you complete this step.
              </p>
              <div class="form-group">
                <label for="dnsHost" class="form-label">
                  DNS Host (if required)
                </label>
                <input
                  type="text"
                  id="dnsHost"
                  class="form-input font-mono"
                  autocorrect="off"
                  value={`_atproto.${handle()}`}
                  readOnly={true}
                />
              </div>
              <div class="form-group">
                <label for="dnsValue" class="form-label">
                  DNS Value (if required)
                </label>
                <input
                  type="text"
                  id="dnsValue"
                  class="form-input font-mono"
                  autocorrect="off"
                  value={`did=did:web:${handle()}`}
                  readOnly={true}
                />
              </div>
              <div class="flex">
                <div class="text-left flex-grow">
                  <button
                    class="form-button"
                    onClick={() => setStep(step() - 1)}
                  >
                    Back
                  </button>
                </div>
                <div class="text-right flex-grow">
                  <button class="form-button" onClick={createAccount}>
                    Next
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {step() === 6 && (
          <div>
            <h4>{step()}. Updated DID File</h4>
            <p class="text-xs mb-2">
              Upload the updated JSON below to the did.json URL specified below,
              it's the same as last time. You can click that URL to make sure
              it's resolving correctly with the new information before
              continuing.
            </p>
            <div class="form">
              {updatedDIDFile() === "" ? (
                <p>Loading...</p>
              ) : (
                <>
                  <div class="form-group">
                    <p class="font-xs text-sky-700 mb-1 flex opacity-50">
                      <img
                        src={fileSolid}
                        width="10"
                        height="10"
                        class="mr-2"
                      />
                      <a target="_blank" href={didFileLocation()}>
                        {didFileLocation()}
                      </a>
                    </p>
                    <pre>{updatedDIDFile()}</pre>
                  </div>
                  <div class="flex">
                    <div class="text-left flex-grow">
                      <button
                        class="form-button"
                        onClick={() => setStep(step() - 1)}
                      >
                        Back
                      </button>
                    </div>
                    <div class="text-right flex-grow">
                      <button
                        class="form-button"
                        onClick={validateUpdatedDIDFile}
                      >
                        Next
                      </button>
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        )}

        {step() === 7 && (
          <div>
            <h4>{step()}. Activate Account</h4>
            <div class="form">
              <p class="mb-2 text-xs">
                Everything should be in place to activate your account for use.
                Cross your fingers and hit next.
              </p>
              <div class="flex">
                <div class="text-left flex-grow">
                  <button
                    class="form-button"
                    onClick={() => setStep(step() - 1)}
                  >
                    Back
                  </button>
                </div>
                <div class="text-right flex-grow">
                  <button class="form-button" onClick={activateAccount}>
                    Next
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {step() === 8 && (
          <div>
            <h4>Success!</h4>
            <p class="mb-2 text-xs">
              Your new account was successfully activated with the details below
              and is ready to use! Don't forget to change your password when you
              first login.
            </p>
            <div class="form-group">
              <label for="pdsEndpoint" class="form-label">
                PDS Endpoint
              </label>
              <input
                type="text"
                id="pdsEndpoint"
                class="form-input font-mono"
                autocorrect="off"
                value={pdsEndpoint()}
                readOnly={true}
              />
            </div>
            <div class="form-group">
              <label for="did" class="form-label">
                DID
              </label>
              <input
                type="text"
                id="did"
                class="form-input font-mono"
                autocorrect="off"
                value={`did:web:${handle()}`}
                readOnly={true}
              />
            </div>
            <div class="form-group">
              <label for="handle" class="form-label">
                Handle
              </label>
              <input
                type="text"
                id="handle"
                class="form-input font-mono"
                autocorrect="off"
                value={handle()}
                readOnly={true}
              />
            </div>
            <div class="form-group">
              <label for="password" class="form-label">
                Password
              </label>
              <input
                type="text"
                id="password"
                class="form-input font-mono"
                autocorrect="off"
                value={password()}
                readOnly={true}
              />
            </div>
            <div class="flex">
              <div class="text-left flex-grow">
                <button class="form-button" onClick={() => setStep(step() - 1)}>
                  Back
                </button>
              </div>
            </div>
          </div>
        )}
      </main>
    </section>
  );
};

export default DIDWeb;
