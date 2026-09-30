(function (root) {
  "use strict";

  const webcrypto = root.crypto;
  const subtle = webcrypto && webcrypto.subtle;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const ARMOR_BEGIN = "-----BEGIN ZMAIL ZMATH PROTECTED MESSAGE-----";
  const ARMOR_END = "-----END ZMAIL ZMATH PROTECTED MESSAGE-----";
  const AAD_INNER = encoder.encode("zmail-zmath-mail-v1|inner");
  const AAD_OUTER = encoder.encode("zmail-zmath-mail-v1|outer");
  const MAX_ARMORED_MESSAGE_BYTES = 8 * 1024 * 1024;
  const MAX_RECIPIENT_SLOTS = 64;

  function requireCrypto() {
    if (!subtle || typeof webcrypto.getRandomValues !== "function") {
      throw new Error("This browser does not provide the Web Crypto API.");
    }
  }

  function bytes(value) {
    return value instanceof Uint8Array ? value : new Uint8Array(value);
  }

  function base64url(value) {
    let binary = "";
    for (const item of bytes(value)) binary += String.fromCharCode(item);
    return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
  }

  function fromBase64url(value) {
    if (
      typeof value !== "string"
      || value.length > MAX_ARMORED_MESSAGE_BYTES
      || !/^[A-Za-z0-9_-]+$/u.test(value)
    ) {
      throw new Error("Invalid protected-message encoding.");
    }
    const padded = value.replaceAll("-", "+").replaceAll("_", "/")
      + "=".repeat((4 - (value.length % 4)) % 4);
    const binary = atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  }

  function random(length) {
    const value = new Uint8Array(length);
    webcrypto.getRandomValues(value);
    return value;
  }

  function canonical(value) {
    if (value === null || typeof value !== "object") return JSON.stringify(value);
    if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }

  async function sha256(value) {
    return bytes(await subtle.digest("SHA-256", typeof value === "string" ? encoder.encode(value) : value));
  }

  async function fingerprint(jwk) {
    return base64url(await sha256(canonical(jwk))).slice(0, 22);
  }

  async function hardenedPair(algorithm, usages) {
    const generated = await subtle.generateKey(algorithm, true, usages);
    const [privateJwk, publicJwk] = await Promise.all([
      subtle.exportKey("jwk", generated.privateKey),
      subtle.exportKey("jwk", generated.publicKey),
    ]);
    const privateKey = await subtle.importKey("jwk", privateJwk, algorithm, false, usages.filter((use) =>
      use === "deriveBits" || use === "sign"
    ));
    return { privateKey, publicJwk };
  }

  async function generateDevice() {
    requireCrypto();
    const encryption = await hardenedPair(
      { name: "ECDH", namedCurve: "P-256" },
      ["deriveBits"]
    );
    const signing = await hardenedPair(
      { name: "ECDSA", namedCurve: "P-256" },
      ["sign", "verify"]
    );
    const deviceId = base64url(random(24));
    return {
      version: 1,
      deviceId,
      encryptionPrivateKey: encryption.privateKey,
      encryptionPublicJwk: encryption.publicJwk,
      signingPrivateKey: signing.privateKey,
      signingPublicJwk: signing.publicJwk,
      fingerprint: await fingerprint(signing.publicJwk),
      createdAt: new Date().toISOString(),
    };
  }

  async function wrappingKey(privateKey, publicJwk, salt, deviceId, usages) {
    const publicKey = await subtle.importKey(
      "jwk",
      publicJwk,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );
    const shared = await subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256);
    const material = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
    return subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt,
        info: encoder.encode(`zmail-zmath-mail-v1|wrap|${deviceId}`),
      },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      usages
    );
  }

  async function aesKey(rawValue, usages) {
    return subtle.importKey("raw", rawValue, { name: "AES-GCM" }, false, usages);
  }

  async function encryptForDevices({
    plaintext,
    from,
    devices,
    senderDevice,
  }) {
    requireCrypto();
    if (!senderDevice?.signingPrivateKey || !devices?.length) {
      throw new Error("Protected-mail device keys are unavailable.");
    }
    const payload = {
      type: "text/plain",
      text: String(plaintext),
    };
    const innerRaw = random(32);
    const outerRaw = random(32);
    const innerIv = random(12);
    const outerIv = random(12);
    const innerKey = await aesKey(innerRaw, ["encrypt"]);
    const outerKey = await aesKey(outerRaw, ["encrypt"]);
    const innerCiphertext = await subtle.encrypt(
      { name: "AES-GCM", iv: innerIv, additionalData: AAD_INNER, tagLength: 128 },
      innerKey,
      encoder.encode(JSON.stringify(payload))
    );
    const innerEnvelope = encoder.encode(JSON.stringify({
      iv: base64url(innerIv),
      ciphertext: base64url(innerCiphertext),
    }));
    const outerCiphertext = await subtle.encrypt(
      { name: "AES-GCM", iv: outerIv, additionalData: AAD_OUTER, tagLength: 128 },
      outerKey,
      innerEnvelope
    );

    if (devices.length > MAX_RECIPIENT_SLOTS) {
      throw new Error("This protected message has too many recipient devices.");
    }
    const recipientSlots = [];
    for (const device of devices) {
      const ephemeral = await subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"]
      );
      const slotId = base64url(random(18));
      const salt = random(16);
      const iv = random(12);
      const key = await wrappingKey(
        ephemeral.privateKey,
        device.encryptionPublicJwk,
        salt,
        slotId,
        ["encrypt"]
      );
      const keyBundle = encoder.encode(JSON.stringify({
        inner: base64url(innerRaw),
        outer: base64url(outerRaw),
      }));
      const wrapped = await subtle.encrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: encoder.encode(`zmail-zmath-mail-v1|keys|${slotId}`),
          tagLength: 128,
        },
        key,
        keyBundle
      );
      recipientSlots.push({
        slotId,
        ephemeralPublicJwk: await subtle.exportKey("jwk", ephemeral.publicKey),
        salt: base64url(salt),
        iv: base64url(iv),
        wrappedKeys: base64url(wrapped),
      });
    }

    const envelope = {
      version: 2,
      type: "zmail-zmath-protected-message",
      algorithm: "AES-256-GCMx2/ECDH-P256/HKDF-SHA256/ECDSA-P256",
      createdAt: new Date().toISOString(),
      from: String(from).toLowerCase(),
      outer: {
        iv: base64url(outerIv),
        ciphertext: base64url(outerCiphertext),
      },
      recipientSlots,
      sender: {
        fingerprint: senderDevice.fingerprint,
        signingPublicJwk: senderDevice.signingPublicJwk,
      },
    };
    const signature = await subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      senderDevice.signingPrivateKey,
      encoder.encode(canonical(envelope))
    );
    envelope.signature = base64url(signature);
    return envelope;
  }

  async function decryptForDevice(envelope, device) {
    requireCrypto();
    if (
      !envelope
      || ![1, 2].includes(envelope.version)
      || envelope.type !== "zmail-zmath-protected-message"
    ) {
      throw new Error("This is not a supported ZMath protected message.");
    }
    const slots = envelope.version === 2 ? envelope.recipientSlots : envelope.recipients;
    if (!Array.isArray(slots) || slots.length < 1 || slots.length > MAX_RECIPIENT_SLOTS) {
      throw new Error("This protected message has an invalid recipient directory.");
    }
    const signature = envelope.signature;
    const signed = { ...envelope };
    delete signed.signature;
    const signingKey = await subtle.importKey(
      "jwk",
      envelope.sender?.signingPublicJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
    const verified = await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      signingKey,
      fromBase64url(signature),
      encoder.encode(canonical(signed))
    );
    if (!verified) throw new Error("The protected-message signature is invalid.");

    const computedFingerprint = await fingerprint(envelope.sender?.signingPublicJwk);
    if (
      typeof envelope.sender?.fingerprint !== "string"
      || envelope.sender.fingerprint !== computedFingerprint
    ) {
      throw new Error("The protected-message sender fingerprint is invalid.");
    }
    let keyBundleBytes;
    if (envelope.version === 1) {
      const recipient = slots.find((item) => item.deviceId === device.deviceId);
      if (recipient) {
        const key = await wrappingKey(
          device.encryptionPrivateKey,
          recipient.ephemeralPublicJwk,
          fromBase64url(recipient.salt),
          device.deviceId,
          ["decrypt"]
        );
        keyBundleBytes = await subtle.decrypt(
          {
            name: "AES-GCM",
            iv: fromBase64url(recipient.iv),
            additionalData: encoder.encode(`zmail-zmath-mail-v1|keys|${device.deviceId}`),
            tagLength: 128,
          },
          key,
          fromBase64url(recipient.wrappedKeys)
        );
      }
    } else {
      for (const slot of slots) {
        if (
          typeof slot?.slotId !== "string"
          || !/^[A-Za-z0-9_-]{20,32}$/u.test(slot.slotId)
        ) {
          continue;
        }
        try {
          const key = await wrappingKey(
            device.encryptionPrivateKey,
            slot.ephemeralPublicJwk,
            fromBase64url(slot.salt),
            slot.slotId,
            ["decrypt"]
          );
          keyBundleBytes = await subtle.decrypt(
            {
              name: "AES-GCM",
              iv: fromBase64url(slot.iv),
              additionalData: encoder.encode(`zmail-zmath-mail-v1|keys|${slot.slotId}`),
              tagLength: 128,
            },
            key,
            fromBase64url(slot.wrappedKeys)
          );
          break;
        } catch {
          // Opaque slots intentionally do not reveal which address or device
          // they belong to. Try each bounded slot locally.
        }
      }
    }
    if (!keyBundleBytes) {
      throw new Error("This message was not encrypted for this browser device.");
    }
    const keyBundle = JSON.parse(decoder.decode(keyBundleBytes));
    const outerKey = await aesKey(fromBase64url(keyBundle.outer), ["decrypt"]);
    const innerEnvelopeBytes = await subtle.decrypt(
      {
        name: "AES-GCM",
        iv: fromBase64url(envelope.outer.iv),
        additionalData: AAD_OUTER,
        tagLength: 128,
      },
      outerKey,
      fromBase64url(envelope.outer.ciphertext)
    );
    const innerEnvelope = JSON.parse(decoder.decode(innerEnvelopeBytes));
    const innerKey = await aesKey(fromBase64url(keyBundle.inner), ["decrypt"]);
    const payloadBytes = await subtle.decrypt(
      {
        name: "AES-GCM",
        iv: fromBase64url(innerEnvelope.iv),
        additionalData: AAD_INNER,
        tagLength: 128,
      },
      innerKey,
      fromBase64url(innerEnvelope.ciphertext)
    );
    const payload = JSON.parse(decoder.decode(payloadBytes));
    if (payload.type !== "text/plain" || typeof payload.text !== "string") {
      throw new Error("The protected message contains an unsupported payload.");
    }
    return {
      plaintext: payload.text,
      verified,
      senderFingerprint: computedFingerprint,
      from: envelope.from,
      createdAt: envelope.createdAt,
    };
  }

  function armor(envelope) {
    const encoded = base64url(encoder.encode(JSON.stringify(envelope)));
    const lines = encoded.match(/.{1,76}/gu) || [];
    return `${ARMOR_BEGIN}\n${lines.join("\n")}\n${ARMOR_END}`;
  }

  function unarmor(value) {
    const text = String(value);
    if (text.length > MAX_ARMORED_MESSAGE_BYTES) {
      throw new Error("This protected message is too large to open safely.");
    }
    const start = text.indexOf(ARMOR_BEGIN);
    const end = text.indexOf(ARMOR_END, start + ARMOR_BEGIN.length);
    if (start < 0 || end < 0) return null;
    const encoded = text.slice(start + ARMOR_BEGIN.length, end).replace(/\s+/gu, "");
    if (!encoded || encoded.length > MAX_ARMORED_MESSAGE_BYTES) {
      throw new Error("This protected message has an invalid size.");
    }
    const envelope = JSON.parse(decoder.decode(fromBase64url(encoded)));
    return { envelope, start, end: end + ARMOR_END.length };
  }

  root.ZMathMailCrypto = Object.freeze({
    ARMOR_BEGIN,
    ARMOR_END,
    armor,
    canonical,
    decryptForDevice,
    encryptForDevices,
    fingerprint,
    generateDevice,
    unarmor,
  });
})(globalThis);
