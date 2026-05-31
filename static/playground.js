document.addEventListener("DOMContentLoaded", () => {
  const BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  const ZQLU_PREFIX = "zq.lu";
  const KEY_TYPE_LABELS = {
    A: "Ed25519",
    B: "RSA 2048",
    C: "P-256",
    D: "P-256",
    E: "P-384",
    F: "P-384",
    G: "P-521",
    H: "P-521",
    I: "RSA 3072",
    J: "RSA 4096",
    K: "RSA"
  };
  const RSA_F4 = Uint8Array.of(0x01, 0x00, 0x01);
  const RSA_FIXED_TYPES = {
    256: "B",
    384: "I",
    512: "J"
  };
  const RSA_FIXED_LENGTHS = {
    B: 256,
    I: 384,
    J: 512
  };
  const CURVE_TO_TYPES = {
    nistp256: { even: "D", odd: "C", xLength: 32, label: "P-256" },
    nistp384: { even: "F", odd: "E", xLength: 48, label: "P-384" },
    nistp521: { even: "H", odd: "G", xLength: 66, label: "P-521" }
  };
  const KEY_TYPE_TO_CURVE = {
    C: "nistp256",
    D: "nistp256",
    E: "nistp384",
    F: "nistp384",
    G: "nistp521",
    H: "nistp521"
  };
  const CURVE_PARAMS = {
    nistp256: {
      p: hexToBigInt("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
      b: hexToBigInt("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
      size: 32
    },
    nistp384: {
      p: hexToBigInt("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"),
      b: hexToBigInt("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
      size: 48
    },
    nistp521: {
      p: hexToBigInt("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
      b: hexToBigInt("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00"),
      size: 66
    }
  };
  const OID_ED25519 = "1.3.101.112";
  const OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
  const OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";
  const OID_P256 = "1.2.840.10045.3.1.7";
  const OID_P384 = "1.3.132.0.34";
  const OID_P521 = "1.3.132.0.35";

  const source = document.getElementById("source");
  const result = document.getElementById("result");
  const status = document.getElementById("status");
  const keyTypeNode = document.getElementById("keyType");
  const fingerprintNode = document.getElementById("fingerprint");
  const resultLabelNode = document.getElementById("resultLabel");
  const copyButton = document.getElementById("copyButton");

  if (!source || !result || !status || !keyTypeNode || !fingerprintNode || !resultLabelNode || !copyButton) {
    return;
  }

  source.addEventListener("input", update);
  copyButton.addEventListener("click", copyResult);
  update();

  async function update() {
    const raw = source.value;
    if (!raw.trim()) {
      result.value = "";
      resultLabelNode.textContent = "Converted Key";
      copyButton.disabled = true;
      keyTypeNode.textContent = "-";
      fingerprintNode.textContent = "-";
      setStatus("Waiting for input.");
      return;
    }

    try {
      const parsed = parseAny(raw);
      if (parsed.format === "zqlu") {
        result.value = encodeOpenSsh(parsed);
        resultLabelNode.textContent = "OpenSSH Key";
      } else {
        result.value = encodeZqlu(parsed.keyType, parsed.payload);
        resultLabelNode.textContent = "zqlu Key";
      }
      copyButton.disabled = false;
      keyTypeNode.textContent = KEY_TYPE_LABELS[parsed.keyType] || parsed.keyType;
      fingerprintNode.textContent = await computeFingerprint(parsed);
      setStatus("Key parsed successfully.");
    } catch (error) {
      result.value = "";
      resultLabelNode.textContent = "Converted Key";
      copyButton.disabled = true;
      keyTypeNode.textContent = "-";
      fingerprintNode.textContent = "-";
      setStatus(error instanceof Error ? error.message : String(error), true);
    }
  }

  async function copyResult() {
    if (!result.value) {
      return;
    }

    try {
      await navigator.clipboard.writeText(result.value);
      setStatus("Converted key copied to clipboard.");
    } catch {
      setStatus("Could not copy to clipboard in this browser.", true);
    }
  }

  function setStatus(message, isError = false) {
    status.textContent = message;
    status.className = isError ? "status error" : "status";
  }

  function parseAny(input) {
    const trimmed = input.trim();
    if (trimmed.startsWith(ZQLU_PREFIX)) {
      return parseZqlu(trimmed);
    }
    if (trimmed.startsWith("-----BEGIN PUBLIC KEY-----")) {
      return parsePem(trimmed);
    }
    return parseOpenSsh(trimmed);
  }

  function parseZqlu(input) {
    if (!input.startsWith(ZQLU_PREFIX)) {
      throw new Error("Input must start with 'zq.lu'.");
    }
    if (input.length < 7) {
      throw new Error("zqlu input is too short.");
    }

    const keyType = input[5];
    if (!(keyType in KEY_TYPE_LABELS)) {
      throw new Error("Unsupported zqlu key type.");
    }

    const encoded = input.slice(6).replace(/\s+/g, "");
    if (!encoded) {
      throw new Error("zqlu key is missing payload bytes.");
    }
    if (!/^[0-9A-Za-z]+$/.test(encoded)) {
      throw new Error("zqlu payload contains invalid characters.");
    }

    const keyAndChecksum = decodeBase62(encoded);
    if (keyAndChecksum.length < 3) {
      throw new Error("zqlu payload is too short.");
    }

    const payload = keyAndChecksum.slice(0, -2);
    const expected = crc16IbmSdlc(bytes(ZQLU_PREFIX), bytes(keyType), payload);
    const actual = (keyAndChecksum[keyAndChecksum.length - 2] << 8) | keyAndChecksum[keyAndChecksum.length - 1];
    if (expected !== actual) {
      throw new Error("CRC check failed for zqlu input.");
    }

    return { format: "zqlu", keyType, payload };
  }

  function parseOpenSsh(input) {
    const parts = input.split(/\s+/).filter(Boolean);
    if (parts.length < 2) {
      throw new Error("Expected an OpenSSH public key.");
    }

    const algorithm = parts[0];
    const decoded = decodeBase64(parts[1]);
    const reader = createReader(decoded);
    const wireAlgorithm = decodeUtf8(reader.readString());
    if (wireAlgorithm !== algorithm) {
      throw new Error("OpenSSH algorithm prefix does not match key payload.");
    }

    if (algorithm === "ssh-ed25519") {
      const key = reader.readString();
      if (key.length !== 32) {
        throw new Error("Ed25519 OpenSSH key must be 32 bytes.");
      }
      reader.assertDone();
      return { format: "OpenSSH", keyType: "A", payload: key };
    }

    if (algorithm.startsWith("ecdsa-sha2-")) {
      const curveName = decodeUtf8(reader.readString());
      const point = reader.readString();
      reader.assertDone();
      return {
        format: "OpenSSH",
        ...parseEcPoint(curveName, point)
      };
    }

    if (algorithm === "ssh-rsa") {
      const exponent = parsePositiveMpint(reader.readString(), "RSA exponent");
      const modulus = parsePositiveMpint(reader.readString(), "RSA modulus");
      reader.assertDone();
      return {
        format: "OpenSSH",
        ...encodeRsaPayload(exponent, modulus)
      };
    }

    throw new Error("Unsupported OpenSSH key type.");
  }

  function parsePem(input) {
    const match = input.match(/-----BEGIN PUBLIC KEY-----([\s\S]*?)-----END PUBLIC KEY-----/);
    if (!match) {
      throw new Error("Expected a PEM public key.");
    }

    const der = decodeBase64(match[1].replace(/\s+/g, ""));
    const spki = parseSubjectPublicKeyInfo(der);

    if (spki.algorithmOid === OID_ED25519) {
      if (spki.algorithmParameters !== null) {
        throw new Error("Ed25519 PEM keys must not include algorithm parameters.");
      }
      if (spki.subjectPublicKey.length !== 32) {
        throw new Error("Ed25519 PEM key must contain a 32-byte public key.");
      }
      return { format: "PEM/SPKI", keyType: "A", payload: spki.subjectPublicKey };
    }

    if (spki.algorithmOid === OID_EC_PUBLIC_KEY) {
      if (spki.algorithmParameters === null) {
        throw new Error("EC PEM key is missing its curve OID.");
      }
      const curveName = curveNameFromOid(spki.algorithmParameters);
      return {
        format: "PEM/SPKI",
        ...parseEcPoint(curveName, spki.subjectPublicKey)
      };
    }

    if (spki.algorithmOid === OID_RSA_ENCRYPTION) {
      if (spki.algorithmParameters !== null) {
        throw new Error("RSA PEM keys must use NULL or absent algorithm parameters.");
      }
      return {
        format: "PEM/SPKI",
        ...parseRsaPublicKey(spki.subjectPublicKey)
      };
    }

    throw new Error("Unsupported PEM public key type.");
  }

  function parseEcPoint(curveName, point) {
    const curve = CURVE_TO_TYPES[curveName];
    if (!curve) {
      throw new Error("Unsupported EC curve.");
    }
    const expectedLength = 1 + curve.xLength * 2;
    if (point.length !== expectedLength) {
      throw new Error(`Unexpected ${curve.label} point length.`);
    }
    if (point[0] !== 0x04) {
      throw new Error("Only uncompressed EC public keys are supported.");
    }

    const x = point.slice(1, 1 + curve.xLength);
    const yLastByte = point[point.length - 1];
    return {
      keyType: yLastByte % 2 === 0 ? curve.even : curve.odd,
      payload: x
    };
  }

  function parseRsaPublicKey(der) {
    const reader = createAsn1Reader(der);
    const outer = reader.readElement(0x30);
    reader.assertDone();

    const rsaReader = createAsn1Reader(outer.value);
    const modulus = parsePositiveDerInteger(rsaReader.readElement(0x02).value, "RSA modulus");
    const exponent = parsePositiveDerInteger(rsaReader.readElement(0x02).value, "RSA exponent");
    rsaReader.assertDone();
    return encodeRsaPayload(exponent, modulus);
  }

  function encodeRsaPayload(exponent, modulus) {
    if (bytesEqual(exponent, RSA_F4) && RSA_FIXED_TYPES[modulus.length]) {
      return {
        keyType: RSA_FIXED_TYPES[modulus.length],
        payload: modulus
      };
    }

    return {
      keyType: "K",
      payload: concatBytes(
        encodeVarint(exponent.length),
        exponent,
        encodeVarint(modulus.length),
        modulus
      )
    };
  }

  function encodeZqlu(keyType, payload) {
    const checksum = crc16IbmSdlc(bytes(ZQLU_PREFIX), bytes(keyType), payload);
    const combined = new Uint8Array(payload.length + 2);
    combined.set(payload, 0);
    combined[payload.length] = checksum >> 8;
    combined[payload.length + 1] = checksum & 0xff;
    return `${ZQLU_PREFIX}${keyType}${encodeBase62(combined)}`;
  }

  async function computeFingerprint(parsed) {
    const keyBlob = buildOpenSshBlob(parsed);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", keyBlob));
    return `SHA256:${base64Encode(digest).replace(/=+$/g, "")}`;
  }

  function buildOpenSshBlob(parsed) {
    if (parsed.keyType === "A") {
      return concatBytes(
        sshString(bytes("ssh-ed25519")),
        sshString(parsed.payload)
      );
    }

    if (isRsaType(parsed.keyType)) {
      const rsa = decodeRsaPayload(parsed.keyType, parsed.payload);
      return concatBytes(
        sshString(bytes("ssh-rsa")),
        sshString(toOpenSshMpint(rsa.exponent, "RSA exponent")),
        sshString(toOpenSshMpint(rsa.modulus, "RSA modulus"))
      );
    }

    const curveName = KEY_TYPE_TO_CURVE[parsed.keyType];
    if (!curveName) {
      throw new Error("Unsupported key type for fingerprint generation.");
    }
    const algorithm = `ecdsa-sha2-${curveName}`;
    const point = encodeEcPoint(parsed.keyType, parsed.payload);
    return concatBytes(
      sshString(bytes(algorithm)),
      sshString(bytes(curveName)),
      sshString(point)
    );
  }

  function encodeOpenSsh(parsed) {
    const keyBlob = buildOpenSshBlob(parsed);
    let algorithm;
    if (parsed.keyType === "A") {
      algorithm = "ssh-ed25519";
    } else if (isRsaType(parsed.keyType)) {
      algorithm = "ssh-rsa";
    } else {
      algorithm = `ecdsa-sha2-${KEY_TYPE_TO_CURVE[parsed.keyType]}`;
    }
    return `${algorithm} ${base64Encode(keyBlob)}`;
  }

  function decodeRsaPayload(keyType, payload) {
    const fixedLength = RSA_FIXED_LENGTHS[keyType];
    if (fixedLength !== undefined) {
      if (payload.length !== fixedLength) {
        throw new Error("Invalid RSA modulus length.");
      }
      return {
        exponent: RSA_F4,
        modulus: payload
      };
    }

    if (keyType !== "K") {
      throw new Error("Unsupported RSA key type.");
    }

    const reader = createValueReader(payload);
    const exponent = reader.readLengthValue("RSA exponent");
    const modulus = reader.readLengthValue("RSA modulus");
    reader.assertDone();
    return { exponent, modulus };
  }

  function createValueReader(data) {
    let offset = 0;
    return {
      readLengthValue(fieldName) {
        const varint = readVarint(data, offset);
        const length = varint.value;
        offset = varint.nextOffset;
        if (length === 0) {
          throw new Error(`${fieldName} is empty.`);
        }
        if (offset + length > data.length) {
          throw new Error(`${fieldName} length exceeds remaining RSA key data.`);
        }
        const value = data.slice(offset, offset + length);
        offset += length;
        rejectLeadingZero(value, fieldName);
        return value;
      },
      assertDone() {
        if (offset !== data.length) {
          throw new Error("RSA key has trailing data.");
        }
      }
    };
  }

  function readVarint(data, initialOffset) {
    let value = 0;
    let shift = 0;
    let offset = initialOffset;

    while (offset < data.length) {
      const byte = data[offset];
      value += (byte & 0x7f) * (2 ** shift);
      offset += 1;
      if ((byte & 0x80) === 0) {
        return { value, nextOffset: offset };
      }
      shift += 7;
      if (shift >= 53) {
        throw new Error("RSA length varint overflow.");
      }
    }

    throw new Error("Truncated RSA length varint.");
  }

  function encodeVarint(value) {
    const bytesOut = [];
    let current = value;
    while (current >= 0x80) {
      bytesOut.push((current & 0x7f) | 0x80);
      current = Math.floor(current / 0x80);
    }
    bytesOut.push(current);
    return Uint8Array.from(bytesOut);
  }

  function parsePositiveMpint(value, fieldName) {
    if (value.length === 0) {
      throw new Error(`${fieldName} is empty.`);
    }
    if (value[0] === 0) {
      const withoutSignPadding = value.slice(1);
      if (withoutSignPadding.length === 0) {
        throw new Error(`${fieldName} must be positive.`);
      }
      rejectLeadingZero(withoutSignPadding, fieldName);
      return withoutSignPadding;
    }
    if (value[0] & 0x80) {
      throw new Error(`${fieldName} is not a positive mpint.`);
    }
    rejectLeadingZero(value, fieldName);
    return value;
  }

  function parsePositiveDerInteger(value, fieldName) {
    if (value.length === 0) {
      throw new Error(`${fieldName} is empty.`);
    }
    if (value[0] & 0x80) {
      throw new Error(`${fieldName} is negative.`);
    }
    if (value[0] === 0) {
      const withoutSignPadding = value.slice(1);
      if (withoutSignPadding.length === 0) {
        throw new Error(`${fieldName} must be positive.`);
      }
      rejectLeadingZero(withoutSignPadding, fieldName);
      return withoutSignPadding;
    }
    rejectLeadingZero(value, fieldName);
    return value;
  }

  function toOpenSshMpint(value, fieldName) {
    if (value.length === 0) {
      throw new Error(`${fieldName} is empty.`);
    }
    rejectLeadingZero(value, fieldName);
    if (value[0] & 0x80) {
      return concatBytes(Uint8Array.of(0), value);
    }
    return value;
  }

  function rejectLeadingZero(value, fieldName) {
    if (value[0] === 0) {
      throw new Error(`${fieldName} contains a leading zero octet.`);
    }
  }

  function isRsaType(keyType) {
    return keyType === "B" || keyType === "I" || keyType === "J" || keyType === "K";
  }

  function encodeEcPoint(keyType, xBytes) {
    const curveName = KEY_TYPE_TO_CURVE[keyType];
    const params = CURVE_PARAMS[curveName];
    const x = bytesToBigInt(xBytes);
    const y = recoverY(curveName, x, keyType === "D" || keyType === "F" || keyType === "H");
    return concatBytes(Uint8Array.of(0x04), xBytes, bigIntToBytes(y, params.size));
  }

  function recoverY(curveName, x, wantEven) {
    const params = CURVE_PARAMS[curveName];
    const { p, b } = params;
    const rhs = mod(modPow(x, 3n, p) - mod(3n * x, p) + b, p);
    let y = modPow(rhs, (p + 1n) / 4n, p);
    if (modPow(y, 2n, p) !== rhs) {
      throw new Error("Failed to reconstruct EC point from zqlu key.");
    }
    const isEven = (y & 1n) === 0n;
    if (isEven !== wantEven) {
      y = mod(-y, p);
    }
    return y;
  }

  function mod(value, modulus) {
    const result = value % modulus;
    return result >= 0n ? result : result + modulus;
  }

  function modPow(base, exponent, modulus) {
    let result = 1n;
    let factor = mod(base, modulus);
    let power = exponent;
    while (power > 0n) {
      if (power & 1n) {
        result = mod(result * factor, modulus);
      }
      factor = mod(factor * factor, modulus);
      power >>= 1n;
    }
    return result;
  }

  function bytesToBigInt(data) {
    let result = 0n;
    for (const byte of data) {
      result = (result << 8n) | BigInt(byte);
    }
    return result;
  }

  function bigIntToBytes(value, size) {
    const out = new Uint8Array(size);
    let current = value;
    for (let i = size - 1; i >= 0; i -= 1) {
      out[i] = Number(current & 0xffn);
      current >>= 8n;
    }
    return out;
  }

  function hexToBigInt(hex) {
    return BigInt(`0x${hex}`);
  }

  function sshString(data) {
    const out = new Uint8Array(4 + data.length);
    const view = new DataView(out.buffer);
    view.setUint32(0, data.length);
    out.set(data, 4);
    return out;
  }

  function concatBytes(...chunks) {
    const length = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const out = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
      out.set(chunk, offset);
      offset += chunk.length;
    }
    return out;
  }

  function bytesEqual(left, right) {
    if (left.length !== right.length) {
      return false;
    }
    for (let i = 0; i < left.length; i += 1) {
      if (left[i] !== right[i]) {
        return false;
      }
    }
    return true;
  }

  function encodeBase62(data) {
    let leadingZeroes = 0;
    while (leadingZeroes < data.length && data[leadingZeroes] === 0) {
      leadingZeroes += 1;
    }

    const encoded = rawBase62Encode(data);
    if (leadingZeroes === 0) {
      return encoded;
    }
    return "0".repeat(leadingZeroes) + encoded.slice(leadingZeroes);
  }

  function rawBase62Encode(data) {
    let zeros = 0;
    while (zeros < data.length && data[zeros] === 0) {
      zeros += 1;
    }

    let num = Array.from(data);
    let encoded = "";

    while (!num.every((value) => value === 0)) {
      const { quotient, remainder } = divmod62(num);
      encoded += BASE62_ALPHABET[remainder];
      num = quotient;
    }

    for (let i = 0; i < zeros; i += 1) {
      encoded += "1";
    }

    return encoded.split("").reverse().join("");
  }

  function divmod62(num) {
    const quotient = [];
    let remainder = 0;
    for (const digit of num) {
      const value = remainder * 256 + digit;
      remainder = value % 62;
      quotient.push(Math.floor(value / 62));
    }
    while (quotient.length > 1 && quotient[0] === 0) {
      quotient.shift();
    }
    return { quotient, remainder };
  }

  function decodeBase62(input) {
    let num = [0];
    for (const char of input) {
      const value = BASE62_ALPHABET.indexOf(char);
      if (value === -1) {
        continue;
      }

      let carry = value;
      for (let i = 0; i < num.length; i += 1) {
        const total = num[i] * 62 + carry;
        num[i] = total & 0xff;
        carry = total >> 8;
      }

      while (carry > 0) {
        num.push(carry & 0xff);
        carry >>= 8;
      }
    }

    let zeroes = 0;
    while (zeroes < input.length && input[zeroes] === "0") {
      zeroes += 1;
    }

    const result = new Uint8Array(zeroes + num.length);
    for (let i = 0; i < num.length; i += 1) {
      result[zeroes + i] = num[num.length - 1 - i];
    }
    return result;
  }

  function crc16IbmSdlc(...chunks) {
    let crc = 0xffff;
    for (const chunk of chunks) {
      for (const byte of chunk) {
        crc ^= reflect8(byte) << 8;
        for (let i = 0; i < 8; i += 1) {
          if (crc & 0x8000) {
            crc = ((crc << 1) ^ 0x1021) & 0xffff;
          } else {
            crc = (crc << 1) & 0xffff;
          }
        }
      }
    }
    return reflect16(crc ^ 0xffff);
  }

  function reflect8(value) {
    let reflected = 0;
    for (let i = 0; i < 8; i += 1) {
      reflected = (reflected << 1) | ((value >> i) & 1);
    }
    return reflected;
  }

  function reflect16(value) {
    let reflected = 0;
    for (let i = 0; i < 16; i += 1) {
      reflected = (reflected << 1) | ((value >> i) & 1);
    }
    return reflected;
  }

  function parseSubjectPublicKeyInfo(der) {
    const reader = createAsn1Reader(der);
    const outer = reader.readElement(0x30);
    reader.assertDone();

    const outerReader = createAsn1Reader(outer.value);
    const algorithmSequence = outerReader.readElement(0x30);
    const bitString = outerReader.readElement(0x03);
    outerReader.assertDone();

    const algorithmReader = createAsn1Reader(algorithmSequence.value);
    const algorithmOid = readOid(algorithmReader.readElement(0x06).value);
    let algorithmParameters = null;
    if (!algorithmReader.done()) {
      const parameterElement = algorithmReader.readAny();
      if (parameterElement.tag === 0x06) {
        algorithmParameters = readOid(parameterElement.value);
      } else if (parameterElement.tag === 0x05 && parameterElement.value.length === 0) {
        algorithmParameters = null;
      } else {
        throw new Error("Unsupported PEM algorithm parameters.");
      }
    }
    algorithmReader.assertDone();

    if (bitString.value.length === 0 || bitString.value[0] !== 0x00) {
      throw new Error("PEM public key contains an invalid BIT STRING.");
    }

    return {
      algorithmOid,
      algorithmParameters,
      subjectPublicKey: bitString.value.slice(1)
    };
  }

  function curveNameFromOid(oid) {
    switch (oid) {
      case OID_P256:
        return "nistp256";
      case OID_P384:
        return "nistp384";
      case OID_P521:
        return "nistp521";
      default:
        throw new Error("Unsupported EC curve OID.");
    }
  }

  function readOid(bytesValue) {
    if (bytesValue.length === 0) {
      throw new Error("OID is empty.");
    }
    const values = [];
    const first = bytesValue[0];
    values.push(Math.floor(first / 40));
    values.push(first % 40);

    let current = 0;
    for (let i = 1; i < bytesValue.length; i += 1) {
      current = (current << 7) | (bytesValue[i] & 0x7f);
      if ((bytesValue[i] & 0x80) === 0) {
        values.push(current);
        current = 0;
      }
    }
    if ((bytesValue[bytesValue.length - 1] & 0x80) !== 0) {
      throw new Error("OID terminated unexpectedly.");
    }

    return values.join(".");
  }

  function createReader(data) {
    let offset = 0;
    return {
      readString() {
        const length = this.readUint32();
        if (offset + length > data.length) {
          throw new Error("OpenSSH key ended unexpectedly.");
        }
        const value = data.slice(offset, offset + length);
        offset += length;
        return value;
      },
      readUint32() {
        if (offset + 4 > data.length) {
          throw new Error("OpenSSH key ended unexpectedly.");
        }
        const value =
          (data[offset] << 24) |
          (data[offset + 1] << 16) |
          (data[offset + 2] << 8) |
          data[offset + 3];
        offset += 4;
        return value >>> 0;
      },
      assertDone() {
        if (offset !== data.length) {
          throw new Error("OpenSSH key has trailing data.");
        }
      }
    };
  }

  function createAsn1Reader(data) {
    let offset = 0;
    return {
      readAny() {
        if (offset >= data.length) {
          throw new Error("ASN.1 data ended unexpectedly.");
        }
        const tag = data[offset++];
        const length = readAsn1Length(data, offset - 1);
        offset = length.nextOffset;
        const end = offset + length.length;
        if (end > data.length) {
          throw new Error("ASN.1 element length exceeds input.");
        }
        const value = data.slice(offset, end);
        offset = end;
        return { tag, value };
      },
      readElement(expectedTag) {
        const element = this.readAny();
        if (element.tag !== expectedTag) {
          throw new Error("Unexpected ASN.1 structure.");
        }
        return element;
      },
      done() {
        return offset === data.length;
      },
      assertDone() {
        if (offset !== data.length) {
          throw new Error("ASN.1 data has trailing bytes.");
        }
      }
    };
  }

  function readAsn1Length(data, offsetAfterTag) {
    const first = data[offsetAfterTag + 1];
    if (first === undefined) {
      throw new Error("ASN.1 length missing.");
    }

    if ((first & 0x80) === 0) {
      return { length: first, nextOffset: offsetAfterTag + 2 };
    }

    const byteCount = first & 0x7f;
    if (byteCount === 0 || byteCount > 4) {
      throw new Error("Unsupported ASN.1 length encoding.");
    }

    let length = 0;
    let index = offsetAfterTag + 2;
    for (let i = 0; i < byteCount; i += 1) {
      if (index >= data.length) {
        throw new Error("ASN.1 length ended unexpectedly.");
      }
      length = (length << 8) | data[index];
      index += 1;
    }
    return { length, nextOffset: index };
  }

  function decodeBase64(input) {
    try {
      return Uint8Array.from(atob(input), (char) => char.charCodeAt(0));
    } catch {
      throw new Error("Invalid base64 payload.");
    }
  }

  function decodeUtf8(input) {
    return new TextDecoder().decode(input);
  }

  function base64Encode(input) {
    let binary = "";
    for (const byte of input) {
      binary += String.fromCharCode(byte);
    }
    return btoa(binary);
  }

  function bytes(value) {
    return new TextEncoder().encode(value);
  }
});
