/**
 * JWT Decoder
 * Decode and inspect JSON Web Tokens
 *
 * Online tool: https://devtools.at/tools/jwt-decoder
 *
 * @packageDocumentation
 */

function base64UrlDecode(str: string): string {
  // Replace Base64URL chars with Base64 chars
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');

  // Pad with = to make length multiple of 4
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }

  try {
    // Decode Base64 to binary string
    const binary = atob(base64);
    // Convert binary string to UTF-8
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    const decoder = new TextDecoder('utf-8');
    return decoder.decode(bytes);
  } catch {
    throw new Error('Invalid Base64URL encoding');
  }
}

function decodeJWT(token: string): DecodedJWT {
  const parts = token.trim().split('.');

  if (parts.length !== 3) {
    throw new Error('Invalid JWT format. Expected 3 parts separated by dots.');
  }

  const [headerStr, payloadStr, signature] = parts;

  if (!headerStr || !payloadStr) {
    throw new Error('JWT header or payload is empty');
  }

  try {
    const headerJson = base64UrlDecode(headerStr);
    const payloadJson = base64UrlDecode(payloadStr);

    const header = JSON.parse(headerJson);
    const payload = JSON.parse(payloadJson);

    return {
      header,
      payload,
      signature,
      raw: {
        header: headerStr,
        payload: payloadStr,
        signature,
      },
    };
  } catch (err) {
    if (err instanceof Error) {
      throw new Error(`Failed to decode JWT: ${err.message}`);
    }
    throw new Error('Failed to decode JWT: Unknown error');
  }
}

function formatTimestamp(timestamp: number): string {
  const date = new Date(timestamp * 1000);
  return date.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZoneName: 'short',
  });
}

function getTokenStatus(payload: Record<string, unknown>): TokenStatus {
  const now = Math.floor(Date.now() / 1000);
  const exp = typeof payload.exp === 'number' ? payload.exp : null;
  const nbf = typeof payload.nbf === 'number' ? payload.nbf : null;

  if (exp !== null) {
    if (now >= exp) {
      return {
        type: 'expired',
        message: `Token expired on ${formatTimestamp(exp)}`,
      };
    }
  }

  if (nbf !== null) {
    if (now < nbf) {
      return {
        type: 'not_yet_valid',
        message: `Token not valid until ${formatTimestamp(nbf)}`,
      };
    }
  }

  if (exp !== null) {
    return {
      type: 'valid',
      message: `Token valid until ${formatTimestamp(exp)}`,
    };
  }

  return {
    type: 'no_expiration',
    message: 'Token has no expiration (not recommended)',
  };
}

// Export for convenience
export default { encode, decode };
