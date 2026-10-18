"use strict";

import { satisfiesIdnaBidiRule } from "./idnaBidi.js";

const PUNYCODE_OVERFLOW_MESSAGE = "punycode label overflow";

function invalidDomainIdLabel(context, message) {
  throw new TypeError(`${context} ${message}`);
}

function decodePunycodeLabel(input) {
  const output = [];
  const delimiter = input.lastIndexOf("-");
  let cursor = 0;
  if (delimiter >= 0) {
    for (const character of input.slice(0, delimiter)) {
      if (character.codePointAt(0) >= 0x80) {
        throw new Error("punycode basic segment is not ASCII");
      }
      output.push(character.codePointAt(0));
    }
    cursor = delimiter + 1;
  }
  let codePoint = 128;
  let bias = 72;
  let accumulator = 0;
  const adapt = (delta, length, first) => {
    let value = first ? Math.floor(delta / 700) : Math.floor(delta / 2);
    value += Math.floor(value / length);
    let scale = 0;
    while (value > 455) {
      value = Math.floor(value / 35);
      scale += 36;
    }
    return scale + Math.floor((36 * value) / (value + 38));
  };
  const digit = (character) => {
    const value = character.codePointAt(0);
    if (value >= 0x30 && value <= 0x39) return value - 0x30 + 26;
    if (value >= 0x41 && value <= 0x5a) return value - 0x41;
    if (value >= 0x61 && value <= 0x7a) return value - 0x61;
    throw new Error("invalid punycode digit");
  };
  while (cursor < input.length) {
    const previous = accumulator;
    let weight = 1;
    for (let thresholdIndex = 36; ; thresholdIndex += 36) {
      if (cursor >= input.length) throw new Error("truncated punycode label");
      const value = digit(input[cursor]);
      cursor += 1;
      if (value > Math.floor((Number.MAX_SAFE_INTEGER - accumulator) / weight)) {
        throw new Error(PUNYCODE_OVERFLOW_MESSAGE);
      }
      accumulator += value * weight;
      const threshold =
        thresholdIndex <= bias + 1 ? 1 : thresholdIndex >= bias + 26 ? 26 : thresholdIndex - bias;
      if (value < threshold) break;
      const factor = 36 - threshold;
      if (weight > Math.floor(Number.MAX_SAFE_INTEGER / factor)) {
        throw new Error(PUNYCODE_OVERFLOW_MESSAGE);
      }
      weight *= factor;
    }
    const length = output.length + 1;
    bias = adapt(accumulator - previous, length, previous === 0);
    const increment = Math.floor(accumulator / length);
    if (increment > 0x10ffff - codePoint) throw new Error("punycode code point overflow");
    codePoint += increment;
    const insertion = accumulator % length;
    if (codePoint >= 0xd800 && codePoint <= 0xdfff) {
      throw new Error("punycode decoded a surrogate");
    }
    output.splice(insertion, 0, codePoint);
    accumulator = insertion + 1;
  }
  return String.fromCodePoint(...output);
}

/** Canonicalize one explicit DomainId label for Norito encoding. */
export function canonicalizeDomainIdLabel(value, context = "DomainId label") {
  if (typeof value !== "string") {
    invalidDomainIdLabel(context, "must be a string");
  }
  const trimmed = value.trim();
  if (trimmed !== value) {
    invalidDomainIdLabel(context, "must not contain surrounding whitespace");
  }
  if (trimmed.length === 0) {
    invalidDomainIdLabel(context, "must be non-empty");
  }
  if (/\s/u.test(trimmed)) {
    invalidDomainIdLabel(context, "must not contain whitespace");
  }
  if (/[@#$]/u.test(trimmed)) {
    invalidDomainIdLabel(context, "must not contain reserved identifier characters");
  }

  let normalized;
  try {
    normalized = trimmed.normalize("NFC");
  } catch {
    invalidDomainIdLabel(context, "could not be normalized");
  }
  if (/[\u1E00-\u1EFF]/u.test(normalized)) {
    invalidDomainIdLabel(context, "contains an extended Latin character rejected by policy");
  }
  for (const character of normalized) {
    const code = character.charCodeAt(0);
    const isAsciiDigit = code >= 0x30 && code <= 0x39;
    const isAsciiUpper = code >= 0x41 && code <= 0x5a;
    const isAsciiLower = code >= 0x61 && code <= 0x7a;
    if (
      code <= 0x7f &&
      !isAsciiDigit &&
      !isAsciiUpper &&
      !isAsciiLower &&
      character !== "." &&
      character !== "_" &&
      character !== "-"
    ) {
      invalidDomainIdLabel(context, "contains an ASCII delimiter rejected by policy");
    }
  }

  let ascii;
  try {
    ascii = new URL(`http://${normalized}/`).hostname;
  } catch {
    invalidDomainIdLabel(context, "failed UTS-46 ASCII canonicalization");
  }
  if (typeof ascii !== "string" || ascii.length === 0) {
    invalidDomainIdLabel(context, "failed UTS-46 ASCII canonicalization");
  }

  const canonical = ascii.toLowerCase();
  if (canonical.length === 0 || canonical.length > 63) {
    invalidDomainIdLabel(context, "must contain between 1 and 63 characters");
  }
  if (canonical.startsWith("-") || canonical.endsWith("-")) {
    invalidDomainIdLabel(context, "must not start or end with a hyphen");
  }
  if (
    canonical.length >= 4 &&
    canonical[2] === "-" &&
    canonical[3] === "-" &&
    !canonical.startsWith("xn--")
  ) {
    invalidDomainIdLabel(context, "must not contain a double hyphen in positions three and four");
  }
  if (canonical.startsWith("xn--")) {
    try {
      const decoded = decodePunycodeLabel(canonical.slice(4));
      if (!satisfiesIdnaBidiRule(decoded)) {
        throw new Error("punycode label violates the UTS-46 Bidi rule");
      }
      if (new URL(`http://${decoded}/`).hostname.toLowerCase() !== canonical) {
        throw new Error("punycode label does not round-trip through UTS-46");
      }
    } catch {
      invalidDomainIdLabel(context, "contains invalid ACE punycode");
    }
  }
  for (let index = 0; index < canonical.length; index += 1) {
    const code = canonical.charCodeAt(index);
    const isDigit = code >= 0x30 && code <= 0x39;
    const isLower = code >= 0x61 && code <= 0x7a;
    const isAllowed =
      isDigit || isLower || canonical[index] === "-" || canonical[index] === "_";
    if (!isAllowed) {
      invalidDomainIdLabel(context, "contains an unsupported character");
    }
  }
  return canonical;
}

/**
 * Canonicalize one fully qualified `domain.dataspace` DomainId literal.
 *
 * Both labels use {@link canonicalizeDomainIdLabel}; the result is the native
 * `DomainId` display form.
 */
export function canonicalizeDomainId(value, context = "DomainId") {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${context} must be a non-empty string`);
  }
  if (value.trim() !== value) {
    throw new TypeError(`${context} must not contain surrounding whitespace`);
  }
  const segments = value.split(".");
  if (segments.length !== 2 || segments.some((segment) => segment.length === 0)) {
    throw new TypeError(`${context} must use the exact domain.dataspace form`);
  }
  return segments
    .map((segment) => canonicalizeDomainIdLabel(segment, `${context} label`))
    .join(".");
}
