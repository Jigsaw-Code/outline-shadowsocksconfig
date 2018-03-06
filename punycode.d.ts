// Copyright 2018 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * Converts a Punycode string of ASCII-only symbols to a string of Unicode
 * symbols.
 *
 * ```js
 * // decode domain name parts
 * punycode.decode('maana-pta'); // 'mañana'
 * punycode.decode('--dqo34k'); // '☃-⌘'
 * ```
 *
 * @param {string} input The Punycode string of ASCII-only symbols.
 * @returns {string} The resulting string of Unicode symbols.
 */
export function decode(input: string): string;

/**
 * Converts a string of Unicode symbols (e.g. a domain name label) to a
 * Punycode string of ASCII symbols.
 *
 * ```js
 * // encode domain name parts
 * punycode.encode('mañana'); // 'maana-pta'
 * punycode.encode('☃-⌘'); // '--dqo34k'
 * ```
 *
 * @param {string} input The string of Unicode symbols.
 * @returns {string} The resulting Punycode string of ASCII-only symbols.
 */
export function encode(input: string): string;

/**
 * Converts a Punycode string representing a domain name or an email address
 * to Unicode. Only the Punycoded parts of the input will be converted,
 * i.e. it doesn’t matter if you call it on a string that has already been
 * converted to Unicode.
 *
 * ```js
 * // decode domain names
 * punycode.toUnicode('xn--maana-pta.com');
 * // → 'mañana.com'
 * punycode.toUnicode('xn----dqo34k.com');
 * // → '☃-⌘.com'
 *
 * // decode email addresses
 * punycode.toUnicode('джумла@xn--p-8sbkgc5ag7bhce.xn--ba-lmcq');
 * // → 'джумла@джpумлатест.bрфa'
 * ```
 *
 * @param {string} input The Punycoded domain name or email address to
 * convert to Unicode.
 * @returns {string} The Unicode representation of the given Punycode
 * string.
 */
export function toUnicode(input: string): string;

/**
 * Converts a lowercased Unicode string representing a domain name or an
 * email address to Punycode. Only the non-ASCII parts of the input will be
 * converted, i.e. it doesn’t matter if you call it with a domain that’s
 * already in ASCII.
 *
 * ```js
 * // encode domain names
 * punycode.toASCII('mañana.com');
 * // → 'xn--maana-pta.com'
 * punycode.toASCII('☃-⌘.com');
 * // → 'xn----dqo34k.com'
 *
 * // encode email addresses
 * punycode.toASCII('джумла@джpумлатест.bрфa');
 * // → 'джумла@xn--p-8sbkgc5ag7bhce.xn--ba-lmcq'
 * ```
 *
 * @param {string} input The domain name or email address to convert, as a
 * Unicode string.
 * @returns {string} The Punycode representation of the given domain name or
 * email address.
 */
export function toASCII(input: string): string;

/**
 * An object of methods to convert from JavaScript's internal character
 * representation (UCS-2) to Unicode code points, and back.
 *
 * @see <https://mathiasbynens.be/notes/javascript-encoding>
 */
export namespace ucs2 {
  /**
   * Creates an array containing the numeric code points of each Unicode
   * character in the string. While JavaScript uses UCS-2 internally,
   * this function will convert a pair of surrogate halves (each of which
   * UCS-2 exposes as separate characters) into a single code point,
   * matching UTF-16.
   *
   * ```js
   * punycode.ucs2.decode('abc');
   * // → [0x61, 0x62, 0x63]
   * // surrogate pair for U+1D306 TETRAGRAM FOR CENTRE:
   * punycode.ucs2.decode('\uD834\uDF06');
   * // → [0x1D306]
   * ```
   *
   * @see `punycode.ucs2.encode`
   * @see <https://mathiasbynens.be/notes/javascript-encoding>
   * @param {string} string The Unicode input string (UCS-2).
   * @returns {number[]} The new array of code points.
   */
  export function decode(string: string): number[];

  /**
   * Creates a string based on an array of numeric code point values.
   *
   * ```js
   * punycode.ucs2.encode([0x61, 0x62, 0x63]);
   * // → 'abc'
   * punycode.ucs2.encode([0x1D306]);
   * // → '\uD834\uDF06'
   * ```
   *
   * @see `punycode.ucs2.decode`
   * @param {number[]} codePoints The array of numeric code points.
   * @returns {string} The new Unicode string (UCS-2).
   */
  export function encode(codePoints: number[]): string;
}

/**
 * A string representing the current Punycode.js version number.
 */
export const version: string;
