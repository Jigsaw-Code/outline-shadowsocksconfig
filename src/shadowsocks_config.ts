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

import * as ipaddr from 'ipaddr.js';
import {Base64} from 'js-base64';
import * as punycode from 'punycode';
import {URLSearchParams} from 'url';

// Custom error base class
export class ShadowsocksConfigError extends Error {
  constructor(message: string) {
    super(message);  // 'Error' breaks prototype chain here if this is transpiled to es5
    Object.setPrototypeOf(this, new.target.prototype);  // restore prototype chain
    this.name = new.target.name;
  }
}

export class InvalidConfigField extends ShadowsocksConfigError {}

export class InvalidUri extends ShadowsocksConfigError {}

// Self-validating/normalizing config data types implement this ValidatedConfigField interface.
// Constructors take some data, validate, normalize, and store if valid, or throw otherwise.
export abstract class ValidatedConfigField {}

function throwErrorForInvalidField(name: string, value: {}, reason?: string) {
  throw new InvalidConfigField(`Invalid ${name}: ${value} ${reason || ''}`);
}

export class Host extends ValidatedConfigField {
  public static HOSTNAME_PATTERN = /^[A-z0-9]+[A-z0-9_.-]*$/;
  public readonly data: string;
  public readonly isIPv4: boolean = false;
  public readonly isIPv6: boolean = false;
  public readonly isHostname: boolean = false;

  constructor(host: Host | string) {
    super();
    if (!host) {
      throwErrorForInvalidField('host', host);
    }
    if (host instanceof Host) {
      host = host.data;
    }
    if (ipaddr.isValid(host)) {
      const ip = ipaddr.parse(host);
      this.isIPv4 = ip.kind() === 'ipv4';
      this.isIPv6 = ip.kind() === 'ipv6';
      // Previous versions of outline-ShadowsocksConfig only accept
      // IPv6 in normalized (expanded) form, so we normalize the
      // input here to ensure that access keys remain compatible.
      host = ip.toNormalizedString();
    } else {
      host = punycode.toASCII(host) as string;
      this.isHostname = Host.HOSTNAME_PATTERN.test(host);
      if (!this.isHostname) {
        throwErrorForInvalidField('host', host);
      }
    }
    this.data = host;
  }
}

export class Port extends ValidatedConfigField {
  public static readonly PATTERN = /^[0-9]{1,5}$/;
  public readonly data: number;

  constructor(port: Port | string | number) {
    super();
    if (port instanceof Port) {
      port = port.data;
    }
    if (typeof port === 'number') {
      // Stringify in case negative or floating point -> the regex test below will catch.
      port = port.toString();
    }
    if (!Port.PATTERN.test(port)) {
      throwErrorForInvalidField('port', port);
    }
    // Could exceed the maximum port number, so convert to Number to check. Could also have leading
    // zeros. Converting to Number drops those, so we get normalization for free. :)
    port = Number(port);
    if (port > 65535) {
      throwErrorForInvalidField('port', port);
    }
    this.data = port;
  }
}

// A method value must exactly match an element in the set of known ciphers.
// ref: https://github.com/shadowsocks/shadowsocks-libev/blob/10a2d3e3/completions/bash/ss-redir#L5
export const METHODS = new Set([
  'rc4-md5',
  'aes-128-gcm',
  'aes-192-gcm',
  'aes-256-gcm',
  'aes-128-cfb',
  'aes-192-cfb',
  'aes-256-cfb',
  'aes-128-ctr',
  'aes-192-ctr',
  'aes-256-ctr',
  'camellia-128-cfb',
  'camellia-192-cfb',
  'camellia-256-cfb',
  'bf-cfb',
  'chacha20-ietf-poly1305',
  'salsa20',
  'chacha20',
  'chacha20-ietf',
  'xchacha20-ietf-poly1305',
]);

export class Method extends ValidatedConfigField {
  public readonly data: string;
  constructor(method: Method | string) {
    super();
    if (method instanceof Method) {
      method = method.data;
    }
    if (!METHODS.has(method)) {
      throwErrorForInvalidField('method', method);
    }
    this.data = method;
  }
}

export class Password extends ValidatedConfigField {
  public readonly data: string;

  constructor(password: Password | string) {
    super();
    this.data = password instanceof Password ? password.data : password;
  }
}

export class Tag extends ValidatedConfigField {
  public readonly data: string;

  constructor(tag: Tag | string = '') {
    super();
    this.data = tag instanceof Tag ? tag.data : tag;
  }
}

export interface Config {
  host: Host;
  port: Port;
  method: Method;
  password: Password;
  tag: Tag;
  // Any additional configuration (e.g. `timeout`, SIP003 `plugin`, etc.) may be stored here.
  extra: {[key: string]: string};
}

// tslint:disable-next-line:no-any
export function makeConfig(input: {[key: string]: any}): Config {
  // Use "!" for the required fields to tell tsc that we handle undefined in the
  // ValidatedConfigFields we call; tsc can't figure that out otherwise.
  const config = {
    host: new Host(input.host!),
    port: new Port(input.port!),
    method: new Method(input.method!),
    password: new Password(input.password!),
    tag: new Tag(input.tag),  // input.tag might be undefined but Tag() handles that fine.
    extra: {} as {[key: string]: string},
  };
  // Put any remaining fields in `input` into `config.extra`.
  for (const key of Object.keys(input)) {
    if (!/^(host|port|method|password|tag)$/.test(key)) {
      config.extra[key] = input[key] && input[key].toString();
    }
  }
  return config;
}

export const SHADOWSOCKS_URI = {
  PROTOCOL: 'ss:',

  getUriFormattedHost: (host: Host) => {
    return host.isIPv6 ? `[${host.data}]` : host.data;
  },

  getHash: (tag: Tag) => {
    return tag.data ? `#${encodeURIComponent(tag.data)}` : '';
  },

  validateProtocol: (uri: string) => {
    if (!uri.startsWith(SHADOWSOCKS_URI.PROTOCOL)) {
      throw new InvalidUri(`URI must start with "${SHADOWSOCKS_URI.PROTOCOL}"`);
    }
  },

  parse: (uri: string): Config => {
    let error: Error | undefined;
    for (const uriType of [SIP002_URI, LEGACY_BASE64_URI]) {
      try {
        return uriType.parse(uri);
      } catch (e) {
        error = e;
      }
    }
    if (!(error instanceof InvalidUri)) {
      const originalErrorName = error!.name! || '(Unnamed Error)';
      const originalErrorMessage = error!.message! || '(no error message provided)';
      const originalErrorString = `${originalErrorName}: ${originalErrorMessage}`;
      const newErrorMessage = `Invalid input: ${originalErrorString}`;
      error = new InvalidUri(newErrorMessage);
    }
    throw error;
  },
};

// Ref: https://shadowsocks.org/en/config/quick-guide.html
export const LEGACY_BASE64_URI = {
  parse: (uri: string): Config => {
    SHADOWSOCKS_URI.validateProtocol(uri);
    const hashIndex = uri.indexOf('#');
    const hasTag = hashIndex !== -1;
    const b64EndIndex = hasTag ? hashIndex : uri.length;
    const tagStartIndex = hasTag ? hashIndex + 1 : uri.length;
    const tag = new Tag(decodeURIComponent(uri.substring(tagStartIndex)));
    const b64EncodedData = uri.substring('ss://'.length, b64EndIndex);
    const b64DecodedData = Base64.decode(b64EncodedData);
    const atSignIndex = b64DecodedData.lastIndexOf('@');
    if (atSignIndex === -1) {
      throw new InvalidUri(`Missing "@"`);
    }
    const methodAndPassword = b64DecodedData.substring(0, atSignIndex);
    const methodEndIndex = methodAndPassword.indexOf(':');
    if (methodEndIndex === -1) {
      throw new InvalidUri(`Missing password`);
    }
    const methodString = methodAndPassword.substring(0, methodEndIndex);
    const method = new Method(methodString);
    const passwordStartIndex = methodEndIndex + 1;
    const passwordString = methodAndPassword.substring(passwordStartIndex);
    const password = new Password(passwordString);
    const hostStartIndex = atSignIndex + 1;
    const hostAndPort = b64DecodedData.substring(hostStartIndex);
    const hostEndIndex = hostAndPort.lastIndexOf(':');
    if (hostEndIndex === -1) {
      throw new InvalidUri(`Missing port`);
    }
    const uriFormattedHost = hostAndPort.substring(0, hostEndIndex);
    let host: Host;
    try {
      host = new Host(uriFormattedHost);
    } catch (_) {
      // Could be IPv6 host formatted with surrounding brackets, so try stripping first and last
      // characters. If this throws, give up and let the exception propagate.
      host = new Host(uriFormattedHost.substring(1, uriFormattedHost.length - 1));
    }
    const portStartIndex = hostEndIndex + 1;
    const portString = hostAndPort.substring(portStartIndex);
    const port = new Port(portString);
    const extra = {} as {[key: string]: string};  // empty because LegacyBase64Uri can't hold extra
    return {method, password, host, port, tag, extra};
  },

  stringify: (config: Config) => {
    const {host, port, method, password, tag} = config;
    const hash = SHADOWSOCKS_URI.getHash(tag);
    const data = `${method.data}:${password.data}@${host.data}:${port.data}`;
    let b64EncodedData = Base64.encode(data);
    // Remove "=" padding
    while (b64EncodedData.slice(-1) === '=') {
      b64EncodedData = b64EncodedData.slice(0, -1);
    }
    return `ss://${b64EncodedData}${hash}`;
  },
};

// Ref: https://shadowsocks.org/en/spec/SIP002-URI-Scheme.html
export const SIP002_URI = {
  parse: (uri: string): Config => {
    SHADOWSOCKS_URI.validateProtocol(uri);
    // Can use built-in URL parser for expedience. Just have to replace "ss" with "http" to ensure
    // correct results, otherwise browsers like Safari fail to parse it.
    const inputForUrlParser = `http${uri.substring(2)}`;
    // The built-in URL parser throws as desired when given URIs with invalid syntax.
    const urlParserResult = new URL(inputForUrlParser);
    const uriFormattedHost = urlParserResult.hostname;
    // URI-formatted IPv6 hostnames have surrounding brackets.
    const last = uriFormattedHost.length - 1;
    const brackets = uriFormattedHost[0] === '[' && uriFormattedHost[last] === ']';
    const hostString = brackets ? uriFormattedHost.substring(1, last) : uriFormattedHost;
    const host = new Host(hostString);
    let parsedPort = urlParserResult.port;
    if (!parsedPort && uri.match(/:80($|\/)/g)) {
      // The default URL parser fails to recognize the default port (80) when the URI being parsed
      // is HTTP. Check if the port is present at the end of the string or before the parameters.
      parsedPort = '80';
    }
    const port = new Port(parsedPort);
    const tag = new Tag(decodeURIComponent(urlParserResult.hash.substring(1)));
    const b64EncodedUserInfo = urlParserResult.username.replace(/%3D/g, '=');
    // base64.decode throws as desired when given invalid base64 input.
    const b64DecodedUserInfo = Base64.decode(b64EncodedUserInfo);
    const colonIdx = b64DecodedUserInfo.indexOf(':');
    if (colonIdx === -1) {
      throw new InvalidUri(`Missing password`);
    }
    const methodString = b64DecodedUserInfo.substring(0, colonIdx);
    const method = new Method(methodString);
    const passwordString = b64DecodedUserInfo.substring(colonIdx + 1);
    const password = new Password(passwordString);
    const queryParams = urlParserResult.search.substring(1).split('&');
    const extra = {} as {[key: string]: string};
    for (const pair of queryParams) {
      const [key, value] = pair.split('=', 2);
      if (!key) continue;
      extra[key] = decodeURIComponent(value || '');
    }
    return {method, password, host, port, tag, extra};
  },

  stringify: (config: Config) => {
    const {host, port, method, password, tag, extra} = config;
    const userInfo = Base64.encodeURI(`${method.data}:${password.data}`);
    const uriHost = SHADOWSOCKS_URI.getUriFormattedHost(host);
    const hash = SHADOWSOCKS_URI.getHash(tag);
    let queryString = '';
    for (const key in extra) {
      if (!key) continue;
      queryString += (queryString ? '&' : '?') + `${key}=${encodeURIComponent(extra[key])}`;
    }
    return `ss://${userInfo}@${uriHost}:${port.data}/${queryString}${hash}`;
  },
};

export interface ConfigFetchParams {
  // URL endpoint to retrieve a Shadowsocks configuration.
  readonly url: string;
  // Server cerficate hash.
  readonly certFingerprint?: string;
  // HTTP method to use when accessing `url`.
  readonly httpMethod?: string;
}

export const ONLINE_CONFIG_PROTOCOL = 'ssconf';

// Parses access parameters to retrieve a Shadowsocks proxy config from an
// online config URL. See: https://github.com/shadowsocks/shadowsocks-org/issues/89
export function parseOnlineConfigUrl(url: string): ConfigFetchParams {
  if (!url || !url.startsWith(ONLINE_CONFIG_PROTOCOL)) {
    throw new InvalidUri(`URI must start with "${ONLINE_CONFIG_PROTOCOL}"`);
  }
  // Replace the protocol "ssconf" with "https" to ensure correct results,
  // otherwise some Safari versions fail to parse it.
  const inputForUrlParser = url.replace(new RegExp(`^${ONLINE_CONFIG_PROTOCOL}`), 'https');
  // The built-in URL parser throws as desired when given URIs with invalid syntax.
  const urlParserResult = new URL(inputForUrlParser);
  // Use ValidatedConfigFields subclasses (Host, Port, Tag) to throw on validation failure.
  const uriFormattedHost = urlParserResult.hostname;
  let host: Host;
  try {
    host = new Host(uriFormattedHost);
  } catch (_) {
    // Could be IPv6 host formatted with surrounding brackets, so try stripping first and last
    // characters. If this throws, give up and let the exception propagate.
    host = new Host(uriFormattedHost.substring(1, uriFormattedHost.length - 1));
  }
  // The default URL parser fails to recognize the default HTTPs port (443).
  const port = new Port(urlParserResult.port || '443');
  // Parse extra parameters from the tag, which has the URL search parameters format.
  const tag = new Tag(decodeURIComponent(urlParserResult.hash.substring(1)));
  const params = new URLSearchParams(tag.data);
  return {
    // Build the access URL with the parsed parameters Exclude the query string and tag.
    url: `https://${uriFormattedHost}:${port.data}${urlParserResult.pathname}`,
    certFingerprint: params.get('certFp') || undefined,
    httpMethod: params.get('httpMethod') || undefined
  };
}
