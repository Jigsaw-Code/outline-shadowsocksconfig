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

import {
  Host, Port, Method, Password, Tag, Config, makeConfig,
  SHADOWSOCKS_URI, SIP002_URI, LEGACY_BASE64_URI, InvalidConfigField, InvalidUri,
} from './shadowsocks_config';

describe('shadowsocks_config', () => {
  describe('Config API', () => {
    it('has expected shape', () => {
      const config = makeConfig({
        host: '192.168.100.1',
        port: 8888,
        method: 'chacha20',
        password: 'P@$$W0RD!',
      });
      const host: string = config.host.data;
      const port: number = config.port.data;
      const method: string = config.method.data;
      const password: string = config.password.data;
      expect(host).toEqual('192.168.100.1');
      expect(port).toEqual(8888);
      expect(method).toEqual('chacha20');
      expect(password).toEqual('P@$$W0RD!');
    });
  });

  describe('field validation', () => {
    it('accepts IPv4 address hosts', () => {
      for (const valid of ['127.0.0.1', '8.8.8.8', '192.168.0.1']) {
        const host = new Host(valid);
        expect(host.data).toEqual(valid);
        expect(host.isIPv4).toBeTruthy();
        expect(host.isIPv6).toBeFalsy();
        expect(host.isHostname).toBeFalsy();
      }
    });

    it('accepts IPv6 address hosts', () => {
      // IPv6 '::' shorthand is unsupported, so '::1' would fail here.
      for (const valid of ['0:0:0:0:0:0:0:1', '2001:0:ce49:7601:e866:efff:62c3:fffe']) {
        const host = new Host(valid);
        expect(host.data).toEqual(valid);
        expect(host.isIPv4).toBeFalsy();
        expect(host.isIPv6).toBeTruthy();
        expect(host.isHostname).toBeFalsy();
      }
    });

    it('accepts valid hostname hosts', () => {
      for (const valid of ['localhost', 'example.com']) {
        const host = new Host(valid);
        expect(host.data).toEqual(valid);
        expect(host.isIPv4).toBeFalsy();
        expect(host.isIPv6).toBeFalsy();
        expect(host.isHostname).toBeTruthy();
      }
    });

    it('accepts valid unicode hostnames and converts them to punycode', () => {
      const testCases = [['mañana.com', 'xn--maana-pta.com'], ['☃-⌘.com', 'xn----dqo34k.com']];
      for (const [input, converted] of testCases) {
        const host = new Host(input);
        expect(host.data).toEqual(converted);
        expect(host.isIPv6).toBeFalsy();
        expect(host.isIPv4).toBeFalsy();
        expect(host.isHostname).toBeTruthy();
      }
    });

    it('rejects invalid host values', () => {
      for (const invalid of ['-', '-pwned', ';echo pwned', '.', '....']) {
        expect(() => new Host(invalid)).toThrowError(InvalidConfigField);
      }
    });

    it('throws on empty host', () => {
      expect(() => new Host('')).toThrowError(InvalidConfigField);
    });

    it('accepts valid ports', () => {
      expect(new Port('8388').data).toEqual(8388);
      expect(new Port('443').data).toEqual(443);
      expect(new Port(8388).data).toEqual(8388);
      expect(new Port(443).data).toEqual(443);
    });

    it('throws on empty port', () => {
      expect(() => new Port('')).toThrowError(InvalidConfigField);
    });

    it('throws on invalid port', () => {
      expect(() => new Port('foo')).toThrowError(InvalidConfigField);
      expect(() => new Port('-123')).toThrowError(InvalidConfigField);
      expect(() => new Port('123.4')).toThrowError(InvalidConfigField);
      expect(() => new Port('123.4')).toThrowError(InvalidConfigField);
      expect(() => new Port(-123)).toThrowError(InvalidConfigField);
      expect(() => new Port(123.4)).toThrowError(InvalidConfigField);
      // Maximum port number possible is 65535.
      expect(() => new Port(65536)).toThrowError(InvalidConfigField);
    });

    it('normalizes non-normalized but valid port', () => {
      expect(new Port('01234').data).toEqual(1234);
    });

    it('throws on empty method', () => {
      expect(() => new Method('')).toThrowError(InvalidConfigField);
    });

    it('throws on invalid method', () => {
      expect(() => new Method('foo')).toThrowError(InvalidConfigField);
    });

    it('accepts valid methods', () => {
      for (const method
               of ['rc4-md5',
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
      ]) {
        expect(new Method(method).data).toEqual(method);
      }
    });

    it('accepts empty password', () => {
      expect(new Password('').data).toEqual('');
    });

    it('accepts empty or undefined tag', () => {
      expect(new Tag('').data).toEqual('');
      expect(new Tag().data).toEqual('');
    });

    it('throws on Config with missing or invalid fields', () => {
      expect(() => makeConfig({
        host: '192.168.100.1',
        port: '8989',
      })).toThrowError(InvalidConfigField);

      expect(() => makeConfig({
        method: 'aes-128-gcm',
        password: 'test',
      })).toThrowError(InvalidConfigField);
    });

    it('throw on invalid configs', () => {
      expect(() => makeConfig({
        port: 'foo',
        method: 'aes-128-gcm',
      })).toThrowError(InvalidConfigField);

      expect(() => makeConfig({
        port: '1337',
        method: 'foo',
      })).toThrowError(InvalidConfigField);
    });
  });

  describe('URI serializer', () => {

    it('can serialize a SIP002 URI', () => {
      const config = makeConfig({
        host: '192.168.100.1',
        port: '8888',
        method: 'aes-128-gcm',
        password: 'test',
        tag: 'Foo Bar',
      });
      expect(SIP002_URI.stringify(config)).toEqual(
        'ss://YWVzLTEyOC1nY206dGVzdA==@192.168.100.1:8888/#Foo%20Bar');
    });

    it('can serialize a SIP002 URI with IPv6 host', () => {
      const config = makeConfig({
        host: '2001:0:ce49:7601:e866:efff:62c3:fffe',
        port: '8888',
        method: 'aes-128-gcm',
        password: 'test',
        tag: 'Foo Bar',
      });
      expect(SIP002_URI.stringify(config)).toEqual(
        'ss://YWVzLTEyOC1nY206dGVzdA==@[2001:0:ce49:7601:e866:efff:62c3:fffe]:8888/#Foo%20Bar');
    });

    it('can serialize a legacy base64 URI', () => {
      const config = makeConfig({
        host: '192.168.100.1',
        port: '8888',
        method: 'bf-cfb',
        password: 'test',
        tag: 'Foo Bar',
      });
      expect(LEGACY_BASE64_URI.stringify(config)).toEqual(
        'ss://YmYtY2ZiOnRlc3RAMTkyLjE2OC4xMDAuMTo4ODg4#Foo%20Bar');
    });
  });

  describe('URI parser', () => {

    it('exposes a PROTOCOL property with value "ss:"', () => {
      expect(SHADOWSOCKS_URI.PROTOCOL).toEqual('ss:');
    });

    it('can parse a valid SIP002 URI with IPv4 host', () => {
      const input = 'ss://YWVzLTEyOC1nY206dGVzdA==@192.168.100.1:8888#Foo%20Bar';
      const config = SHADOWSOCKS_URI.parse(input);
      expect(config.method.data).toEqual('aes-128-gcm');
      expect(config.password.data).toEqual('test');
      expect(config.host.data).toEqual('192.168.100.1');
      expect(config.port.data).toEqual(8888);
      expect(config.tag.data).toEqual('Foo Bar');
    });

    it('can parse a valid SIP002 URI with IPv6 host', () => {
      const input = 'ss://YWVzLTEyOC1nY206dGVzdA==@[2001:0:ce49:7601:e866:efff:62c3:fffe]:8888';
      const config = SHADOWSOCKS_URI.parse(input);
      expect(config.method.data).toEqual('aes-128-gcm');
      expect(config.password.data).toEqual('test');
      expect(config.host.data).toEqual('2001:0:ce49:7601:e866:efff:62c3:fffe');
      expect(config.port.data).toEqual(8888);
    });

    it('can parse a valid SIP002 URI with an arbitray query param', () => {
      const input = 'ss://cmM0LW1kNTpwYXNzd2Q=@192.168.100.1:8888/?foo=1';
      const config = SHADOWSOCKS_URI.parse(input);
      expect(config.extra.foo!).toEqual('1');
    });

    it('can parse a valid SIP002 URI with a plugin param', () => {
      const input = 'ss://cmM0LW1kNTpwYXNzd2Q=@192.168.100.1:8888/?plugin=obfs-local%3Bobfs%3Dhttp';
      const config = SHADOWSOCKS_URI.parse(input);
      expect(config.method.data).toEqual('rc4-md5');
      expect(config.password.data).toEqual('passwd');
      expect(config.host.data).toEqual('192.168.100.1');
      expect(config.port.data).toEqual(8888);
      expect(config.extra.plugin!).toEqual('obfs-local;obfs=http');
    });

    it('can parse a valid SIP002 URI with the default HTTP port and no plugin parameters', () => {
      const input = 'ss://cmM0LW1kNTpwYXNzd2Q=@192.168.100.1:80';
      const config = SHADOWSOCKS_URI.parse(input);
      expect(config.method.data).toEqual('rc4-md5');
      expect(config.password.data).toEqual('passwd');
      expect(config.host.data).toEqual('192.168.100.1');
      expect(config.port.data).toEqual(80);
    });

    it('can parse a valid SIP002 URI with the default HTTP port and parameters', () => {
      const input = 'ss://cmM0LW1kNTpwYXNzd2Q=@192.168.100.1:80/?foo=1&bar=';
      const config = SHADOWSOCKS_URI.parse(input);
      expect(config.method.data).toEqual('rc4-md5');
      expect(config.password.data).toEqual('passwd');
      expect(config.host.data).toEqual('192.168.100.1');
      expect(config.port.data).toEqual(80);
    });

    it('can parse a valid legacy base64 URI with IPv4 host', () => {
      const input = 'ss://YmYtY2ZiOnRlc3RAMTkyLjE2OC4xMDAuMTo4ODg4#Foo%20Bar';
      const config = SHADOWSOCKS_URI.parse(input);
      expect(config.method.data).toEqual('bf-cfb');
      expect(config.password.data).toEqual('test');
      expect(config.host.data).toEqual('192.168.100.1');
      expect(config.port.data).toEqual(8888);
      expect(config.tag.data).toEqual('Foo Bar');
    });

    it('can parse a valid legacy base64 URI with IPv6 host', () => {
      const input = 'ss://YmYtY2ZiOnRlc3RAWzIwMDE6MDpjZTQ5Ojc2MDE6ZTg2NjplZmZmOjYyYzM6ZmZmZV06ODg4OA';
      const config = SHADOWSOCKS_URI.parse(input);
      expect(config.host.data).toEqual('2001:0:ce49:7601:e866:efff:62c3:fffe');
      expect(config.port.data).toEqual(8888);
      expect(config.method.data).toEqual('bf-cfb');
      expect(config.password.data).toEqual('test');
      expect(config.tag.data).toEqual('');
    });

    it('can parse a valid legacy base64 URI default HTTP port', () => {
      const input = 'ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzdzByZEAxOTIuMTY4LjEwMC4xOjgw';
      const config = SHADOWSOCKS_URI.parse(input);
      expect(config.host.data).toEqual('192.168.100.1');
      expect(config.port.data).toEqual(80);
      expect(config.method.data).toEqual('chacha20-ietf-poly1305');
      expect(config.password.data).toEqual('passw0rd');
    });

    it('throws when parsing empty input', () => {
      expect(() => SHADOWSOCKS_URI.parse('')).toThrowError(InvalidUri);
    });

    it('throws when parsing invalid input', () => {
      expect(() => SHADOWSOCKS_URI.parse('not a URI')).toThrowError(InvalidUri);
      expect(() => SHADOWSOCKS_URI.parse('ss://not-base64')).toThrowError(InvalidUri);
    });
  });
});
