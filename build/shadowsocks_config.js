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
(function (factory) {
    if (typeof module === "object" && typeof module.exports === "object") {
        var v = factory(require, exports);
        if (v !== undefined) module.exports = v;
    }
    else if (typeof define === "function" && define.amd) {
        define("outline_shadowsocksconfig/src/shadowsocks_config", ["require", "exports"], factory);
    }
})(function (require, exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    /* tslint:disable */
    const isBrowser = typeof window !== 'undefined';
    const b64Encode = isBrowser ? btoa : require('base-64').encode;
    const b64Decode = isBrowser ? atob : require('base-64').decode;
    const URL = isBrowser ? window.URL : require('url').URL;
    const punycode = isBrowser ? window.punycode : require('punycode');
    if (!punycode) {
        throw new Error(`Could not find punycode. Did you forget to add e.g.
  <script src="bower_components/punycode/punycode.min.js"></script>?`);
    }
    /* tslint:enable */
    // Custom error base class
    class ShadowsocksConfigError extends Error {
        constructor(message) {
            super(message); // 'Error' breaks prototype chain here if this is transpiled to es5
            Object.setPrototypeOf(this, new.target.prototype); // restore prototype chain
            this.name = new.target.name;
        }
    }
    exports.ShadowsocksConfigError = ShadowsocksConfigError;
    class InvalidConfigField extends ShadowsocksConfigError {
    }
    exports.InvalidConfigField = InvalidConfigField;
    class InvalidUri extends ShadowsocksConfigError {
    }
    exports.InvalidUri = InvalidUri;
    // Self-validating/normalizing config data types implement this ValidatedConfigField interface.
    // Constructors take some data, validate, normalize, and store if valid, or throw otherwise.
    class ValidatedConfigField {
    }
    exports.ValidatedConfigField = ValidatedConfigField;
    function throwErrorForInvalidField(name, value, reason) {
        throw new InvalidConfigField(`Invalid ${name}: ${value} ${reason || ''}`);
    }
    class Host extends ValidatedConfigField {
        constructor(host) {
            super();
            if (!host) {
                throwErrorForInvalidField('host', host);
            }
            if (host instanceof Host) {
                host = host.data;
            }
            host = punycode.toASCII(host);
            this.isIPv4 = Host.IPV4_PATTERN.test(host);
            this.isIPv6 = this.isIPv4 ? false : Host.IPV6_PATTERN.test(host);
            this.isHostname = this.isIPv4 || this.isIPv6 ? false : Host.HOSTNAME_PATTERN.test(host);
            if (!(this.isIPv4 || this.isIPv6 || this.isHostname)) {
                throwErrorForInvalidField('host', host);
            }
            this.data = host;
        }
    }
    Host.IPV4_PATTERN = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    Host.IPV6_PATTERN = /^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$/i;
    Host.HOSTNAME_PATTERN = /^[A-z0-9]+[A-z0-9_.-]*$/;
    exports.Host = Host;
    class Port extends ValidatedConfigField {
        constructor(port) {
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
    Port.PATTERN = /^[0-9]{1,5}$/;
    exports.Port = Port;
    // A method value must exactly match an element in the set of known ciphers.
    // ref: https://github.com/shadowsocks/shadowsocks-libev/blob/10a2d3e3/completions/bash/ss-redir#L5
    exports.METHODS = new Set([
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
    class Method extends ValidatedConfigField {
        constructor(method) {
            super();
            if (method instanceof Method) {
                method = method.data;
            }
            if (!exports.METHODS.has(method)) {
                throwErrorForInvalidField('method', method);
            }
            this.data = method;
        }
    }
    exports.Method = Method;
    class Password extends ValidatedConfigField {
        constructor(password) {
            super();
            this.data = password instanceof Password ? password.data : password;
        }
    }
    exports.Password = Password;
    class Tag extends ValidatedConfigField {
        constructor(tag = '') {
            super();
            this.data = tag instanceof Tag ? tag.data : tag;
        }
    }
    exports.Tag = Tag;
    // tslint:disable-next-line:no-any
    function makeConfig(input) {
        // Use "!" for the required fields to tell tsc that we handle undefined in the
        // ValidatedConfigFields we call; tsc can't figure that out otherwise.
        const config = {
            host: new Host(input.host),
            port: new Port(input.port),
            method: new Method(input.method),
            password: new Password(input.password),
            tag: new Tag(input.tag),
            extra: {},
        };
        // Put any remaining fields in `input` into `config.extra`.
        for (const key of Object.keys(input)) {
            if (!/^(host|port|method|password|tag)$/.test(key)) {
                config.extra[key] = input[key] && input[key].toString();
            }
        }
        return config;
    }
    exports.makeConfig = makeConfig;
    exports.SHADOWSOCKS_URI = {
        PROTOCOL: 'ss:',
        getUriFormattedHost: (host) => {
            return host.isIPv6 ? `[${host.data}]` : host.data;
        },
        getHash: (tag) => {
            return tag.data ? `#${encodeURIComponent(tag.data)}` : '';
        },
        validateProtocol: (uri) => {
            if (!uri.startsWith(exports.SHADOWSOCKS_URI.PROTOCOL)) {
                throw new InvalidUri(`URI must start with "${exports.SHADOWSOCKS_URI.PROTOCOL}"`);
            }
        },
        parse: (uri) => {
            let error;
            for (const uriType of [exports.SIP002_URI, exports.LEGACY_BASE64_URI]) {
                try {
                    return uriType.parse(uri);
                }
                catch (e) {
                    error = e;
                }
            }
            if (!(error instanceof InvalidUri)) {
                const originalErrorName = error.name || '(Unnamed Error)';
                const originalErrorMessage = error.message || '(no error message provided)';
                const originalErrorString = `${originalErrorName}: ${originalErrorMessage}`;
                const newErrorMessage = `Invalid input: ${originalErrorString}`;
                error = new InvalidUri(newErrorMessage);
            }
            throw error;
        },
    };
    // Ref: https://shadowsocks.org/en/config/quick-guide.html
    exports.LEGACY_BASE64_URI = {
        parse: (uri) => {
            exports.SHADOWSOCKS_URI.validateProtocol(uri);
            const hashIndex = uri.indexOf('#');
            const hasTag = hashIndex !== -1;
            const b64EndIndex = hasTag ? hashIndex : uri.length;
            const tagStartIndex = hasTag ? hashIndex + 1 : uri.length;
            const tag = new Tag(decodeURIComponent(uri.substring(tagStartIndex)));
            const b64EncodedData = uri.substring('ss://'.length, b64EndIndex);
            const b64DecodedData = b64Decode(b64EncodedData);
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
            let host;
            try {
                host = new Host(uriFormattedHost);
            }
            catch (_) {
                // Could be IPv6 host formatted with surrounding brackets, so try stripping first and last
                // characters. If this throws, give up and let the exception propagate.
                host = new Host(uriFormattedHost.substring(1, uriFormattedHost.length - 1));
            }
            const portStartIndex = hostEndIndex + 1;
            const portString = hostAndPort.substring(portStartIndex);
            const port = new Port(portString);
            const extra = {}; // empty because LegacyBase64Uri can't hold extra
            return { method, password, host, port, tag, extra };
        },
        stringify: (config) => {
            const { host, port, method, password, tag } = config;
            const hash = exports.SHADOWSOCKS_URI.getHash(tag);
            let b64EncodedData = b64Encode(`${method.data}:${password.data}@${host.data}:${port.data}`);
            const dataLength = b64EncodedData.length;
            let paddingLength = 0;
            for (; b64EncodedData[dataLength - 1 - paddingLength] === '='; paddingLength++)
                ;
            b64EncodedData = paddingLength === 0 ? b64EncodedData :
                b64EncodedData.substring(0, dataLength - paddingLength);
            return `ss://${b64EncodedData}${hash}`;
        },
    };
    // Ref: https://shadowsocks.org/en/spec/SIP002-URI-Scheme.html
    exports.SIP002_URI = {
        parse: (uri) => {
            exports.SHADOWSOCKS_URI.validateProtocol(uri);
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
                parsedPort = 80;
            }
            const port = new Port(parsedPort);
            const tag = new Tag(decodeURIComponent(urlParserResult.hash.substring(1)));
            const b64EncodedUserInfo = urlParserResult.username.replace(/%3D/g, '=');
            // base64.decode throws as desired when given invalid base64 input.
            const b64DecodedUserInfo = b64Decode(b64EncodedUserInfo);
            const colonIdx = b64DecodedUserInfo.indexOf(':');
            if (colonIdx === -1) {
                throw new InvalidUri(`Missing password`);
            }
            const methodString = b64DecodedUserInfo.substring(0, colonIdx);
            const method = new Method(methodString);
            const passwordString = b64DecodedUserInfo.substring(colonIdx + 1);
            const password = new Password(passwordString);
            const queryParams = urlParserResult.search.substring(1).split('&');
            const extra = {};
            for (const pair of queryParams) {
                const [key, value] = pair.split('=', 2);
                if (!key)
                    continue;
                extra[key] = decodeURIComponent(value || '');
            }
            return { method, password, host, port, tag, extra };
        },
        stringify: (config) => {
            const { host, port, method, password, tag, extra } = config;
            const userInfo = b64Encode(`${method.data}:${password.data}`);
            const uriHost = exports.SHADOWSOCKS_URI.getUriFormattedHost(host);
            const hash = exports.SHADOWSOCKS_URI.getHash(tag);
            let queryString = '';
            for (const key in extra) {
                if (!key)
                    continue;
                queryString += (queryString ? '&' : '?') + `${key}=${encodeURIComponent(extra[key])}`;
            }
            return `ss://${userInfo}@${uriHost}:${port.data}/${queryString}${hash}`;
        },
    };
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic2hhZG93c29ja3NfY29uZmlnLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vLi4vc3JjL3NoYWRvd3NvY2tzX2NvbmZpZy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxxQ0FBcUM7QUFDckMsRUFBRTtBQUNGLGtFQUFrRTtBQUNsRSxtRUFBbUU7QUFDbkUsMENBQTBDO0FBQzFDLEVBQUU7QUFDRixrREFBa0Q7QUFDbEQsRUFBRTtBQUNGLHNFQUFzRTtBQUN0RSxvRUFBb0U7QUFDcEUsMkVBQTJFO0FBQzNFLHNFQUFzRTtBQUN0RSxpQ0FBaUM7Ozs7Ozs7Ozs7OztJQUVqQyxvQkFBb0I7SUFDcEIsTUFBTSxTQUFTLEdBQUcsT0FBTyxNQUFNLEtBQUssV0FBVyxDQUFDO0lBQ2hELE1BQU0sU0FBUyxHQUFHLFNBQVMsQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsU0FBUyxDQUFDLENBQUMsTUFBTSxDQUFDO0lBQy9ELE1BQU0sU0FBUyxHQUFHLFNBQVMsQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsU0FBUyxDQUFDLENBQUMsTUFBTSxDQUFDO0lBQy9ELE1BQU0sR0FBRyxHQUFHLFNBQVMsQ0FBQyxDQUFDLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLEtBQUssQ0FBQyxDQUFDLEdBQUcsQ0FBQztJQUN4RCxNQUFNLFFBQVEsR0FBRyxTQUFTLENBQUMsQ0FBQyxDQUFFLE1BQWMsQ0FBQyxRQUFRLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxVQUFVLENBQUMsQ0FBQztJQUM1RSxJQUFJLENBQUMsUUFBUSxFQUFFO1FBQ2IsTUFBTSxJQUFJLEtBQUssQ0FBQztxRUFDbUQsQ0FBQyxDQUFDO0tBQ3RFO0lBQ0QsbUJBQW1CO0lBRW5CLDBCQUEwQjtJQUMxQixNQUFhLHNCQUF1QixTQUFRLEtBQUs7UUFDL0MsWUFBWSxPQUFl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dkY7WUFDRCxPQUFPLFFBQVEsUUFBUSxJQUFJLE9BQU8sSUFBSSxJQUFJLENBQUMsSUFBSSxJQUFJLFdBQVcsR0FBRyxJQUFJLEVBQUUsQ0FBQztRQUMxRSxDQUFDO0tBQ0YsQ0FBQyIsInNvdXJjZXNDb250ZW50IjpbIi8vIENvcHlyaWdodCAyMDE4IFRoZSBPdXRsaW5lIEF1dGhvcnNcbi8vXG4vLyBMaWNlbnNlZCB1bmRlciB0aGUgQXBhY2hlIExpY2Vuc2UsIFZlcnNpb24gMi4wICh0aGUgXCJMaWNlbnNlXCIpO1xuLy8geW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLlxuLy8gWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0XG4vL1xuLy8gICAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjBcbi8vXG4vLyBVbmxlc3MgcmVxdWlyZWQgYnkgYXBwbGljYWJsZSBsYXcgb3IgYWdyZWVkIHRvIGluIHdyaXRpbmcsIHNvZnR3YXJlXG4vLyBkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiBcIkFTIElTXCIgQkFTSVMsXG4vLyBXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC5cbi8vIFNlZSB0aGUgTGljZW5zZSBmb3IgdGhlIHNwZWNpZmljIGxhbmd1YWdlIGdvdmVybmluZyBwZXJtaXNzaW9ucyBhbmRcbi8vIGxpbWl0YXRpb25zIHVuZGVyIHRoZSBMaWNlbnNlLlxuXG4vKiB0c2xpbnQ6ZGlzYWJsZSAqL1xuY29uc3QgaXNCcm93c2VyID0gdHlwZW9mIHdpbmRvdyAhPT0gJ3VuZGVmaW5lZCc7XG5jb25zdCBiNjRFbmNvZGUgPSBpc0Jyb3dzZXIgPyBidG9hIDogcmVxdWlyZSgnYmFzZS02NCcpLmVuY29kZTtcbmNvbnN0IGI2NERlY29kZSA9IGlzQnJvd3NlciA/IGF0b2IgOiByZXF1aXJlKCdiYXNlLTY0JykuZGVjb2RlO1xuY29uc3QgVVJMID0gaXNCcm93c2VyID8gd2luZG93LlVSTCA6IHJlcXVpcmUoJ3VybCcpLlVSTDtcbmNvbnN0IHB1bnljb2RlID0gaXNCcm93c2VyID8gKHdpbmRvdyBhcyBhbnkpLnB1bnljb2RlIDogcmVxdWlyZSgncHVueWNvZGUnKTtcbmlmICghcHVueWNvZGUpIHtcbiAgdGhyb3cgbmV3IEVycm9yKGBDb3VsZCBub3QgZmluZCBwdW55Y29kZS4gRGlkIHlvdSBmb3JnZXQgdG8gYWRkIGUuZy5cbiAgPHNjcmlwdCBzcmM9XCJib3dlcl9jb21wb25lbnRzL3B1bnljb2RlL3B1bnljb2RlLm1pbi5qc1wiPjwvc2NyaXB0Pj9gKTtcbn1cbi8qIHRzbGludDplbmFibGUgKi9cblxuLy8gQ3VzdG9tIGVycm9yIGJhc2UgY2xhc3NcbmV4cG9ydCBjbGFzcyBTaGFkb3dzb2Nrc0NvbmZpZ0Vycm9yIGV4dGVuZHMgRXJyb3Ige1xuICBjb25zdHJ1Y3RvcihtZXNzYWdlOiBzdHJpbmcpIHtcbiAgICBzdXBlcihtZXNzYWdlKTsgIC8vICdFcnJvcicgYnJlYWtzIHByb3RvdHlwZSBjaGFpbiBoZXJlIGlmIHRoaXMgaXMgdHJhbnNwaWxlZCB0byBlczVcbiAgICBPYmplY3Quc2V0UHJvdG90eXBlT2YodGhpcywgbmV3LnRhcmdldC5wcm90b3R5cGUpOyAgLy8gcmVzdG9yZSBwcm90b3R5cGUgY2hhaW5cbiAgICB0aGlzLm5hbWUgPSBuZXcudGFyZ2V0Lm5hbWU7XG4gIH1cbn1cblxuZXhwb3J0IGNsYXNzIEludmFsaWRDb25maWdGaWVsZCBleHRlbmRzIFNoYWRvd3NvY2tzQ29uZmlnRXJyb3Ige31cblxuZXhwb3J0IGNsYXNzIEludmFsaWRVcmkgZXh0ZW5kcyBTaGFkb3dzb2Nrc0NvbmZpZ0Vycm9yIHt9XG5cbi8vIFNlbGYtdmFsaWRhdGluZy9ub3JtYWxpemluZyBjb25maWcgZGF0YSB0eXBlcyBpbXBsZW1lbnQgdGhpcyBWYWxpZGF0ZWRDb25maWdGaWVsZCBpbnRlcmZhY2UuXG4vLyBDb25zdHJ1Y3RvcnMgdGFrZSBzb21lIGRhdGEsIHZhbGlkYXRlLCBub3JtYWxpemUsIGFuZCBzdG9yZSBpZiB2YWxpZCwgb3IgdGhyb3cgb3RoZXJ3aXNlLlxuZXhwb3J0IGFic3RyYWN0IGNsYXNzIFZhbGlkYXRlZENvbmZpZ0ZpZWxkIHt9XG5cbmZ1bmN0aW9uIHRocm93RXJyb3JGb3JJbnZhbGlkRmllbGQobmFtZTogc3RyaW5nLCB2YWx1ZToge30sIHJlYXNvbj86IHN0cmluZykge1xuICB0aHJvdyBuZXcgSW52YWxpZENvbmZpZ0ZpZWxkKGBJbnZhbGlkICR7bmFtZX06ICR7dmFsdWV9ICR7cmVhc29uIHx8ICcnfWApO1xufVxuXG5leHBvcnQgY2xhc3MgSG9zdCBleHRlbmRzIFZhbGlkYXRlZENvbmZpZ0ZpZWxkIHtcbiAgcHVibGljIHN0YXRpYyBJUFY0X1BBVFRFUk4gPSAvXig/OlswLTldezEsM31cXC4pezN9WzAtOV17MSwzfSQvO1xuICBwdWJsaWMgc3RhdGljIElQVjZfUEFUVEVSTiA9IC9eKD86W0EtRjAtOV17MSw0fTopezd9W0EtRjAtOV17MSw0fSQvaTtcbiAgcHVibGljIHN0YXRpYyBIT1NUTkFNRV9QQVRURVJOID0gL15bQS16MC05XStbQS16MC05Xy4tXSokLztcbiAgcHVibGljIHJlYWRvbmx5IGRhdGE6IHN0cmluZztcbiAgcHVibGljIHJlYWRvbmx5IGlzSVB2NDogYm9vbGVhbjtcbiAgcHVibGljIHJlYWRvbmx5IGlzSVB2NjogYm9vbGVhbjtcbiAgcHVibGljIHJlYWRvbmx5IGlzSG9zdG5hbWU6IGJvb2xlYW47XG5cbiAgY29uc3RydWN0b3IoaG9zdDogSG9zdCB8IHN0cmluZykge1xuICAgIHN1cGVyKCk7XG4gICAgaWYgKCFob3N0KSB7XG4gICAgICB0aHJvd0Vycm9yRm9ySW52YWxpZEZpZWxkKCdob3N0JywgaG9zdCk7XG4gICAgfVxuICAgIGlmIChob3N0IGluc3RhbmNlb2YgSG9zdCkge1xuICAgICAgaG9zdCA9IGhvc3QuZGF0YTtcbiAgICB9XG4gICAgaG9zdCA9IHB1bnljb2RlLnRvQVNDSUkoaG9zdCkgYXMgc3RyaW5nO1xuICAgIHRoaXMuaXNJUHY0ID0gSG9zdC5JUFY0X1BBVFRFUk4udGVzdChob3N0KTtcbiAgICB0aGlzLmlzSVB2NiA9IHRoaXMuaXNJUHY0ID8gZmFsc2UgOiBIb3N0LklQVjZfUEFUVEVSTi50ZXN0KGhvc3QpO1xuICAgIHRoaXMuaXNIb3N0bmFtZSA9IHRoaXMuaXNJUHY0IHx8IHRoaXMuaXNJUHY2ID8gZmFsc2UgOiBIb3N0LkhPU1ROQU1FX1BBVFRFUk4udGVzdChob3N0KTtcbiAgICBpZiAoISh0aGlzLmlzSVB2NCB8fCB0aGlzLmlzSVB2NiB8fCB0aGlzLmlzSG9zdG5hbWUpKSB7XG4gICAgICB0aHJvd0Vycm9yRm9ySW52YWxpZEZpZWxkKCdob3N0JywgaG9zdCk7XG4gICAgfVxuICAgIHRoaXMuZGF0YSA9IGhvc3Q7XG4gIH1cbn1cblxuZXhwb3J0IGNsYXNzIFBvcnQgZXh0ZW5kcyBWYWxpZGF0ZWRDb25maWdGaWVsZCB7XG4gIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgUEFUVEVSTiA9IC9eWzAtOV17MSw1fSQvO1xuICBwdWJsaWMgcmVhZG9ubHkgZGF0YTogbnVtYmVyO1xuXG4gIGNvbnN0cnVjdG9yKHBvcnQ6IFBvcnQgfCBzdHJpbmcgfCBudW1iZXIpIHtcbiAgICBzdXBlcigpO1xuICAgIGlmIChwb3J0IGluc3RhbmNlb2YgUG9ydCkge1xuICAgICAgcG9ydCA9IHBvcnQuZGF0YTtcbiAgICB9XG4gICAgaWYgKHR5cGVvZiBwb3J0ID09PSAnbnVtYmVyJykge1xuICAgICAgLy8gU3RyaW5naWZ5IGluIGNhc2UgbmVnYXRpdmUgb3IgZmxvYXRpbmcgcG9pbnQgLT4gdGhlIHJlZ2V4IHRlc3QgYmVsb3cgd2lsbCBjYXRjaC5cbiAgICAgIHBvcnQgPSBwb3J0LnRvU3RyaW5nKCk7XG4gICAgfVxuICAgIGlmICghUG9ydC5QQVRURVJOLnRlc3QocG9ydCkpIHtcbiAgICAgIHRocm93RXJyb3JGb3JJbnZhbGlkRmllbGQoJ3BvcnQnLCBwb3J0KTtcbiAgICB9XG4gICAgLy8gQ291bGQgZXhjZWVkIHRoZSBtYXhpbXVtIHBvcnQgbnVtYmVyLCBzbyBjb252ZXJ0IHRvIE51bWJlciB0byBjaGVjay4gQ291bGQgYWxzbyBoYXZlIGxlYWRpbmdcbiAgICAvLyB6ZXJvcy4gQ29udmVydGluZyB0byBOdW1iZXIgZHJvcHMgdGhvc2UsIHNvIHdlIGdldCBub3JtYWxpemF0aW9uIGZvciBmcmVlLiA6KVxuICAgIHBvcnQgPSBOdW1iZXIocG9ydCk7XG4gICAgaWYgKHBvcnQgPiA2NTUzNSkge1xuICAgICAgdGhyb3dFcnJvckZvckludmFsaWRGaWVsZCgncG9ydCcsIHBvcnQpO1xuICAgIH1cbiAgICB0aGlzLmRhdGEgPSBwb3J0O1xuICB9XG59XG5cbi8vIEEgbWV0aG9kIHZhbHVlIG11c3QgZXhhY3RseSBtYXRjaCBhbiBlbGVtZW50IGluIHRoZSBzZXQgb2Yga25vd24gY2lwaGVycy5cbi8vIHJlZjogaHR0cHM6Ly9naXRodWIuY29tL3NoYWRvd3NvY2tzL3NoYWRvd3NvY2tzLWxpYmV2L2Jsb2IvMTBhMmQzZTMvY29tcGxldGlvbnMvYmFzaC9zcy1yZWRpciNMNVxuZXhwb3J0IGNvbnN0IE1FVEhPRFMgPSBuZXcgU2V0KFtcbiAgJ3JjNC1tZDUnLFxuICAnYWVzLTEyOC1nY20nLFxuICAnYWVzLTE5Mi1nY20nLFxuICAnYWVzLTI1Ni1nY20nLFxuICAnYWVzLTEyOC1jZmInLFxuICAnYWVzLTE5Mi1jZmInLFxuICAnYWVzLTI1Ni1jZmInLFxuICAnYWVzLTEyOC1jdHInLFxuICAnYWVzLTE5Mi1jdHInLFxuICAnYWVzLTI1Ni1jdHInLFxuICAnY2FtZWxsaWEtMTI4LWNmYicsXG4gICdjYW1lbGxpYS0xOTItY2ZiJyxcbiAgJ2NhbWVsbGlhLTI1Ni1jZmInLFxuICAnYmYtY2ZiJyxcbiAgJ2NoYWNoYTIwLWlldGYtcG9seTEzMDUnLFxuICAnc2Fsc2EyMCcsXG4gICdjaGFjaGEyMCcsXG4gICdjaGFjaGEyMC1pZXRmJyxcbiAgJ3hjaGFjaGEyMC1pZXRmLXBvbHkxMzA1Jyxcbl0pO1xuXG5leHBvcnQgY2xhc3MgTWV0aG9kIGV4dGVuZHMgVmFsaWRhdGVkQ29uZmlnRmllbGQge1xuICBwdWJsaWMgcmVhZG9ubHkgZGF0YTogc3RyaW5nO1xuICBjb25zdHJ1Y3RvcihtZXRob2Q6IE1ldGhvZCB8IHN0cmluZykge1xuICAgIHN1cGVyKCk7XG4gICAgaWYgKG1ldGhvZCBpbnN0YW5jZW9mIE1ldGhvZCkge1xuICAgICAgbWV0aG9kID0gbWV0aG9kLmRhdGE7XG4gICAgfVxuICAgIGlmICghTUVUSE9EUy5oYXMobWV0aG9kKSkge1xuICAgICAgdGhyb3dFcnJvckZvckludmFsaWRGaWVsZCgnbWV0aG9kJywgbWV0aG9kKTtcbiAgICB9XG4gICAgdGhpcy5kYXRhID0gbWV0aG9kO1xuICB9XG59XG5cbmV4cG9ydCBjbGFzcyBQYXNzd29yZCBleHRlbmRzIFZhbGlkYXRlZENvbmZpZ0ZpZWxkIHtcbiAgcHVibGljIHJlYWRvbmx5IGRhdGE6IHN0cmluZztcblxuICBjb25zdHJ1Y3RvcihwYXNzd29yZDogUGFzc3dvcmQgfCBzdHJpbmcpIHtcbiAgICBzdXBlcigpO1xuICAgIHRoaXMuZGF0YSA9IHBhc3N3b3JkIGluc3RhbmNlb2YgUGFzc3dvcmQgPyBwYXNzd29yZC5kYXRhIDogcGFzc3dvcmQ7XG4gIH1cbn1cblxuZXhwb3J0IGNsYXNzIFRhZyBleHRlbmRzIFZhbGlkYXRlZENvbmZpZ0ZpZWxkIHtcbiAgcHVibGljIHJlYWRvbmx5IGRhdGE6IHN0cmluZztcblxuICBjb25zdHJ1Y3Rvcih0YWc6IFRhZyB8IHN0cmluZyA9ICcnKSB7XG4gICAgc3VwZXIoKTtcbiAgICB0aGlzLmRhdGEgPSB0YWcgaW5zdGFuY2VvZiBUYWcgPyB0YWcuZGF0YSA6IHRhZztcbiAgfVxufVxuXG5leHBvcnQgaW50ZXJmYWNlIENvbmZpZyB7XG4gIGhvc3Q6IEhvc3Q7XG4gIHBvcnQ6IFBvcnQ7XG4gIG1ldGhvZDogTWV0aG9kO1xuICBwYXNzd29yZDogUGFzc3dvcmQ7XG4gIHRhZzogVGFnO1xuICAvLyBBbnkgYWRkaXRpb25hbCBjb25maWd1cmF0aW9uIChlLmcuIGB0aW1lb3V0YCwgU0lQMDAzIGBwbHVnaW5gLCBldGMuKSBtYXkgYmUgc3RvcmVkIGhlcmUuXG4gIGV4dHJhOiB7W2tleTogc3RyaW5nXTogc3RyaW5nfTtcbn1cblxuLy8gdHNsaW50OmRpc2FibGUtbmV4dC1saW5lOm5vLWFueVxuZXhwb3J0IGZ1bmN0aW9uIG1ha2VDb25maWcoaW5wdXQ6IHtba2V5OiBzdHJpbmddOiBhbnl9KTogQ29uZmlnIHtcbiAgLy8gVXNlIFwiIVwiIGZvciB0aGUgcmVxdWlyZWQgZmllbGRzIHRvIHRlbGwgdHNjIHRoYXQgd2UgaGFuZGxlIHVuZGVmaW5lZCBpbiB0aGVcbiAgLy8gVmFsaWRhdGVkQ29uZmlnRmllbGRzIHdlIGNhbGw7IHRzYyBjYW4ndCBmaWd1cmUgdGhhdCBvdXQgb3RoZXJ3aXNlLlxuICBjb25zdCBjb25maWcgPSB7XG4gICAgaG9zdDogbmV3IEhvc3QoaW5wdXQuaG9zdCEpLFxuICAgIHBvcnQ6IG5ldyBQb3J0KGlucHV0LnBvcnQhKSxcbiAgICBtZXRob2Q6IG5ldyBNZXRob2QoaW5wdXQubWV0aG9kISksXG4gICAgcGFzc3dvcmQ6IG5ldyBQYXNzd29yZChpbnB1dC5wYXNzd29yZCEpLFxuICAgIHRhZzogbmV3IFRhZyhpbnB1dC50YWcpLCAgLy8gaW5wdXQudGFnIG1pZ2h0IGJlIHVuZGVmaW5lZCBidXQgVGFnKCkgaGFuZGxlcyB0aGF0IGZpbmUuXG4gICAgZXh0cmE6IHt9IGFzIHtba2V5OiBzdHJpbmddOiBzdHJpbmd9LFxuICB9O1xuICAvLyBQdXQgYW55IHJlbWFpbmluZyBmaWVsZHMgaW4gYGlucHV0YCBpbnRvIGBjb25maWcuZXh0cmFgLlxuICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3Qua2V5cyhpbnB1dCkpIHtcbiAgICBpZiAoIS9eKGhvc3R8cG9ydHxtZXRob2R8cGFzc3dvcmR8dGFnKSQvLnRlc3Qoa2V5KSkge1xuICAgICAgY29uZmlnLmV4dHJhW2tleV0gPSBpbnB1dFtrZXldICYmIGlucHV0W2tleV0udG9TdHJpbmcoKTtcbiAgICB9XG4gIH1cbiAgcmV0dXJuIGNvbmZpZztcbn1cblxuZXhwb3J0IGNvbnN0IFNIQURPV1NPQ0tTX1VSSSA9IHtcbiAgUFJPVE9DT0w6ICdzczonLFxuXG4gIGdldFVyaUZvcm1hdHRlZEhvc3Q6IChob3N0OiBIb3N0KSA9PiB7XG4gICAgcmV0dXJuIGhvc3QuaXNJUHY2ID8gYFske2hvc3QuZGF0YX1dYCA6IGhvc3QuZGF0YTtcbiAgfSxcblxuICBnZXRIYXNoOiAodGFnOiBUYWcpID0+IHtcbiAgICByZXR1cm4gdGFnLmRhdGEgPyBgIyR7ZW5jb2RlVVJJQ29tcG9uZW50KHRhZy5kYXRhKX1gIDogJyc7XG4gIH0sXG5cbiAgdmFsaWRhdGVQcm90b2NvbDogKHVyaTogc3RyaW5nKSA9PiB7XG4gICAgaWYgKCF1cmkuc3RhcnRzV2l0aChTSEFET1dTT0NLU19VUkkuUFJPVE9DT0wpKSB7XG4gICAgICB0aHJvdyBuZXcgSW52YWxpZFVyaShgVVJJIG11c3Qgc3RhcnQgd2l0aCBcIiR7U0hBRE9XU09DS1NfVVJJLlBST1RPQ09MfVwiYCk7XG4gICAgfVxuICB9LFxuXG4gIHBhcnNlOiAodXJpOiBzdHJpbmcpOiBDb25maWcgPT4ge1xuICAgIGxldCBlcnJvcjogRXJyb3IgfCB1bmRlZmluZWQ7XG4gICAgZm9yIChjb25zdCB1cmlUeXBlIG9mIFtTSVAwMDJfVVJJLCBMRUdBQ1lfQkFTRTY0X1VSSV0pIHtcbiAgICAgIHRyeSB7XG4gICAgICAgIHJldHVybiB1cmlUeXBlLnBhcnNlKHVyaSk7XG4gICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGVycm9yID0gZTtcbiAgICAgIH1cbiAgICB9XG4gICAgaWYgKCEoZXJyb3IgaW5zdGFuY2VvZiBJbnZhbGlkVXJpKSkge1xuICAgICAgY29uc3Qgb3JpZ2luYWxFcnJvck5hbWUgPSBlcnJvciEubmFtZSEgfHwgJyhVbm5hbWVkIEVycm9yKSc7XG4gICAgICBjb25zdCBvcmlnaW5hbEVycm9yTWVzc2FnZSA9IGVycm9yIS5tZXNzYWdlISB8fCAnKG5vIGVycm9yIG1lc3NhZ2UgcHJvdmlkZWQpJztcbiAgICAgIGNvbnN0IG9yaWdpbmFsRXJyb3JTdHJpbmcgPSBgJHtvcmlnaW5hbEVycm9yTmFtZX06ICR7b3JpZ2luYWxFcnJvck1lc3NhZ2V9YDtcbiAgICAgIGNvbnN0IG5ld0Vycm9yTWVzc2FnZSA9IGBJbnZhbGlkIGlucHV0OiAke29yaWdpbmFsRXJyb3JTdHJpbmd9YDtcbiAgICAgIGVycm9yID0gbmV3IEludmFsaWRVcmkobmV3RXJyb3JNZXNzYWdlKTtcbiAgICB9XG4gICAgdGhyb3cgZXJyb3I7XG4gIH0sXG59O1xuXG4vLyBSZWY6IGh0dHBzOi8vc2hhZG93c29ja3Mub3JnL2VuL2NvbmZpZy9xdWljay1ndWlkZS5odG1sXG5leHBvcnQgY29uc3QgTEVHQUNZX0JBU0U2NF9VUkkgPSB7XG4gIHBhcnNlOiAodXJpOiBzdHJpbmcpOiBDb25maWcgPT4ge1xuICAgIFNIQURPV1NPQ0tTX1VSSS52YWxpZGF0ZVByb3RvY29sKHVyaSk7XG4gICAgY29uc3QgaGFzaEluZGV4ID0gdXJpLmluZGV4T2YoJyMnKTtcbiAgICBjb25zdCBoYXNUYWcgPSBoYXNoSW5kZXggIT09IC0xO1xuICAgIGNvbnN0IGI2NEVuZEluZGV4ID0gaGFzVGFnID8gaGFzaEluZGV4IDogdXJpLmxlbmd0aDtcbiAgICBjb25zdCB0YWdTdGFydEluZGV4ID0gaGFzVGFnID8gaGFzaEluZGV4ICsgMSA6IHVyaS5sZW5ndGg7XG4gICAgY29uc3QgdGFnID0gbmV3IFRhZyhkZWNvZGVVUklDb21wb25lbnQodXJpLnN1YnN0cmluZyh0YWdTdGFydEluZGV4KSkpO1xuICAgIGNvbnN0IGI2NEVuY29kZWREYXRhID0gdXJpLnN1YnN0cmluZygnc3M6Ly8nLmxlbmd0aCwgYjY0RW5kSW5kZXgpO1xuICAgIGNvbnN0IGI2NERlY29kZWREYXRhID0gYjY0RGVjb2RlKGI2NEVuY29kZWREYXRhKTtcbiAgICBjb25zdCBhdFNpZ25JbmRleCA9IGI2NERlY29kZWREYXRhLmxhc3RJbmRleE9mKCdAJyk7XG4gICAgaWYgKGF0U2lnbkluZGV4ID09PSAtMSkge1xuICAgICAgdGhyb3cgbmV3IEludmFsaWRVcmkoYE1pc3NpbmcgXCJAXCJgKTtcbiAgICB9XG4gICAgY29uc3QgbWV0aG9kQW5kUGFzc3dvcmQgPSBiNjREZWNvZGVkRGF0YS5zdWJzdHJpbmcoMCwgYXRTaWduSW5kZXgpO1xuICAgIGNvbnN0IG1ldGhvZEVuZEluZGV4ID0gbWV0aG9kQW5kUGFzc3dvcmQuaW5kZXhPZignOicpO1xuICAgIGlmIChtZXRob2RFbmRJbmRleCA9PT0gLTEpIHtcbiAgICAgIHRocm93IG5ldyBJbnZhbGlkVXJpKGBNaXNzaW5nIHBhc3N3b3JkYCk7XG4gICAgfVxuICAgIGNvbnN0IG1ldGhvZFN0cmluZyA9IG1ldGhvZEFuZFBhc3N3b3JkLnN1YnN0cmluZygwLCBtZXRob2RFbmRJbmRleCk7XG4gICAgY29uc3QgbWV0aG9kID0gbmV3IE1ldGhvZChtZXRob2RTdHJpbmcpO1xuICAgIGNvbnN0IHBhc3N3b3JkU3RhcnRJbmRleCA9IG1ldGhvZEVuZEluZGV4ICsgMTtcbiAgICBjb25zdCBwYXNzd29yZFN0cmluZyA9IG1ldGhvZEFuZFBhc3N3b3JkLnN1YnN0cmluZyhwYXNzd29yZFN0YXJ0SW5kZXgpO1xuICAgIGNvbnN0IHBhc3N3b3JkID0gbmV3IFBhc3N3b3JkKHBhc3N3b3JkU3RyaW5nKTtcbiAgICBjb25zdCBob3N0U3RhcnRJbmRleCA9IGF0U2lnbkluZGV4ICsgMTtcbiAgICBjb25zdCBob3N0QW5kUG9ydCA9IGI2NERlY29kZWREYXRhLnN1YnN0cmluZyhob3N0U3RhcnRJbmRleCk7XG4gICAgY29uc3QgaG9zdEVuZEluZGV4ID0gaG9zdEFuZFBvcnQubGFzdEluZGV4T2YoJzonKTtcbiAgICBpZiAoaG9zdEVuZEluZGV4ID09PSAtMSkge1xuICAgICAgdGhyb3cgbmV3IEludmFsaWRVcmkoYE1pc3NpbmcgcG9ydGApO1xuICAgIH1cbiAgICBjb25zdCB1cmlGb3JtYXR0ZWRIb3N0ID0gaG9zdEFuZFBvcnQuc3Vic3RyaW5nKDAsIGhvc3RFbmRJbmRleCk7XG4gICAgbGV0IGhvc3Q6IEhvc3Q7XG4gICAgdHJ5IHtcbiAgICAgIGhvc3QgPSBuZXcgSG9zdCh1cmlGb3JtYXR0ZWRIb3N0KTtcbiAgICB9IGNhdGNoIChfKSB7XG4gICAgICAvLyBDb3VsZCBiZSBJUHY2IGhvc3QgZm9ybWF0dGVkIHdpdGggc3Vycm91bmRpbmcgYnJhY2tldHMsIHNvIHRyeSBzdHJpcHBpbmcgZmlyc3QgYW5kIGxhc3RcbiAgICAgIC8vIGNoYXJhY3RlcnMuIElmIHRoaXMgdGhyb3dzLCBnaXZlIHVwIGFuZCBsZXQgdGhlIGV4Y2VwdGlvbiBwcm9wYWdhdGUuXG4gICAgICBob3N0ID0gbmV3IEhvc3QodXJpRm9ybWF0dGVkSG9zdC5zdWJzdHJpbmcoMSwgdXJpRm9ybWF0dGVkSG9zdC5sZW5ndGggLSAxKSk7XG4gICAgfVxuICAgIGNvbnN0IHBvcnRTdGFydEluZGV4ID0gaG9zdEVuZEluZGV4ICsgMTtcbiAgICBjb25zdCBwb3J0U3RyaW5nID0gaG9zdEFuZFBvcnQuc3Vic3RyaW5nKHBvcnRTdGFydEluZGV4KTtcbiAgICBjb25zdCBwb3J0ID0gbmV3IFBvcnQocG9ydFN0cmluZyk7XG4gICAgY29uc3QgZXh0cmEgPSB7fSBhcyB7W2tleTogc3RyaW5nXTogc3RyaW5nfTsgIC8vIGVtcHR5IGJlY2F1c2UgTGVnYWN5QmFzZTY0VXJpIGNhbid0IGhvbGQgZXh0cmFcbiAgICByZXR1cm4ge21ldGhvZCwgcGFzc3dvcmQsIGhvc3QsIHBvcnQsIHRhZywgZXh0cmF9O1xuICB9LFxuXG4gIHN0cmluZ2lmeTogKGNvbmZpZzogQ29uZmlnKSA9PiB7XG4gICAgY29uc3Qge2hvc3QsIHBvcnQsIG1ldGhvZCwgcGFzc3dvcmQsIHRhZ30gPSBjb25maWc7XG4gICAgY29uc3QgaGFzaCA9IFNIQURPV1NPQ0tTX1VSSS5nZXRIYXNoKHRhZyk7XG4gICAgbGV0IGI2NEVuY29kZWREYXRhID0gYjY0RW5jb2RlKGAke21ldGhvZC5kYXRhfToke3Bhc3N3b3JkLmRhdGF9QCR7aG9zdC5kYXRhfToke3BvcnQuZGF0YX1gKTtcbiAgICBjb25zdCBkYXRhTGVuZ3RoID0gYjY0RW5jb2RlZERhdGEubGVuZ3RoO1xuICAgIGxldCBwYWRkaW5nTGVuZ3RoID0gMDtcbiAgICBmb3IgKDsgYjY0RW5jb2RlZERhdGFbZGF0YUxlbmd0aCAtIDEgLSBwYWRkaW5nTGVuZ3RoXSA9PT0gJz0nOyBwYWRkaW5nTGVuZ3RoKyspO1xuICAgIGI2NEVuY29kZWREYXRhID0gcGFkZGluZ0xlbmd0aCA9PT0gMCA/IGI2NEVuY29kZWREYXRhIDpcbiAgICAgICAgYjY0RW5jb2RlZERhdGEuc3Vic3RyaW5nKDAsIGRhdGFMZW5ndGggLSBwYWRkaW5nTGVuZ3RoKTtcbiAgICByZXR1cm4gYHNzOi8vJHtiNjRFbmNvZGVkRGF0YX0ke2hhc2h9YDtcbiAgfSxcbn07XG5cbi8vIFJlZjogaHR0cHM6Ly9zaGFkb3dzb2Nrcy5vcmcvZW4vc3BlYy9TSVAwMDItVVJJLVNjaGVtZS5odG1sXG5leHBvcnQgY29uc3QgU0lQMDAyX1VSSSA9IHtcbiAgcGFyc2U6ICh1cmk6IHN0cmluZyk6IENvbmZpZyA9PiB7XG4gICAgU0hBRE9XU09DS1NfVVJJLnZhbGlkYXRlUHJvdG9jb2wodXJpKTtcbiAgICAvLyBDYW4gdXNlIGJ1aWx0LWluIFVSTCBwYXJzZXIgZm9yIGV4cGVkaWVuY2UuIEp1c3QgaGF2ZSB0byByZXBsYWNlIFwic3NcIiB3aXRoIFwiaHR0cFwiIHRvIGVuc3VyZVxuICAgIC8vIGNvcnJlY3QgcmVzdWx0cywgb3RoZXJ3aXNlIGJyb3dzZXJzIGxpa2UgU2FmYXJpIGZhaWwgdG8gcGFyc2UgaXQuXG4gICAgY29uc3QgaW5wdXRGb3JVcmxQYXJzZXIgPSBgaHR0cCR7dXJpLnN1YnN0cmluZygyKX1gO1xuICAgIC8vIFRoZSBidWlsdC1pbiBVUkwgcGFyc2VyIHRocm93cyBhcyBkZXNpcmVkIHdoZW4gZ2l2ZW4gVVJJcyB3aXRoIGludmFsaWQgc3ludGF4LlxuICAgIGNvbnN0IHVybFBhcnNlclJlc3VsdCA9IG5ldyBVUkwoaW5wdXRGb3JVcmxQYXJzZXIpO1xuICAgIGNvbnN0IHVyaUZvcm1hdHRlZEhvc3QgPSB1cmxQYXJzZXJSZXN1bHQuaG9zdG5hbWU7XG4gICAgLy8gVVJJLWZvcm1hdHRlZCBJUHY2IGhvc3RuYW1lcyBoYXZlIHN1cnJvdW5kaW5nIGJyYWNrZXRzLlxuICAgIGNvbnN0IGxhc3QgPSB1cmlGb3JtYXR0ZWRIb3N0Lmxlbmd0aCAtIDE7XG4gICAgY29uc3QgYnJhY2tldHMgPSB1cmlGb3JtYXR0ZWRIb3N0WzBdID09PSAnWycgJiYgdXJpRm9ybWF0dGVkSG9zdFtsYXN0XSA9PT0gJ10nO1xuICAgIGNvbnN0IGhvc3RTdHJpbmcgPSBicmFja2V0cyA/IHVyaUZvcm1hdHRlZEhvc3Quc3Vic3RyaW5nKDEsIGxhc3QpIDogdXJpRm9ybWF0dGVkSG9zdDtcbiAgICBjb25zdCBob3N0ID0gbmV3IEhvc3QoaG9zdFN0cmluZyk7XG4gICAgbGV0IHBhcnNlZFBvcnQgPSB1cmxQYXJzZXJSZXN1bHQucG9ydDtcbiAgICBpZiAoIXBhcnNlZFBvcnQgJiYgdXJpLm1hdGNoKC86ODAoJHxcXC8pL2cpKSB7XG4gICAgICAvLyBUaGUgZGVmYXVsdCBVUkwgcGFyc2VyIGZhaWxzIHRvIHJlY29nbml6ZSB0aGUgZGVmYXVsdCBwb3J0ICg4MCkgd2hlbiB0aGUgVVJJIGJlaW5nIHBhcnNlZFxuICAgICAgLy8gaXMgSFRUUC4gQ2hlY2sgaWYgdGhlIHBvcnQgaXMgcHJlc2VudCBhdCB0aGUgZW5kIG9mIHRoZSBzdHJpbmcgb3IgYmVmb3JlIHRoZSBwYXJhbWV0ZXJzLlxuICAgICAgcGFyc2VkUG9ydCA9IDgwO1xuICAgIH1cbiAgICBjb25zdCBwb3J0ID0gbmV3IFBvcnQocGFyc2VkUG9ydCk7XG4gICAgY29uc3QgdGFnID0gbmV3IFRhZyhkZWNvZGVVUklDb21wb25lbnQodXJsUGFyc2VyUmVzdWx0Lmhhc2guc3Vic3RyaW5nKDEpKSk7XG4gICAgY29uc3QgYjY0RW5jb2RlZFVzZXJJbmZvID0gdXJsUGFyc2VyUmVzdWx0LnVzZXJuYW1lLnJlcGxhY2UoLyUzRC9nLCAnPScpO1xuICAgIC8vIGJhc2U2NC5kZWNvZGUgdGhyb3dzIGFzIGRlc2lyZWQgd2hlbiBnaXZlbiBpbnZhbGlkIGJhc2U2NCBpbnB1dC5cbiAgICBjb25zdCBiNjREZWNvZGVkVXNlckluZm8gPSBiNjREZWNvZGUoYjY0RW5jb2RlZFVzZXJJbmZvKTtcbiAgICBjb25zdCBjb2xvbklkeCA9IGI2NERlY29kZWRVc2VySW5mby5pbmRleE9mKCc6Jyk7XG4gICAgaWYgKGNvbG9uSWR4ID09PSAtMSkge1xuICAgICAgdGhyb3cgbmV3IEludmFsaWRVcmkoYE1pc3NpbmcgcGFzc3dvcmRgKTtcbiAgICB9XG4gICAgY29uc3QgbWV0aG9kU3RyaW5nID0gYjY0RGVjb2RlZFVzZXJJbmZvLnN1YnN0cmluZygwLCBjb2xvbklkeCk7XG4gICAgY29uc3QgbWV0aG9kID0gbmV3IE1ldGhvZChtZXRob2RTdHJpbmcpO1xuICAgIGNvbnN0IHBhc3N3b3JkU3RyaW5nID0gYjY0RGVjb2RlZFVzZXJJbmZvLnN1YnN0cmluZyhjb2xvbklkeCArIDEpO1xuICAgIGNvbnN0IHBhc3N3b3JkID0gbmV3IFBhc3N3b3JkKHBhc3N3b3JkU3RyaW5nKTtcbiAgICBjb25zdCBxdWVyeVBhcmFtcyA9IHVybFBhcnNlclJlc3VsdC5zZWFyY2guc3Vic3RyaW5nKDEpLnNwbGl0KCcmJyk7XG4gICAgY29uc3QgZXh0cmEgPSB7fSBhcyB7W2tleTogc3RyaW5nXTogc3RyaW5nfTtcbiAgICBmb3IgKGNvbnN0IHBhaXIgb2YgcXVlcnlQYXJhbXMpIHtcbiAgICAgIGNvbnN0IFtrZXksIHZhbHVlXSA9IHBhaXIuc3BsaXQoJz0nLCAyKTtcbiAgICAgIGlmICgha2V5KSBjb250aW51ZTtcbiAgICAgIGV4dHJhW2tleV0gPSBkZWNvZGVVUklDb21wb25lbnQodmFsdWUgfHwgJycpO1xuICAgIH1cbiAgICByZXR1cm4ge21ldGhvZCwgcGFzc3dvcmQsIGhvc3QsIHBvcnQsIHRhZywgZXh0cmF9O1xuICB9LFxuXG4gIHN0cmluZ2lmeTogKGNvbmZpZzogQ29uZmlnKSA9PiB7XG4gICAgY29uc3Qge2hvc3QsIHBvcnQsIG1ldGhvZCwgcGFzc3dvcmQsIHRhZywgZXh0cmF9ID0gY29uZmlnO1xuICAgIGNvbnN0IHVzZXJJbmZvID0gYjY0RW5jb2RlKGAke21ldGhvZC5kYXRhfToke3Bhc3N3b3JkLmRhdGF9YCk7XG4gICAgY29uc3QgdXJpSG9zdCA9IFNIQURPV1NPQ0tTX1VSSS5nZXRVcmlGb3JtYXR0ZWRIb3N0KGhvc3QpO1xuICAgIGNvbnN0IGhhc2ggPSBTSEFET1dTT0NLU19VUkkuZ2V0SGFzaCh0YWcpO1xuICAgIGxldCBxdWVyeVN0cmluZyA9ICcnO1xuICAgIGZvciAoY29uc3Qga2V5IGluIGV4dHJhKSB7XG4gICAgICBpZiAoIWtleSkgY29udGludWU7XG4gICAgICBxdWVyeVN0cmluZyArPSAocXVlcnlTdHJpbmcgPyAnJicgOiAnPycpICsgYCR7a2V5fT0ke2VuY29kZVVSSUNvbXBvbmVudChleHRyYVtrZXldKX1gO1xuICAgIH1cbiAgICByZXR1cm4gYHNzOi8vJHt1c2VySW5mb31AJHt1cmlIb3N0fToke3BvcnQuZGF0YX0vJHtxdWVyeVN0cmluZ30ke2hhc2h9YDtcbiAgfSxcbn07XG4iXX0=