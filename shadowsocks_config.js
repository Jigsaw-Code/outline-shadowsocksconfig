"use strict";
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
var __extends = (this && this.__extends) || (function () {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
(function iife() {
  const platformExportObj = (function detectPlatformExportObj() {
    if (typeof module !== 'undefined' && module.exports) {
      return module.exports;  // node
    } else if (typeof window !== 'undefined') {
      return window;  // browser
    }
    throw new Error('Could not detect platform global object (no window or module.exports)');
  })();
/* tslint:disable */
var isBrowser = typeof window !== 'undefined';
var b64Encode = isBrowser ? btoa : require('base-64').encode;
var b64Decode = isBrowser ? atob : require('base-64').decode;
var URL = isBrowser ? window.URL : require('url').URL;
var punycode = isBrowser ? window.punycode : require('punycode');
if (!punycode) {
    throw new Error("Could not find punycode. Did you forget to add e.g.\n  <script src=\"bower_components/punycode/punycode.min.js\"></script>?");
}
/* tslint:enable */
// Custom error base class
var ShadowsocksConfigError = /** @class */ (function (_super) {
    __extends(ShadowsocksConfigError, _super);
    function ShadowsocksConfigError(message) {
        var _newTarget = this.constructor;
        var _this = _super.call(this, message) || this;
        Object.setPrototypeOf(_this, _newTarget.prototype); // restore prototype chain
        _this.name = _newTarget.name;
        return _this;
    }
    return ShadowsocksConfigError;
}(Error));
platformExportObj.ShadowsocksConfigError = ShadowsocksConfigError;
var InvalidConfigField = /** @class */ (function (_super) {
    __extends(InvalidConfigField, _super);
    function InvalidConfigField() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return InvalidConfigField;
}(ShadowsocksConfigError));
platformExportObj.InvalidConfigField = InvalidConfigField;
var InvalidUri = /** @class */ (function (_super) {
    __extends(InvalidUri, _super);
    function InvalidUri() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return InvalidUri;
}(ShadowsocksConfigError));
platformExportObj.InvalidUri = InvalidUri;
// Self-validating/normalizing config data types implement this ValidatedConfigField interface.
// Constructors take some data, validate, normalize, and store if valid, or throw otherwise.
var ValidatedConfigField = /** @class */ (function () {
    function ValidatedConfigField() {
    }
    return ValidatedConfigField;
}());
platformExportObj.ValidatedConfigField = ValidatedConfigField;
function throwErrorForInvalidField(name, value, reason) {
    throw new InvalidConfigField("Invalid " + name + ": " + value + " " + (reason || ''));
}
var Host = /** @class */ (function (_super) {
    __extends(Host, _super);
    function Host(host) {
        var _this = _super.call(this) || this;
        if (!host) {
            throwErrorForInvalidField('host', host);
        }
        if (host instanceof Host) {
            host = host.data;
        }
        host = punycode.toASCII(host);
        _this.isIPv4 = Host.IPV4_PATTERN.test(host);
        _this.isIPv6 = _this.isIPv4 ? false : Host.IPV6_PATTERN.test(host);
        _this.isHostname = _this.isIPv4 || _this.isIPv6 ? false : Host.HOSTNAME_PATTERN.test(host);
        if (!(_this.isIPv4 || _this.isIPv6 || _this.isHostname)) {
            throwErrorForInvalidField('host', host);
        }
        _this.data = host;
        return _this;
    }
    Host.IPV4_PATTERN = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    Host.IPV6_PATTERN = /^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$/i;
    Host.HOSTNAME_PATTERN = /^[A-z0-9]+[A-z0-9_.-]*$/;
    return Host;
}(ValidatedConfigField));
platformExportObj.Host = Host;
var Port = /** @class */ (function (_super) {
    __extends(Port, _super);
    function Port(port) {
        var _this = _super.call(this) || this;
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
        _this.data = port;
        return _this;
    }
    Port.PATTERN = /^[0-9]{1,5}$/;
    return Port;
}(ValidatedConfigField));
platformExportObj.Port = Port;
// A method value must exactly match an element in the set of known ciphers.
// ref: https://github.com/shadowsocks/shadowsocks-libev/blob/10a2d3e3/completions/bash/ss-redir#L5
platformExportObj.METHODS = new Set([
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
var Method = /** @class */ (function (_super) {
    __extends(Method, _super);
    function Method(method) {
        var _this = _super.call(this) || this;
        if (method instanceof Method) {
            method = method.data;
        }
        if (!platformExportObj.METHODS.has(method)) {
            throwErrorForInvalidField('method', method);
        }
        _this.data = method;
        return _this;
    }
    return Method;
}(ValidatedConfigField));
platformExportObj.Method = Method;
var Password = /** @class */ (function (_super) {
    __extends(Password, _super);
    function Password(password) {
        var _this = _super.call(this) || this;
        _this.data = password instanceof Password ? password.data : password;
        return _this;
    }
    return Password;
}(ValidatedConfigField));
platformExportObj.Password = Password;
var Tag = /** @class */ (function (_super) {
    __extends(Tag, _super);
    function Tag(tag) {
        if (tag === void 0) { tag = ''; }
        var _this = _super.call(this) || this;
        _this.data = tag instanceof Tag ? tag.data : tag;
        return _this;
    }
    return Tag;
}(ValidatedConfigField));
platformExportObj.Tag = Tag;
// tslint:disable-next-line:no-any
function makeConfig(input) {
    // Use "!" for the required fields to tell tsc that we handle undefined in the
    // ValidatedConfigFields we call; tsc can't figure that out otherwise.
    var config = {
        host: new Host(input.host),
        port: new Port(input.port),
        method: new Method(input.method),
        password: new Password(input.password),
        tag: new Tag(input.tag),
        extra: {},
    };
    // Put any remaining fields in `input` into `config.extra`.
    for (var _i = 0, _a = Object.keys(input); _i < _a.length; _i++) {
        var key = _a[_i];
        if (!/^(host|port|method|password|tag)$/.test(key)) {
            config.extra[key] = input[key] && input[key].toString();
        }
    }
    return config;
}
platformExportObj.makeConfig = makeConfig;
platformExportObj.SHADOWSOCKS_URI = {
    PROTOCOL: 'ss:',
    getUriFormattedHost: function (host) {
        return host.isIPv6 ? "[" + host.data + "]" : host.data;
    },
    getHash: function (tag) {
        return tag.data ? "#" + encodeURIComponent(tag.data) : '';
    },
    validateProtocol: function (uri) {
        if (!uri.startsWith(platformExportObj.SHADOWSOCKS_URI.PROTOCOL)) {
            throw new InvalidUri("URI must start with \"" + platformExportObj.SHADOWSOCKS_URI.PROTOCOL + "\": " + uri);
        }
    },
    parse: function (uri) {
        var error;
        for (var _i = 0, _a = [platformExportObj.SIP002_URI, platformExportObj.LEGACY_BASE64_URI]; _i < _a.length; _i++) {
            var uriType = _a[_i];
            try {
                return uriType.parse(uri);
            }
            catch (e) {
                error = e;
            }
        }
        if (!(error instanceof InvalidUri)) {
            var originalErrorName = error.name || '(Unnamed Error)';
            var originalErrorMessage = error.message || '(no error message provided)';
            var originalErrorString = originalErrorName + ": " + originalErrorMessage;
            var newErrorMessage = "Invalid input: " + uri + " - Original error: " + originalErrorString;
            error = new InvalidUri(newErrorMessage);
        }
        throw error;
    },
};
// Ref: https://shadowsocks.org/en/config/quick-guide.html
platformExportObj.LEGACY_BASE64_URI = {
    parse: function (uri) {
        platformExportObj.SHADOWSOCKS_URI.validateProtocol(uri);
        var hashIndex = uri.indexOf('#');
        var hasTag = hashIndex !== -1;
        var b64EndIndex = hasTag ? hashIndex : uri.length;
        var tagStartIndex = hasTag ? hashIndex + 1 : uri.length;
        var tag = new Tag(decodeURIComponent(uri.substring(tagStartIndex)));
        var b64EncodedData = uri.substring('ss://'.length, b64EndIndex);
        var b64DecodedData = b64Decode(b64EncodedData);
        var atSignIndex = b64DecodedData.indexOf('@');
        if (atSignIndex === -1) {
            throw new InvalidUri("Missing \"@\": " + b64DecodedData);
        }
        var methodAndPassword = b64DecodedData.substring(0, atSignIndex);
        var methodEndIndex = methodAndPassword.indexOf(':');
        if (methodEndIndex === -1) {
            throw new InvalidUri("Missing password part: " + methodAndPassword);
        }
        var methodString = methodAndPassword.substring(0, methodEndIndex);
        var method = new Method(methodString);
        var passwordStartIndex = methodEndIndex + 1;
        var passwordString = methodAndPassword.substring(passwordStartIndex);
        var password = new Password(passwordString);
        var hostStartIndex = atSignIndex + 1;
        var hostAndPort = b64DecodedData.substring(hostStartIndex);
        var hostEndIndex = hostAndPort.lastIndexOf(':');
        if (hostEndIndex === -1) {
            throw new InvalidUri("Missing port part: " + hostAndPort);
        }
        var uriFormattedHost = hostAndPort.substring(0, hostEndIndex);
        var host;
        try {
            host = new Host(uriFormattedHost);
        }
        catch (_) {
            // Could be IPv6 host formatted with surrounding brackets, so try stripping first and last
            // characters. If this throws, give up and let the exception propagate.
            host = new Host(uriFormattedHost.substring(1, uriFormattedHost.length - 1));
        }
        var portStartIndex = hostEndIndex + 1;
        var portString = hostAndPort.substring(portStartIndex);
        var port = new Port(portString);
        var extra = {}; // empty because LegacyBase64Uri can't hold extra
        return { method: method, password: password, host: host, port: port, tag: tag, extra: extra };
    },
    stringify: function (config) {
        var host = config.host, port = config.port, method = config.method, password = config.password, tag = config.tag;
        var hash = platformExportObj.SHADOWSOCKS_URI.getHash(tag);
        var b64EncodedData = b64Encode(method.data + ":" + password.data + "@" + host.data + ":" + port.data);
        var dataLength = b64EncodedData.length;
        var paddingLength = 0;
        for (; b64EncodedData[dataLength - 1 - paddingLength] === '='; paddingLength++)
            ;
        b64EncodedData = paddingLength === 0 ? b64EncodedData :
            b64EncodedData.substring(0, dataLength - paddingLength);
        return "ss://" + b64EncodedData + hash;
    },
};
// Ref: https://shadowsocks.org/en/spec/SIP002-URI-Scheme.html
platformExportObj.SIP002_URI = {
    parse: function (uri) {
        platformExportObj.SHADOWSOCKS_URI.validateProtocol(uri);
        // Can use built-in URL parser for expedience. Just have to replace "ss" with "http" to ensure
        // correct results.
        var inputForUrlParser = "http" + uri.substring(2);
        // The built-in URL parser throws as desired when given URIs with invalid syntax.
        var urlParserResult = new URL(inputForUrlParser);
        var uriFormattedHost = urlParserResult.hostname;
        // URI-formatted IPv6 hostnames have surrounding brackets.
        var last = uriFormattedHost.length - 1;
        var brackets = uriFormattedHost[0] === '[' && uriFormattedHost[last] === ']';
        var hostString = brackets ? uriFormattedHost.substring(1, last) : uriFormattedHost;
        var host = new Host(hostString);
        var port = new Port(urlParserResult.port);
        var tag = new Tag(decodeURIComponent(urlParserResult.hash.substring(1)));
        var b64EncodedUserInfo = urlParserResult.username.replace(/%3D/g, '=');
        // base64.decode throws as desired when given invalid base64 input.
        var b64DecodedUserInfo = b64Decode(b64EncodedUserInfo);
        var colonIdx = b64DecodedUserInfo.indexOf(':');
        if (colonIdx === -1) {
            throw new InvalidUri("Missing password part: " + b64DecodedUserInfo);
        }
        var methodString = b64DecodedUserInfo.substring(0, colonIdx);
        var method = new Method(methodString);
        var passwordString = b64DecodedUserInfo.substring(colonIdx + 1);
        var password = new Password(passwordString);
        var queryParams = urlParserResult.search.substring(1).split('&');
        var extra = {};
        for (var _i = 0, queryParams_1 = queryParams; _i < queryParams_1.length; _i++) {
            var pair = queryParams_1[_i];
            var _a = pair.split('=', 2), key = _a[0], value = _a[1];
            if (!key)
                continue;
            extra[key] = decodeURIComponent(value || '');
        }
        return { method: method, password: password, host: host, port: port, tag: tag, extra: extra };
    },
    stringify: function (config) {
        var host = config.host, port = config.port, method = config.method, password = config.password, tag = config.tag, extra = config.extra;
        var userInfo = b64Encode(method.data + ":" + password.data);
        var uriHost = platformExportObj.SHADOWSOCKS_URI.getUriFormattedHost(host);
        var hash = platformExportObj.SHADOWSOCKS_URI.getHash(tag);
        var queryString = '';
        for (var key in extra) {
            if (!key)
                continue;
            queryString += (queryString ? '&' : '?') + (key + "=" + encodeURIComponent(extra[key]));
        }
        return "ss://" + userInfo + "@" + uriHost + ":" + port.data + "/" + queryString + hash;
    },
};
})();
//# sourceMappingURL=data:application/json;charset=utf8;base64,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O1FBQ0QsTUFBTSxDQUFDLEVBQUMsTUFBTSxRQUFBLEVBQUUsUUFBUSxVQUFBLEVBQUUsSUFBSSxNQUFBLEVBQUUsSUFBSSxNQUFBLEVBQUUsR0FBRyxLQUFBLEVBQUUsS0FBSyxPQUFBLEVBQUMsQ0FBQztJQUNwRCxDQUFDO0lBRUQsU0FBUyxFQUFFLFVBQUMsTUFBYztRQUNqQixJQUFBLGtCQUFJLEVBQUUsa0JBQUksRUFBRSxzQkFBTSxFQUFFLDBCQUFRLEVBQUUsZ0JBQUcsRUFBRSxvQkFBSyxDQUFXO1FBQzFELElBQU0sUUFBUSxHQUFHLFNBQVMsQ0FBSSxNQUFNLENBQUMsSUFBSSxTQUFJLFFBQVEsQ0FBQyxJQUFNLENBQUMsQ0FBQztRQUM5RCxJQUFNLE9BQU8sR0FBRyx1QkFBZSxDQUFDLG1CQUFtQixDQUFDLElBQUksQ0FBQyxDQUFDO1FBQzFELElBQU0sSUFBSSxHQUFHLHVCQUFlLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO1FBQzFDLElBQUksV0FBVyxHQUFHLEVBQUUsQ0FBQztRQUNyQixHQUFHLENBQUMsQ0FBQyxJQUFNLEdBQUcsSUFBSSxLQUFLLENBQUMsQ0FBQyxDQUFDO1lBQ3hCLEVBQUUsQ0FBQyxDQUFDLENBQUMsR0FBRyxDQUFDO2dCQUFDLFFBQVEsQ0FBQztZQUNuQixXQUFXLElBQUksQ0FBQyxXQUFXLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsR0FBRyxDQUFDLElBQU0sR0FBRyxTQUFJLGtCQUFrQixDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBRyxDQUFBLENBQUM7UUFDeEYsQ0FBQztRQUNELE1BQU0sQ0FBQyxVQUFRLFFBQVEsU0FBSSxPQUFPLFNBQUksSUFBSSxDQUFDLElBQUksU0FBSSxXQUFXLEdBQUcsSUFBTSxDQUFDO0lBQzFFLENBQUM7Q0FDRixDQUFDIiwiZmlsZSI6InNoYWRvd3NvY2tzX2NvbmZpZy5qcyIsInNvdXJjZXNDb250ZW50IjpbIi8vIENvcHlyaWdodCAyMDE4IFRoZSBPdXRsaW5lIEF1dGhvcnNcbi8vXG4vLyBMaWNlbnNlZCB1bmRlciB0aGUgQXBhY2hlIExpY2Vuc2UsIFZlcnNpb24gMi4wICh0aGUgXCJMaWNlbnNlXCIpO1xuLy8geW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLlxuLy8gWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0XG4vL1xuLy8gICAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjBcbi8vXG4vLyBVbmxlc3MgcmVxdWlyZWQgYnkgYXBwbGljYWJsZSBsYXcgb3IgYWdyZWVkIHRvIGluIHdyaXRpbmcsIHNvZnR3YXJlXG4vLyBkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiBcIkFTIElTXCIgQkFTSVMsXG4vLyBXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC5cbi8vIFNlZSB0aGUgTGljZW5zZSBmb3IgdGhlIHNwZWNpZmljIGxhbmd1YWdlIGdvdmVybmluZyBwZXJtaXNzaW9ucyBhbmRcbi8vIGxpbWl0YXRpb25zIHVuZGVyIHRoZSBMaWNlbnNlLlxuXG4vKiB0c2xpbnQ6ZGlzYWJsZSAqL1xuY29uc3QgaXNCcm93c2VyID0gdHlwZW9mIHdpbmRvdyAhPT0gJ3VuZGVmaW5lZCc7XG5jb25zdCBiNjRFbmNvZGUgPSBpc0Jyb3dzZXIgPyBidG9hIDogcmVxdWlyZSgnYmFzZS02NCcpLmVuY29kZTtcbmNvbnN0IGI2NERlY29kZSA9IGlzQnJvd3NlciA/IGF0b2IgOiByZXF1aXJlKCdiYXNlLTY0JykuZGVjb2RlO1xuY29uc3QgVVJMID0gaXNCcm93c2VyID8gd2luZG93LlVSTCA6IHJlcXVpcmUoJ3VybCcpLlVSTDtcbmNvbnN0IHB1bnljb2RlID0gaXNCcm93c2VyID8gKHdpbmRvdyBhcyBhbnkpLnB1bnljb2RlIDogcmVxdWlyZSgncHVueWNvZGUnKTtcbmlmICghcHVueWNvZGUpIHtcbiAgdGhyb3cgbmV3IEVycm9yKGBDb3VsZCBub3QgZmluZCBwdW55Y29kZS4gRGlkIHlvdSBmb3JnZXQgdG8gYWRkIGUuZy5cbiAgPHNjcmlwdCBzcmM9XCJib3dlcl9jb21wb25lbnRzL3B1bnljb2RlL3B1bnljb2RlLm1pbi5qc1wiPjwvc2NyaXB0Pj9gKTtcbn1cbi8qIHRzbGludDplbmFibGUgKi9cblxuLy8gQ3VzdG9tIGVycm9yIGJhc2UgY2xhc3NcbmV4cG9ydCBjbGFzcyBTaGFkb3dzb2Nrc0NvbmZpZ0Vycm9yIGV4dGVuZHMgRXJyb3Ige1xuICBjb25zdHJ1Y3RvcihtZXNzYWdlOiBzdHJpbmcpIHtcbiAgICBzdXBlcihtZXNzYWdlKTsgIC8vICdFcnJvcicgYnJlYWtzIHByb3RvdHlwZSBjaGFpbiBoZXJlIGlmIHRoaXMgaXMgdHJhbnNwaWxlZCB0byBlczVcbiAgICBPYmplY3Quc2V0UHJvdG90eXBlT2YodGhpcywgbmV3LnRhcmdldC5wcm90b3R5cGUpOyAgLy8gcmVzdG9yZSBwcm90b3R5cGUgY2hhaW5cbiAgICB0aGlzLm5hbWUgPSBuZXcudGFyZ2V0Lm5hbWU7XG4gIH1cbn1cblxuZXhwb3J0IGNsYXNzIEludmFsaWRDb25maWdGaWVsZCBleHRlbmRzIFNoYWRvd3NvY2tzQ29uZmlnRXJyb3Ige31cblxuZXhwb3J0IGNsYXNzIEludmFsaWRVcmkgZXh0ZW5kcyBTaGFkb3dzb2Nrc0NvbmZpZ0Vycm9yIHt9XG5cbi8vIFNlbGYtdmFsaWRhdGluZy9ub3JtYWxpemluZyBjb25maWcgZGF0YSB0eXBlcyBpbXBsZW1lbnQgdGhpcyBWYWxpZGF0ZWRDb25maWdGaWVsZCBpbnRlcmZhY2UuXG4vLyBDb25zdHJ1Y3RvcnMgdGFrZSBzb21lIGRhdGEsIHZhbGlkYXRlLCBub3JtYWxpemUsIGFuZCBzdG9yZSBpZiB2YWxpZCwgb3IgdGhyb3cgb3RoZXJ3aXNlLlxuZXhwb3J0IGFic3RyYWN0IGNsYXNzIFZhbGlkYXRlZENvbmZpZ0ZpZWxkIHt9XG5cbmZ1bmN0aW9uIHRocm93RXJyb3JGb3JJbnZhbGlkRmllbGQobmFtZTogc3RyaW5nLCB2YWx1ZToge30sIHJlYXNvbj86IHN0cmluZykge1xuICB0aHJvdyBuZXcgSW52YWxpZENvbmZpZ0ZpZWxkKGBJbnZhbGlkICR7bmFtZX06ICR7dmFsdWV9ICR7cmVhc29uIHx8ICcnfWApO1xufVxuXG5leHBvcnQgY2xhc3MgSG9zdCBleHRlbmRzIFZhbGlkYXRlZENvbmZpZ0ZpZWxkIHtcbiAgcHVibGljIHN0YXRpYyBJUFY0X1BBVFRFUk4gPSAvXig/OlswLTldezEsM31cXC4pezN9WzAtOV17MSwzfSQvO1xuICBwdWJsaWMgc3RhdGljIElQVjZfUEFUVEVSTiA9IC9eKD86W0EtRjAtOV17MSw0fTopezd9W0EtRjAtOV17MSw0fSQvaTtcbiAgcHVibGljIHN0YXRpYyBIT1NUTkFNRV9QQVRURVJOID0gL15bQS16MC05XStbQS16MC05Xy4tXSokLztcbiAgcHVibGljIHJlYWRvbmx5IGRhdGE6IHN0cmluZztcbiAgcHVibGljIHJlYWRvbmx5IGlzSVB2NDogYm9vbGVhbjtcbiAgcHVibGljIHJlYWRvbmx5IGlzSVB2NjogYm9vbGVhbjtcbiAgcHVibGljIHJlYWRvbmx5IGlzSG9zdG5hbWU6IGJvb2xlYW47XG5cbiAgY29uc3RydWN0b3IoaG9zdDogSG9zdCB8IHN0cmluZykge1xuICAgIHN1cGVyKCk7XG4gICAgaWYgKCFob3N0KSB7XG4gICAgICB0aHJvd0Vycm9yRm9ySW52YWxpZEZpZWxkKCdob3N0JywgaG9zdCk7XG4gICAgfVxuICAgIGlmIChob3N0IGluc3RhbmNlb2YgSG9zdCkge1xuICAgICAgaG9zdCA9IGhvc3QuZGF0YTtcbiAgICB9XG4gICAgaG9zdCA9IHB1bnljb2RlLnRvQVNDSUkoaG9zdCkgYXMgc3RyaW5nO1xuICAgIHRoaXMuaXNJUHY0ID0gSG9zdC5JUFY0X1BBVFRFUk4udGVzdChob3N0KTtcbiAgICB0aGlzLmlzSVB2NiA9IHRoaXMuaXNJUHY0ID8gZmFsc2UgOiBIb3N0LklQVjZfUEFUVEVSTi50ZXN0KGhvc3QpO1xuICAgIHRoaXMuaXNIb3N0bmFtZSA9IHRoaXMuaXNJUHY0IHx8IHRoaXMuaXNJUHY2ID8gZmFsc2UgOiBIb3N0LkhPU1ROQU1FX1BBVFRFUk4udGVzdChob3N0KTtcbiAgICBpZiAoISh0aGlzLmlzSVB2NCB8fCB0aGlzLmlzSVB2NiB8fCB0aGlzLmlzSG9zdG5hbWUpKSB7XG4gICAgICB0aHJvd0Vycm9yRm9ySW52YWxpZEZpZWxkKCdob3N0JywgaG9zdCk7XG4gICAgfVxuICAgIHRoaXMuZGF0YSA9IGhvc3Q7XG4gIH1cbn1cblxuZXhwb3J0IGNsYXNzIFBvcnQgZXh0ZW5kcyBWYWxpZGF0ZWRDb25maWdGaWVsZCB7XG4gIHB1YmxpYyBzdGF0aWMgcmVhZG9ubHkgUEFUVEVSTiA9IC9eWzAtOV17MSw1fSQvO1xuICBwdWJsaWMgcmVhZG9ubHkgZGF0YTogbnVtYmVyO1xuXG4gIGNvbnN0cnVjdG9yKHBvcnQ6IFBvcnQgfCBzdHJpbmcgfCBudW1iZXIpIHtcbiAgICBzdXBlcigpO1xuICAgIGlmIChwb3J0IGluc3RhbmNlb2YgUG9ydCkge1xuICAgICAgcG9ydCA9IHBvcnQuZGF0YTtcbiAgICB9XG4gICAgaWYgKHR5cGVvZiBwb3J0ID09PSAnbnVtYmVyJykge1xuICAgICAgLy8gU3RyaW5naWZ5IGluIGNhc2UgbmVnYXRpdmUgb3IgZmxvYXRpbmcgcG9pbnQgLT4gdGhlIHJlZ2V4IHRlc3QgYmVsb3cgd2lsbCBjYXRjaC5cbiAgICAgIHBvcnQgPSBwb3J0LnRvU3RyaW5nKCk7XG4gICAgfVxuICAgIGlmICghUG9ydC5QQVRURVJOLnRlc3QocG9ydCkpIHtcbiAgICAgIHRocm93RXJyb3JGb3JJbnZhbGlkRmllbGQoJ3BvcnQnLCBwb3J0KTtcbiAgICB9XG4gICAgLy8gQ291bGQgZXhjZWVkIHRoZSBtYXhpbXVtIHBvcnQgbnVtYmVyLCBzbyBjb252ZXJ0IHRvIE51bWJlciB0byBjaGVjay4gQ291bGQgYWxzbyBoYXZlIGxlYWRpbmdcbiAgICAvLyB6ZXJvcy4gQ29udmVydGluZyB0byBOdW1iZXIgZHJvcHMgdGhvc2UsIHNvIHdlIGdldCBub3JtYWxpemF0aW9uIGZvciBmcmVlLiA6KVxuICAgIHBvcnQgPSBOdW1iZXIocG9ydCk7XG4gICAgaWYgKHBvcnQgPiA2NTUzNSkge1xuICAgICAgdGhyb3dFcnJvckZvckludmFsaWRGaWVsZCgncG9ydCcsIHBvcnQpO1xuICAgIH1cbiAgICB0aGlzLmRhdGEgPSBwb3J0O1xuICB9XG59XG5cbi8vIEEgbWV0aG9kIHZhbHVlIG11c3QgZXhhY3RseSBtYXRjaCBhbiBlbGVtZW50IGluIHRoZSBzZXQgb2Yga25vd24gY2lwaGVycy5cbi8vIHJlZjogaHR0cHM6Ly9naXRodWIuY29tL3NoYWRvd3NvY2tzL3NoYWRvd3NvY2tzLWxpYmV2L2Jsb2IvMTBhMmQzZTMvY29tcGxldGlvbnMvYmFzaC9zcy1yZWRpciNMNVxuZXhwb3J0IGNvbnN0IE1FVEhPRFMgPSBuZXcgU2V0KFtcbiAgJ3JjNC1tZDUnLFxuICAnYWVzLTEyOC1nY20nLFxuICAnYWVzLTE5Mi1nY20nLFxuICAnYWVzLTI1Ni1nY20nLFxuICAnYWVzLTEyOC1jZmInLFxuICAnYWVzLTE5Mi1jZmInLFxuICAnYWVzLTI1Ni1jZmInLFxuICAnYWVzLTEyOC1jdHInLFxuICAnYWVzLTE5Mi1jdHInLFxuICAnYWVzLTI1Ni1jdHInLFxuICAnY2FtZWxsaWEtMTI4LWNmYicsXG4gICdjYW1lbGxpYS0xOTItY2ZiJyxcbiAgJ2NhbWVsbGlhLTI1Ni1jZmInLFxuICAnYmYtY2ZiJyxcbiAgJ2NoYWNoYTIwLWlldGYtcG9seTEzMDUnLFxuICAnc2Fsc2EyMCcsXG4gICdjaGFjaGEyMCcsXG4gICdjaGFjaGEyMC1pZXRmJyxcbiAgJ3hjaGFjaGEyMC1pZXRmLXBvbHkxMzA1Jyxcbl0pO1xuXG5leHBvcnQgY2xhc3MgTWV0aG9kIGV4dGVuZHMgVmFsaWRhdGVkQ29uZmlnRmllbGQge1xuICBwdWJsaWMgcmVhZG9ubHkgZGF0YTogc3RyaW5nO1xuICBjb25zdHJ1Y3RvcihtZXRob2Q6IE1ldGhvZCB8IHN0cmluZykge1xuICAgIHN1cGVyKCk7XG4gICAgaWYgKG1ldGhvZCBpbnN0YW5jZW9mIE1ldGhvZCkge1xuICAgICAgbWV0aG9kID0gbWV0aG9kLmRhdGE7XG4gICAgfVxuICAgIGlmICghTUVUSE9EUy5oYXMobWV0aG9kKSkge1xuICAgICAgdGhyb3dFcnJvckZvckludmFsaWRGaWVsZCgnbWV0aG9kJywgbWV0aG9kKTtcbiAgICB9XG4gICAgdGhpcy5kYXRhID0gbWV0aG9kO1xuICB9XG59XG5cbmV4cG9ydCBjbGFzcyBQYXNzd29yZCBleHRlbmRzIFZhbGlkYXRlZENvbmZpZ0ZpZWxkIHtcbiAgcHVibGljIHJlYWRvbmx5IGRhdGE6IHN0cmluZztcblxuICBjb25zdHJ1Y3RvcihwYXNzd29yZDogUGFzc3dvcmQgfCBzdHJpbmcpIHtcbiAgICBzdXBlcigpO1xuICAgIHRoaXMuZGF0YSA9IHBhc3N3b3JkIGluc3RhbmNlb2YgUGFzc3dvcmQgPyBwYXNzd29yZC5kYXRhIDogcGFzc3dvcmQ7XG4gIH1cbn1cblxuZXhwb3J0IGNsYXNzIFRhZyBleHRlbmRzIFZhbGlkYXRlZENvbmZpZ0ZpZWxkIHtcbiAgcHVibGljIHJlYWRvbmx5IGRhdGE6IHN0cmluZztcblxuICBjb25zdHJ1Y3Rvcih0YWc6IFRhZyB8IHN0cmluZyA9ICcnKSB7XG4gICAgc3VwZXIoKTtcbiAgICB0aGlzLmRhdGEgPSB0YWcgaW5zdGFuY2VvZiBUYWcgPyB0YWcuZGF0YSA6IHRhZztcbiAgfVxufVxuXG5leHBvcnQgaW50ZXJmYWNlIENvbmZpZyB7XG4gIGhvc3Q6IEhvc3Q7XG4gIHBvcnQ6IFBvcnQ7XG4gIG1ldGhvZDogTWV0aG9kO1xuICBwYXNzd29yZDogUGFzc3dvcmQ7XG4gIHRhZzogVGFnO1xuICAvLyBBbnkgYWRkaXRpb25hbCBjb25maWd1cmF0aW9uIChlLmcuIGB0aW1lb3V0YCwgU0lQMDAzIGBwbHVnaW5gLCBldGMuKSBtYXkgYmUgc3RvcmVkIGhlcmUuXG4gIGV4dHJhOiB7W2tleTogc3RyaW5nXTogc3RyaW5nfTtcbn1cblxuLy8gdHNsaW50OmRpc2FibGUtbmV4dC1saW5lOm5vLWFueVxuZXhwb3J0IGZ1bmN0aW9uIG1ha2VDb25maWcoaW5wdXQ6IHtba2V5OiBzdHJpbmddOiBhbnl9KTogQ29uZmlnIHtcbiAgLy8gVXNlIFwiIVwiIGZvciB0aGUgcmVxdWlyZWQgZmllbGRzIHRvIHRlbGwgdHNjIHRoYXQgd2UgaGFuZGxlIHVuZGVmaW5lZCBpbiB0aGVcbiAgLy8gVmFsaWRhdGVkQ29uZmlnRmllbGRzIHdlIGNhbGw7IHRzYyBjYW4ndCBmaWd1cmUgdGhhdCBvdXQgb3RoZXJ3aXNlLlxuICBjb25zdCBjb25maWcgPSB7XG4gICAgaG9zdDogbmV3IEhvc3QoaW5wdXQuaG9zdCEpLFxuICAgIHBvcnQ6IG5ldyBQb3J0KGlucHV0LnBvcnQhKSxcbiAgICBtZXRob2Q6IG5ldyBNZXRob2QoaW5wdXQubWV0aG9kISksXG4gICAgcGFzc3dvcmQ6IG5ldyBQYXNzd29yZChpbnB1dC5wYXNzd29yZCEpLFxuICAgIHRhZzogbmV3IFRhZyhpbnB1dC50YWcpLCAgLy8gaW5wdXQudGFnIG1pZ2h0IGJlIHVuZGVmaW5lZCBidXQgVGFnKCkgaGFuZGxlcyB0aGF0IGZpbmUuXG4gICAgZXh0cmE6IHt9IGFzIHtba2V5OiBzdHJpbmddOiBzdHJpbmd9LFxuICB9O1xuICAvLyBQdXQgYW55IHJlbWFpbmluZyBmaWVsZHMgaW4gYGlucHV0YCBpbnRvIGBjb25maWcuZXh0cmFgLlxuICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3Qua2V5cyhpbnB1dCkpIHtcbiAgICBpZiAoIS9eKGhvc3R8cG9ydHxtZXRob2R8cGFzc3dvcmR8dGFnKSQvLnRlc3Qoa2V5KSkge1xuICAgICAgY29uZmlnLmV4dHJhW2tleV0gPSBpbnB1dFtrZXldICYmIGlucHV0W2tleV0udG9TdHJpbmcoKTtcbiAgICB9XG4gIH1cbiAgcmV0dXJuIGNvbmZpZztcbn1cblxuZXhwb3J0IGNvbnN0IFNIQURPV1NPQ0tTX1VSSSA9IHtcbiAgUFJPVE9DT0w6ICdzczonLFxuXG4gIGdldFVyaUZvcm1hdHRlZEhvc3Q6IChob3N0OiBIb3N0KSA9PiB7XG4gICAgcmV0dXJuIGhvc3QuaXNJUHY2ID8gYFske2hvc3QuZGF0YX1dYCA6IGhvc3QuZGF0YTtcbiAgfSxcblxuICBnZXRIYXNoOiAodGFnOiBUYWcpID0+IHtcbiAgICByZXR1cm4gdGFnLmRhdGEgPyBgIyR7ZW5jb2RlVVJJQ29tcG9uZW50KHRhZy5kYXRhKX1gIDogJyc7XG4gIH0sXG5cbiAgdmFsaWRhdGVQcm90b2NvbDogKHVyaTogc3RyaW5nKSA9PiB7XG4gICAgaWYgKCF1cmkuc3RhcnRzV2l0aChTSEFET1dTT0NLU19VUkkuUFJPVE9DT0wpKSB7XG4gICAgICB0aHJvdyBuZXcgSW52YWxpZFVyaShgVVJJIG11c3Qgc3RhcnQgd2l0aCBcIiR7U0hBRE9XU09DS1NfVVJJLlBST1RPQ09MfVwiOiAke3VyaX1gKTtcbiAgICB9XG4gIH0sXG5cbiAgcGFyc2U6ICh1cmk6IHN0cmluZyk6IENvbmZpZyA9PiB7XG4gICAgbGV0IGVycm9yOiBFcnJvciB8IHVuZGVmaW5lZDtcbiAgICBmb3IgKGNvbnN0IHVyaVR5cGUgb2YgW1NJUDAwMl9VUkksIExFR0FDWV9CQVNFNjRfVVJJXSkge1xuICAgICAgdHJ5IHtcbiAgICAgICAgcmV0dXJuIHVyaVR5cGUucGFyc2UodXJpKTtcbiAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgZXJyb3IgPSBlO1xuICAgICAgfVxuICAgIH1cbiAgICBpZiAoIShlcnJvciBpbnN0YW5jZW9mIEludmFsaWRVcmkpKSB7XG4gICAgICBjb25zdCBvcmlnaW5hbEVycm9yTmFtZSA9IGVycm9yIS5uYW1lISB8fCAnKFVubmFtZWQgRXJyb3IpJztcbiAgICAgIGNvbnN0IG9yaWdpbmFsRXJyb3JNZXNzYWdlID0gZXJyb3IhLm1lc3NhZ2UhIHx8ICcobm8gZXJyb3IgbWVzc2FnZSBwcm92aWRlZCknO1xuICAgICAgY29uc3Qgb3JpZ2luYWxFcnJvclN0cmluZyA9IGAke29yaWdpbmFsRXJyb3JOYW1lfTogJHtvcmlnaW5hbEVycm9yTWVzc2FnZX1gO1xuICAgICAgY29uc3QgbmV3RXJyb3JNZXNzYWdlID0gYEludmFsaWQgaW5wdXQ6ICR7dXJpfSAtIE9yaWdpbmFsIGVycm9yOiAke29yaWdpbmFsRXJyb3JTdHJpbmd9YDtcbiAgICAgIGVycm9yID0gbmV3IEludmFsaWRVcmkobmV3RXJyb3JNZXNzYWdlKTtcbiAgICB9XG4gICAgdGhyb3cgZXJyb3I7XG4gIH0sXG59O1xuXG4vLyBSZWY6IGh0dHBzOi8vc2hhZG93c29ja3Mub3JnL2VuL2NvbmZpZy9xdWljay1ndWlkZS5odG1sXG5leHBvcnQgY29uc3QgTEVHQUNZX0JBU0U2NF9VUkkgPSB7XG4gIHBhcnNlOiAodXJpOiBzdHJpbmcpOiBDb25maWcgPT4ge1xuICAgIFNIQURPV1NPQ0tTX1VSSS52YWxpZGF0ZVByb3RvY29sKHVyaSk7XG4gICAgY29uc3QgaGFzaEluZGV4ID0gdXJpLmluZGV4T2YoJyMnKTtcbiAgICBjb25zdCBoYXNUYWcgPSBoYXNoSW5kZXggIT09IC0xO1xuICAgIGNvbnN0IGI2NEVuZEluZGV4ID0gaGFzVGFnID8gaGFzaEluZGV4IDogdXJpLmxlbmd0aDtcbiAgICBjb25zdCB0YWdTdGFydEluZGV4ID0gaGFzVGFnID8gaGFzaEluZGV4ICsgMSA6IHVyaS5sZW5ndGg7XG4gICAgY29uc3QgdGFnID0gbmV3IFRhZyhkZWNvZGVVUklDb21wb25lbnQodXJpLnN1YnN0cmluZyh0YWdTdGFydEluZGV4KSkpO1xuICAgIGNvbnN0IGI2NEVuY29kZWREYXRhID0gdXJpLnN1YnN0cmluZygnc3M6Ly8nLmxlbmd0aCwgYjY0RW5kSW5kZXgpO1xuICAgIGNvbnN0IGI2NERlY29kZWREYXRhID0gYjY0RGVjb2RlKGI2NEVuY29kZWREYXRhKTtcbiAgICBjb25zdCBhdFNpZ25JbmRleCA9IGI2NERlY29kZWREYXRhLmluZGV4T2YoJ0AnKTtcbiAgICBpZiAoYXRTaWduSW5kZXggPT09IC0xKSB7XG4gICAgICB0aHJvdyBuZXcgSW52YWxpZFVyaShgTWlzc2luZyBcIkBcIjogJHtiNjREZWNvZGVkRGF0YX1gKTtcbiAgICB9XG4gICAgY29uc3QgbWV0aG9kQW5kUGFzc3dvcmQgPSBiNjREZWNvZGVkRGF0YS5zdWJzdHJpbmcoMCwgYXRTaWduSW5kZXgpO1xuICAgIGNvbnN0IG1ldGhvZEVuZEluZGV4ID0gbWV0aG9kQW5kUGFzc3dvcmQuaW5kZXhPZignOicpO1xuICAgIGlmIChtZXRob2RFbmRJbmRleCA9PT0gLTEpIHtcbiAgICAgIHRocm93IG5ldyBJbnZhbGlkVXJpKGBNaXNzaW5nIHBhc3N3b3JkIHBhcnQ6ICR7bWV0aG9kQW5kUGFzc3dvcmR9YCk7XG4gICAgfVxuICAgIGNvbnN0IG1ldGhvZFN0cmluZyA9IG1ldGhvZEFuZFBhc3N3b3JkLnN1YnN0cmluZygwLCBtZXRob2RFbmRJbmRleCk7XG4gICAgY29uc3QgbWV0aG9kID0gbmV3IE1ldGhvZChtZXRob2RTdHJpbmcpO1xuICAgIGNvbnN0IHBhc3N3b3JkU3RhcnRJbmRleCA9IG1ldGhvZEVuZEluZGV4ICsgMTtcbiAgICBjb25zdCBwYXNzd29yZFN0cmluZyA9IG1ldGhvZEFuZFBhc3N3b3JkLnN1YnN0cmluZyhwYXNzd29yZFN0YXJ0SW5kZXgpO1xuICAgIGNvbnN0IHBhc3N3b3JkID0gbmV3IFBhc3N3b3JkKHBhc3N3b3JkU3RyaW5nKTtcbiAgICBjb25zdCBob3N0U3RhcnRJbmRleCA9IGF0U2lnbkluZGV4ICsgMTtcbiAgICBjb25zdCBob3N0QW5kUG9ydCA9IGI2NERlY29kZWREYXRhLnN1YnN0cmluZyhob3N0U3RhcnRJbmRleCk7XG4gICAgY29uc3QgaG9zdEVuZEluZGV4ID0gaG9zdEFuZFBvcnQubGFzdEluZGV4T2YoJzonKTtcbiAgICBpZiAoaG9zdEVuZEluZGV4ID09PSAtMSkge1xuICAgICAgdGhyb3cgbmV3IEludmFsaWRVcmkoYE1pc3NpbmcgcG9ydCBwYXJ0OiAke2hvc3RBbmRQb3J0fWApO1xuICAgIH1cbiAgICBjb25zdCB1cmlGb3JtYXR0ZWRIb3N0ID0gaG9zdEFuZFBvcnQuc3Vic3RyaW5nKDAsIGhvc3RFbmRJbmRleCk7XG4gICAgbGV0IGhvc3Q6IEhvc3Q7XG4gICAgdHJ5IHtcbiAgICAgIGhvc3QgPSBuZXcgSG9zdCh1cmlGb3JtYXR0ZWRIb3N0KTtcbiAgICB9IGNhdGNoIChfKSB7XG4gICAgICAvLyBDb3VsZCBiZSBJUHY2IGhvc3QgZm9ybWF0dGVkIHdpdGggc3Vycm91bmRpbmcgYnJhY2tldHMsIHNvIHRyeSBzdHJpcHBpbmcgZmlyc3QgYW5kIGxhc3RcbiAgICAgIC8vIGNoYXJhY3RlcnMuIElmIHRoaXMgdGhyb3dzLCBnaXZlIHVwIGFuZCBsZXQgdGhlIGV4Y2VwdGlvbiBwcm9wYWdhdGUuXG4gICAgICBob3N0ID0gbmV3IEhvc3QodXJpRm9ybWF0dGVkSG9zdC5zdWJzdHJpbmcoMSwgdXJpRm9ybWF0dGVkSG9zdC5sZW5ndGggLSAxKSk7XG4gICAgfVxuICAgIGNvbnN0IHBvcnRTdGFydEluZGV4ID0gaG9zdEVuZEluZGV4ICsgMTtcbiAgICBjb25zdCBwb3J0U3RyaW5nID0gaG9zdEFuZFBvcnQuc3Vic3RyaW5nKHBvcnRTdGFydEluZGV4KTtcbiAgICBjb25zdCBwb3J0ID0gbmV3IFBvcnQocG9ydFN0cmluZyk7XG4gICAgY29uc3QgZXh0cmEgPSB7fSBhcyB7W2tleTogc3RyaW5nXTogc3RyaW5nfTsgIC8vIGVtcHR5IGJlY2F1c2UgTGVnYWN5QmFzZTY0VXJpIGNhbid0IGhvbGQgZXh0cmFcbiAgICByZXR1cm4ge21ldGhvZCwgcGFzc3dvcmQsIGhvc3QsIHBvcnQsIHRhZywgZXh0cmF9O1xuICB9LFxuXG4gIHN0cmluZ2lmeTogKGNvbmZpZzogQ29uZmlnKSA9PiB7XG4gICAgY29uc3Qge2hvc3QsIHBvcnQsIG1ldGhvZCwgcGFzc3dvcmQsIHRhZ30gPSBjb25maWc7XG4gICAgY29uc3QgaGFzaCA9IFNIQURPV1NPQ0tTX1VSSS5nZXRIYXNoKHRhZyk7XG4gICAgbGV0IGI2NEVuY29kZWREYXRhID0gYjY0RW5jb2RlKGAke21ldGhvZC5kYXRhfToke3Bhc3N3b3JkLmRhdGF9QCR7aG9zdC5kYXRhfToke3BvcnQuZGF0YX1gKTtcbiAgICBjb25zdCBkYXRhTGVuZ3RoID0gYjY0RW5jb2RlZERhdGEubGVuZ3RoO1xuICAgIGxldCBwYWRkaW5nTGVuZ3RoID0gMDtcbiAgICBmb3IgKDsgYjY0RW5jb2RlZERhdGFbZGF0YUxlbmd0aCAtIDEgLSBwYWRkaW5nTGVuZ3RoXSA9PT0gJz0nOyBwYWRkaW5nTGVuZ3RoKyspO1xuICAgIGI2NEVuY29kZWREYXRhID0gcGFkZGluZ0xlbmd0aCA9PT0gMCA/IGI2NEVuY29kZWREYXRhIDpcbiAgICAgICAgYjY0RW5jb2RlZERhdGEuc3Vic3RyaW5nKDAsIGRhdGFMZW5ndGggLSBwYWRkaW5nTGVuZ3RoKTtcbiAgICByZXR1cm4gYHNzOi8vJHtiNjRFbmNvZGVkRGF0YX0ke2hhc2h9YDtcbiAgfSxcbn07XG5cbi8vIFJlZjogaHR0cHM6Ly9zaGFkb3dzb2Nrcy5vcmcvZW4vc3BlYy9TSVAwMDItVVJJLVNjaGVtZS5odG1sXG5leHBvcnQgY29uc3QgU0lQMDAyX1VSSSA9IHtcbiAgcGFyc2U6ICh1cmk6IHN0cmluZyk6IENvbmZpZyA9PiB7XG4gICAgU0hBRE9XU09DS1NfVVJJLnZhbGlkYXRlUHJvdG9jb2wodXJpKTtcbiAgICAvLyBDYW4gdXNlIGJ1aWx0LWluIFVSTCBwYXJzZXIgZm9yIGV4cGVkaWVuY2UuIEp1c3QgaGF2ZSB0byByZXBsYWNlIFwic3NcIiB3aXRoIFwiaHR0cFwiIHRvIGVuc3VyZVxuICAgIC8vIGNvcnJlY3QgcmVzdWx0cy5cbiAgICBjb25zdCBpbnB1dEZvclVybFBhcnNlciA9IGBodHRwJHt1cmkuc3Vic3RyaW5nKDIpfWA7XG4gICAgLy8gVGhlIGJ1aWx0LWluIFVSTCBwYXJzZXIgdGhyb3dzIGFzIGRlc2lyZWQgd2hlbiBnaXZlbiBVUklzIHdpdGggaW52YWxpZCBzeW50YXguXG4gICAgY29uc3QgdXJsUGFyc2VyUmVzdWx0ID0gbmV3IFVSTChpbnB1dEZvclVybFBhcnNlcik7XG4gICAgY29uc3QgdXJpRm9ybWF0dGVkSG9zdCA9IHVybFBhcnNlclJlc3VsdC5ob3N0bmFtZTtcbiAgICAvLyBVUkktZm9ybWF0dGVkIElQdjYgaG9zdG5hbWVzIGhhdmUgc3Vycm91bmRpbmcgYnJhY2tldHMuXG4gICAgY29uc3QgbGFzdCA9IHVyaUZvcm1hdHRlZEhvc3QubGVuZ3RoIC0gMTtcbiAgICBjb25zdCBicmFja2V0cyA9IHVyaUZvcm1hdHRlZEhvc3RbMF0gPT09ICdbJyAmJiB1cmlGb3JtYXR0ZWRIb3N0W2xhc3RdID09PSAnXSc7XG4gICAgY29uc3QgaG9zdFN0cmluZyA9IGJyYWNrZXRzID8gdXJpRm9ybWF0dGVkSG9zdC5zdWJzdHJpbmcoMSwgbGFzdCkgOiB1cmlGb3JtYXR0ZWRIb3N0O1xuICAgIGNvbnN0IGhvc3QgPSBuZXcgSG9zdChob3N0U3RyaW5nKTtcbiAgICBjb25zdCBwb3J0ID0gbmV3IFBvcnQodXJsUGFyc2VyUmVzdWx0LnBvcnQpO1xuICAgIGNvbnN0IHRhZyA9IG5ldyBUYWcoZGVjb2RlVVJJQ29tcG9uZW50KHVybFBhcnNlclJlc3VsdC5oYXNoLnN1YnN0cmluZygxKSkpO1xuICAgIGNvbnN0IGI2NEVuY29kZWRVc2VySW5mbyA9IHVybFBhcnNlclJlc3VsdC51c2VybmFtZS5yZXBsYWNlKC8lM0QvZywgJz0nKTtcbiAgICAvLyBiYXNlNjQuZGVjb2RlIHRocm93cyBhcyBkZXNpcmVkIHdoZW4gZ2l2ZW4gaW52YWxpZCBiYXNlNjQgaW5wdXQuXG4gICAgY29uc3QgYjY0RGVjb2RlZFVzZXJJbmZvID0gYjY0RGVjb2RlKGI2NEVuY29kZWRVc2VySW5mbyk7XG4gICAgY29uc3QgY29sb25JZHggPSBiNjREZWNvZGVkVXNlckluZm8uaW5kZXhPZignOicpO1xuICAgIGlmIChjb2xvbklkeCA9PT0gLTEpIHtcbiAgICAgIHRocm93IG5ldyBJbnZhbGlkVXJpKGBNaXNzaW5nIHBhc3N3b3JkIHBhcnQ6ICR7YjY0RGVjb2RlZFVzZXJJbmZvfWApO1xuICAgIH1cbiAgICBjb25zdCBtZXRob2RTdHJpbmcgPSBiNjREZWNvZGVkVXNlckluZm8uc3Vic3RyaW5nKDAsIGNvbG9uSWR4KTtcbiAgICBjb25zdCBtZXRob2QgPSBuZXcgTWV0aG9kKG1ldGhvZFN0cmluZyk7XG4gICAgY29uc3QgcGFzc3dvcmRTdHJpbmcgPSBiNjREZWNvZGVkVXNlckluZm8uc3Vic3RyaW5nKGNvbG9uSWR4ICsgMSk7XG4gICAgY29uc3QgcGFzc3dvcmQgPSBuZXcgUGFzc3dvcmQocGFzc3dvcmRTdHJpbmcpO1xuICAgIGNvbnN0IHF1ZXJ5UGFyYW1zID0gdXJsUGFyc2VyUmVzdWx0LnNlYXJjaC5zdWJzdHJpbmcoMSkuc3BsaXQoJyYnKTtcbiAgICBjb25zdCBleHRyYSA9IHt9IGFzIHtba2V5OiBzdHJpbmddOiBzdHJpbmd9O1xuICAgIGZvciAoY29uc3QgcGFpciBvZiBxdWVyeVBhcmFtcykge1xuICAgICAgY29uc3QgW2tleSwgdmFsdWVdID0gcGFpci5zcGxpdCgnPScsIDIpO1xuICAgICAgaWYgKCFrZXkpIGNvbnRpbnVlO1xuICAgICAgZXh0cmFba2V5XSA9IGRlY29kZVVSSUNvbXBvbmVudCh2YWx1ZSB8fCAnJyk7XG4gICAgfVxuICAgIHJldHVybiB7bWV0aG9kLCBwYXNzd29yZCwgaG9zdCwgcG9ydCwgdGFnLCBleHRyYX07XG4gIH0sXG5cbiAgc3RyaW5naWZ5OiAoY29uZmlnOiBDb25maWcpID0+IHtcbiAgICBjb25zdCB7aG9zdCwgcG9ydCwgbWV0aG9kLCBwYXNzd29yZCwgdGFnLCBleHRyYX0gPSBjb25maWc7XG4gICAgY29uc3QgdXNlckluZm8gPSBiNjRFbmNvZGUoYCR7bWV0aG9kLmRhdGF9OiR7cGFzc3dvcmQuZGF0YX1gKTtcbiAgICBjb25zdCB1cmlIb3N0ID0gU0hBRE9XU09DS1NfVVJJLmdldFVyaUZvcm1hdHRlZEhvc3QoaG9zdCk7XG4gICAgY29uc3QgaGFzaCA9IFNIQURPV1NPQ0tTX1VSSS5nZXRIYXNoKHRhZyk7XG4gICAgbGV0IHF1ZXJ5U3RyaW5nID0gJyc7XG4gICAgZm9yIChjb25zdCBrZXkgaW4gZXh0cmEpIHtcbiAgICAgIGlmICgha2V5KSBjb250aW51ZTtcbiAgICAgIHF1ZXJ5U3RyaW5nICs9IChxdWVyeVN0cmluZyA/ICcmJyA6ICc/JykgKyBgJHtrZXl9PSR7ZW5jb2RlVVJJQ29tcG9uZW50KGV4dHJhW2tleV0pfWA7XG4gICAgfVxuICAgIHJldHVybiBgc3M6Ly8ke3VzZXJJbmZvfUAke3VyaUhvc3R9OiR7cG9ydC5kYXRhfS8ke3F1ZXJ5U3RyaW5nfSR7aGFzaH1gO1xuICB9LFxufTtcbiJdfQ==
