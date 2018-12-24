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
            throw new InvalidUri("URI must start with \"" + platformExportObj.SHADOWSOCKS_URI.PROTOCOL + "\"");
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
            var newErrorMessage = "Invalid input: " + originalErrorString;
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
        var atSignIndex = b64DecodedData.lastIndexOf('@');
        if (atSignIndex === -1) {
            throw new InvalidUri("Missing \"@\"");
        }
        var methodAndPassword = b64DecodedData.substring(0, atSignIndex);
        var methodEndIndex = methodAndPassword.indexOf(':');
        if (methodEndIndex === -1) {
            throw new InvalidUri("Missing password");
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
            throw new InvalidUri("Missing port");
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
        // correct results, otherwise browsers like Safari fail to parse it.
        var inputForUrlParser = "http" + uri.substring(2);
        // The built-in URL parser throws as desired when given URIs with invalid syntax.
        var urlParserResult = new URL(inputForUrlParser);
        var uriFormattedHost = urlParserResult.hostname;
        // URI-formatted IPv6 hostnames have surrounding brackets.
        var last = uriFormattedHost.length - 1;
        var brackets = uriFormattedHost[0] === '[' && uriFormattedHost[last] === ']';
        var hostString = brackets ? uriFormattedHost.substring(1, last) : uriFormattedHost;
        var host = new Host(hostString);
        var parsedPort = urlParserResult.port;
        if (!parsedPort && uri.match(/:80($|\/)/g)) {
            // The default URL parser fails to recognize the default port (80) when the URI being parsed
            // is HTTP. Check if the port is present at the end of the string or before the parameters.
            parsedPort = 80;
        }
        var port = new Port(parsedPort);
        var tag = new Tag(decodeURIComponent(urlParserResult.hash.substring(1)));
        var b64EncodedUserInfo = urlParserResult.username.replace(/%3D/g, '=');
        // base64.decode throws as desired when given invalid base64 input.
        var b64DecodedUserInfo = b64Decode(b64EncodedUserInfo);
        var colonIdx = b64DecodedUserInfo.indexOf(':');
        if (colonIdx === -1) {
            throw new InvalidUri("Missing password");
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
//# sourceMappingURL=data:application/json;charset=utf8;base64,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RyxJQUFNLENBQUM7SUFDMUUsQ0FBQztDQUNGLENBQUMiLCJmaWxlIjoic2hhZG93c29ja3NfY29uZmlnLmpzIiwic291cmNlc0NvbnRlbnQiOlsiLy8gQ29weXJpZ2h0IDIwMTggVGhlIE91dGxpbmUgQXV0aG9yc1xuLy9cbi8vIExpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSBcIkxpY2Vuc2VcIik7XG4vLyB5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuXG4vLyBZb3UgbWF5IG9idGFpbiBhIGNvcHkgb2YgdGhlIExpY2Vuc2UgYXRcbi8vXG4vLyAgICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMFxuLy9cbi8vIFVubGVzcyByZXF1aXJlZCBieSBhcHBsaWNhYmxlIGxhdyBvciBhZ3JlZWQgdG8gaW4gd3JpdGluZywgc29mdHdhcmVcbi8vIGRpc3RyaWJ1dGVkIHVuZGVyIHRoZSBMaWNlbnNlIGlzIGRpc3RyaWJ1dGVkIG9uIGFuIFwiQVMgSVNcIiBCQVNJUyxcbi8vIFdJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLlxuLy8gU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZFxuLy8gbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuXG5cbi8qIHRzbGludDpkaXNhYmxlICovXG5jb25zdCBpc0Jyb3dzZXIgPSB0eXBlb2Ygd2luZG93ICE9PSAndW5kZWZpbmVkJztcbmNvbnN0IGI2NEVuY29kZSA9IGlzQnJvd3NlciA/IGJ0b2EgOiByZXF1aXJlKCdiYXNlLTY0JykuZW5jb2RlO1xuY29uc3QgYjY0RGVjb2RlID0gaXNCcm93c2VyID8gYXRvYiA6IHJlcXVpcmUoJ2Jhc2UtNjQnKS5kZWNvZGU7XG5jb25zdCBVUkwgPSBpc0Jyb3dzZXIgPyB3aW5kb3cuVVJMIDogcmVxdWlyZSgndXJsJykuVVJMO1xuY29uc3QgcHVueWNvZGUgPSBpc0Jyb3dzZXIgPyAod2luZG93IGFzIGFueSkucHVueWNvZGUgOiByZXF1aXJlKCdwdW55Y29kZScpO1xuaWYgKCFwdW55Y29kZSkge1xuICB0aHJvdyBuZXcgRXJyb3IoYENvdWxkIG5vdCBmaW5kIHB1bnljb2RlLiBEaWQgeW91IGZvcmdldCB0byBhZGQgZS5nLlxuICA8c2NyaXB0IHNyYz1cImJvd2VyX2NvbXBvbmVudHMvcHVueWNvZGUvcHVueWNvZGUubWluLmpzXCI+PC9zY3JpcHQ+P2ApO1xufVxuLyogdHNsaW50OmVuYWJsZSAqL1xuXG4vLyBDdXN0b20gZXJyb3IgYmFzZSBjbGFzc1xuZXhwb3J0IGNsYXNzIFNoYWRvd3NvY2tzQ29uZmlnRXJyb3IgZXh0ZW5kcyBFcnJvciB7XG4gIGNvbnN0cnVjdG9yKG1lc3NhZ2U6IHN0cmluZykge1xuICAgIHN1cGVyKG1lc3NhZ2UpOyAgLy8gJ0Vycm9yJyBicmVha3MgcHJvdG90eXBlIGNoYWluIGhlcmUgaWYgdGhpcyBpcyB0cmFuc3BpbGVkIHRvIGVzNVxuICAgIE9iamVjdC5zZXRQcm90b3R5cGVPZih0aGlzLCBuZXcudGFyZ2V0LnByb3RvdHlwZSk7ICAvLyByZXN0b3JlIHByb3RvdHlwZSBjaGFpblxuICAgIHRoaXMubmFtZSA9IG5ldy50YXJnZXQubmFtZTtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgSW52YWxpZENvbmZpZ0ZpZWxkIGV4dGVuZHMgU2hhZG93c29ja3NDb25maWdFcnJvciB7fVxuXG5leHBvcnQgY2xhc3MgSW52YWxpZFVyaSBleHRlbmRzIFNoYWRvd3NvY2tzQ29uZmlnRXJyb3Ige31cblxuLy8gU2VsZi12YWxpZGF0aW5nL25vcm1hbGl6aW5nIGNvbmZpZyBkYXRhIHR5cGVzIGltcGxlbWVudCB0aGlzIFZhbGlkYXRlZENvbmZpZ0ZpZWxkIGludGVyZmFjZS5cbi8vIENvbnN0cnVjdG9ycyB0YWtlIHNvbWUgZGF0YSwgdmFsaWRhdGUsIG5vcm1hbGl6ZSwgYW5kIHN0b3JlIGlmIHZhbGlkLCBvciB0aHJvdyBvdGhlcndpc2UuXG5leHBvcnQgYWJzdHJhY3QgY2xhc3MgVmFsaWRhdGVkQ29uZmlnRmllbGQge31cblxuZnVuY3Rpb24gdGhyb3dFcnJvckZvckludmFsaWRGaWVsZChuYW1lOiBzdHJpbmcsIHZhbHVlOiB7fSwgcmVhc29uPzogc3RyaW5nKSB7XG4gIHRocm93IG5ldyBJbnZhbGlkQ29uZmlnRmllbGQoYEludmFsaWQgJHtuYW1lfTogJHt2YWx1ZX0gJHtyZWFzb24gfHwgJyd9YCk7XG59XG5cbmV4cG9ydCBjbGFzcyBIb3N0IGV4dGVuZHMgVmFsaWRhdGVkQ29uZmlnRmllbGQge1xuICBwdWJsaWMgc3RhdGljIElQVjRfUEFUVEVSTiA9IC9eKD86WzAtOV17MSwzfVxcLil7M31bMC05XXsxLDN9JC87XG4gIHB1YmxpYyBzdGF0aWMgSVBWNl9QQVRURVJOID0gL14oPzpbQS1GMC05XXsxLDR9Oil7N31bQS1GMC05XXsxLDR9JC9pO1xuICBwdWJsaWMgc3RhdGljIEhPU1ROQU1FX1BBVFRFUk4gPSAvXltBLXowLTldK1tBLXowLTlfLi1dKiQvO1xuICBwdWJsaWMgcmVhZG9ubHkgZGF0YTogc3RyaW5nO1xuICBwdWJsaWMgcmVhZG9ubHkgaXNJUHY0OiBib29sZWFuO1xuICBwdWJsaWMgcmVhZG9ubHkgaXNJUHY2OiBib29sZWFuO1xuICBwdWJsaWMgcmVhZG9ubHkgaXNIb3N0bmFtZTogYm9vbGVhbjtcblxuICBjb25zdHJ1Y3Rvcihob3N0OiBIb3N0IHwgc3RyaW5nKSB7XG4gICAgc3VwZXIoKTtcbiAgICBpZiAoIWhvc3QpIHtcbiAgICAgIHRocm93RXJyb3JGb3JJbnZhbGlkRmllbGQoJ2hvc3QnLCBob3N0KTtcbiAgICB9XG4gICAgaWYgKGhvc3QgaW5zdGFuY2VvZiBIb3N0KSB7XG4gICAgICBob3N0ID0gaG9zdC5kYXRhO1xuICAgIH1cbiAgICBob3N0ID0gcHVueWNvZGUudG9BU0NJSShob3N0KSBhcyBzdHJpbmc7XG4gICAgdGhpcy5pc0lQdjQgPSBIb3N0LklQVjRfUEFUVEVSTi50ZXN0KGhvc3QpO1xuICAgIHRoaXMuaXNJUHY2ID0gdGhpcy5pc0lQdjQgPyBmYWxzZSA6IEhvc3QuSVBWNl9QQVRURVJOLnRlc3QoaG9zdCk7XG4gICAgdGhpcy5pc0hvc3RuYW1lID0gdGhpcy5pc0lQdjQgfHwgdGhpcy5pc0lQdjYgPyBmYWxzZSA6IEhvc3QuSE9TVE5BTUVfUEFUVEVSTi50ZXN0KGhvc3QpO1xuICAgIGlmICghKHRoaXMuaXNJUHY0IHx8IHRoaXMuaXNJUHY2IHx8IHRoaXMuaXNIb3N0bmFtZSkpIHtcbiAgICAgIHRocm93RXJyb3JGb3JJbnZhbGlkRmllbGQoJ2hvc3QnLCBob3N0KTtcbiAgICB9XG4gICAgdGhpcy5kYXRhID0gaG9zdDtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgUG9ydCBleHRlbmRzIFZhbGlkYXRlZENvbmZpZ0ZpZWxkIHtcbiAgcHVibGljIHN0YXRpYyByZWFkb25seSBQQVRURVJOID0gL15bMC05XXsxLDV9JC87XG4gIHB1YmxpYyByZWFkb25seSBkYXRhOiBudW1iZXI7XG5cbiAgY29uc3RydWN0b3IocG9ydDogUG9ydCB8IHN0cmluZyB8IG51bWJlcikge1xuICAgIHN1cGVyKCk7XG4gICAgaWYgKHBvcnQgaW5zdGFuY2VvZiBQb3J0KSB7XG4gICAgICBwb3J0ID0gcG9ydC5kYXRhO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIHBvcnQgPT09ICdudW1iZXInKSB7XG4gICAgICAvLyBTdHJpbmdpZnkgaW4gY2FzZSBuZWdhdGl2ZSBvciBmbG9hdGluZyBwb2ludCAtPiB0aGUgcmVnZXggdGVzdCBiZWxvdyB3aWxsIGNhdGNoLlxuICAgICAgcG9ydCA9IHBvcnQudG9TdHJpbmcoKTtcbiAgICB9XG4gICAgaWYgKCFQb3J0LlBBVFRFUk4udGVzdChwb3J0KSkge1xuICAgICAgdGhyb3dFcnJvckZvckludmFsaWRGaWVsZCgncG9ydCcsIHBvcnQpO1xuICAgIH1cbiAgICAvLyBDb3VsZCBleGNlZWQgdGhlIG1heGltdW0gcG9ydCBudW1iZXIsIHNvIGNvbnZlcnQgdG8gTnVtYmVyIHRvIGNoZWNrLiBDb3VsZCBhbHNvIGhhdmUgbGVhZGluZ1xuICAgIC8vIHplcm9zLiBDb252ZXJ0aW5nIHRvIE51bWJlciBkcm9wcyB0aG9zZSwgc28gd2UgZ2V0IG5vcm1hbGl6YXRpb24gZm9yIGZyZWUuIDopXG4gICAgcG9ydCA9IE51bWJlcihwb3J0KTtcbiAgICBpZiAocG9ydCA+IDY1NTM1KSB7XG4gICAgICB0aHJvd0Vycm9yRm9ySW52YWxpZEZpZWxkKCdwb3J0JywgcG9ydCk7XG4gICAgfVxuICAgIHRoaXMuZGF0YSA9IHBvcnQ7XG4gIH1cbn1cblxuLy8gQSBtZXRob2QgdmFsdWUgbXVzdCBleGFjdGx5IG1hdGNoIGFuIGVsZW1lbnQgaW4gdGhlIHNldCBvZiBrbm93biBjaXBoZXJzLlxuLy8gcmVmOiBodHRwczovL2dpdGh1Yi5jb20vc2hhZG93c29ja3Mvc2hhZG93c29ja3MtbGliZXYvYmxvYi8xMGEyZDNlMy9jb21wbGV0aW9ucy9iYXNoL3NzLXJlZGlyI0w1XG5leHBvcnQgY29uc3QgTUVUSE9EUyA9IG5ldyBTZXQoW1xuICAncmM0LW1kNScsXG4gICdhZXMtMTI4LWdjbScsXG4gICdhZXMtMTkyLWdjbScsXG4gICdhZXMtMjU2LWdjbScsXG4gICdhZXMtMTI4LWNmYicsXG4gICdhZXMtMTkyLWNmYicsXG4gICdhZXMtMjU2LWNmYicsXG4gICdhZXMtMTI4LWN0cicsXG4gICdhZXMtMTkyLWN0cicsXG4gICdhZXMtMjU2LWN0cicsXG4gICdjYW1lbGxpYS0xMjgtY2ZiJyxcbiAgJ2NhbWVsbGlhLTE5Mi1jZmInLFxuICAnY2FtZWxsaWEtMjU2LWNmYicsXG4gICdiZi1jZmInLFxuICAnY2hhY2hhMjAtaWV0Zi1wb2x5MTMwNScsXG4gICdzYWxzYTIwJyxcbiAgJ2NoYWNoYTIwJyxcbiAgJ2NoYWNoYTIwLWlldGYnLFxuICAneGNoYWNoYTIwLWlldGYtcG9seTEzMDUnLFxuXSk7XG5cbmV4cG9ydCBjbGFzcyBNZXRob2QgZXh0ZW5kcyBWYWxpZGF0ZWRDb25maWdGaWVsZCB7XG4gIHB1YmxpYyByZWFkb25seSBkYXRhOiBzdHJpbmc7XG4gIGNvbnN0cnVjdG9yKG1ldGhvZDogTWV0aG9kIHwgc3RyaW5nKSB7XG4gICAgc3VwZXIoKTtcbiAgICBpZiAobWV0aG9kIGluc3RhbmNlb2YgTWV0aG9kKSB7XG4gICAgICBtZXRob2QgPSBtZXRob2QuZGF0YTtcbiAgICB9XG4gICAgaWYgKCFNRVRIT0RTLmhhcyhtZXRob2QpKSB7XG4gICAgICB0aHJvd0Vycm9yRm9ySW52YWxpZEZpZWxkKCdtZXRob2QnLCBtZXRob2QpO1xuICAgIH1cbiAgICB0aGlzLmRhdGEgPSBtZXRob2Q7XG4gIH1cbn1cblxuZXhwb3J0IGNsYXNzIFBhc3N3b3JkIGV4dGVuZHMgVmFsaWRhdGVkQ29uZmlnRmllbGQge1xuICBwdWJsaWMgcmVhZG9ubHkgZGF0YTogc3RyaW5nO1xuXG4gIGNvbnN0cnVjdG9yKHBhc3N3b3JkOiBQYXNzd29yZCB8IHN0cmluZykge1xuICAgIHN1cGVyKCk7XG4gICAgdGhpcy5kYXRhID0gcGFzc3dvcmQgaW5zdGFuY2VvZiBQYXNzd29yZCA/IHBhc3N3b3JkLmRhdGEgOiBwYXNzd29yZDtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgVGFnIGV4dGVuZHMgVmFsaWRhdGVkQ29uZmlnRmllbGQge1xuICBwdWJsaWMgcmVhZG9ubHkgZGF0YTogc3RyaW5nO1xuXG4gIGNvbnN0cnVjdG9yKHRhZzogVGFnIHwgc3RyaW5nID0gJycpIHtcbiAgICBzdXBlcigpO1xuICAgIHRoaXMuZGF0YSA9IHRhZyBpbnN0YW5jZW9mIFRhZyA/IHRhZy5kYXRhIDogdGFnO1xuICB9XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ29uZmlnIHtcbiAgaG9zdDogSG9zdDtcbiAgcG9ydDogUG9ydDtcbiAgbWV0aG9kOiBNZXRob2Q7XG4gIHBhc3N3b3JkOiBQYXNzd29yZDtcbiAgdGFnOiBUYWc7XG4gIC8vIEFueSBhZGRpdGlvbmFsIGNvbmZpZ3VyYXRpb24gKGUuZy4gYHRpbWVvdXRgLCBTSVAwMDMgYHBsdWdpbmAsIGV0Yy4pIG1heSBiZSBzdG9yZWQgaGVyZS5cbiAgZXh0cmE6IHtba2V5OiBzdHJpbmddOiBzdHJpbmd9O1xufVxuXG4vLyB0c2xpbnQ6ZGlzYWJsZS1uZXh0LWxpbmU6bm8tYW55XG5leHBvcnQgZnVuY3Rpb24gbWFrZUNvbmZpZyhpbnB1dDoge1trZXk6IHN0cmluZ106IGFueX0pOiBDb25maWcge1xuICAvLyBVc2UgXCIhXCIgZm9yIHRoZSByZXF1aXJlZCBmaWVsZHMgdG8gdGVsbCB0c2MgdGhhdCB3ZSBoYW5kbGUgdW5kZWZpbmVkIGluIHRoZVxuICAvLyBWYWxpZGF0ZWRDb25maWdGaWVsZHMgd2UgY2FsbDsgdHNjIGNhbid0IGZpZ3VyZSB0aGF0IG91dCBvdGhlcndpc2UuXG4gIGNvbnN0IGNvbmZpZyA9IHtcbiAgICBob3N0OiBuZXcgSG9zdChpbnB1dC5ob3N0ISksXG4gICAgcG9ydDogbmV3IFBvcnQoaW5wdXQucG9ydCEpLFxuICAgIG1ldGhvZDogbmV3IE1ldGhvZChpbnB1dC5tZXRob2QhKSxcbiAgICBwYXNzd29yZDogbmV3IFBhc3N3b3JkKGlucHV0LnBhc3N3b3JkISksXG4gICAgdGFnOiBuZXcgVGFnKGlucHV0LnRhZyksICAvLyBpbnB1dC50YWcgbWlnaHQgYmUgdW5kZWZpbmVkIGJ1dCBUYWcoKSBoYW5kbGVzIHRoYXQgZmluZS5cbiAgICBleHRyYToge30gYXMge1trZXk6IHN0cmluZ106IHN0cmluZ30sXG4gIH07XG4gIC8vIFB1dCBhbnkgcmVtYWluaW5nIGZpZWxkcyBpbiBgaW5wdXRgIGludG8gYGNvbmZpZy5leHRyYWAuXG4gIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5rZXlzKGlucHV0KSkge1xuICAgIGlmICghL14oaG9zdHxwb3J0fG1ldGhvZHxwYXNzd29yZHx0YWcpJC8udGVzdChrZXkpKSB7XG4gICAgICBjb25maWcuZXh0cmFba2V5XSA9IGlucHV0W2tleV0gJiYgaW5wdXRba2V5XS50b1N0cmluZygpO1xuICAgIH1cbiAgfVxuICByZXR1cm4gY29uZmlnO1xufVxuXG5leHBvcnQgY29uc3QgU0hBRE9XU09DS1NfVVJJID0ge1xuICBQUk9UT0NPTDogJ3NzOicsXG5cbiAgZ2V0VXJpRm9ybWF0dGVkSG9zdDogKGhvc3Q6IEhvc3QpID0+IHtcbiAgICByZXR1cm4gaG9zdC5pc0lQdjYgPyBgWyR7aG9zdC5kYXRhfV1gIDogaG9zdC5kYXRhO1xuICB9LFxuXG4gIGdldEhhc2g6ICh0YWc6IFRhZykgPT4ge1xuICAgIHJldHVybiB0YWcuZGF0YSA/IGAjJHtlbmNvZGVVUklDb21wb25lbnQodGFnLmRhdGEpfWAgOiAnJztcbiAgfSxcblxuICB2YWxpZGF0ZVByb3RvY29sOiAodXJpOiBzdHJpbmcpID0+IHtcbiAgICBpZiAoIXVyaS5zdGFydHNXaXRoKFNIQURPV1NPQ0tTX1VSSS5QUk9UT0NPTCkpIHtcbiAgICAgIHRocm93IG5ldyBJbnZhbGlkVXJpKGBVUkkgbXVzdCBzdGFydCB3aXRoIFwiJHtTSEFET1dTT0NLU19VUkkuUFJPVE9DT0x9XCJgKTtcbiAgICB9XG4gIH0sXG5cbiAgcGFyc2U6ICh1cmk6IHN0cmluZyk6IENvbmZpZyA9PiB7XG4gICAgbGV0IGVycm9yOiBFcnJvciB8IHVuZGVmaW5lZDtcbiAgICBmb3IgKGNvbnN0IHVyaVR5cGUgb2YgW1NJUDAwMl9VUkksIExFR0FDWV9CQVNFNjRfVVJJXSkge1xuICAgICAgdHJ5IHtcbiAgICAgICAgcmV0dXJuIHVyaVR5cGUucGFyc2UodXJpKTtcbiAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgZXJyb3IgPSBlO1xuICAgICAgfVxuICAgIH1cbiAgICBpZiAoIShlcnJvciBpbnN0YW5jZW9mIEludmFsaWRVcmkpKSB7XG4gICAgICBjb25zdCBvcmlnaW5hbEVycm9yTmFtZSA9IGVycm9yIS5uYW1lISB8fCAnKFVubmFtZWQgRXJyb3IpJztcbiAgICAgIGNvbnN0IG9yaWdpbmFsRXJyb3JNZXNzYWdlID0gZXJyb3IhLm1lc3NhZ2UhIHx8ICcobm8gZXJyb3IgbWVzc2FnZSBwcm92aWRlZCknO1xuICAgICAgY29uc3Qgb3JpZ2luYWxFcnJvclN0cmluZyA9IGAke29yaWdpbmFsRXJyb3JOYW1lfTogJHtvcmlnaW5hbEVycm9yTWVzc2FnZX1gO1xuICAgICAgY29uc3QgbmV3RXJyb3JNZXNzYWdlID0gYEludmFsaWQgaW5wdXQ6ICR7b3JpZ2luYWxFcnJvclN0cmluZ31gO1xuICAgICAgZXJyb3IgPSBuZXcgSW52YWxpZFVyaShuZXdFcnJvck1lc3NhZ2UpO1xuICAgIH1cbiAgICB0aHJvdyBlcnJvcjtcbiAgfSxcbn07XG5cbi8vIFJlZjogaHR0cHM6Ly9zaGFkb3dzb2Nrcy5vcmcvZW4vY29uZmlnL3F1aWNrLWd1aWRlLmh0bWxcbmV4cG9ydCBjb25zdCBMRUdBQ1lfQkFTRTY0X1VSSSA9IHtcbiAgcGFyc2U6ICh1cmk6IHN0cmluZyk6IENvbmZpZyA9PiB7XG4gICAgU0hBRE9XU09DS1NfVVJJLnZhbGlkYXRlUHJvdG9jb2wodXJpKTtcbiAgICBjb25zdCBoYXNoSW5kZXggPSB1cmkuaW5kZXhPZignIycpO1xuICAgIGNvbnN0IGhhc1RhZyA9IGhhc2hJbmRleCAhPT0gLTE7XG4gICAgY29uc3QgYjY0RW5kSW5kZXggPSBoYXNUYWcgPyBoYXNoSW5kZXggOiB1cmkubGVuZ3RoO1xuICAgIGNvbnN0IHRhZ1N0YXJ0SW5kZXggPSBoYXNUYWcgPyBoYXNoSW5kZXggKyAxIDogdXJpLmxlbmd0aDtcbiAgICBjb25zdCB0YWcgPSBuZXcgVGFnKGRlY29kZVVSSUNvbXBvbmVudCh1cmkuc3Vic3RyaW5nKHRhZ1N0YXJ0SW5kZXgpKSk7XG4gICAgY29uc3QgYjY0RW5jb2RlZERhdGEgPSB1cmkuc3Vic3RyaW5nKCdzczovLycubGVuZ3RoLCBiNjRFbmRJbmRleCk7XG4gICAgY29uc3QgYjY0RGVjb2RlZERhdGEgPSBiNjREZWNvZGUoYjY0RW5jb2RlZERhdGEpO1xuICAgIGNvbnN0IGF0U2lnbkluZGV4ID0gYjY0RGVjb2RlZERhdGEubGFzdEluZGV4T2YoJ0AnKTtcbiAgICBpZiAoYXRTaWduSW5kZXggPT09IC0xKSB7XG4gICAgICB0aHJvdyBuZXcgSW52YWxpZFVyaShgTWlzc2luZyBcIkBcImApO1xuICAgIH1cbiAgICBjb25zdCBtZXRob2RBbmRQYXNzd29yZCA9IGI2NERlY29kZWREYXRhLnN1YnN0cmluZygwLCBhdFNpZ25JbmRleCk7XG4gICAgY29uc3QgbWV0aG9kRW5kSW5kZXggPSBtZXRob2RBbmRQYXNzd29yZC5pbmRleE9mKCc6Jyk7XG4gICAgaWYgKG1ldGhvZEVuZEluZGV4ID09PSAtMSkge1xuICAgICAgdGhyb3cgbmV3IEludmFsaWRVcmkoYE1pc3NpbmcgcGFzc3dvcmRgKTtcbiAgICB9XG4gICAgY29uc3QgbWV0aG9kU3RyaW5nID0gbWV0aG9kQW5kUGFzc3dvcmQuc3Vic3RyaW5nKDAsIG1ldGhvZEVuZEluZGV4KTtcbiAgICBjb25zdCBtZXRob2QgPSBuZXcgTWV0aG9kKG1ldGhvZFN0cmluZyk7XG4gICAgY29uc3QgcGFzc3dvcmRTdGFydEluZGV4ID0gbWV0aG9kRW5kSW5kZXggKyAxO1xuICAgIGNvbnN0IHBhc3N3b3JkU3RyaW5nID0gbWV0aG9kQW5kUGFzc3dvcmQuc3Vic3RyaW5nKHBhc3N3b3JkU3RhcnRJbmRleCk7XG4gICAgY29uc3QgcGFzc3dvcmQgPSBuZXcgUGFzc3dvcmQocGFzc3dvcmRTdHJpbmcpO1xuICAgIGNvbnN0IGhvc3RTdGFydEluZGV4ID0gYXRTaWduSW5kZXggKyAxO1xuICAgIGNvbnN0IGhvc3RBbmRQb3J0ID0gYjY0RGVjb2RlZERhdGEuc3Vic3RyaW5nKGhvc3RTdGFydEluZGV4KTtcbiAgICBjb25zdCBob3N0RW5kSW5kZXggPSBob3N0QW5kUG9ydC5sYXN0SW5kZXhPZignOicpO1xuICAgIGlmIChob3N0RW5kSW5kZXggPT09IC0xKSB7XG4gICAgICB0aHJvdyBuZXcgSW52YWxpZFVyaShgTWlzc2luZyBwb3J0YCk7XG4gICAgfVxuICAgIGNvbnN0IHVyaUZvcm1hdHRlZEhvc3QgPSBob3N0QW5kUG9ydC5zdWJzdHJpbmcoMCwgaG9zdEVuZEluZGV4KTtcbiAgICBsZXQgaG9zdDogSG9zdDtcbiAgICB0cnkge1xuICAgICAgaG9zdCA9IG5ldyBIb3N0KHVyaUZvcm1hdHRlZEhvc3QpO1xuICAgIH0gY2F0Y2ggKF8pIHtcbiAgICAgIC8vIENvdWxkIGJlIElQdjYgaG9zdCBmb3JtYXR0ZWQgd2l0aCBzdXJyb3VuZGluZyBicmFja2V0cywgc28gdHJ5IHN0cmlwcGluZyBmaXJzdCBhbmQgbGFzdFxuICAgICAgLy8gY2hhcmFjdGVycy4gSWYgdGhpcyB0aHJvd3MsIGdpdmUgdXAgYW5kIGxldCB0aGUgZXhjZXB0aW9uIHByb3BhZ2F0ZS5cbiAgICAgIGhvc3QgPSBuZXcgSG9zdCh1cmlGb3JtYXR0ZWRIb3N0LnN1YnN0cmluZygxLCB1cmlGb3JtYXR0ZWRIb3N0Lmxlbmd0aCAtIDEpKTtcbiAgICB9XG4gICAgY29uc3QgcG9ydFN0YXJ0SW5kZXggPSBob3N0RW5kSW5kZXggKyAxO1xuICAgIGNvbnN0IHBvcnRTdHJpbmcgPSBob3N0QW5kUG9ydC5zdWJzdHJpbmcocG9ydFN0YXJ0SW5kZXgpO1xuICAgIGNvbnN0IHBvcnQgPSBuZXcgUG9ydChwb3J0U3RyaW5nKTtcbiAgICBjb25zdCBleHRyYSA9IHt9IGFzIHtba2V5OiBzdHJpbmddOiBzdHJpbmd9OyAgLy8gZW1wdHkgYmVjYXVzZSBMZWdhY3lCYXNlNjRVcmkgY2FuJ3QgaG9sZCBleHRyYVxuICAgIHJldHVybiB7bWV0aG9kLCBwYXNzd29yZCwgaG9zdCwgcG9ydCwgdGFnLCBleHRyYX07XG4gIH0sXG5cbiAgc3RyaW5naWZ5OiAoY29uZmlnOiBDb25maWcpID0+IHtcbiAgICBjb25zdCB7aG9zdCwgcG9ydCwgbWV0aG9kLCBwYXNzd29yZCwgdGFnfSA9IGNvbmZpZztcbiAgICBjb25zdCBoYXNoID0gU0hBRE9XU09DS1NfVVJJLmdldEhhc2godGFnKTtcbiAgICBsZXQgYjY0RW5jb2RlZERhdGEgPSBiNjRFbmNvZGUoYCR7bWV0aG9kLmRhdGF9OiR7cGFzc3dvcmQuZGF0YX1AJHtob3N0LmRhdGF9OiR7cG9ydC5kYXRhfWApO1xuICAgIGNvbnN0IGRhdGFMZW5ndGggPSBiNjRFbmNvZGVkRGF0YS5sZW5ndGg7XG4gICAgbGV0IHBhZGRpbmdMZW5ndGggPSAwO1xuICAgIGZvciAoOyBiNjRFbmNvZGVkRGF0YVtkYXRhTGVuZ3RoIC0gMSAtIHBhZGRpbmdMZW5ndGhdID09PSAnPSc7IHBhZGRpbmdMZW5ndGgrKyk7XG4gICAgYjY0RW5jb2RlZERhdGEgPSBwYWRkaW5nTGVuZ3RoID09PSAwID8gYjY0RW5jb2RlZERhdGEgOlxuICAgICAgICBiNjRFbmNvZGVkRGF0YS5zdWJzdHJpbmcoMCwgZGF0YUxlbmd0aCAtIHBhZGRpbmdMZW5ndGgpO1xuICAgIHJldHVybiBgc3M6Ly8ke2I2NEVuY29kZWREYXRhfSR7aGFzaH1gO1xuICB9LFxufTtcblxuLy8gUmVmOiBodHRwczovL3NoYWRvd3NvY2tzLm9yZy9lbi9zcGVjL1NJUDAwMi1VUkktU2NoZW1lLmh0bWxcbmV4cG9ydCBjb25zdCBTSVAwMDJfVVJJID0ge1xuICBwYXJzZTogKHVyaTogc3RyaW5nKTogQ29uZmlnID0+IHtcbiAgICBTSEFET1dTT0NLU19VUkkudmFsaWRhdGVQcm90b2NvbCh1cmkpO1xuICAgIC8vIENhbiB1c2UgYnVpbHQtaW4gVVJMIHBhcnNlciBmb3IgZXhwZWRpZW5jZS4gSnVzdCBoYXZlIHRvIHJlcGxhY2UgXCJzc1wiIHdpdGggXCJodHRwXCIgdG8gZW5zdXJlXG4gICAgLy8gY29ycmVjdCByZXN1bHRzLCBvdGhlcndpc2UgYnJvd3NlcnMgbGlrZSBTYWZhcmkgZmFpbCB0byBwYXJzZSBpdC5cbiAgICBjb25zdCBpbnB1dEZvclVybFBhcnNlciA9IGBodHRwJHt1cmkuc3Vic3RyaW5nKDIpfWA7XG4gICAgLy8gVGhlIGJ1aWx0LWluIFVSTCBwYXJzZXIgdGhyb3dzIGFzIGRlc2lyZWQgd2hlbiBnaXZlbiBVUklzIHdpdGggaW52YWxpZCBzeW50YXguXG4gICAgY29uc3QgdXJsUGFyc2VyUmVzdWx0ID0gbmV3IFVSTChpbnB1dEZvclVybFBhcnNlcik7XG4gICAgY29uc3QgdXJpRm9ybWF0dGVkSG9zdCA9IHVybFBhcnNlclJlc3VsdC5ob3N0bmFtZTtcbiAgICAvLyBVUkktZm9ybWF0dGVkIElQdjYgaG9zdG5hbWVzIGhhdmUgc3Vycm91bmRpbmcgYnJhY2tldHMuXG4gICAgY29uc3QgbGFzdCA9IHVyaUZvcm1hdHRlZEhvc3QubGVuZ3RoIC0gMTtcbiAgICBjb25zdCBicmFja2V0cyA9IHVyaUZvcm1hdHRlZEhvc3RbMF0gPT09ICdbJyAmJiB1cmlGb3JtYXR0ZWRIb3N0W2xhc3RdID09PSAnXSc7XG4gICAgY29uc3QgaG9zdFN0cmluZyA9IGJyYWNrZXRzID8gdXJpRm9ybWF0dGVkSG9zdC5zdWJzdHJpbmcoMSwgbGFzdCkgOiB1cmlGb3JtYXR0ZWRIb3N0O1xuICAgIGNvbnN0IGhvc3QgPSBuZXcgSG9zdChob3N0U3RyaW5nKTtcbiAgICBsZXQgcGFyc2VkUG9ydCA9IHVybFBhcnNlclJlc3VsdC5wb3J0O1xuICAgIGlmICghcGFyc2VkUG9ydCAmJiB1cmkubWF0Y2goLzo4MCgkfFxcLykvZykpIHtcbiAgICAgIC8vIFRoZSBkZWZhdWx0IFVSTCBwYXJzZXIgZmFpbHMgdG8gcmVjb2duaXplIHRoZSBkZWZhdWx0IHBvcnQgKDgwKSB3aGVuIHRoZSBVUkkgYmVpbmcgcGFyc2VkXG4gICAgICAvLyBpcyBIVFRQLiBDaGVjayBpZiB0aGUgcG9ydCBpcyBwcmVzZW50IGF0IHRoZSBlbmQgb2YgdGhlIHN0cmluZyBvciBiZWZvcmUgdGhlIHBhcmFtZXRlcnMuXG4gICAgICBwYXJzZWRQb3J0ID0gODA7XG4gICAgfVxuICAgIGNvbnN0IHBvcnQgPSBuZXcgUG9ydChwYXJzZWRQb3J0KTtcbiAgICBjb25zdCB0YWcgPSBuZXcgVGFnKGRlY29kZVVSSUNvbXBvbmVudCh1cmxQYXJzZXJSZXN1bHQuaGFzaC5zdWJzdHJpbmcoMSkpKTtcbiAgICBjb25zdCBiNjRFbmNvZGVkVXNlckluZm8gPSB1cmxQYXJzZXJSZXN1bHQudXNlcm5hbWUucmVwbGFjZSgvJTNEL2csICc9Jyk7XG4gICAgLy8gYmFzZTY0LmRlY29kZSB0aHJvd3MgYXMgZGVzaXJlZCB3aGVuIGdpdmVuIGludmFsaWQgYmFzZTY0IGlucHV0LlxuICAgIGNvbnN0IGI2NERlY29kZWRVc2VySW5mbyA9IGI2NERlY29kZShiNjRFbmNvZGVkVXNlckluZm8pO1xuICAgIGNvbnN0IGNvbG9uSWR4ID0gYjY0RGVjb2RlZFVzZXJJbmZvLmluZGV4T2YoJzonKTtcbiAgICBpZiAoY29sb25JZHggPT09IC0xKSB7XG4gICAgICB0aHJvdyBuZXcgSW52YWxpZFVyaShgTWlzc2luZyBwYXNzd29yZGApO1xuICAgIH1cbiAgICBjb25zdCBtZXRob2RTdHJpbmcgPSBiNjREZWNvZGVkVXNlckluZm8uc3Vic3RyaW5nKDAsIGNvbG9uSWR4KTtcbiAgICBjb25zdCBtZXRob2QgPSBuZXcgTWV0aG9kKG1ldGhvZFN0cmluZyk7XG4gICAgY29uc3QgcGFzc3dvcmRTdHJpbmcgPSBiNjREZWNvZGVkVXNlckluZm8uc3Vic3RyaW5nKGNvbG9uSWR4ICsgMSk7XG4gICAgY29uc3QgcGFzc3dvcmQgPSBuZXcgUGFzc3dvcmQocGFzc3dvcmRTdHJpbmcpO1xuICAgIGNvbnN0IHF1ZXJ5UGFyYW1zID0gdXJsUGFyc2VyUmVzdWx0LnNlYXJjaC5zdWJzdHJpbmcoMSkuc3BsaXQoJyYnKTtcbiAgICBjb25zdCBleHRyYSA9IHt9IGFzIHtba2V5OiBzdHJpbmddOiBzdHJpbmd9O1xuICAgIGZvciAoY29uc3QgcGFpciBvZiBxdWVyeVBhcmFtcykge1xuICAgICAgY29uc3QgW2tleSwgdmFsdWVdID0gcGFpci5zcGxpdCgnPScsIDIpO1xuICAgICAgaWYgKCFrZXkpIGNvbnRpbnVlO1xuICAgICAgZXh0cmFba2V5XSA9IGRlY29kZVVSSUNvbXBvbmVudCh2YWx1ZSB8fCAnJyk7XG4gICAgfVxuICAgIHJldHVybiB7bWV0aG9kLCBwYXNzd29yZCwgaG9zdCwgcG9ydCwgdGFnLCBleHRyYX07XG4gIH0sXG5cbiAgc3RyaW5naWZ5OiAoY29uZmlnOiBDb25maWcpID0+IHtcbiAgICBjb25zdCB7aG9zdCwgcG9ydCwgbWV0aG9kLCBwYXNzd29yZCwgdGFnLCBleHRyYX0gPSBjb25maWc7XG4gICAgY29uc3QgdXNlckluZm8gPSBiNjRFbmNvZGUoYCR7bWV0aG9kLmRhdGF9OiR7cGFzc3dvcmQuZGF0YX1gKTtcbiAgICBjb25zdCB1cmlIb3N0ID0gU0hBRE9XU09DS1NfVVJJLmdldFVyaUZvcm1hdHRlZEhvc3QoaG9zdCk7XG4gICAgY29uc3QgaGFzaCA9IFNIQURPV1NPQ0tTX1VSSS5nZXRIYXNoKHRhZyk7XG4gICAgbGV0IHF1ZXJ5U3RyaW5nID0gJyc7XG4gICAgZm9yIChjb25zdCBrZXkgaW4gZXh0cmEpIHtcbiAgICAgIGlmICgha2V5KSBjb250aW51ZTtcbiAgICAgIHF1ZXJ5U3RyaW5nICs9IChxdWVyeVN0cmluZyA/ICcmJyA6ICc/JykgKyBgJHtrZXl9PSR7ZW5jb2RlVVJJQ29tcG9uZW50KGV4dHJhW2tleV0pfWA7XG4gICAgfVxuICAgIHJldHVybiBgc3M6Ly8ke3VzZXJJbmZvfUAke3VyaUhvc3R9OiR7cG9ydC5kYXRhfS8ke3F1ZXJ5U3RyaW5nfSR7aGFzaH1gO1xuICB9LFxufTtcbiJdfQ==
