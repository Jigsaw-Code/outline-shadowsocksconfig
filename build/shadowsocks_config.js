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
Object.defineProperty(exports, "__esModule", { value: true });
var ipaddr = require("ipaddr.js");
var js_base64_1 = require("js-base64");
var punycode = require("punycode/");
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
exports.ShadowsocksConfigError = ShadowsocksConfigError;
var InvalidConfigField = /** @class */ (function (_super) {
    __extends(InvalidConfigField, _super);
    function InvalidConfigField() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return InvalidConfigField;
}(ShadowsocksConfigError));
exports.InvalidConfigField = InvalidConfigField;
var InvalidUri = /** @class */ (function (_super) {
    __extends(InvalidUri, _super);
    function InvalidUri() {
        return _super !== null && _super.apply(this, arguments) || this;
    }
    return InvalidUri;
}(ShadowsocksConfigError));
exports.InvalidUri = InvalidUri;
// Self-validating/normalizing config data types implement this ValidatedConfigField interface.
// Constructors take some data, validate, normalize, and store if valid, or throw otherwise.
var ValidatedConfigField = /** @class */ (function () {
    function ValidatedConfigField() {
    }
    return ValidatedConfigField;
}());
exports.ValidatedConfigField = ValidatedConfigField;
function throwErrorForInvalidField(name, value, reason) {
    throw new InvalidConfigField("Invalid " + name + ": " + value + " " + (reason || ''));
}
var Host = /** @class */ (function (_super) {
    __extends(Host, _super);
    function Host(host) {
        var _this = _super.call(this) || this;
        _this.isIPv4 = false;
        _this.isIPv6 = false;
        _this.isHostname = false;
        if (!host) {
            throwErrorForInvalidField('host', host);
        }
        if (host instanceof Host) {
            host = host.data;
        }
        if (ipaddr.isValid(host)) {
            var ip = ipaddr.parse(host);
            _this.isIPv4 = ip.kind() === 'ipv4';
            _this.isIPv6 = ip.kind() === 'ipv6';
            // Previous versions of outline-ShadowsocksConfig only accept
            // IPv6 in normalized (expanded) form, so we normalize the
            // input here to ensure that access keys remain compatible.
            host = ip.toNormalizedString();
        }
        else {
            host = punycode.toASCII(host);
            _this.isHostname = Host.HOSTNAME_PATTERN.test(host);
            if (!_this.isHostname) {
                throwErrorForInvalidField('host', host);
            }
        }
        _this.data = host;
        return _this;
    }
    Host.HOSTNAME_PATTERN = /^[A-z0-9]+[A-z0-9_.-]*$/;
    return Host;
}(ValidatedConfigField));
exports.Host = Host;
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
var Method = /** @class */ (function (_super) {
    __extends(Method, _super);
    function Method(method) {
        var _this = _super.call(this) || this;
        if (method instanceof Method) {
            method = method.data;
        }
        if (!exports.METHODS.has(method)) {
            throwErrorForInvalidField('method', method);
        }
        _this.data = method;
        return _this;
    }
    return Method;
}(ValidatedConfigField));
exports.Method = Method;
var Password = /** @class */ (function (_super) {
    __extends(Password, _super);
    function Password(password) {
        var _this = _super.call(this) || this;
        _this.data = password instanceof Password ? password.data : password;
        return _this;
    }
    return Password;
}(ValidatedConfigField));
exports.Password = Password;
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
exports.Tag = Tag;
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
exports.makeConfig = makeConfig;
exports.SHADOWSOCKS_URI = {
    PROTOCOL: 'ss:',
    getUriFormattedHost: function (host) {
        return host.isIPv6 ? "[" + host.data + "]" : host.data;
    },
    getHash: function (tag) {
        return tag.data ? "#" + encodeURIComponent(tag.data) : '';
    },
    validateProtocol: function (uri) {
        if (!uri.startsWith(exports.SHADOWSOCKS_URI.PROTOCOL)) {
            throw new InvalidUri("URI must start with \"" + exports.SHADOWSOCKS_URI.PROTOCOL + "\"");
        }
    },
    parse: function (uri) {
        var error;
        for (var _i = 0, _a = [exports.SIP002_URI, exports.LEGACY_BASE64_URI]; _i < _a.length; _i++) {
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
exports.LEGACY_BASE64_URI = {
    parse: function (uri) {
        exports.SHADOWSOCKS_URI.validateProtocol(uri);
        var hashIndex = uri.indexOf('#');
        var hasTag = hashIndex !== -1;
        var b64EndIndex = hasTag ? hashIndex : uri.length;
        var tagStartIndex = hasTag ? hashIndex + 1 : uri.length;
        var tag = new Tag(decodeURIComponent(uri.substring(tagStartIndex)));
        var b64EncodedData = uri.substring('ss://'.length, b64EndIndex);
        var b64DecodedData = js_base64_1.Base64.decode(b64EncodedData);
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
        var hash = exports.SHADOWSOCKS_URI.getHash(tag);
        var data = method.data + ":" + password.data + "@" + host.data + ":" + port.data;
        var b64EncodedData = js_base64_1.Base64.encode(data);
        // Remove "=" padding
        while (b64EncodedData.slice(-1) === '=') {
            b64EncodedData = b64EncodedData.slice(0, -1);
        }
        return "ss://" + b64EncodedData + hash;
    },
};
// Ref: https://shadowsocks.org/en/spec/SIP002-URI-Scheme.html
exports.SIP002_URI = {
    parse: function (uri) {
        exports.SHADOWSOCKS_URI.validateProtocol(uri);
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
            parsedPort = '80';
        }
        var port = new Port(parsedPort);
        var tag = new Tag(decodeURIComponent(urlParserResult.hash.substring(1)));
        var b64EncodedUserInfo = urlParserResult.username.replace(/%3D/g, '=');
        // base64.decode throws as desired when given invalid base64 input.
        var b64DecodedUserInfo = js_base64_1.Base64.decode(b64EncodedUserInfo);
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
        var userInfo = js_base64_1.Base64.encodeURI(method.data + ":" + password.data);
        var uriHost = exports.SHADOWSOCKS_URI.getUriFormattedHost(host);
        var hash = exports.SHADOWSOCKS_URI.getHash(tag);
        var queryString = '';
        for (var key in extra) {
            if (!key)
                continue;
            queryString += (queryString ? '&' : '?') + (key + "=" + encodeURIComponent(extra[key]));
        }
        return "ss://" + userInfo + "@" + uriHost + ":" + port.data + "/" + queryString + hash;
    },
};
exports.ONLINE_CONFIG_PROTOCOL = 'ssconf';
// Parses access parameters to retrieve a Shadowsocks proxy config from an
// online config URL. See: https://github.com/shadowsocks/shadowsocks-org/issues/89
function parseOnlineConfigUrl(url) {
    if (!url || !url.startsWith(exports.ONLINE_CONFIG_PROTOCOL + ":")) {
        throw new InvalidUri("URI protocol must be \"" + exports.ONLINE_CONFIG_PROTOCOL + "\"");
    }
    // Replace the protocol "ssconf" with "https" to ensure correct results,
    // otherwise some Safari versions fail to parse it.
    var inputForUrlParser = url.replace(new RegExp("^" + exports.ONLINE_CONFIG_PROTOCOL), 'https');
    // The built-in URL parser throws as desired when given URIs with invalid syntax.
    var urlParserResult = new URL(inputForUrlParser);
    // Use ValidatedConfigFields subclasses (Host, Port, Tag) to throw on validation failure.
    var uriFormattedHost = urlParserResult.hostname;
    var host;
    try {
        host = new Host(uriFormattedHost);
    }
    catch (_) {
        // Could be IPv6 host formatted with surrounding brackets, so try stripping first and last
        // characters. If this throws, give up and let the exception propagate.
        host = new Host(uriFormattedHost.substring(1, uriFormattedHost.length - 1));
    }
    // The default URL parser fails to recognize the default HTTPs port (443).
    var port = new Port(urlParserResult.port || '443');
    // Parse extra parameters from the tag, which has the URL search parameters format.
    var tag = new Tag(urlParserResult.hash.substring(1));
    var params = new URLSearchParams(tag.data);
    return {
        // Build the access URL with the parsed parameters Exclude the query string and tag.
        location: "https://" + uriFormattedHost + ":" + port.data + urlParserResult.pathname,
        certFingerprint: params.get('certFp') || undefined,
        httpMethod: params.get('httpMethod') || undefined
    };
}
exports.parseOnlineConfigUrl = parseOnlineConfigUrl;
