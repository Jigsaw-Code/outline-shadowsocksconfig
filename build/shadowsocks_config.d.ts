export declare class ShadowsocksConfigError extends Error {
    constructor(message: string);
}
export declare class InvalidConfigField extends ShadowsocksConfigError {
}
export declare class InvalidUri extends ShadowsocksConfigError {
}
export declare abstract class ValidatedConfigField {
}
export declare class Host extends ValidatedConfigField {
    static IPV4_PATTERN: RegExp;
    static IPV6_PATTERN: RegExp;
    static HOSTNAME_PATTERN: RegExp;
    readonly data: string;
    readonly isIPv4: boolean;
    readonly isIPv6: boolean;
    readonly isHostname: boolean;
    constructor(host: Host | string);
}
export declare class Port extends ValidatedConfigField {
    static readonly PATTERN: RegExp;
    readonly data: number;
    constructor(port: Port | string | number);
}
export declare const METHODS: Set<string>;
export declare class Method extends ValidatedConfigField {
    readonly data: string;
    constructor(method: Method | string);
}
export declare class Password extends ValidatedConfigField {
    readonly data: string;
    constructor(password: Password | string);
}
export declare class Tag extends ValidatedConfigField {
    readonly data: string;
    constructor(tag?: Tag | string);
}
export interface Config {
    host: Host;
    port: Port;
    method: Method;
    password: Password;
    tag: Tag;
    extra: {
        [key: string]: string;
    };
}
export declare function makeConfig(input: {
    [key: string]: any;
}): Config;
export declare const SHADOWSOCKS_URI: {
    PROTOCOL: string;
    getUriFormattedHost: (host: Host) => string;
    getHash: (tag: Tag) => string;
    validateProtocol: (uri: string) => void;
    parse: (uri: string) => Config;
};
export declare const LEGACY_BASE64_URI: {
    parse: (uri: string) => Config;
    stringify: (config: Config) => string;
};
export declare const SIP002_URI: {
    parse: (uri: string) => Config;
    stringify: (config: Config) => string;
};
export interface DynamicConfig {
  url: string;
  extra: {[key: string]: string;};
}
export declare const SIP008_URI: {
  PROTOCOL: string; validateProtocol: (uri: string) => void; parse: (uri: string) => DynamicConfig;
};
