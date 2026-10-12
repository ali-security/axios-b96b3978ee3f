"use strict";

import assert from "assert";
import http from "http";
import net from "net";
import vm from "vm";
import axios from "../../../index.js";
import utils from "../../../lib/utils.js";
import mergeConfig from "../../../lib/core/mergeConfig.js";
import defaults from "../../../lib/defaults/index.js";
import AxiosHeaders from "../../../lib/core/AxiosHeaders.js";
import httpAdapter, { __setProxy } from "../../../lib/adapters/http.js";

const nodeMajorVersion = parseInt(process.versions.node.split('.')[0], 10);

describe("Prototype Pollution Protection", function () {
  afterEach(function () {
    // Clean up any pollution that might have occurred
    delete Object.prototype.polluted;
    delete Object.prototype.validateStatus;
    delete Object.prototype.parseReviver;
    delete Object.prototype.responseType;
    delete Object.prototype.transitional;
    delete Object.prototype.formSerializer;
    delete Object.prototype.env;
    delete Object.prototype.response;
    delete Object.prototype.auth;
    delete Object.prototype.baseURL;
    delete Object.prototype.socketPath;
    delete Object.prototype.beforeRedirect;
    delete Object.prototype.insecureHTTPParser;
    delete Object.prototype.adapter;
    delete Object.prototype.httpAgent;
    delete Object.prototype.httpsAgent;
    delete Object.prototype.proxy;
    delete Object.prototype.maxContentLength;
    delete Object.prototype.maxBodyLength;
    delete Object.prototype.maxRedirects;
    delete Object.prototype.maxRate;
    delete Object.prototype.timeout;
    delete Object.prototype.timeoutErrorMessage;
    delete Object.prototype.cancelToken;
    delete Object.prototype.signal;
    delete Object.prototype.decompress;
    delete Object.prototype.params;
    delete Object.prototype.paramsSerializer;
    delete Object.prototype.method;
    delete Object.prototype.withCredentials;
    delete Object.prototype.fetchOptions;
    delete Object.prototype.transformRequest;
    delete Object.prototype.transformResponse;
    delete Object.prototype.transport;
    delete Object.prototype.lookup;
    delete Object.prototype.family;
    delete Object.prototype.responseEncoding;
    delete Object.prototype.data;
    delete Object.prototype.headers;
    delete Object.prototype.xsrfCookieName;
    delete Object.prototype.xsrfHeaderName;
    delete Object.prototype.username;
    delete Object.prototype.password;
    delete Object.prototype.hostname;
    delete Object.prototype.host;
    delete Object.prototype.port;
    delete Object.prototype.protocol;
    delete Object.prototype.get;
    delete Object.prototype.set;
    delete Object.prototype.createConnection;
    delete Object.prototype.getHeaders;
    delete Object.prototype.visitor;
    delete Object.prototype.maxDepth;
    delete Object.prototype.customNested;
  });

  describe("utils.merge", function () {
    it("should filter __proto__ key at top level", function () {
      const result = utils.merge(
        {},
        { __proto__: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
    });

    it("should filter constructor key at top level", function () {
      const result = utils.merge(
        {},
        { constructor: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("constructor"), false);
    });

    it("should filter prototype key at top level", function () {
      const result = utils.merge(
        {},
        { prototype: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("prototype"), false);
    });

    it("should filter __proto__ key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            __proto__: { polluted: "nested" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("__proto__"), false);
    });

    it("should filter constructor key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            constructor: { prototype: { polluted: "nested" } },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("constructor"), false);
    });

    it("should filter prototype key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            prototype: { polluted: "nested" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("prototype"), false);
    });

    it("should filter dangerous keys in deeply nested objects", function () {
      const result = utils.merge(
        {},
        {
          level1: {
            level2: {
              __proto__: { polluted: "deep" },
              prototype: { polluted: "deep" },
              safe: "value",
            },
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.level1.level2.safe, "value");
      assert.strictEqual(
        result.level1.level2.hasOwnProperty("__proto__"),
        false,
      );
    });

    it("should still merge regular properties correctly", function () {
      const result = utils.merge({ a: 1, b: { c: 2 } }, { b: { d: 3 }, e: 4 });

      assert.strictEqual(result.a, 1);
      assert.strictEqual(result.b.c, 2);
      assert.strictEqual(result.b.d, 3);
      assert.strictEqual(result.e, 4);
    });

    it("should handle JSON.parse payloads safely", function () {
      const malicious = JSON.parse('{"__proto__": {"polluted": "yes"}}');
      const result = utils.merge({}, malicious);

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
    });

    it("should handle nested JSON.parse payloads safely", function () {
      const malicious = JSON.parse(
        '{"headers": {"constructor": {"prototype": {"polluted": "yes"}}}}',
      );
      const result = utils.merge({}, malicious);

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers.hasOwnProperty("constructor"), false);
    });
  });

  describe("mergeConfig", function () {
    it("should filter dangerous keys at top level", function () {
      const result = mergeConfig(
        {},
        {
          __proto__: { polluted: "yes" },
          constructor: { polluted: "yes" },
          prototype: { polluted: "yes" },
          url: "/api/test",
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.url, "/api/test");
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
      assert.strictEqual(result.hasOwnProperty("constructor"), false);
      assert.strictEqual(result.hasOwnProperty("prototype"), false);
    });

    it("should filter dangerous keys in headers", function () {
      const result = mergeConfig(
        {},
        {
          headers: {
            __proto__: { polluted: "yes" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("__proto__"), false);
    });

    it("should filter dangerous keys in custom config properties", function () {
      const result = mergeConfig(
        {},
        {
          customProp: {
            __proto__: { polluted: "yes" },
            safe: "value",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.customProp.safe, "value");
      assert.strictEqual(result.customProp.hasOwnProperty("__proto__"), false);
    });

    it("should not inherit transport from Object.prototype", function () {
      Object.prototype.transport = { request: function () {} };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(result.hasOwnProperty("transport"), false);
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transport"),
        false
      );
    });

    it("should not inherit transformRequest from Object.prototype", function () {
      Object.prototype.transformRequest = function () { return "hijacked"; };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transformRequest"),
        false
      );
    });

    it("should not inherit transformResponse from Object.prototype", function () {
      Object.prototype.transformResponse = function () { return "hijacked"; };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transformResponse"),
        false
      );
    });

    it("should not inherit arbitrary keys from Object.prototype", function () {
      Object.prototype.polluted = "yes";
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "polluted"),
        false
      );
    });

    it("should still merge configs correctly", function () {
      const config1 = {
        baseURL: "https://api.example.com",
        timeout: 1000,
        headers: {
          common: {
            Accept: "application/json",
          },
        },
      };

      const config2 = {
        url: "/users",
        timeout: 5000,
        headers: {
          common: {
            "Content-Type": "application/json",
          },
        },
      };

      const result = mergeConfig(config1, config2);

      assert.strictEqual(result.baseURL, "https://api.example.com");
      assert.strictEqual(result.url, "/users");
      assert.strictEqual(result.timeout, 5000);
      assert.strictEqual(result.headers.common.Accept, "application/json");
      assert.strictEqual(
        result.headers.common["Content-Type"],
        "application/json",
      );
    });
  });

  // GHSA-w9j2-pvgh-6h63: mergeDirectKeys must not inherit validateStatus from
  // Object.prototype (was using the `in` operator which traverses the chain).
  describe("GHSA-w9j2-pvgh-6h63 validateStatus merge", function () {
    it("should not inherit a polluted validateStatus during mergeConfig", function () {
      Object.prototype.validateStatus = function () {
        return true;
      };

      const merged = mergeConfig(defaults, { url: "/x" });

      assert.strictEqual(merged.validateStatus, defaults.validateStatus);
    });

    it("should keep 4xx/5xx responses rejected when Object.prototype.validateStatus is polluted", async function () {
      this.timeout(10000);

      Object.prototype.validateStatus = function () {
        return true;
      };

      const server = http.createServer(function (req, res) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end('{"error":"unauthorized"}');
      });

      await new Promise(function (resolve) {
        server.listen(0, "127.0.0.1", resolve);
      });
      const { port } = server.address();

      try {
        let threw = false;
        try {
          await axios.get(`http://127.0.0.1:${port}/`);
        } catch (err) {
          threw = true;
          assert.strictEqual(err.response.status, 401);
        }
        assert.strictEqual(threw, true);
      } finally {
        await new Promise(function (resolve) {
          server.close(resolve);
        });
      }
    });
  });

  // CVE-2026-42044 (GHSA-3w6x-2g7m-8v23): the default transformRequest /
  // transformResponse must only read options that are own properties of the
  // config, never values inherited from a polluted Object.prototype.
  describe("CVE-2026-42044 default transform gadgets", function () {
    const transformRequest = defaults.transformRequest[0];
    const transformResponse = defaults.transformResponse[0];

    function tamperingReviver(key, value) {
      if (key === "isAdmin") return true;
      if (key === "role") return "admin";
      if (key === "balance") return 999999;
      return value;
    }

    it("should ignore a polluted parseReviver in transformResponse", function () {
      Object.prototype.parseReviver = tamperingReviver;

      const data = transformResponse.call(
        {},
        '{"isAdmin":false,"role":"viewer","balance":100}',
      );

      assert.strictEqual(data.isAdmin, false);
      assert.strictEqual(data.role, "viewer");
      assert.strictEqual(data.balance, 100);
    });

    it("should not let a polluted parseReviver tamper with axios JSON responses", async function () {
      this.timeout(10000);

      const server = http.createServer(function (req, res) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end('{"isAdmin":false,"role":"viewer","balance":100}');
      });

      await new Promise(function (resolve) {
        server.listen(0, "127.0.0.1", resolve);
      });
      const { port } = server.address();

      Object.prototype.parseReviver = tamperingReviver;

      try {
        const response = await axios.get(`http://127.0.0.1:${port}/`);

        assert.strictEqual(response.data.isAdmin, false);
        assert.strictEqual(response.data.role, "viewer");
        assert.strictEqual(response.data.balance, 100);
      } finally {
        delete Object.prototype.parseReviver;
        await new Promise(function (resolve) {
          server.close(resolve);
        });
      }
    });

    it("should ignore a polluted transitional in transformResponse", function () {
      Object.prototype.transitional = {
        silentJSONParsing: true,
        forcedJSONParsing: false,
      };

      const data = transformResponse.call({}, '{"foo":"bar"}');

      assert.strictEqual(typeof data, "object");
      assert.strictEqual(data.foo, "bar");
    });

    it("should ignore a polluted responseType in transformResponse", function () {
      Object.prototype.responseType = "text";

      const data = transformResponse.call(
        { transitional: defaults.transitional },
        '{"foo":"bar"}',
      );

      assert.strictEqual(typeof data, "object");
      assert.strictEqual(data.foo, "bar");
    });

    it("should not attach a polluted response to JSON parse errors", function () {
      Object.prototype.response = { status: 200, data: "spoofed" };

      let error;
      try {
        transformResponse.call(
          {
            transitional: { silentJSONParsing: false, forcedJSONParsing: true },
            responseType: "json",
          },
          "{invalid",
        );
      } catch (err) {
        error = err;
      }

      assert.ok(error, "expected a JSON parse error");
      assert.strictEqual(error.code, "ERR_BAD_RESPONSE");
      assert.strictEqual(Object.prototype.hasOwnProperty.call(error, "response"), false);
      assert.strictEqual(Object.prototype.hasOwnProperty.call(error, "status"), false);
    });

    it("should ignore a polluted formSerializer in transformRequest", function () {
      const payload = { user: { name: "alice" } };
      const urlencoded = function () {
        return new AxiosHeaders({
          "Content-Type": "application/x-www-form-urlencoded",
        });
      };

      const expected = transformRequest.call({}, payload, urlencoded());

      Object.prototype.formSerializer = {
        visitor: function () {
          this.append("isAdmin", "true");
          return false;
        },
      };

      const actual = transformRequest.call({}, payload, urlencoded());

      assert.strictEqual(actual, expected);
      assert.strictEqual(actual.indexOf("isAdmin"), -1);
    });

    it("should ignore a polluted env.FormData in transformRequest", function () {
      let constructed = false;

      function SpoofedFormData() {
        constructed = true;
        this.entries = [];
      }

      SpoofedFormData.prototype.append = function (key, value) {
        this.entries.push([key, value]);
      };

      Object.prototype.env = { FormData: SpoofedFormData };

      const result = transformRequest.call(
        {},
        { foo: "bar" },
        new AxiosHeaders({ "Content-Type": "multipart/form-data" }),
      );

      assert.strictEqual(constructed, false);
      assert.strictEqual(result instanceof SpoofedFormData, false);
    });

    it("should still honour own config values", function () {
      const data = transformResponse.call(
        {
          transitional: defaults.transitional,
          parseReviver: function (key, value) {
            return key === "foo" ? "own" : value;
          },
        },
        '{"foo":"bar"}',
      );

      assert.strictEqual(data.foo, "own");

      const text = transformResponse.call(
        { transitional: defaults.transitional, responseType: "text" },
        '{"foo":"bar"}',
      );

      assert.strictEqual(text, '{"foo":"bar"}');
    });
  });

  // GHSA-q8qp-cvcw-x6jj: five config properties were read via direct property
  // access in the http adapter and resolveConfig, bypassing hasOwnProperty and
  // allowing prototype pollution gadgets (auth, baseURL, socketPath,
  // beforeRedirect, insecureHTTPParser).
  describe('GHSA-q8qp-cvcw-x6jj http adapter gadgets', function () {
    function startServer(handler) {
      return new Promise((resolve) => {
        const server = http.createServer(handler || ((req, res) => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ headers: req.headers, url: req.url }));
        }));
        server.listen(0, '127.0.0.1', () => resolve(server));
      });
    }

    function stopServer(server) {
      return new Promise((resolve) => server.close(resolve));
    }

    it('should not pick up Object.prototype.auth as an Authorization header', async function () {
      this.timeout(10000);
      Object.prototype.auth = { username: 'attacker', password: 'exfil' };

      const server = await startServer();
      const { port } = server.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${port}/api`);
        assert.strictEqual(res.data.headers.authorization, undefined);
      } finally {
        await stopServer(server);
      }
    });

    it('should not pick up Object.prototype.socketPath and redirect the request', async function () {
      this.timeout(10000);
      Object.prototype.socketPath = '/tmp/axios-should-never-be-used.sock';

      const server = await startServer();
      const { port } = server.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${port}/api`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.data.url, '/api');
      } finally {
        await stopServer(server);
      }
    });

    it('should not invoke Object.prototype.beforeRedirect during redirects', async function () {
      this.timeout(10000);
      let hijackCalled = false;
      Object.prototype.beforeRedirect = function polluted() {
        hijackCalled = true;
      };

      const target = await startServer();
      const { port: targetPort } = target.address();

      const redirector = await startServer((req, res) => {
        res.writeHead(302, { Location: `http://127.0.0.1:${targetPort}/final` });
        res.end();
      });
      const { port: redirectorPort } = redirector.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${redirectorPort}/start`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(hijackCalled, false);
      } finally {
        await stopServer(redirector);
        await stopServer(target);
      }
    });

    it('should pass an own inert createConnection option to transports', async function () {
      this.timeout(10000);
      Object.prototype.createConnection = function () {
        throw new Error('unexpected inherited createConnection');
      };

      const server = await startServer((req, res) => res.end('ok'));
      const { port } = server.address();

      try {
        const response = await axios.get(`http://127.0.0.1:${port}/`, {
          transport: {
            request(options, handleResponse) {
              assert.strictEqual(
                Object.prototype.hasOwnProperty.call(options, 'createConnection'),
                true
              );
              assert.strictEqual(options.createConnection, undefined);
              return http.request(options, handleResponse);
            }
          }
        });

        assert.strictEqual(response.data, 'ok');
      } finally {
        delete Object.prototype.createConnection;
        await stopServer(server);
      }
    });

    [
      ['follow-redirects transport', {}],
      ['native transport (maxRedirects: 0)', { maxRedirects: 0 }]
    ].forEach(function ([description, extraConfig]) {
      it(`should not open sockets through Object.prototype.createConnection with the ${description}`, async function () {
        this.timeout(10000);
        const legitHits = [];
        const attackerHits = [];
        let pollutedCalls = 0;

        const legit = await startServer((req, res) => {
          legitHits.push(req.headers.authorization);
          res.end('LEGIT');
        });
        const attacker = await startServer((req, res) => {
          attackerHits.push(req.headers.authorization);
          res.end('ATTACKER');
        });

        Object.prototype.createConnection = function (options, cb) {
          pollutedCalls++;
          const sock = net.createConnection({
            host: '127.0.0.1',
            port: attacker.address().port
          }, () => {
            if (typeof cb === 'function') cb(null, sock);
          });
          return sock;
        };

        try {
          const res = await axios.get(`http://127.0.0.1:${legit.address().port}/secret`, Object.assign({
            headers: { Authorization: 'Bearer SECRET' },
            proxy: false
          }, extraConfig));

          assert.strictEqual(res.data, 'LEGIT');
          assert.strictEqual(pollutedCalls, 0);
          assert.deepStrictEqual(attackerHits, []);
          assert.deepStrictEqual(legitHits, ['Bearer SECRET']);
        } finally {
          delete Object.prototype.createConnection;
          await stopServer(legit);
          await stopServer(attacker);
        }
      });
    });

    it('should not enable insecureHTTPParser via Object.prototype', async function () {
      if (nodeMajorVersion < 14) this.skip();
      this.timeout(10000);
      // A raw TCP server emits a response that uses LF-only line terminators
      // instead of CRLF. Node's strict HTTP parser rejects this payload with
      // HPE_CR_EXPECTED; the insecure parser accepts it. Verified: with an
      // explicit `insecureHTTPParser: true` on the request config, this
      // payload is parsed successfully — so if Object.prototype.insecureHTTPParser
      // were picked up, the request would succeed. The request must fail when
      // the gadget is properly blocked.
      Object.prototype.insecureHTTPParser = true;

      const net = await import('net');
      const malformedPayload =
        'HTTP/1.1 200 OK\n' +
        'Content-Type: application/json\n' +
        'Content-Length: 2\n' +
        '\n' +
        '{}';
      const malformed = await new Promise((resolve) => {
        const srv = net.createServer((socket) => {
          socket.once('data', () => socket.end(malformedPayload));
        });
        srv.listen(0, '127.0.0.1', () => resolve(srv));
      });
      const { port } = malformed.address();

      try {
        let threw = false;
        let caughtCode = '';
        try {
          await axios.get(`http://127.0.0.1:${port}/`, {
            transitional: { clarifyTimeoutError: false },
          });
        } catch (err) {
          threw = true;
          caughtCode = String(err && (err.code || err.message));
        }
        assert.strictEqual(
          threw,
          true,
          `request should be rejected by the strict HTTP parser (got: ${caughtCode || 'success'})`
        );
        // The exact llhttp code for LF-only line terminators varies across
        // Node versions (historically HPE_LF_EXPECTED, more recently
        // HPE_CR_EXPECTED). Match any parser error to remain stable across
        // Node releases while still confirming the strict parser rejected
        // the payload.
        assert.match(
          caughtCode,
          /^HPE_/,
          `expected an HPE_* parser error, got: ${caughtCode}`
        );
      } finally {
        await new Promise((resolve) => malformed.close(resolve));
      }
    });

    it('should not pass insecureHTTPParser: true to http.request via Object.prototype', async function () {
      this.timeout(10000);
      Object.prototype.insecureHTTPParser = true;

      let capturedValue;
      const origRequest = http.request;
      http.request = function(options, callback) {
        capturedValue = options.insecureHTTPParser;
        return origRequest.apply(this, arguments);
      };

      const server = await startServer();
      const { port } = server.address();
      try {
        await axios.get(`http://127.0.0.1:${port}/`, { maxRedirects: 0 });
      } catch (_) {}
      finally {
        http.request = origRequest;
        await stopServer(server);
      }

      assert.strictEqual(capturedValue, false);
    });

    it('should not inject Proxy-Authorization from polluted Object.prototype.auth', async function () {
      this.timeout(10000);
      // setProxy reads `proxy.auth` directly. When `proxy` is a
      // URL instance from the environment proxy or a plain object without an own `auth`,
      // a polluted Object.prototype.auth would otherwise be base64-encoded into the
      // Proxy-Authorization header, leaking attacker-controlled credentials.
      Object.prototype.auth = { username: 'attacker', password: 'exfil' };

      const proxy = await startServer();
      const { port: proxyPort } = proxy.address();

      const target = await startServer();
      const { port: targetPort } = target.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${targetPort}/api`, {
          proxy: { host: '127.0.0.1', port: proxyPort, protocol: 'http' },
        });
        assert.strictEqual(res.status, 200);
        assert.strictEqual(
          res.data.headers['proxy-authorization'],
          undefined,
          'polluted Object.prototype.auth must not produce a Proxy-Authorization header'
        );
      } finally {
        await stopServer(target);
        await stopServer(proxy);
      }
    });

    it('should not inject Proxy-Authorization from polluted Object.prototype.username', async function () {
      this.timeout(10000);
      // The setProxy username/password branch builds basic creds from `proxy.username`
      // and `proxy.password`. For a plain object proxy, both reads must be guarded
      // against prototype pollution.
      Object.prototype.username = 'attacker';
      Object.prototype.password = 'exfil';

      const proxy = await startServer();
      const { port: proxyPort } = proxy.address();

      const target = await startServer();
      const { port: targetPort } = target.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${targetPort}/api`, {
          proxy: { host: '127.0.0.1', port: proxyPort, protocol: 'http' },
        });
        assert.strictEqual(res.status, 200);
        assert.strictEqual(
          res.data.headers['proxy-authorization'],
          undefined,
          'polluted Object.prototype.username must not produce a Proxy-Authorization header'
        );
      } finally {
        await stopServer(target);
        await stopServer(proxy);
      }
    });
  });

  describe('GHSA-q8qp-cvcw-x6jj resolveConfig baseURL gadget', function () {
    // The baseURL branch in buildFullPath only runs when the requested URL is
    // relative (or allowAbsoluteUrls === false). An absolute URL would skip
    // baseURL regardless of pollution and would not exercise the gadget. We
    // therefore issue a relative GET and assert that either:
    //   - the request fails (no host to resolve) because baseURL is correctly
    //     absent from the merged config, OR
    //   - the request is fulfilled without hitting the hijacker.
    // Critically, hijackHit must always be false.
    it('should not hijack relative-URL requests via Object.prototype.baseURL', async function () {
      this.timeout(10000);
      let hijackHit = false;
      const hijacker = http.createServer((req, res) => {
        hijackHit = true;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"hijacked":true}');
      });
      await new Promise((resolve) => hijacker.listen(0, '127.0.0.1', resolve));
      const { port: hijackerPort } = hijacker.address();

      Object.prototype.baseURL = `http://127.0.0.1:${hijackerPort}`;

      try {
        let threw = false;
        try {
          await axios.get('/api');
        } catch (_err) {
          threw = true;
        }
        // Either the request fails (desired — no baseURL means no host) or it
        // resolves, but it must NOT hit the polluted hijacker.
        assert.strictEqual(hijackHit, false);
        assert.strictEqual(threw, true);
      } finally {
        await new Promise((resolve) => hijacker.close(resolve));
      }
    });

    // Second variant using allowAbsoluteUrls: false to force the baseURL path
    // even for a fully-qualified requested URL.
    it('should not hijack requests via Object.prototype.baseURL with allowAbsoluteUrls:false', async function () {
      this.timeout(10000);
      let hijackHit = false;
      const hijacker = http.createServer((req, res) => {
        hijackHit = true;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"hijacked":true}');
      });
      await new Promise((resolve) => hijacker.listen(0, '127.0.0.1', resolve));
      const { port: hijackerPort } = hijacker.address();

      const target = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true}');
      });
      await new Promise((resolve) => target.listen(0, '127.0.0.1', resolve));
      const { port: targetPort } = target.address();

      Object.prototype.baseURL = `http://127.0.0.1:${hijackerPort}`;

      try {
        // If the gadget were picked up, combineURLs(hijacker, `http://target`)
        // would route to the hijacker. It must not.
        let threw = false;
        try {
          await axios.get(`http://127.0.0.1:${targetPort}/api`, {
            allowAbsoluteUrls: false,
          });
        } catch (_err) {
          threw = true;
        }
        assert.strictEqual(hijackHit, false);
        // allowAbsoluteUrls:false + no baseURL → combineURLs not invoked
        // (baseURL falsy) → returns requested URL as-is → target receives it.
        // If baseURL were inherited from prototype, it would be truthy and
        // combineURLs would be invoked, routing to the hijacker.
        assert.strictEqual(threw, false);
      } finally {
        await new Promise((resolve) => hijacker.close(resolve));
        await new Promise((resolve) => target.close(resolve));
      }
    });
  });

  // Structural defense: mergeConfig returns a null-prototype object, so any
  // property read that is not an own property of config cannot inherit from
  // Object.prototype. Adding a new key to Object.prototype must never appear
  // as a property of the merged config.
  describe('mergeConfig null-prototype structural defense', function () {
    it('should return an object whose prototype is null', function () {
      const merged = mergeConfig({ url: '/x' }, { method: 'get' });
      assert.strictEqual(Object.getPrototypeOf(merged), null);
    });

    it('should preserve hasOwnProperty as a callable own slot', function () {
      const merged = mergeConfig({}, { url: '/x', method: 'get' });
      assert.strictEqual(typeof merged.hasOwnProperty, 'function');
      assert.strictEqual(merged.hasOwnProperty('url'), true);
      assert.strictEqual(merged.hasOwnProperty('method'), true);
      assert.strictEqual(merged.hasOwnProperty('bogus'), false);
    });

    it('should not serialize hasOwnProperty slot via Object.keys', function () {
      const merged = mergeConfig({ url: '/x' }, {});
      assert.ok(!Object.keys(merged).includes('hasOwnProperty'));
    });

    it('should not expose arbitrary polluted keys as inherited properties', function () {
      Object.prototype.polluted = 'attacker';
      try {
        const merged = mergeConfig({ url: '/x' }, {});
        assert.strictEqual(merged.polluted, undefined);
      } finally {
        delete Object.prototype.polluted;
      }
    });
  });

  describe('dispatch config compatibility', function () {
    it('should preserve an unchanged merged config through dispatch', async function () {
      let interceptedConfig;
      let adapterConfig;

      const instance = axios.create({
        adapter: async (config) => {
          adapterConfig = config;
          return {
            data: 'ok',
            status: 200,
            statusText: 'OK',
            headers: {},
            config
          };
        }
      });

      instance.interceptors.request.use((config) => {
        interceptedConfig = config;
        return config;
      });

      const response = await instance.get('/config-identity');

      assert.strictEqual(adapterConfig, interceptedConfig);
      assert.strictEqual(response.config, interceptedConfig);
      assert.strictEqual(Object.getPrototypeOf(adapterConfig), null);
      assert.strictEqual(
        Object.prototype.propertyIsEnumerable.call(adapterConfig, 'hasOwnProperty'),
        false
      );
      assert.strictEqual(Object.keys(adapterConfig).includes('hasOwnProperty'), false);
    });

    it('should materialize a frozen null-prototype interceptor replacement', async function () {
      let replacement;

      const instance = axios.create({
        adapter: async (config) => ({
          data: 'ok',
          status: 200,
          statusText: 'OK',
          headers: {},
          config
        })
      });

      instance.interceptors.request.use((config) => {
        replacement = Object.freeze(Object.assign(Object.create(null), config));
        return replacement;
      });

      const response = await instance.get('/frozen-replacement');

      assert.strictEqual(response.data, 'ok');
      assert.notStrictEqual(response.config, replacement);
      assert.strictEqual(Object.getPrototypeOf(response.config), null);
      assert.strictEqual(Object.isFrozen(response.config), false);
    });

    it('should filter unsafe keys from a null-prototype interceptor replacement', async function () {
      let replacement;

      const instance = axios.create({
        adapter: async (config) => ({
          data: {
            safe: config.safe,
            hasProto: Object.prototype.hasOwnProperty.call(config, '__proto__'),
            hasConstructor: Object.prototype.hasOwnProperty.call(config, 'constructor'),
            hasPrototype: Object.prototype.hasOwnProperty.call(config, 'prototype')
          },
          status: 200,
          statusText: 'OK',
          headers: {},
          config
        })
      });

      instance.interceptors.request.use((config) => {
        replacement = Object.assign(Object.create(null), config);
        replacement.safe = 'preserved';
        Object.defineProperty(replacement, '__proto__', {
          value: 'excluded',
          enumerable: true,
          configurable: true,
          writable: true
        });
        replacement.constructor = 'excluded';
        replacement.prototype = 'excluded';
        return replacement;
      });

      const response = await instance.get('/unsafe-own-keys');

      assert.deepStrictEqual(response.data, {
        safe: 'preserved',
        hasProto: false,
        hasConstructor: false,
        hasPrototype: false
      });
      assert.notStrictEqual(response.config, replacement);
    });

    it('should normalize a class-based interceptor replacement', async function () {
      let replacement;

      class ConfigTemplate {
        marker() {
          return 'template';
        }
      }

      const instance = axios.create({
        adapter: async (config) => ({
          data: config.marker(),
          status: 200,
          statusText: 'OK',
          headers: {},
          config
        })
      });

      instance.interceptors.request.use((config) => {
        replacement = new ConfigTemplate();
        replacement.url = config.url;
        replacement.method = config.method;
        replacement.headers = config.headers;
        replacement.adapter = config.adapter;
        return replacement;
      });

      const response = await instance.get('/normalized-replacement');

      assert.strictEqual(response.data, 'template');
      assert.notStrictEqual(response.config, replacement);
      assert.strictEqual(response.config instanceof ConfigTemplate, false);
      assert.strictEqual(Object.getPrototypeOf(response.config), null);
      assert.strictEqual(Object.prototype.hasOwnProperty.call(response.config, 'marker'), true);
    });
  });

  // Verify every gadget enumerated in the audit (extension of GHSA-q8qp-cvcw-x6jj)
  // is neutralized end-to-end by the null-prototype config.
  describe('Full gadget coverage via null-prototype config', function () {
    function startEcho(handler) {
      return new Promise((resolve) => {
        const server = http.createServer(handler || ((req, res) => {
          let body = '';
          req.on('data', (c) => (body += c));
          req.on('end', () => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              url: req.url,
              method: req.method,
              headers: req.headers,
              body,
            }));
          });
        }));
        server.listen(0, '127.0.0.1', () => resolve(server));
      });
    }
    const stop = (s) => new Promise((r) => s.close(r));

    it('should ignore polluted transformRequest', async function () {
      this.timeout(10000);
      let invoked = false;
      Object.prototype.transformRequest = function polluted(data) {
        invoked = true;
        return 'INJECTED';
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.post(`http://127.0.0.1:${port}/`, { hello: 'world' });
        assert.strictEqual(invoked, false);
        assert.notStrictEqual(res.data.body, 'INJECTED');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted transformResponse', async function () {
      this.timeout(10000);
      let invoked = false;
      Object.prototype.transformResponse = function polluted() {
        invoked = true;
        return 'HIJACKED';
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(invoked, false);
        assert.notStrictEqual(res.data, 'HIJACKED');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted adapter', async function () {
      this.timeout(10000);
      let hijacked = false;
      Object.prototype.adapter = function pollutedAdapter() {
        hijacked = true;
        return Promise.resolve({ data: 'pwned', status: 200, statusText: 'OK', headers: {}, config: {}, request: {} });
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/ok`);
        assert.strictEqual(hijacked, false);
        assert.notStrictEqual(res.data, 'pwned');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted httpAgent', async function () {
      this.timeout(10000);
      let agentUsed = false;
      Object.prototype.httpAgent = new http.Agent({
        keepAlive: false,
      });
      // Wrap createConnection to detect usage
      const origCreate = Object.prototype.httpAgent.createConnection;
      Object.prototype.httpAgent.createConnection = function (...args) {
        agentUsed = true;
        return origCreate.apply(this, args);
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(agentUsed, false);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted proxy', async function () {
      this.timeout(10000);
      Object.prototype.proxy = {
        protocol: 'http',
        host: '127.0.0.1',
        port: 1, // would fail if actually used
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted maxContentLength', async function () {
      this.timeout(10000);
      // Polluted tiny limit would reject a normal response if applied.
      Object.prototype.maxContentLength = 1;

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted maxRedirects', async function () {
      this.timeout(10000);
      // Pollute with 0 — if picked up, follow-redirects path would be skipped.
      // We make sure regular requests still succeed via the expected path.
      Object.prototype.maxRedirects = 0;

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted timeout at the merged config level', function () {
      Object.prototype.timeout = 1;
      const merged = mergeConfig({}, { url: '/x' });
      assert.strictEqual(Object.prototype.hasOwnProperty.call(merged, 'timeout'), false);
      assert.strictEqual(merged.timeout, undefined);
    });

    it('should ignore polluted timeoutErrorMessage', async function () {
      this.timeout(10000);
      Object.prototype.timeoutErrorMessage = 'INJECTED_TIMEOUT';
      // Not easy to assert without triggering a real timeout; just confirm
      // normal requests still succeed and do not read the polluted key.
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted transitional', async function () {
      this.timeout(10000);
      Object.prototype.transitional = { forcedJSONParsing: true, silentJSONParsing: false };
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted params and paramsSerializer', async function () {
      this.timeout(10000);
      let serializerInvoked = false;
      Object.prototype.params = { injected: 'yes' };
      Object.prototype.paramsSerializer = function polluted() {
        serializerInvoked = true;
        return 'injected=yes';
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/x`);
        assert.strictEqual(serializerInvoked, false);
        assert.strictEqual(res.data.url, '/x');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted method', async function () {
      this.timeout(10000);
      Object.prototype.method = 'DELETE';
      const server = await startEcho();
      const { port } = server.address();
      try {
        // axios.get should still send GET, not DELETE.
        const res = await axios.get(`http://127.0.0.1:${port}/ok`);
        assert.strictEqual(res.data.method, 'GET');
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted decompress', async function () {
      this.timeout(10000);
      Object.prototype.decompress = false;
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stop(server);
      }
    });

    it('should ignore polluted responseType', async function () {
      this.timeout(10000);
      Object.prototype.responseType = 'arraybuffer';
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        // When responseType is not set on config, json parsing should apply
        // and res.data should be an object, not an ArrayBuffer/Buffer.
        assert.strictEqual(typeof res.data, 'object');
        assert.ok(!Buffer.isBuffer(res.data));
      } finally {
        await stop(server);
      }
    });

    it('should use GET when the default instance has no own method', async function () {
      Object.prototype.method = 'DELETE';

      const response = await axios({
        url: '/default-method',
        adapter: async (config) => ({
          data: config.method,
          status: 200,
          statusText: 'OK',
          headers: {},
          config
        })
      });

      assert.strictEqual(response.data, 'get');
    });

    it('should send GET over the wire when the default instance has no own method', async function () {
      this.timeout(10000);
      const server = await startEcho();
      const { port } = server.address();

      Object.prototype.method = 'DELETE';

      try {
        const res = await axios.request({ url: `http://127.0.0.1:${port}/resource` });

        assert.strictEqual(res.data.method, 'GET');
      } finally {
        delete Object.prototype.method;
        await stop(server);
      }
    });

    it('should ignore headers inherited after a request interceptor replaces config', async function () {
      Object.prototype.headers = { 'X-Injected': 'yes' };

      const instance = axios.create({
        adapter: async (config) => ({
          data: config.headers.get('X-Injected'),
          status: 200,
          statusText: 'OK',
          headers: {},
          config
        })
      });

      instance.interceptors.request.use((config) => {
        const replacement = { ...config };
        delete replacement.headers;
        return replacement;
      });

      const response = await instance.get('/interceptor-headers');

      assert.strictEqual(response.data, undefined);
    });

    it('should not send inherited headers after a minimal interceptor replacement', async function () {
      this.timeout(10000);
      const server = await startEcho();
      const { port } = server.address();

      const client = axios.create();
      client.interceptors.request.use((config) => ({
        url: config.url,
        method: config.method,
        timeout: config.timeout
      }));

      Object.prototype.headers = {
        'X-Poisoned': 'yes',
        'If-None-Match': '*'
      };

      try {
        const res = await client.get(`http://127.0.0.1:${port}/headers`, { timeout: 3000 });
        const body = typeof res.data === 'string' ? JSON.parse(res.data) : res.data;

        assert.strictEqual(body.url, '/headers');
        assert.strictEqual(body.headers['x-poisoned'], undefined);
        assert.strictEqual(body.headers['if-none-match'], undefined);
      } finally {
        delete Object.prototype.headers;
        await stop(server);
      }
    });

    it('should ignore behavior inherited after a request interceptor replaces config', async function () {
      let requestTransformCalled = false;
      let responseTransformCalled = false;

      Object.prototype.transformRequest = () => {
        requestTransformCalled = true;
      };
      Object.prototype.transformResponse = () => {
        responseTransformCalled = true;
      };
      Object.prototype.cancelToken = {
        throwIfRequested() {
          throw new Error('unexpected inherited cancelToken');
        }
      };
      Object.prototype.signal = { aborted: true };
      Object.prototype.method = 'delete';

      const instance = axios.create({
        adapter: async (config) => ({
          data: config.method,
          status: 200,
          statusText: 'OK',
          headers: {},
          config
        })
      });

      instance.interceptors.request.use((config) => {
        const replacement = { ...config };
        delete replacement.transformRequest;
        delete replacement.transformResponse;
        delete replacement.cancelToken;
        delete replacement.signal;
        delete replacement.method;
        return replacement;
      });

      const response = await instance.get('/interceptor-behavior');

      assert.strictEqual(requestTransformCalled, false);
      assert.strictEqual(responseTransformCalled, false);
      assert.strictEqual(response.data, undefined);
    });

    it('should ignore an adapter inherited after a request interceptor replaces config', async function () {
      let called = false;

      Object.prototype.adapter = async (config) => {
        called = true;
        return {
          data: 'unexpected',
          status: 200,
          statusText: 'OK',
          headers: {},
          config
        };
      };

      const instance = axios.create();

      instance.interceptors.request.use((config) => {
        const replacement = { ...config };
        delete replacement.adapter;
        return replacement;
      });

      const response = await instance.get('data:,safe', {
        responseType: 'text'
      });

      assert.strictEqual(called, false);
      assert.strictEqual(response.data, 'safe');
    });

    it('should preserve config inherited from a non-shared prototype after interception', async function () {
      const instance = axios.create();

      instance.interceptors.request.use((config) => {
        const replacement = Object.create({
          adapter: async (resolvedConfig) => ({
            data: resolvedConfig.customValue,
            status: 200,
            statusText: 'OK',
            headers: {},
            config: resolvedConfig
          }),
          customValue: 'preserved'
        });

        replacement.url = config.url;
        replacement.method = config.method;
        replacement.headers = config.headers;

        return replacement;
      });

      const response = await instance.get('/prototype-template');

      assert.strictEqual(response.data, 'preserved');
    });

    [
      ['unchanged', ''],
      ['set to null', 'Object.prototype.constructor = null;'],
      ['deleted', 'delete Object.prototype.constructor;'],
      [
        'replaced by an accessor',
        `Object.defineProperty(Object.prototype, 'constructor', {
          configurable: true,
          get() { return Object; }
        });`
      ]
    ].forEach(function ([description, mutateConstructor]) {
      it(`should exclude a foreign realm Object.prototype with its constructor ${description}`, async function () {
        const context = vm.createContext({
          adapter: async (config) => ({
            data: config.customValue,
            status: 200,
            statusText: 'OK',
            headers: {},
            config
          })
        });

        const replacement = vm.runInContext(
          `
            Object.prototype.transformResponse = () => 'polluted';
            ${mutateConstructor}
            Object.create({adapter, customValue: 'preserved'});
          `,
          context
        );

        const instance = axios.create();

        instance.interceptors.request.use((config) => {
          replacement.url = config.url;
          replacement.method = config.method;
          replacement.headers = config.headers;

          return replacement;
        });

        const response = await instance.get('/cross-realm-prototype-template');

        assert.strictEqual(response.data, 'preserved');
      });
    });

    it('should not run a visitor inherited from Object.prototype during multipart serialization', async function () {
      const stolen = [];

      Object.prototype.visitor = function (value, key) {
        stolen.push(key);
        return false;
      };
      Object.prototype.maxDepth = 0;

      let sentData;

      try {
        await axios.post('/upload', {
          username: 'john',
          password: 'SuperSecret123!',
          profile: { ssn: '123-45-6789' }
        }, {
          headers: { 'Content-Type': 'multipart/form-data' },
          adapter: async (config) => {
            sentData = config.data;
            return {
              data: 'ok',
              status: 200,
              statusText: 'OK',
              headers: {},
              config
            };
          }
        });
      } finally {
        delete Object.prototype.visitor;
        delete Object.prototype.maxDepth;
      }

      assert.deepStrictEqual(stolen, []);
      assert.ok(sentData, 'multipart body must be serialized');
    });
  });

  function startEchoServer() {
    return new Promise(function (resolve) {
      const server = http.createServer(function (req, res) {
        let body = "";
        req.on("data", function (chunk) {
          body += chunk;
        });
        req.on("end", function () {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({
            url: req.url,
            method: req.method,
            headers: req.headers,
            body: body,
          }));
        });
      });
      server.listen(0, "127.0.0.1", function () {
        resolve(server);
      });
    });
  }

  function stopEchoServer(server) {
    return new Promise(function (resolve) {
      server.close(resolve);
    });
  }

  // CVE-2026-44495 (GHSA-3g43-6gmg-66jw): mergeConfig must only read own
  // properties of config1/config2. A key that is own on one side (e.g. the
  // defaults' transformResponse) must never pick up a polluted
  // Object.prototype value from the other side, otherwise the gadget is copied
  // into the merged config as an own property and bypasses every later
  // hasOwnProperty / null-prototype defense.
  describe("CVE-2026-44495 mergeConfig inherited value reads", function () {
    it("should not let a polluted transformResponse override the defaults", function () {
      const polluted = function pollutedTransformResponse() {
        return "HIJACKED";
      };
      Object.prototype.transformResponse = polluted;

      const merged = mergeConfig(defaults, { url: "/x" });

      assert.notStrictEqual(merged.transformResponse, polluted);
      assert.deepStrictEqual(merged.transformResponse, defaults.transformResponse);
    });

    it("should not let polluted keys override any default value", function () {
      const keys = [
        "adapter",
        "transformRequest",
        "transformResponse",
        "timeout",
        "xsrfCookieName",
        "xsrfHeaderName",
        "maxContentLength",
        "maxBodyLength",
        "env",
        "transitional",
        "headers",
      ];

      keys.forEach(function (key) {
        const sentinel = { __pollutedMarker: key };
        Object.prototype[key] = sentinel;
        try {
          const merged = mergeConfig(defaults, { url: "/x" });
          const value = merged[key];
          assert.notStrictEqual(value, sentinel, key + " was taken from Object.prototype");
          assert.ok(
            !(value && Object.prototype.hasOwnProperty.call(value, "__pollutedMarker")),
            key + " was merged with Object.prototype." + key
          );
        } finally {
          delete Object.prototype[key];
        }
      });
    });

    it("should not merge polluted headers read from config1", function () {
      Object.prototype.headers = { "X-Injected": "evil" };

      const merged = mergeConfig({}, { headers: { "X-Own": "1" } });

      assert.strictEqual(merged.headers["X-Own"], "1");
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(merged.headers, "X-Injected"),
        false
      );
    });

    it("should not leak credentials to a polluted transformResponse via axios(config)", async function () {
      this.timeout(10000);
      const server = await startEchoServer();
      const { port } = server.address();

      let invoked = false;
      let leaked;
      Object.prototype.transformResponse = function pollutedTransformResponse() {
        invoked = true;
        leaked = this && this.auth ? this.auth.username + ":" + this.auth.password : undefined;
        return "HIJACKED";
      };

      try {
        const res = await axios({
          url: `http://127.0.0.1:${port}/secret`,
          method: "get",
          auth: { username: "user", password: "s3cret" },
        });

        assert.strictEqual(invoked, false);
        assert.strictEqual(leaked, undefined);
        assert.notStrictEqual(res.data, "HIJACKED");
        assert.strictEqual(res.data.url, "/secret");
      } finally {
        delete Object.prototype.transformResponse;
        await stopEchoServer(server);
      }
    });

    it("should not run a polluted transformRequest via axios.request(config)", async function () {
      this.timeout(10000);
      const server = await startEchoServer();
      const { port } = server.address();

      let invoked = false;
      Object.prototype.transformRequest = function pollutedTransformRequest() {
        invoked = true;
        return "INJECTED";
      };

      try {
        const res = await axios.request({
          url: `http://127.0.0.1:${port}/`,
          method: "post",
          data: { hello: "world" },
        });

        assert.strictEqual(invoked, false);
        assert.strictEqual(res.data.body, JSON.stringify({ hello: "world" }));
      } finally {
        delete Object.prototype.transformRequest;
        await stopEchoServer(server);
      }
    });

    it("should not dispatch through a polluted adapter via axios(config)", async function () {
      this.timeout(10000);
      const server = await startEchoServer();
      const { port } = server.address();

      let hijacked = false;
      Object.prototype.adapter = function pollutedAdapter(config) {
        hijacked = true;
        return Promise.resolve({
          data: "pwned",
          status: 200,
          statusText: "OK",
          headers: {},
          config: config,
          request: {},
        });
      };

      try {
        const res = await axios({ url: `http://127.0.0.1:${port}/ok` });

        assert.strictEqual(hijacked, false);
        assert.strictEqual(res.data.url, "/ok");
      } finally {
        delete Object.prototype.adapter;
        await stopEchoServer(server);
      }
    });

    it("should not bake a polluted transformResponse into axios.create() defaults", function () {
      const polluted = function pollutedTransformResponse() {
        return "HIJACKED";
      };
      Object.prototype.transformResponse = polluted;

      let instance;
      try {
        instance = axios.create();
      } finally {
        delete Object.prototype.transformResponse;
      }

      assert.notStrictEqual(instance.defaults.transformResponse, polluted);
      assert.deepStrictEqual(instance.defaults.transformResponse, defaults.transformResponse);
    });

    it("should not inject polluted headers into axios.post requests", async function () {
      this.timeout(10000);
      const server = await startEchoServer();
      const { port } = server.address();

      Object.prototype.headers = { "X-Injected": "evil" };

      let res;
      try {
        res = await axios.post(`http://127.0.0.1:${port}/`, { hello: "world" });
      } finally {
        delete Object.prototype.headers;
        await stopEchoServer(server);
      }

      assert.strictEqual(res.data.headers["x-injected"], undefined);
      assert.strictEqual(res.data.body, JSON.stringify({ hello: "world" }));
    });

    it("should still honour own config values", async function () {
      this.timeout(10000);
      const server = await startEchoServer();
      const { port } = server.address();

      let invoked = false;
      try {
        const res = await axios({
          url: `http://127.0.0.1:${port}/own`,
          headers: { "X-Own": "1" },
          transformResponse: [function (data) {
            invoked = true;
            return JSON.parse(data);
          }],
        });

        assert.strictEqual(invoked, true);
        assert.strictEqual(res.data.url, "/own");
        assert.strictEqual(res.data.headers["x-own"], "1");
      } finally {
        await stopEchoServer(server);
      }
    });
  });

  // The http adapter must only read own config properties, so a config that is
  // a plain object (e.g. returned as `{...config}` by a request interceptor, or
  // passed directly to the exported adapter) cannot inherit gadgets such as
  // transport, lookup, family, responseType, responseEncoding, data or env from
  // a polluted Object.prototype.
  describe("CVE-2026-44495 http adapter own config reads", function () {
    function createSpreadingInstance() {
      const instance = axios.create();
      instance.interceptors.request.use(function (config) {
        return Object.assign({}, config);
      });
      return instance;
    }

    it("should not route requests through a polluted transport", async function () {
      this.timeout(10000);
      const server = await startEchoServer();
      const { port } = server.address();
      const instance = createSpreadingInstance();

      let hijacked = false;
      Object.prototype.transport = {
        request: function () {
          hijacked = true;
          return http.request.apply(http, arguments);
        },
      };

      try {
        const res = await instance.get(`http://127.0.0.1:${port}/transport`);

        assert.strictEqual(hijacked, false);
        assert.strictEqual(res.data.url, "/transport");
      } finally {
        delete Object.prototype.transport;
        await stopEchoServer(server);
      }
    });

    it("should not pass a polluted lookup or family to http.request", async function () {
      this.timeout(10000);
      const server = await startEchoServer();
      const { port } = server.address();
      const instance = createSpreadingInstance();

      let captured;
      const origRequest = http.request;
      http.request = function (options) {
        captured = { lookup: options.lookup, family: options.family };
        return origRequest.apply(this, arguments);
      };

      Object.prototype.lookup = function pollutedLookup(hostname, opts, cb) {
        cb(null, "127.0.0.1", 4);
      };
      Object.prototype.family = 6;

      try {
        try {
          await instance.get(`http://127.0.0.1:${port}/`, { maxRedirects: 0 });
        } catch (_) {
          // the outcome of the request itself is irrelevant here
        }
      } finally {
        delete Object.prototype.lookup;
        delete Object.prototype.family;
        http.request = origRequest;
        await stopEchoServer(server);
      }

      assert.ok(captured, "http.request should have been called");
      assert.strictEqual(captured.lookup, undefined);
      assert.strictEqual(captured.family, undefined);
    });

    it("should ignore a polluted responseType", async function () {
      this.timeout(10000);
      const server = await startEchoServer();
      const { port } = server.address();
      const instance = createSpreadingInstance();

      Object.prototype.responseType = "arraybuffer";

      try {
        const res = await instance.get(`http://127.0.0.1:${port}/type`);

        assert.ok(!Buffer.isBuffer(res.data));
        assert.strictEqual(res.data.url, "/type");
      } finally {
        delete Object.prototype.responseType;
        await stopEchoServer(server);
      }
    });

    it("should ignore a polluted responseEncoding", async function () {
      this.timeout(10000);
      const server = await startEchoServer();
      const { port } = server.address();
      const instance = createSpreadingInstance();

      Object.prototype.responseEncoding = "base64";

      try {
        const res = await instance.get(`http://127.0.0.1:${port}/encoding`);

        assert.strictEqual(typeof res.data, "object");
        assert.strictEqual(res.data.url, "/encoding");
      } finally {
        delete Object.prototype.responseEncoding;
        await stopEchoServer(server);
      }
    });

    it("should not send a polluted data as the request body", async function () {
      this.timeout(10000);
      const server = await startEchoServer();
      const { port } = server.address();

      Object.prototype.data = "INJECTED_BODY";

      let res;
      try {
        res = await httpAdapter({
          url: `http://127.0.0.1:${port}/data`,
          method: "post",
          headers: new AxiosHeaders(),
          maxRedirects: 0,
        });
      } finally {
        delete Object.prototype.data;
        await stopEchoServer(server);
      }

      const echoed = JSON.parse(res.data);
      assert.strictEqual(echoed.url, "/data");
      assert.strictEqual(echoed.body, "");
    });

    it("should not construct a polluted env.Blob for data: URIs", async function () {
      let hijacked = false;
      Object.prototype.env = {
        Blob: function PollutedBlob() {
          hijacked = true;
        },
      };

      try {
        try {
          await httpAdapter({
            url: "data:text/plain;base64,SGVsbG8=",
            method: "get",
            responseType: "blob",
          });
        } catch (_) {
          // Blob may be unsupported on older Node versions
        }
      } finally {
        delete Object.prototype.env;
      }

      assert.strictEqual(hijacked, false);
    });
  });

  // utils.merge previously read `result[targetKey]` directly, which walks the
  // prototype chain. A polluted Object.prototype.<key> object would surface as
  // the existing value and be merged into the result.
  describe('utils.merge prototype-chain read', function () {
    it('should not pick up polluted Object.prototype.<key> as the existing value', function () {
      Object.prototype.headers = { evil: 'yes' };

      const result = utils.merge({}, { headers: { 'Content-Type': 'application/json' } });

      assert.strictEqual(result.headers.evil, undefined);
      assert.strictEqual(result.headers['Content-Type'], 'application/json');
    });

    it('should not absorb polluted nested objects when the key is absent from inputs', function () {
      // When the source does not carry `customNested`, the merged result should
      // not surface it either, even if Object.prototype carries it.
      Object.prototype.customNested = { evil: 'yes' };

      const result = utils.merge({}, { safe: 'value' });

      assert.strictEqual(result.hasOwnProperty('customNested'), false);
      assert.strictEqual(result.safe, 'value');
    });
  });

  // Object.defineProperty calls a HasProperty check on `get`/`set` of the
  // descriptor. A polluted Object.prototype.get with a non-function value would
  // throw TypeError at every defineProperty site that uses a plain literal
  // descriptor. Each fixed site should be shielded with `__proto__: null`.
  describe('Object.defineProperty descriptor literals', function () {
    it('should construct AxiosHeaders accessor methods when Object.prototype.get is polluted', function () {
      Object.prototype.get = 'attacker';

      // AxiosHeaders.accessor uses Object.defineProperty on the prototype.
      // Triggering a fresh accessor definition exercises the descriptor literal.
      AxiosHeaders.accessor('X-Pp-Test');

      const h = new AxiosHeaders();
      h.setXPpTest('value');
      assert.strictEqual(h.getXPpTest(), 'value');
    });

    it('should not throw in mergeConfig when Object.prototype.get is polluted', function () {
      Object.prototype.get = 'attacker';

      const result = mergeConfig({}, { url: '/x', method: 'get' });

      assert.strictEqual(result.url, '/x');
      assert.strictEqual(result.method, 'get');
      assert.strictEqual(typeof result.hasOwnProperty, 'function');
    });

    it('should not throw in utils.inherits when Object.prototype.get is polluted', function () {
      Object.prototype.get = 'attacker';

      function Parent() {}
      function Child() {}
      utils.inherits(Child, Parent);

      assert.strictEqual(Child.prototype.constructor, Child);
      assert.strictEqual(Child.super, Parent.prototype);
    });

    it('should also be shielded against a polluted Object.prototype.set', function () {
      Object.prototype.set = 'attacker';

      // Same surface as `get` — ToPropertyDescriptor checks both. One spot-check
      // covers them all since they share the same fix.
      const result = mergeConfig({}, { url: '/y' });
      assert.strictEqual(result.url, '/y');
    });
  });

  // End-to-end regressions covering published advisory PoCs against full axios
  // request flow. Each test mirrors the exploit scenario from the advisory and
  // asserts the attack does not succeed.
  describe('advisory regression — full request flow', function () {
    function startServer(handler) {
      return new Promise((resolve) => {
        const server = http.createServer(handler);
        server.listen(0, '127.0.0.1', () => resolve(server));
      });
    }
    const stop = (s) => new Promise((r) => s.close(r));

    // Full MITM via prototype pollution gadget in
    // `config.proxy`. mergeConfig must not surface a polluted Object.prototype.proxy
    // as the merged config's proxy, otherwise every request would route through
    // an attacker-controlled host.
    it('polluted Object.prototype.proxy must not redirect requests through an attacker proxy', async function () {
      this.timeout(10000);
      const proxyHits = [];
      const attackerProxy = await startServer((req, res) => {
        proxyHits.push({
          url: req.url,
          authorization: req.headers.authorization,
          host: req.headers.host,
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"hijacked":true}');
      });

      const realHits = [];
      const realServer = await startServer((req, res) => {
        realHits.push({ url: req.url });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"data":"real"}');
      });

      try {
        Object.prototype.proxy = {
          protocol: 'http',
          host: '127.0.0.1',
          port: attackerProxy.address().port,
        };

        const realPort = realServer.address().port;
        const res = await axios.get(`http://127.0.0.1:${realPort}/api/secrets`, {
          auth: { username: 'admin', password: 'SuperSecret123!' },
        });

        assert.strictEqual(proxyHits.length, 0, 'attacker proxy must not receive any request');
        assert.strictEqual(realHits.length, 1, 'request must reach the real target');
        assert.deepStrictEqual(res.data, { data: 'real' });
      } finally {
        await stop(attackerProxy);
        await stop(realServer);
      }
    });

    // Credential theft and response hijacking via
    // prototype pollution gadget in config merge. A polluted
    // Object.prototype.transformResponse function would otherwise execute with
    // `this = config`, exposing `auth.username`/`auth.password` to the attacker.
    it('polluted Object.prototype.transformResponse must not be invoked or leak request credentials', async function () {
      this.timeout(10000);
      let invoked = false;
      let stolen = null;
      Object.prototype.transformResponse = function pollutedTransform(data) {
        invoked = true;
        stolen = {
          url: this && this.url,
          username: this && this.auth && this.auth.username,
          password: this && this.auth && this.auth.password,
          data,
        };
        return true;
      };

      const server = await startServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"secret":"keep-me"}');
      });

      try {
        const { port } = server.address();
        const res = await axios.get(`http://127.0.0.1:${port}/users`, {
          auth: { username: 'svc-account', password: 'prod-secret-key-123!' },
        });

        assert.strictEqual(invoked, false, 'polluted transformResponse must not run');
        assert.strictEqual(stolen, null, 'no request context must be captured');
        assert.deepStrictEqual(
          res.data,
          { secret: 'keep-me' },
          'response data must reach the caller untampered'
        );
      } finally {
        await stop(server);
      }
    });
  });


  // CVE-2026-44494: a polluted Object.prototype.proxy (or a polluted field that
  // setProxy reads off the proxy object) must never steer requests through an
  // attacker-controlled proxy or inject attacker-chosen Proxy-Authorization
  // credentials, including for configs that bypass mergeConfig's null-prototype
  // object (spread by an interceptor or passed straight to the http adapter).
  describe("CVE-2026-44494 proxy gadgets", function () {
    const PROXY_ENV_KEYS = [
      "http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY",
      "npm_config_http_proxy", "npm_config_https_proxy", "npm_config_proxy",
      "no_proxy", "NO_PROXY", "npm_config_no_proxy",
    ];

    function withProxyEnv(env, fn) {
      const original = {};
      PROXY_ENV_KEYS.forEach(function (key) {
        original[key] = process.env[key];
        delete process.env[key];
      });
      Object.keys(env).forEach(function (key) {
        process.env[key] = env[key];
      });
      try {
        return fn();
      } finally {
        PROXY_ENV_KEYS.forEach(function (key) {
          if (original[key] === undefined) {
            delete process.env[key];
          } else {
            process.env[key] = original[key];
          }
        });
      }
    }

    function startRecordingProxy(hits) {
      return new Promise(function (resolve) {
        const server = http.createServer(function (req, res) {
          hits.push({ url: req.url, headers: req.headers });
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end('{"hijacked":true}');
        });
        server.listen(0, "127.0.0.1", function () {
          resolve(server);
        });
      });
    }

    function newOptions() {
      return {
        headers: {},
        beforeRedirects: {},
        hostname: "target.example.com",
        host: "target.example.com",
        port: 80,
        protocol: "http:",
      };
    }

    it("should not route an interceptor-spread config through a polluted Object.prototype.proxy", async function () {
      this.timeout(10000);
      const proxyHits = [];
      const attackerProxy = await startRecordingProxy(proxyHits);
      const server = await startEchoServer();
      const { port } = server.address();

      const instance = axios.create();
      instance.interceptors.request.use(function (config) {
        return Object.assign({}, config);
      });

      Object.prototype.proxy = {
        protocol: "http",
        host: "127.0.0.1",
        port: attackerProxy.address().port,
      };

      try {
        const res = await instance.get(`http://127.0.0.1:${port}/secrets`, {
          auth: { username: "admin", password: "SuperSecret123!" },
        });

        assert.strictEqual(proxyHits.length, 0, "attacker proxy must not receive any request");
        assert.strictEqual(res.data.url, "/secrets");
      } finally {
        delete Object.prototype.proxy;
        await stopEchoServer(server);
        await stopEchoServer(attackerProxy);
      }
    });

    it("should not route a plain config passed to the http adapter through a polluted Object.prototype.proxy", async function () {
      this.timeout(10000);
      const proxyHits = [];
      const attackerProxy = await startRecordingProxy(proxyHits);
      const server = await startEchoServer();
      const { port } = server.address();

      Object.prototype.proxy = {
        protocol: "http",
        host: "127.0.0.1",
        port: attackerProxy.address().port,
      };

      let res;
      try {
        res = await httpAdapter({
          url: `http://127.0.0.1:${port}/direct`,
          method: "get",
          headers: new AxiosHeaders(),
          maxRedirects: 0,
        });
      } finally {
        delete Object.prototype.proxy;
        await stopEchoServer(server);
        await stopEchoServer(attackerProxy);
      }

      assert.strictEqual(proxyHits.length, 0, "attacker proxy must not receive any request");
      assert.strictEqual(JSON.parse(res.data).url, "/direct");
    });

    it("should not let a polluted Object.prototype.hostname override the proxy host", function () {
      Object.prototype.hostname = "attacker.example.com";

      const options = newOptions();
      __setProxy(options, { host: "127.0.0.1", port: 8030, protocol: "http" }, "http://target.example.com/");

      assert.strictEqual(options.hostname, "127.0.0.1");
      assert.strictEqual(options.host, "127.0.0.1");
    });

    it("should not apply a polluted Object.prototype.port or protocol to the proxy", function () {
      Object.prototype.port = 6666;
      Object.prototype.protocol = "https";

      const options = newOptions();
      __setProxy(options, { host: "127.0.0.1" }, "http://target.example.com/");

      assert.strictEqual(options.hostname, "127.0.0.1");
      assert.strictEqual(options.port, undefined);
      assert.strictEqual(options.protocol, "http:");
    });

    it("should not replace configured proxy credentials with polluted Object.prototype.username/password", function () {
      Object.prototype.username = "attacker";
      Object.prototype.password = "exfil";

      const options = newOptions();
      __setProxy(
        options,
        { host: "127.0.0.1", port: 8030, auth: { username: "user", password: "pass" } },
        "http://target.example.com/"
      );

      assert.strictEqual(
        options.headers["Proxy-Authorization"],
        "Basic " + Buffer.from("user:pass", "utf8").toString("base64")
      );
    });

    it("should not inject Proxy-Authorization from polluted Object.prototype.auth into an env-derived proxy", function () {
      Object.prototype.auth = { username: "attacker", password: "exfil" };

      const options = newOptions();
      withProxyEnv({ http_proxy: "http://127.0.0.1:8030" }, function () {
        __setProxy(options, undefined, "http://target.example.com/");
      });

      assert.strictEqual(options.hostname, "127.0.0.1", "precondition: env proxy must be applied");
      assert.strictEqual(options.port, "8030");
      assert.strictEqual(options.headers["Proxy-Authorization"], undefined);
    });

    it("should keep env-derived proxy credentials when Object.prototype.auth is polluted", function () {
      Object.prototype.auth = { username: "attacker", password: "exfil" };

      const options = newOptions();
      withProxyEnv({ http_proxy: "http://user:pass@127.0.0.1:8030" }, function () {
        __setProxy(options, undefined, "http://target.example.com/");
      });

      assert.strictEqual(
        options.headers["Proxy-Authorization"],
        "Basic " + Buffer.from("user:pass", "utf8").toString("base64")
      );
    });
  });

  describe("CVE-2026-44494 Object.defineProperty descriptor literals (extend)", function () {
    it("should not throw in utils.extend when Object.prototype.get is polluted", function () {
      Object.prototype.get = "attacker";

      const context = { name: "ctx" };
      const target = {};
      utils.extend(target, { value: 1, fn: function () { return this.name; } }, context);

      assert.strictEqual(target.value, 1);
      assert.strictEqual(target.fn(), "ctx");
    });

    it("should create an axios instance when Object.prototype.get is polluted", function () {
      Object.prototype.get = "attacker";

      const instance = axios.create({ baseURL: "http://127.0.0.1/" });

      assert.strictEqual(typeof instance.request, "function");
      assert.strictEqual(instance.defaults.baseURL, "http://127.0.0.1/");
    });
  });

});
