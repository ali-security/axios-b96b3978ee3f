"use strict";

import assert from "assert";
import http from "http";
import axios from "../../../index.js";
import utils from "../../../lib/utils.js";
import mergeConfig from "../../../lib/core/mergeConfig.js";
import defaults from "../../../lib/defaults/index.js";
import AxiosHeaders from "../../../lib/core/AxiosHeaders.js";

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
});
