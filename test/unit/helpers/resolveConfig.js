import assert from 'assert';
import resolveConfig from '../../../lib/helpers/resolveConfig.js';

describe('helpers::resolveConfig', function () {
  it('should ignore FormData getHeaders inherited only from Object.prototype', function () {
    // Requires a spec-compliant global FormData (Node.js >= 18)
    if (typeof globalThis.FormData !== 'function') {
      this.skip();
      return;
    }

    let called = false;
    Object.prototype.getHeaders = () => {
      called = true;
      return { 'X-Injected': 'yes', 'Content-Type': 'text/injected' };
    };

    try {
      const config = resolveConfig({
        url: '/upload',
        data: new globalThis.FormData()
      });

      assert.strictEqual(called, false);
      assert.strictEqual(config.headers.get('X-Injected'), undefined);
      assert.notStrictEqual(config.headers.get('Content-Type'), 'text/injected');
    } finally {
      delete Object.prototype.getHeaders;
    }
  });

  it('should still use an own or class-provided FormData getHeaders', function () {
    class NodeFormData {
      append() {}

      getHeaders() {
        return { 'Content-Type': 'multipart/form-data; boundary=own-boundary' };
      }

      get [Symbol.toStringTag]() {
        return 'FormData';
      }
    }

    const config = resolveConfig({
      url: '/upload',
      data: new NodeFormData()
    });

    assert.strictEqual(
      config.headers.get('Content-Type'),
      'multipart/form-data; boundary=own-boundary'
    );
  });

  it('should ignore inherited nested auth fields', function () {
    // resolveConfig relies on the global btoa, which is absent on Node < 16
    if (typeof btoa === 'undefined') {
      this.skip();
      return;
    }

    Object.defineProperty(Object.prototype, 'username', {
      value: 'inherited-user',
      configurable: true,
      writable: true
    });
    Object.defineProperty(Object.prototype, 'password', {
      value: 'inherited-pass',
      configurable: true,
      writable: true
    });

    try {
      const config = resolveConfig({
        url: '/foo',
        auth: {}
      });

      assert.strictEqual(config.headers.get('Authorization'), 'Basic Og==');
    } finally {
      delete Object.prototype.username;
      delete Object.prototype.password;
    }
  });

  it('should ignore inherited nested serializer fields', function () {
    let serializeInvoked = false;
    let encodeInvoked = false;

    Object.defineProperty(Object.prototype, 'serialize', {
      value() {
        serializeInvoked = true;
        return 'inherited=1';
      },
      configurable: true
    });
    Object.defineProperty(Object.prototype, 'encode', {
      value() {
        encodeInvoked = true;
        return 'inherited';
      },
      configurable: true
    });

    try {
      const config = resolveConfig({
        url: '/foo',
        params: { value: 'a b' },
        paramsSerializer: {}
      });

      assert.strictEqual(config.url, '/foo?value=a+b');
      assert.strictEqual(serializeInvoked, false);
      assert.strictEqual(encodeInvoked, false);
    } finally {
      delete Object.prototype.serialize;
      delete Object.prototype.encode;
    }
  });
});
