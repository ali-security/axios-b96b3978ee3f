import assert from 'assert';
import buildURL from '../../../lib/helpers/buildURL.js';

describe('helpers::buildURL', function () {
  it('should ignore inherited serializer options', function () {
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
      assert.strictEqual(buildURL('/foo', { value: 'a b' }, {}), '/foo?value=a+b');
      assert.strictEqual(serializeInvoked, false);
      assert.strictEqual(encodeInvoked, false);
    } finally {
      delete Object.prototype.serialize;
      delete Object.prototype.encode;
    }
  });

  it('should still honor own serializer options', function () {
    assert.strictEqual(
      buildURL('/foo', { value: 'a b' }, { serialize: () => 'custom=1' }),
      '/foo?custom=1'
    );
    assert.strictEqual(
      buildURL('/foo', { value: 'a b' }, { encode: () => 'x' }),
      '/foo?x=x'
    );
  });
});
