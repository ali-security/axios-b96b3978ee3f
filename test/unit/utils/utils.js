import assert from 'assert';
import utils from '../../../lib/utils.js';
import FormData from 'form-data';
import stream from 'stream';

describe('utils', function (){
  it('should validate Stream', function () {
    assert.strictEqual(utils.isStream(new stream.Readable()),true);
    assert.strictEqual(utils.isStream({ foo: 'bar' }),false);
  });

  it('should validate Buffer', function () {
    assert.strictEqual(utils.isBuffer(Buffer.from('a')),true);
    assert.strictEqual(utils.isBuffer(null),false);
    assert.strictEqual(utils.isBuffer(undefined),false);
  });

  describe('utils::isFormData', function () {
    it('should detect the FormData instance provided by the `form-data` package', function () {
      [1, 'str', {}, new RegExp()].forEach(function (thing) {
        assert.equal(utils.isFormData(thing), false);
      });
      assert.equal(utils.isFormData(new FormData()), true);
    });

    it('should not call toString method on built-in objects instances', () => {
      const buf = Buffer.from('123');

      buf.toString = () => assert.fail('should not be called');

      assert.equal(utils.isFormData(buf), false);
    });

    it('should not call toString method on built-in objects instances, even if append method exists', () => {
      const buf = Buffer.from('123');

      buf.append = () => {};

      buf.toString = () => assert.fail('should not be called');

      assert.equal(utils.isFormData(buf), false);
    });

    it('should detect custom FormData instances by toStringTag signature and append method presence', () => {
      class FormData {
        append(){

        }

        get [Symbol.toStringTag]() {
          return 'FormData';
        }
      }
      assert.equal(utils.isFormData(new FormData()), true);
    });

    it('should not detect plain objects as FormData when Object.prototype is polluted', () => {
      Object.prototype[Symbol.toStringTag] = 'FormData';
      Object.prototype.append = () => {};

      try {
        assert.equal(utils.isFormData({userId: 42}), false);
        assert.equal(utils.isFormData(Object.create(null)), false);
      } finally {
        delete Object.prototype.append;
        delete Object.prototype[Symbol.toStringTag];
      }
    });
  });

  describe('utils::isX', function () {
    it('should ignore inherited symbol properties when validating plain Object', function () {
      try {
        Object.prototype[Symbol.iterator] = function* () {
          yield ['x-injected', 'yes'];
        };
        Object.prototype[Symbol.toStringTag] = 'Custom';

        assert.strictEqual(utils.isPlainObject({}), true);
        assert.strictEqual(utils.isPlainObject([]), false);
        assert.strictEqual(
          utils.isPlainObject({
            [Symbol.iterator]: function* () {
              yield ['x-own', 'yes'];
            }
          }),
          false
        );
        assert.strictEqual(
          utils.isPlainObject({
            [Symbol.toStringTag]: 'Custom'
          }),
          false
        );
      } finally {
        delete Object.prototype[Symbol.iterator];
        delete Object.prototype[Symbol.toStringTag];
      }
    });

    it('should treat an object with a genuinely inherited iterator as non-plain', function () {
      // Iterator inherited from a custom (non-Object.prototype) source: this is a
      // real iterable, not prototype pollution, so it must not be classified plain.
      const proto = Object.create(null);
      proto[Symbol.iterator] = function* () {
        yield ['x', '1'];
      };

      assert.strictEqual(utils.isPlainObject(Object.create(proto)), false);
    });

    it('should not read polluted Object.prototype iterator accessors for safe iterable checks', function () {
      let accessed = false;

      try {
        Object.defineProperty(Object.prototype, Symbol.iterator, {
          configurable: true,
          get() {
            accessed = true;
            throw new Error('polluted iterator accessor');
          }
        });

        assert.strictEqual(utils.isSafeIterable({}), false);
        assert.strictEqual(accessed, false);
      } finally {
        delete Object.prototype[Symbol.iterator];
      }
    });

    it('should stop safe prototype-chain reads on cyclic Proxy prototypes', function () {
      let calls = 0;
      let proxy;
      proxy = new Proxy({}, {
        getPrototypeOf() {
          calls += 1;
          if (calls > 5) {
            throw new Error('cycled');
          }
          return proxy;
        }
      });

      assert.strictEqual(utils.hasOwnInPrototypeChain(proxy, 'missing'), false);
      assert.strictEqual(utils.getSafeProp(proxy, 'missing'), undefined);
      assert.ok(calls <= 2, `expected at most 2 getPrototypeOf calls, got ${calls}`);
    });

    it('should honor own and template-prototype members but ignore Object.prototype pollution in getSafeProp', function () {
      try {
        Object.prototype.polluted = 'injected';

        const template = { inherited: 'template' };
        const derived = Object.create(template);
        derived.own = 'own';

        assert.strictEqual(utils.getSafeProp(derived, 'own'), 'own');
        assert.strictEqual(utils.getSafeProp(derived, 'inherited'), 'template');
        assert.strictEqual(utils.getSafeProp(derived, 'polluted'), undefined);
        assert.strictEqual(utils.getSafeProp({}, 'polluted'), undefined);
        assert.strictEqual(utils.getSafeProp(null, 'polluted'), undefined);
      } finally {
        delete Object.prototype.polluted;
      }
    });
  });

  describe('toJSON', function (){
    it('should convert to a plain object without circular references', function () {
      const obj= {a: [0]}
      const source = {x:1, y:2, obj};
      source.circular1 = source;
      obj.a[1] = obj;

      assert.deepStrictEqual(utils.toJSONObject(source), {
        x: 1, y:2, obj: {a: [0]}
      });
    });

    it('should use objects with defined toJSON method without rebuilding', function () {
      const objProp = {};
      const obj= {objProp, toJSON(){
        return {ok: 1}
      }};
      const source = {x:1, y:2, obj};

      const jsonObject = utils.toJSONObject(source);

      assert.strictEqual(jsonObject.obj.objProp, objProp);
      assert.strictEqual(JSON.stringify(jsonObject), JSON.stringify({x: 1, y:2, obj: {ok: 1}}))
    });
  });

  describe('Buffer RangeError Fix', function () {
    it('should handle large Buffer in isEmptyObject without RangeError', function () {
      // Create a big buffer that used to cause the error
      const largeBuffer = Buffer.alloc(1024 * 1024 * 200); // 200MB
      
      // This used to throw: RangeError: Invalid array length
      // Now it should work fine
      const result = utils.isEmptyObject(largeBuffer);
      
      // Buffer should not be considered an empty object
      assert.strictEqual(result, false);
    });

    it('should handle large Buffer in forEach without RangeError', function () {
      const largeBuffer = Buffer.alloc(1024 * 1024 * 200); // 200MB
      let count = 0;
      
      // This should skip the buffer (not iterate through it)
      utils.forEach(largeBuffer, () => count++);
      
      // Count should be 0 because forEach skips Buffers
      assert.strictEqual(count, 0);
    });

    it('should handle large Buffer in findKey without RangeError', function () {
      const largeBuffer = Buffer.alloc(1024 * 1024 * 200); // 200MB
      
      // Should return null for Buffers
      const result = utils.findKey(largeBuffer, 'test');
      
      assert.strictEqual(result, null);
    });
  });
});
