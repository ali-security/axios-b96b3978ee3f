import assert from 'assert';
import formDataToJSON from '../../../lib/helpers/formDataToJSON.js';
import AxiosError from '../../../lib/core/AxiosError.js';
import axios from '../../../index.js';

describe('helpers::formDataToJSON', function () {
  before(function () {
    if (typeof FormData !== 'function') {
      this.skip();
    }
  });

  it('should throw AxiosError when a field path exceeds the default depth limit', function () {
    const formData = new FormData();

    formData.append('foo' + '[bar]'.repeat(101), '123');

    try {
      formDataToJSON(formData);
      assert.fail('Should have thrown');
    } catch (err) {
      assert.ok(err instanceof AxiosError, 'error must be AxiosError, not RangeError');
      assert.strictEqual(err.code, AxiosError.ERR_FORM_DATA_DEPTH_EXCEEDED);
      assert.ok(!(err instanceof RangeError));
    }
  });

  it('should throw AxiosError while tokenizing very deep field paths', function () {
    const formData = new FormData();

    formData.append('foo' + '[bar]'.repeat(10000), '123');

    try {
      formDataToJSON(formData);
      assert.fail('Should have thrown');
    } catch (err) {
      assert.ok(err instanceof AxiosError, 'error must be AxiosError, not RangeError');
      assert.strictEqual(err.code, AxiosError.ERR_FORM_DATA_DEPTH_EXCEEDED);
      assert.ok(!(err instanceof RangeError));
    }
  });

  it('should convert a field path at the default depth limit', function () {
    const formData = new FormData();

    formData.append('foo' + '[bar]'.repeat(100), '123');

    let value = formDataToJSON(formData).foo;

    for (let i = 0; i < 100; i++) {
      value = value.bar;
    }

    assert.strictEqual(value, '123');
  });

  it('should reject deeply nested field paths in a JSON FormData request before adapter dispatch', async function () {
    const data = new FormData();
    let adapterCalled = false;

    data.append('foo' + '[bar]'.repeat(101), '123');

    await assert.rejects(
      axios.post('/foo', data, {
        headers: { 'Content-Type': 'application/json' },
        adapter(config) {
          adapterCalled = true;
          return Promise.resolve({
            data: null,
            status: 200,
            statusText: 'OK',
            headers: {},
            config,
            request: {}
          });
        }
      }),
      (err) => {
        assert.ok(err instanceof AxiosError, 'must be AxiosError');
        assert.strictEqual(err.code, AxiosError.ERR_FORM_DATA_DEPTH_EXCEEDED);
        return true;
      }
    );

    assert.strictEqual(adapterCalled, false);
  });
});
