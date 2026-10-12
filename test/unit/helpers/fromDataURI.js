import assert from 'assert';
import fromDataURI from '../../../lib/helpers/fromDataURI.js';

describe('helpers::fromDataURI', function () {
  it('should return buffer from data uri', function () {
    const buffer= Buffer.from('123');

    const dataURI = 'data:application/octet-stream;base64,' + buffer.toString('base64');

    assert.deepStrictEqual(fromDataURI(dataURI, false), buffer);
  });

  it('should reject a media type containing more than one slash', function () {
    assert.throws(
      () => {
        fromDataURI('data:text/plain/extra,hello', false);
      },
      (err) => err.code === 'ERR_INVALID_URL'
    );
  });

  it('should reject long malformed media types without excessive backtracking', function () {
    const payloads = [
      `data:${'a/'.repeat(50000)}invalid`,
      'data:' + '/'.repeat(100000)
    ];

    payloads.forEach((payload) => {
      const start = Date.now();

      assert.throws(
        () => {
          fromDataURI(payload, false);
        },
        (err) => err.code === 'ERR_INVALID_URL'
      );

      const elapsed = Date.now() - start;
      assert.ok(elapsed < 1000, `expected to reject within 1000ms, took ${elapsed}ms`);
    });
  });
});
