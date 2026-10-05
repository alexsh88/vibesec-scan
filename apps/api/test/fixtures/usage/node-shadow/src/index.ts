// Documented limitation: no scope analysis. A parameter named `merge` shadows the import of the
// same name, but the analyzer still (incorrectly) reports the call below as a lodash usage.
import merge from 'lodash';

function unrelated(merge: (x: number) => number) {
  return merge(1);
}
