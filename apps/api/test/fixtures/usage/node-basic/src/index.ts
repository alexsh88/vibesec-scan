// Default import -> symbol 'default'; member/call tracking on the local binding.
import def1 from 'lodash';
// Named imports with an alias -> symbol is the ORIGINAL name ('merge'), never the local alias 'm'.
import { merge as m, debounce } from 'lodash';
// Namespace import -> symbol null; member/call tracking, but bare ns(...) is not tracked.
import * as ns from 'lodash';
// Subpath default import -> symbol is the subpath's last segment ('merge'), not 'default'.
import merge2 from 'lodash/merge';
// Named import FROM a subpath -> symbol is still the original name ('debounce'), not subpath-derived.
import { debounce as dsub } from 'lodash/fp';
// Side-effect import -> symbol null.
import 'lodash/noop';
// Re-export forms.
export * from 'lodash';
export { debounce as dd } from 'lodash';
// Destructured require, with and without aliasing.
const { merge: dm } = require('lodash');
const { debounce: db2 } = require('lodash');
// Plain require, whole module bound to an identifier.
const whole = require('lodash');
// Plain require of a subpath, whole (sub)module bound to an identifier.
const sub = require('lodash/merge');
// Dynamic import, string literal only.
const dyn = import('lodash');
// Dynamic import of a subpath.
const dynSub = import('lodash/merge');

def1();
def1.pick();
m();
debounce();
ns.merge();
ns.other;
merge2();
dsub();
dm();
db2();
whole();
whole.pick();
sub();

// Same line, two calls of the same binding -> dedupes to one usage record.
function twice() { m(); m(); }
