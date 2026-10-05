// Scoped package, @scope/pkg — exact import and a recognized subpath.
import x from '@scope/pkg';
import { a as b } from '@scope/pkg/sub';
import xeq = require('@scope/pkg');

x.thing();
b();
xeq();
