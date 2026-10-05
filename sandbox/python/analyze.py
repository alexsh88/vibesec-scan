#!/usr/bin/env python3
"""Offline, read-only "who uses which package API" analyzer for Python repos.

Runs with no network access, read-only /src (and optional read-only /deps). Stdlib only. Never
imports, execs, unpickles, or otherwise runs any code from the repo being scanned -- it only
parses syntax trees via `ast.parse`.

See ../USAGES.md for the input/output schema and documented behavior/limitations.
"""
import ast
import json
import os
import sys

SKIP_DIRS = {'.git', 'venv', '.venv', 'site-packages', 'node_modules', 'build', 'dist', '__pycache__'}
DEFAULT_MAX_FILES = 20_000
DEFAULT_MAX_FILE_BYTES = 1_048_576
MAX_USAGES = 200_000


def parse_args(argv):
    opts = {'src': '/src', 'deps': '/deps', 'in': '/in/packages.json', 'out': '/out/usages.json'}
    for arg in argv:
        for key in ('src', 'deps', 'in', 'out'):
            prefix = '--' + key + '='
            if arg.startswith(prefix):
                opts[key] = arg[len(prefix):]
    return opts


def fail(message):
    sys.stderr.write('analyze.py: ' + message + '\n')
    sys.exit(2)


def read_input(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            raw = f.read()
    except OSError as e:
        fail('cannot read input {}: {}'.format(path, e))
        return None
    try:
        data = json.loads(raw)
    except ValueError as e:
        fail('invalid input JSON at {}: {}'.format(path, e))
        return None
    if not isinstance(data, dict) or not isinstance(data.get('packages'), list):
        fail('invalid input JSON at {}: missing "packages" array'.format(path))
        return None
    max_files = data.get('maxFiles')
    if not isinstance(max_files, (int, float)) or isinstance(max_files, bool):
        max_files = DEFAULT_MAX_FILES
    max_file_bytes = data.get('maxFileBytes')
    if not isinstance(max_file_bytes, (int, float)) or isinstance(max_file_bytes, bool):
        max_file_bytes = DEFAULT_MAX_FILE_BYTES
    return {
        'ecosystem': data.get('ecosystem', 'PyPI'),
        'packages': data['packages'],
        'maxFiles': int(max_files),
        'maxFileBytes': int(max_file_bytes),
    }


def to_posix(path):
    return path.replace(os.sep, '/')


def collect_files(root, max_file_bytes, out, errors):
    """Recursively collects candidate *.py files under `root`, never following symlinks."""
    try:
        names = sorted(os.listdir(root))
    except OSError as e:
        errors.append('readdir failed: {}: {}'.format(root, e))
        return
    for name in names:
        full = os.path.join(root, name)
        if os.path.islink(full):
            continue  # never follow symlinks
        is_dir = os.path.isdir(full)
        if is_dir:
            if name in SKIP_DIRS:
                continue
            collect_files(full, max_file_bytes, out, errors)
            continue
        if not os.path.isfile(full):
            continue
        if not name.endswith('.py'):
            continue
        try:
            size = os.path.getsize(full)
        except OSError:
            continue
        if size > max_file_bytes:
            continue  # oversized: skipped silently, not an error
        out.append(full)


def match_package(module, packages):
    """module -> {'pkgName', 'importName', 'remainder'} | None. Longest matching importName wins."""
    best = None
    for pkg in packages:
        for import_name in pkg.get('importNames') or []:
            if module == import_name:
                if best is None or len(import_name) > len(best['importName']):
                    best = {'pkgName': pkg['name'], 'importName': import_name, 'remainder': None}
            elif module.startswith(import_name + '.'):
                if best is None or len(import_name) > len(best['importName']):
                    remainder = module[len(import_name) + 1:]
                    best = {'pkgName': pkg['name'], 'importName': import_name, 'remainder': remainder}
    return best


def resolve_chain(node):
    """Given an ast.Attribute, returns (root_name, [attr, ...]) root-to-outer, or None if the
    base of the chain isn't a plain Name (e.g. a call result or subscript)."""
    parts = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if not isinstance(cur, ast.Name):
        return None
    parts.reverse()
    return cur.id, parts


def analyze_file(tree, packages):
    usages = []
    bindings = {}  # localName -> {'package', 'kind': 'named'|'whole', 'symbol'?, 'suffix'?}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                module = alias.name
                match = match_package(module, packages)
                if not match:
                    continue
                line = getattr(alias, 'lineno', node.lineno)
                usages.append((match['pkgName'], line, None, 'import'))
                if alias.asname:
                    bindings[alias.asname] = {'package': match['pkgName'], 'kind': 'whole', 'suffix': []}
                else:
                    root = module.split('.')[0]
                    suffix = module.split('.')[1:]
                    bindings[root] = {'package': match['pkgName'], 'kind': 'whole', 'suffix': suffix}
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                continue  # relative import: local module, never a third-party package
            module = node.module
            if not module:
                continue
            match = match_package(module, packages)
            if not match:
                continue
            for alias in node.names:
                if alias.name == '*':
                    continue  # star import: cannot resolve statically what landed in scope
                orig_name = alias.name
                local_name = alias.asname or alias.name
                line = getattr(alias, 'lineno', node.lineno)
                usages.append((match['pkgName'], line, orig_name, 'import'))
                bindings[local_name] = {'package': match['pkgName'], 'kind': 'named', 'symbol': orig_name}

    if not bindings:
        return usages

    called_ids = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            called_ids.add(id(node.func))

    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            binding = bindings.get(node.id)
            if binding and binding['kind'] == 'named' and id(node) in called_ids:
                usages.append((binding['package'], node.lineno, binding['symbol'], 'call'))
        elif isinstance(node, ast.Attribute):
            chain = resolve_chain(node)
            if not chain:
                continue
            root, parts = chain
            binding = bindings.get(root)
            if not binding or binding['kind'] != 'whole':
                continue
            suffix = binding['suffix']
            if len(parts) != len(suffix) + 1 or parts[:len(suffix)] != suffix:
                continue
            symbol = parts[-1]
            kind = 'call' if id(node) in called_ids else 'member'
            usages.append((binding['package'], node.lineno, symbol, kind))

    return usages


def main(argv):
    opts = parse_args(argv)
    input_data = read_input(opts['in'])
    packages = [
        {
            'name': p['name'],
            'importNames': [n for n in p['importNames'] if isinstance(n, str)] if isinstance(p.get('importNames'), list) else [],
        }
        for p in input_data['packages']
        if isinstance(p, dict) and isinstance(p.get('name'), str)
    ]

    errors = []
    candidates = []
    collect_files(opts['src'], input_data['maxFileBytes'], candidates, errors)
    candidates.sort(key=lambda p: to_posix(os.path.relpath(p, opts['src'])))

    files = candidates
    if len(files) > input_data['maxFiles']:
        files = files[:input_data['maxFiles']]
        errors.append('file list capped at {} files'.format(input_data['maxFiles']))

    usage_map = {}
    files_scanned = 0
    for abs_path in files:
        rel_path = to_posix(os.path.relpath(abs_path, opts['src']))
        try:
            with open(abs_path, 'r', encoding='utf-8', errors='replace') as f:
                text = f.read()
        except OSError as e:
            errors.append('{}: read failed: {}'.format(rel_path, e))
            continue
        try:
            tree = ast.parse(text, filename=abs_path)
        except SyntaxError as e:
            errors.append('{}: syntax error: {} (line {})'.format(rel_path, e.msg, e.lineno))
            continue
        except (RecursionError, MemoryError) as e:
            errors.append('{}: too deeply nested to parse ({})'.format(rel_path, type(e).__name__))
            continue
        except ValueError as e:
            errors.append('{}: parse failed: {}'.format(rel_path, e))
            continue
        files_scanned += 1
        try:
            file_usages = analyze_file(tree, packages)
        except (RecursionError, MemoryError) as e:
            errors.append('{}: too deeply nested to analyze ({})'.format(rel_path, type(e).__name__))
            continue
        except Exception as e:  # noqa: BLE001 - one bad file must never abort the scan
            errors.append('{}: analysis failed: {}'.format(rel_path, e))
            continue
        for pkg_name, line, symbol, kind in file_usages:
            key = (rel_path, line, pkg_name, symbol, kind)
            if key not in usage_map:
                usage_map[key] = {'package': pkg_name, 'file': rel_path, 'line': line, 'symbol': symbol, 'kind': kind}

    usages = sorted(
        usage_map.values(),
        key=lambda u: (u['file'], u['line'], u['package'], '' if u['symbol'] is None else u['symbol'], u['kind']),
    )
    if len(usages) > MAX_USAGES:
        usages = usages[:MAX_USAGES]
        errors.append('usages capped at {}'.format(MAX_USAGES))

    output = {'version': 1, 'usages': usages, 'filesScanned': files_scanned, 'errors': errors}
    try:
        out_dir = os.path.dirname(opts['out'])
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(opts['out'], 'w', encoding='utf-8') as f:
            json.dump(output, f)
    except OSError as e:
        fail('cannot write output {}: {}'.format(opts['out'], e))


if __name__ == '__main__':
    main(sys.argv[1:])
