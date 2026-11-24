import builtins
import symtable
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMPLICIT = set(dir(builtins)) | {'__file__', '__name__', '__doc__', '__spec__', '__builtins__'}


def sources():
    yield from ROOT.glob('install*.py')
    for folder in ('companion', 'companion_web', 'assets'):
        yield from (ROOT / folder).rglob('*.py')


def undefined_names(path):
    """Global names a module reads but never defines or imports at module level.

    install-operations.py imported `secrets` inside main() but used it in install(),
    which only ran on a fresh server; this catches that class of error without running it.
    """
    module = symtable.symtable(path.read_text(encoding='utf-8'), str(path), 'exec')
    defined = {symbol.get_name() for symbol in module.get_symbols()
               if symbol.is_assigned() or symbol.is_imported() or symbol.is_namespace()} | IMPLICIT
    missing = set()
    pending = [module]
    while pending:
        table = pending.pop()
        pending.extend(table.get_children())
        for symbol in table.get_symbols():
            if symbol.is_referenced() and (symbol.is_global() or table is module) and symbol.get_name() not in defined:
                missing.add(symbol.get_name())
    return missing


class SourceNameTests(unittest.TestCase):
    def test_no_undefined_global_names(self):
        for path in sources():
            with self.subTest(path=path.relative_to(ROOT).as_posix()):
                self.assertEqual(undefined_names(path), set())


if __name__ == '__main__':
    unittest.main()
