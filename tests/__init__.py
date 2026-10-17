

def load_tests(loader, standard_tests, pattern):
    """`unittest discover -s tests -t .` runs these modules only; tests/acceptance is a pytest suite."""
    from . import test_core, test_fixes, test_ops, test_settings
    suite = type(standard_tests)()
    for mod in (test_core, test_fixes, test_ops, test_settings):
        suite.addTests(loader.loadTestsFromModule(mod))
    return suite
