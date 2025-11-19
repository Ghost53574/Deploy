#!/usr/bin/env python3
"""
Central test runner for the `tests/` directory.

This file centralizes test initialization (project root on sys.path)
so individual test modules don't need to insert the path themselves.

Run with:
    python tests/run_tests.py
"""
import os
import sys

# Ensure repo root is on sys.path so test modules can `import modules`.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

tests = []

def main():
    failures = 0
    errors = 0

    for root, _, files in os.walk(os.path.dirname(__file__)):
        for f in files:
            if f.startswith("test_") and f.endswith(".py"):
                rel_dir = os.path.relpath(root, os.path.dirname(__file__))
                mod_name = f[:-3]  # strip .py
                if rel_dir != ".":
                    mod_name = f"{rel_dir.replace(os.sep, '.')}.{mod_name}"
                tests.append(mod_name)

    import importlib
    for test in tests:
        module = importlib.import_module(f"tests.{test}")
        module_name = module.__name__
        print(f"Running tests in module: {module_name}")
        test_funcs = [
            getattr(module, name)
            for name in dir(module)
            if name.startswith("test_") and callable(getattr(module, name))
        ]
        try:
            if not test_funcs:
                print(f"[ERROR] {module_name} has no run_all_tests() and no test_* functions")
                errors += 1
            else:
                for func in test_funcs:
                    fname = f"{module_name}.{func.__name__}"
                    try:
                        func()
                        print(f"[PASS] {fname}")
                    except AssertionError as e:
                        print(f"[FAIL] {fname}: {e}")
                        failures += 1
                    except SystemExit:
                        raise
                    except Exception as e:
                        print(f"[ERROR] {fname}: {e}")
                        errors += 1
        except SystemExit:
            raise
        except AssertionError as e:
            print(f"[FAIL] {module_name}.run_all_tests: {e}")
            failures += 1
        except Exception as e:
            print(f"[ERROR] {module_name}.run_all_tests: {e}")
            errors += 1

    print(f"\nSummary: failures={failures}, errors={errors}")
    if errors:
        raise SystemExit(2)
    if failures:
        raise SystemExit(1)
    print("All tests passed.")


if __name__ == '__main__':
    main()
