"""确保项目根目录始终在 sys.path 中，便于直接 `uv run pytest`。"""
import os
import sys
import tempfile

# Set before test-module collection: importing the API seeds its database.
# Keep resets and all API mutations away from the application's data directory.
_test_data = tempfile.TemporaryDirectory(prefix="gunreg-tests-", ignore_cleanup_errors=True)
os.environ["GUNREG_DATA_DIR"] = _test_data.name

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def pytest_unconfigure(config):
    module = sys.modules.get("webapp.main")
    if module is not None:
        module.SYSTEM.repo.db.close()
        module.SYSTEM.view.db.close()
    _test_data.cleanup()
