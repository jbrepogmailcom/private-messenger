"""Platform-tagged wheels; source installs require the explicitly built backend."""

from pathlib import Path

from setuptools import Distribution, setup
from setuptools.command.build_py import build_py


class NativeDistribution(Distribution):
    def has_ext_modules(self):
        return True


class CheckedBuild(build_py):
    def run(self):
        if not Path("src/private_messenger/_crypto_native.abi3.so").is_file():
            raise RuntimeError("Build the pinned backend first: bash scripts/build_crypto.sh")
        super().run()


setup(distclass=NativeDistribution, cmdclass={"build_py": CheckedBuild})
