"""SecretSync: declarative and safe secret delivery across deployment platforms."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("secretsync-cli")
except PackageNotFoundError:  # editable / source tree without install metadata
    __version__ = "0.0.0"
