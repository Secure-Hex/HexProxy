from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("hexproxy")
except PackageNotFoundError:
    # Cuando se ejecuta en desarrollo sin instalar
    __version__ = "0.0.0"
