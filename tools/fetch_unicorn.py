"""Fetch the exact Unicorn 2.1.4 x64 runtime and its source distribution."""
import hashlib
import io
from pathlib import Path
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
WHEEL = 'https://files.pythonhosted.org/packages/70/3d/de7be9bd1addabe6d8a1369381f8a080400c349850e978689c5e18287957/unicorn-2.1.4-cp37-abi3-win_amd64.whl'
WHEEL_SHA256 = 'd7107500c64ce5c168fbff6bef9485b5db1350050036f4cea568650cf8bdbdf5'
SOURCE = 'https://files.pythonhosted.org/packages/b2/1b/b4248aa8422e86de690cf8e85cf8feae4c33405a097d1ebe71570bdaa6f5/unicorn-2.1.4.tar.gz'
SOURCE_SHA256 = '00567a70e323f749b419cd86bee4f9115beab7ebba32194581c090cbb7c59cff'

def fetch(url, expected):
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError('SHA256 mismatch: ' + url)
    return data

if __name__ == '__main__':
    runtime = ROOT / 'runtime'
    runtime.mkdir(exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(fetch(WHEEL, WHEEL_SHA256))) as wheel:
        (runtime / 'unicorn.dll').write_bytes(wheel.read('unicorn/lib/unicorn.dll'))
    dist = ROOT / 'dist'
    dist.mkdir(exist_ok=True)
    (dist / 'unicorn-2.1.4.tar.gz').write_bytes(fetch(SOURCE, SOURCE_SHA256))
    print('Verified Unicorn runtime and corresponding source downloaded.')
