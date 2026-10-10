"""源码包：把正在运行的 vps_probe 打成 tar.gz，供子服务器从面板下载

文件顺序、时间戳、权限都是固定的，同样的代码总是得到同样的 SHA-256。
"""
import gzip
import hashlib
import io
import os
import tarfile


def make_bundle(pkg_dir):
    """返回 (tar.gz 内容, SHA-256)"""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for root, dirs, files in os.walk(pkg_dir):
                dirs[:] = sorted(d for d in dirs if d != "__pycache__")
                for name in sorted(files):
                    if name.endswith((".pyc", ".pyo")):
                        continue
                    path = os.path.join(root, name)
                    with open(path, "rb") as f:
                        data = f.read()
                    info = tarfile.TarInfo("vps_probe/" + os.path.relpath(path, pkg_dir).replace(os.sep, "/"))
                    info.size, info.mode, info.mtime = len(data), 0o644, 0
                    tar.addfile(info, io.BytesIO(data))
    data = buf.getvalue()
    return data, hashlib.sha256(data).hexdigest()
