#!/usr/bin/env python3
"""
Build the DeepJS Burp Suite extension → burp/build/deepjs-burp.jar

    python burp/build.py                       # compile against the Montoya API from Maven Central
    python burp/build.py --api burpsuite.jar   # …or against a local Burp / montoya-api jar (no download)
    python burp/build.py --test                # also run the harness against the built jar

Needs a JDK 17+ (`javac`, `jar`) on PATH or in JAVA_HOME. The repository's
build.gradle produces the same jar; this script exists so that the extension
can be built and tested with nothing but a JDK and Python.

The jar holds the extension's classes and, under engine/, the analysis engine
(this repository's `deepjs` package). The Burp API is provided by Burp at run
time and is not packaged.
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import shutil
import subprocess
import sys
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
API_VERSION = "2023.12.1"       # oldest API the code is written against — loads in every Burp since then
API_URL = (f"https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/"
           f"{API_VERSION}/montoya-api-{API_VERSION}.jar")


def tool(name: str) -> str:
    home = os.environ.get("JAVA_HOME")
    if home:
        candidate = os.path.join(home, "bin", name + (".exe" if os.name == "nt" else ""))
        if os.path.isfile(candidate):
            return candidate
    found = shutil.which(name)
    if not found:
        sys.exit(f"build: `{name}` not found — install a JDK 17+ and put it on PATH or set JAVA_HOME")
    return found


def run(cmd, **kw) -> None:
    print("  $", " ".join(f'"{c}"' if " " in c else c for c in cmd))
    result = subprocess.run(cmd, **kw)
    if result.returncode != 0:
        sys.exit(result.returncode)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api", metavar="JAR", help="montoya-api jar or burpsuite.jar to compile against")
    ap.add_argument("--out", metavar="DIR", default=os.path.join(HERE, "build"), help="output directory")
    ap.add_argument("--test", action="store_true", help="compile and run burp/test (the harness)")
    args = ap.parse_args()

    out = os.path.abspath(args.out)
    classes, test_classes = os.path.join(out, "classes"), os.path.join(out, "test-classes")
    for d in (classes, test_classes):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)

    api = args.api
    if not api:
        api = os.path.join(out, f"montoya-api-{API_VERSION}.jar")
        if not os.path.isfile(api):
            print(f"  downloading the Burp Montoya API {API_VERSION} from Maven Central")
            urllib.request.urlretrieve(API_URL, api)
    api = os.path.abspath(api)

    sources = sorted(glob.glob(os.path.join(HERE, "src", "deepjs", "burp", "*.java")))
    # -implicit:none: burpsuite.jar ships the API as *source*; without this javac would
    # compile those sources into our output directory.
    run([tool("javac"), "--release", "17", "-encoding", "UTF-8", "-implicit:none", "-cp", api, "-d", classes, *sources])

    # The engine travels with the extension: one version, nothing to install with pip.
    engine = os.path.join(classes, "engine", "deepjs")
    os.makedirs(engine)
    package = os.path.join(ROOT, "deepjs")
    for name in sorted(os.listdir(package)):
        if name.endswith(".py"):
            shutil.copyfile(os.path.join(package, name), os.path.join(engine, name))
    with open(os.path.join(package, "__init__.py"), encoding="utf-8") as fh:
        engine_version = re.search(r'__version__\s*=\s*"([^"]+)"', fh.read()).group(1)
    with open(os.path.join(HERE, "src", "deepjs", "burp", "DeepJsExtension.java"), encoding="utf-8") as fh:
        extension_version = re.search(r'String VERSION\s*=\s*"([^"]+)"', fh.read()).group(1)
    if engine_version != extension_version:
        sys.exit(f"build: the extension says {extension_version} but the engine is {engine_version} — keep them equal")

    jar = os.path.join(out, "deepjs-burp.jar")
    if os.path.exists(jar):
        os.remove(jar)
    # Package only our own classes. A copy of the Burp API inside the jar would be
    # loaded by the extension's class loader and no longer match Burp's own types.
    run([tool("jar"), "--create", "--file", jar, "-C", classes, "deepjs", "-C", classes, "engine"])
    with zipfile.ZipFile(jar) as zf:
        names = zf.namelist()
    foreign = [n for n in names if n.endswith(".class") and not n.startswith("deepjs/burp/")]
    if foreign:
        sys.exit(f"build: the jar contains classes that are not ours: {foreign[:3]} …")
    if "engine/deepjs/__main__.py" not in names:
        sys.exit("build: the engine is missing from the jar")
    print(f"  built {jar} ({os.path.getsize(jar) // 1024} KB, extension and engine {engine_version})")

    if args.test:
        tests = sorted(glob.glob(os.path.join(HERE, "test", "deepjs", "burp", "*.java")))
        cp = os.pathsep.join([classes, api])
        run([tool("javac"), "--release", "17", "-encoding", "UTF-8", "-implicit:none", "-cp", cp, "-d", test_classes, *tests])
        cp = os.pathsep.join([classes, test_classes, api])
        # Run from the output directory, where there is no `deepjs` package to import:
        # the engine can then only come from the jar, as it does inside Burp.
        run([tool("java"), "-Djava.awt.headless=true", f"-Ddeepjs.jar={jar}", "-cp", cp, "deepjs.burp.Harness",
             sys.executable], cwd=out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
