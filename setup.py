from setuptools import Extension
from setuptools import setup

setup(
    ext_modules=[
        Extension(
            '_pylibfuzzer',
            ['fuzz_wrappers/libfuzzer/pylibfuzzer.c'],
            # py_limited_api=True,
            # define_macros=[('Py_LIMITED_API', None)],
        ),
    ],
)