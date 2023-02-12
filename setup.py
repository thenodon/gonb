from os.path import dirname, join

from setuptools import setup, find_packages


def read(fname):
    return open(join(dirname(__file__), fname)).read()


setup(
    name='gonb',
    setuptools_git_versioning={
        "template": "{tag}",
        "dev_template": "{tag}.dev{ccount}",
        "dirty_template": "{tag}.post{ccount}+git.{sha}.dirty",
        "starting_version": "0.0.1",
        "version_callback": None,
        "version_file": None,
        "count_commits_from_version_file": False,
        "branch_formatter": None
    },
    setup_requires=['setuptools-git-versioning'],
    packages=find_packages(),
    author='thenodon',
    author_email='aha@ingby.co,',
    url='https://github.com/thenodon/gonb',
    license='Apache Software License (http://www.apache.org/licenses/LICENSE-2.0)',
    include_package_data=True,
    zip_safe=False,
    description='A Grafana onboarding tool',
    install_requires=read('requirements.txt').split(),
    python_requires='>=3.8',
)