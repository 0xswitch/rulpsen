from setuptools import find_packages, setup

setup(name='rulpsen',
      version='1.1',
      description='small https proxy.',
      url='https://github.com/0xswitch/rulpsen',
      author='switch',
      author_email='switch@switch.re',
      license='WTFPL',
      python_requires='>=3',
      packages=find_packages(),
      zip_safe=False)