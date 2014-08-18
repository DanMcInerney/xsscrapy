from setuptools import setup, find_packages

setup(
    name='queuelib',
    version='1.2.2',
    license='BSD',
    description='Collection of persistent (disk-based) queues',
    long_description=open('README.rst').read(),
    author='Scrapy project',
    author_email='info@scrapy.org',
    url='https://github.com/scrapy/queuelib',
    packages=find_packages(),
    platforms=['Any'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
    ]
)
