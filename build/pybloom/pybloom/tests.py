import os
import doctest
import unittest
import random
import tempfile
from pybloom import BloomFilter, ScalableBloomFilter
from unittest import TestSuite

def additional_tests():
    proj_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    readme_fn = os.path.join(proj_dir, 'README.txt')
    suite = TestSuite([doctest.DocTestSuite('pybloom.pybloom')])
    if os.path.exists(readme_fn):
        suite.addTest(doctest.DocFileSuite(readme_fn, module_relative=False))
    return suite

class TestUnionIntersection(unittest.TestCase):
    def test_union(self):
        bloom_one = BloomFilter(100, 0.001)
        bloom_two = BloomFilter(100, 0.001)
        chars = [chr(i) for i in range(97, 123)]
        for char in chars[len(chars)/2:]:
            bloom_one.add(char)
        for char in chars[:len(chars)/2]:
            bloom_two.add(char)
        new_bloom = bloom_one.union(bloom_two)
        for char in chars:
            self.assert_(char in new_bloom)

    def test_intersection(self):
        bloom_one = BloomFilter(100, 0.001)
        bloom_two = BloomFilter(100, 0.001)
        chars = [chr(i) for i in range(97, 123)]
        for char in chars:
            bloom_one.add(char)
        for char in chars[:len(chars)/2]:
            bloom_two.add(char)
        new_bloom = bloom_one.intersection(bloom_two)
        for char in chars[:len(chars)/2]:
            self.assert_(char in new_bloom)
        for char in chars[len(chars)/2:]:
            self.assert_(char not in new_bloom)

    def test_intersection_capacity_fail(self):
        bloom_one = BloomFilter(1000, 0.001)
        bloom_two = BloomFilter(100, 0.001)
        def _run():
            new_bloom = bloom_one.intersection(bloom_two)
        self.assertRaises(ValueError, _run)

    def test_union_capacity_fail(self):
        bloom_one = BloomFilter(1000, 0.001)
        bloom_two = BloomFilter(100, 0.001)
        def _run():
            new_bloom = bloom_one.union(bloom_two)
        self.assertRaises(ValueError, _run)

    def test_intersection_k_fail(self):
        bloom_one = BloomFilter(100, 0.001)
        bloom_two = BloomFilter(100, 0.01)
        def _run():
            new_bloom = bloom_one.intersection(bloom_two)
        self.assertRaises(ValueError, _run)

    def test_union_k_fail(self):
        bloom_one = BloomFilter(100, 0.01)
        bloom_two = BloomFilter(100, 0.001)
        def _run():
            new_bloom = bloom_one.union(bloom_two)
        self.assertRaises(ValueError, _run)

class Serialization(unittest.TestCase):
    SIZE = 12345
    EXPECTED = set([random.randint(0, 10000100) for _ in xrange(SIZE)])

    def test_serialization(self):
        for klass, args in [(BloomFilter, (self.SIZE,)),
                            (ScalableBloomFilter, ())]:
            filter = klass(*args)
            for item in self.EXPECTED:
                filter.add(item)

            # It seems bitarray is finicky about the object being an
            # actual file, so we can't just use StringIO. Grr.
            f = tempfile.TemporaryFile()
            filter.tofile(f)
            del filter

            f.seek(0)
            filter = klass.fromfile(f)

            for item in self.EXPECTED:
                self.assert_(item in filter)

if __name__ == '__main__':
    unittest.main()
