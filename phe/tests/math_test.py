#!/usr/bin/env python

"""Unittest for maths involving the paillier module."""

# This file is part of pyphe.
#
# Pyphe is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Pyphe is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with pyphe.  If not, see <http://www.gnu.org/licenses/>.

import unittest
import numpy as np
from phe import paillier
import test


class PaillierTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Could move this into setUpModule() if we get too many classes
        cls.public_key, cls.private_key = paillier.generate_paillier_keypair()

        enc_flt = cls.public_key.encrypt

        cls.vec4_1_non_neg ,cls.vec4_2 =LoadData()

        cls.e_vec4_1 = [enc_flt(x) for x in cls.vec4_1_non_neg]
        cls.e_vec4_2 = [enc_flt(x) for x in cls.vec4_2]



class ArithmeticTest(PaillierTest):

    def testMean(self):
        # Check that we can take an average as good as numpy
        e_mean4_1 = np.mean(self.e_vec4_1)
        self.assertAlmostEqual(np.mean(self.vec4_1_non_neg),
                               self.private_key.decrypt(e_mean4_1))

        emean4_2 = np.mean(self.e_vec4_2)
        self.assertAlmostEqual(np.mean(self.vec4_2),
                               self.private_key.decrypt(emean4_2))

    def testDot(self):
        # Check that our dot product is as good as numpy's
        e_dot_4_2_4_1 = np.dot(self.e_vec4_2, self.vec4_1_non_neg)
        self.assertAlmostEqual(np.dot(self.vec4_2, self.vec4_1_non_neg),
                               self.private_key.decrypt(e_dot_4_2_4_1))

def gram(list):
    len = np.shape(list)[0]
    Tlist = []
    gramMetric = []
    for i in list:
        Tlist.append(np.transpose(i))
    for i in range(len):
        for j in range(len):
            gramMetric.append(np.dot(list[i],Tlist[j]))
    return np.reshape(gramMetric,[len,len])

def  add_product(a,b):
    alen = len(a)
    blen = len(b)
    addAB=[]
    ABline=[]
    if(alen<blen):
        a=lena2b(a,alen,blen)
    elif(alen>blen):
        b=lena2b(b,blen,alen)
    length=max(alen,blen)
    for i in range(0,length):
        for j in range(0,length):
            ABline.append(a[i][j]+(b[i][j]))
        addAB.append(ABline)
        ABline=[]
    return addAB


def lena2b(a,alen,blen):
    ilist = []
    new_a = []
    for i in range(0, blen):
        for j in range(0, blen):
            if i < alen:
                if j < alen:
                    ilist.append(a[i][j])
                else:
                    zero = 0
                    ilist.append(zero)
            else:
                zero = 0
                ilist.append(zero)
        new_a.append(ilist)
        ilist = []
    return new_a

def array2list(array):
    L=[]
    for i in array:
        for j in i:
            L.append(int(j))
    return L

def LoadData():
    array1 = gram([[12, 2], [3, 4], [7, 8]])
    array2 = gram([[5, 3], [7, 9]])
    array=[[182, 106, 100], [106, 155, 53], [100, 53, 113]]
    return array2list(add_product(array1,array2)),array2list(array)

if __name__ == '__main__':
    unittest.main()
