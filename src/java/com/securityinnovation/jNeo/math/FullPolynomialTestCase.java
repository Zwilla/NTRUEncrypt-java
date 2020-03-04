/*
 * **************************************************************************** NTRU Cryptography
 * Reference Source Code
 *
 * <p>Copyright (C) 2009-2016 Security Innovation (SI)
 *
 * <p>SI has dedicated the work to the public domain by waiving all of its rights to the work
 * worldwide under copyright law, including all related and neighboring rights, to the extent
 * allowed by law.
 *
 * <p>This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. You can
 * copy, modify, distribute and perform the work, even for commercial purposes, all without asking
 * permission. You should have received a copy of the creative commons license (CC0 1.0 universal)
 * along with this program. See the license file for more information.
 *
 * <p>*******************************************************************************
 */
package com.securityinnovation.jNeo.math;

import org.junit.Test;
import static org.junit.Assert.*;

import com.securityinnovation.jNeo.ParamSetNotSupportedException;
import com.securityinnovation.jNeo.ntruencrypt.KeyParams;
import com.securityinnovation.testvectors.NtruEncryptTestVector;

public class FullPolynomialTestCase {

  // Test recentering to 0 and to a non-zero value.
  @Test
  public void test_recenterModQ_0() {
    short[] aCoeffs = {1, 2, 3, 4, 5, 6, 7, 8};
    FullPolynomial a = new FullPolynomial(aCoeffs);
    FullPolynomial.recenterModQ(a, 4, 0);
    short[] expectedCoeffs = {1, 2, 3, 0, 1, 2, 3, 0};
    assertArrayEquals(a.p, aCoeffs);
  }

  @Test
  public void test_recenterModQ_2() {
    short[] aCoeffs = {1, 2, 3, 4, 5, 6, 7, 8};
    FullPolynomial a = new FullPolynomial(aCoeffs);
    FullPolynomial.recenterModQ(a, 4, -2);
    short[] expectedCoeffs = {1, -2, -1, 0, 1, -2, -1, 0};
    assertArrayEquals(a.p, aCoeffs);
  }

  // Test convolution without limiting the coefficients
  @Test
  public void test_basic_convolution_x1() {
    short[] aCoeffs = {1, 0, 1, 0};
    short[] bCoeffs = {1, 0, 0, 0}; // f(x) = 1
    FullPolynomial p =
        FullPolynomial.convolution(new FullPolynomial(aCoeffs), new FullPolynomial(bCoeffs));
    assertArrayEquals(aCoeffs, p.p);
  }

  @Test
  public void test_basic_convolution_xX() {
    short[] aCoeffs = {1, 0, 1, 0};
    short[] bCoeffs = {0, 1, 0, 0}; // f(x) = x
    short[] expectedCoeffs = {0, 1, 0, 1};
    FullPolynomial p =
        FullPolynomial.convolution(new FullPolynomial(aCoeffs), new FullPolynomial(bCoeffs));
    assertArrayEquals(expectedCoeffs, p.p);
  }

  @Test
  public void test_basic_convolution_3x_2x2() {
    short[] aCoeffs = {10, 0, 5, 0};
    short[] bCoeffs = {0, 3, 2, 0}; // f(x) = 3x + 2x^2
    short[] expectedCoeffs = {10, 30, 20, 15};
    FullPolynomial p =
        FullPolynomial.convolution(new FullPolynomial(aCoeffs), new FullPolynomial(bCoeffs));
    assertArrayEquals(expectedCoeffs, p.p);
  }

  // Test convolution limiting the coefficients modlulo q.
  // Use samples from the NtruEncrypt test vector paper:
  //  R = r * h (mod q)
  @Test
  public void test_convolution() throws ParamSetNotSupportedException {
    NtruEncryptTestVector[] tests = NtruEncryptTestVector.getTestVectors();
    for (NtruEncryptTestVector test : tests) {
      KeyParams keyParams = KeyParams.getKeyParams(test.oid);
      FullPolynomial r = new FullPolynomial(test.r);
      FullPolynomial h = new FullPolynomial(test.h);
      FullPolynomial R = new FullPolynomial(test.R);

      FullPolynomial out = FullPolynomial.convolution(r, h, keyParams.q);
      assertEquals(out, R);
    }
  }

  // Use samples from the NtruEncrypt test vector paper:
  //  e = R + m' (mod q)
  @Test
  public void test_add() throws ParamSetNotSupportedException {
    NtruEncryptTestVector[] tests = NtruEncryptTestVector.getTestVectors();
    for (NtruEncryptTestVector test : tests) {
      KeyParams keyParams = KeyParams.getKeyParams(test.oid);
      FullPolynomial R = new FullPolynomial(test.R);
      FullPolynomial mP = new FullPolynomial(test.mPrime);
      FullPolynomial e = new FullPolynomial(test.e);

      FullPolynomial out = FullPolynomial.add(R, mP, keyParams.q);
      assertEquals(out, e);
    }
  }

  // Use samples from the NtruEncrypt test vector paper:
  //   m' = M + mask (mod p) centered on 0.
  @Test
  public void test_addAndRecenter() throws ParamSetNotSupportedException {
    NtruEncryptTestVector[] tests = NtruEncryptTestVector.getTestVectors();
    for (NtruEncryptTestVector test : tests) {
      KeyParams keyParams = KeyParams.getKeyParams(test.oid);

      // m' = mask + Mtrin (mod p)
      FullPolynomial mask = new FullPolynomial(test.mask);
      FullPolynomial Mtrin = new FullPolynomial(test.Mtrin);

      FullPolynomial out = FullPolynomial.addAndRecenter(mask, Mtrin, keyParams.p, -1);

      FullPolynomial mP = new FullPolynomial(test.mPrime);
      assertEquals(out, mP);
    }
  }

  // Use samples from the NtruEncrypt test vector paper:
  //  R = e - m' (mod q)
  @Test
  public void test_subtract() throws ParamSetNotSupportedException {
    NtruEncryptTestVector[] tests = NtruEncryptTestVector.getTestVectors();
    for (NtruEncryptTestVector test : tests) {
      KeyParams keyParams = KeyParams.getKeyParams(test.oid);
      FullPolynomial R = new FullPolynomial(test.R);
      FullPolynomial mP = new FullPolynomial(test.mPrime);
      FullPolynomial e = new FullPolynomial(test.e);

      FullPolynomial out = FullPolynomial.subtract(e, mP, keyParams.q);
      assertEquals(out, R);
    }
  }

  // Use samples from the NtruEncrypt test vector paper:
  //   m' - mask = M (mod p) centered on 0.
  @Test
  public void test_subtractAndRecenter() throws ParamSetNotSupportedException {
    NtruEncryptTestVector[] tests = NtruEncryptTestVector.getTestVectors();
    for (NtruEncryptTestVector test : tests) {
      KeyParams keyParams = KeyParams.getKeyParams(test.oid);

      // m' = mask + Mtrin (mod p)
      FullPolynomial mask = new FullPolynomial(test.mask);
      FullPolynomial Mtrin = new FullPolynomial(test.Mtrin);
      FullPolynomial mP = new FullPolynomial(test.mPrime);

      FullPolynomial out = FullPolynomial.subtractAndRecenter(mP, mask, keyParams.p, -1);

      assertEquals(out, Mtrin);
    }
  }

  @Test
  public void test_equals_hashCode() {
    short[] a1Bytes = {0, 1, 2, 3, 4, 5};
    short[] a2Bytes = {0, 1, 2, 3, 4, 5};
    FullPolynomial a1 = new FullPolynomial(a1Bytes);
    FullPolynomial a2 = new FullPolynomial(a2Bytes);
    assertEquals(a1, a2);
    assertEquals(a1.hashCode(), a2.hashCode());

        // Make the polynomials differ
        a2.p[0]++;
        assertFalse(a1.equals(a2));
        assertTrue(a1.hashCode() != a2.hashCode());
    }
}
