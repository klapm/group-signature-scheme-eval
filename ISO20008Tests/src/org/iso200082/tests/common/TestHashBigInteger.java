/*
 * This file is part of an unofficial ISO20008-2.2 sample implementation to
 * evaluate certain schemes for their applicability on Android-based mobile
 * devices. The source is licensed under the modified 3-clause BSD license,
 * see the readme.
 * 
 * The code was published in conjunction with the publication called 
 * "Group Signatures on Mobile Devices: Practical Experiences" by
 * Potzmader, Winter, Hein, Hanser, Teufl and Chen
 */

package org.iso200082.tests.common;


import java.math.BigInteger;

import org.iso200082.common.ecc.num.FqBigInteger;
import org.iso200082.tests.TestData;
import org.junit.Before;
import org.junit.Test;

/**
 * Simple tests whether the hash algorithms as shown in Annex B work as
 * expected
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 */
public class TestHashBigInteger extends TestHash<BigInteger>
{  
  
  @Before
  public void setUp()
  {
    Fq = new FqBigInteger(rnd, TestData.M4.getBeuchatCurveParameters().get("q"));
  }
  
  @Override
  @Test
  public void testHashingToAFieldElement()
  {
    super.testHashingToAFieldElement();
  }
  
  @Override
  @Test
  public void testHashingToAPoint()
  {
    super.testHashingToAPoint();
  }

}
