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

package org.iso200082.tests.m4;


import java.math.BigInteger;

import org.iso200082.common.ecc.num.FqBigInteger;
import org.iso200082.tests.TestData;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

/**
 * Note that more complete testing is done in TestLib. Here, only
 * special M4 cases are tested. 
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 */
public class TestMechanism4BigInteger extends TestMechanism4<BigInteger>
{
  
  @Before
  public void setUp()
  {
    Fq = new FqBigInteger(rnd, TestData.M4.getBeuchatCurveParameters().get("q"));
    identifier  = "m4-nr-bigint-mixed";
  }
  
  @Override
  @Test
  @Ignore
  public void testProtocolWithBeuchatDataNonJpbc()
  {
    super.testProtocolWithBeuchatDataNonJpbc();
  }
  
  @Override
  @Test
  public void testCreate()
  {
    super.testCreate();
  }
  
  @Override
  @Test
  public void testJoin()
  {
    super.testJoin();
  }
  
  @Override
  @Test
  public void testJoinSignVerify()
  {
    super.testJoinSignVerify();
  }
  
  @Override
  @Test
  public void testSign()
  {
    super.testSign();
  }
  
  @Override
  @Test
  public void testSignPartiallyPrecomputed()
  {
    super.testSignPartiallyPrecomputed();
  }
  
  @Override
  @Test
  public void testSignFullyPrecomputed()
  {
    super.testSignFullyPrecomputed();
  }
  
  @Override
  @Test
  public void testVerify()
  {
    super.testVerify();
  }
    
}
