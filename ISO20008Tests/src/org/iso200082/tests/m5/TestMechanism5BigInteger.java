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

package org.iso200082.tests.m5;


import java.math.BigInteger;

import org.iso200082.common.ecc.num.FqBigInteger;
import org.junit.Before;
import org.junit.Test;

public class TestMechanism5BigInteger extends TestMechanism5<BigInteger>
{
  @Before
  public void setUp()
  {
    identifier = "m5-nr-bigint-affine";
    Fq         = new FqBigInteger(rnd, BigInteger.ONE/* dummy */);
  }
  
  @Override
  @Test
  public void testJoin()
  {
    super.testJoin();
  }
  
  @Override
  @Test
  public void testCreate()
  {
    super.testCreate();
  }
  
  @Override
  @Test
  public void testJoinSampleData()
  {
    super.testJoinSampleData();
  }
  
  @Override
  @Test
  public void testJoinSignVerify()
  {
    super.testJoinSignVerify();
  }
  
  @Override
  @Test
  public void testProtocolRun()
  {
    super.testProtocolRun();
  }
  
  @Override
  @Test
  public void testSign()
  {
    super.testSign();
  }
  
  @Override
  @Test
  public void testSignPrecomputed()
  {
    super.testSignPrecomputed();
  }
  
  @Override
  @Test
  public void testVerify()
  {
    super.testVerify();
  }
  

}
