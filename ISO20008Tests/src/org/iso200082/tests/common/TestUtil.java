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
import java.security.SecureRandom;
import java.util.Arrays;

import junit.framework.Assert;

import org.iso200082.common.util.IntegerUtil;
import org.iso200082.common.util.Util;
import org.junit.Test;

/**
 * Utility-Tests
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 */
public class TestUtil
{
  /** RNG instance */
  private static SecureRandom rnd = new SecureRandom();

  static {
    rnd.setSeed(System.currentTimeMillis());
  }
  
  @Test
  public void testIntegerConversion()
  {
    
    for(int i = 0; i < 100; i++) {
      BigInteger bi = new BigInteger((int) Math.floor(Math.random() * 1000),
                                     rnd);
      Assert.assertEquals(bi, IntegerUtil.bs2ip(IntegerUtil.i2bsp(bi)));
    }
  }
  
  @Test
  public void testArrayConcatenation()
  {
    byte[] test1 = new byte[] { (byte) 0x1, (byte) 0x0  };
    byte[] test2 = new byte[] { (byte) 0xFF };
    byte[] test3 = new byte[] { (byte) 0x0  };
    byte[] test4 = new byte[] { (byte) 0xAE };
    byte[] test5 = new byte[] { (byte) 0xDE, (byte) 0xAD,
                                (byte) 0xBE, (byte) 0xEF };
    
    byte[] merged = Util.concatArrays(test1, test2, test3, test4, test5);

    Assert.assertTrue(Arrays.equals(Util.extractBytes(merged, 0, 2),
                                    test1));
    Assert.assertEquals(merged[2], test2[0]);
    Assert.assertEquals(merged[3], test3[0]);
    Assert.assertEquals(merged[4], test4[0]);
    Assert.assertTrue(Arrays.equals(Util.extractBytes(merged, 5, 4),
                                    test5));
  }
  
  @Test
  public void testArrayBigIntegerConcatenation()
  {
    BigInteger b1 = BigInteger.valueOf(1);
    BigInteger b2 = BigInteger.valueOf(0);
    BigInteger b3 = BigInteger.valueOf(255);
    BigInteger b4 = BigInteger.valueOf(128);
    
    byte[] merged = Util.concatAsArrays(b1, b2, b3, b4);

    BigInteger b1t = new BigInteger(1, Util.extractBytes(merged, 0, 1));
    BigInteger b2t = new BigInteger(1, Util.extractBytes(merged, 1, 1));
    BigInteger b3t = new BigInteger(1, Util.extractBytes(merged, 2, 1));
    BigInteger b4t = new BigInteger(1, Util.extractBytes(merged, 3, 1));
    
    Assert.assertEquals(b1, b1t);
    Assert.assertEquals(b2, b2t);
    Assert.assertEquals(b3, b3t);
    Assert.assertEquals(b4, b4t);
  }
  
  @Test
  public void testXgcd()
  {
    BigInteger a, b;
    for(int i = 0; i < 150; i++)
    {
      a = new BigInteger(1024, rnd);
      b = new BigInteger(1024, rnd);
      BigInteger[] cf = IntegerUtil.xgcd(a, b);
      Assert.assertEquals(a.gcd(b),
                          a.multiply(cf[0]).add(b.multiply(cf[1])));
    }
  }
  
  @Test
  public void testSqrt()
  {
    BigInteger a, a2;
    for(int i = 0; i < 150; i++)
    {
      a  = new BigInteger(1024, rnd);
      a2 = a.multiply(a);
      Assert.assertEquals(a, IntegerUtil.sqrt(a2));
    }
  }

}
