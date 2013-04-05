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


import java.security.SecureRandom;
import java.util.Random;

import junit.framework.Assert;

import org.iso200082.common.Hash;
import org.iso200082.common.ecc.api.AsymmetricPairing;
import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.tests.TestData;
import org.junit.BeforeClass;

/**
 * Simple tests whether the hash algorithms as shown in Annex B work as
 * expected
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 */
public class TestHash<P>
{  
  protected static Random rnd = new SecureRandom();
  
  protected Fq<P> Fq;
  
  @BeforeClass
  public static void init()
  {
    rnd.setSeed(System.currentTimeMillis());
  }
    
  public void testHashingToAFieldElement()
  {    
    AsymmetricPairing<P> ate = TestData.M4.getBeuchatPairingData(rnd, Fq);

    try{
      for(int i = 0; i < 150; i++)
      {
        Point<FqElement<P>, Fq<P>> pt = ate.getG1().getRandomElement();
        FqElement<P> v = Hash.HBS2PF2("SHA-512", pt.toByteArray(), Fq);
        Assert.assertNotNull(v);
      }
    }
    catch(Exception e)
    {
      Assert.fail("Exception = bad.");
      e.printStackTrace();
    }
  }
  
  public void testHashingToAPoint()
  {
    AsymmetricPairing<P> ate = TestData.M4.getBeuchatPairingData(rnd, Fq);
  
    try{
      for(int i = 0; i < 150; i++)
      {
        byte[] array = new byte[50];
        rnd.nextBytes(array);
        Point<FqElement<P>, Fq<P>> pt = 
          Hash.HBS2ECP("SHA-512", array, ate.getG1());
        Assert.assertFalse(pt.isInfinite());
      }
    }
    catch(Exception e)
    {
      Assert.fail("Exception = bad.");
      e.printStackTrace();
    }
  }

}
