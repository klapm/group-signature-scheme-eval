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
import java.util.Map;

import org.iso200082.common.ecc.elements.Fq2Element;
import org.iso200082.common.ecc.fields.G1;
import org.iso200082.common.ecc.fields.G2;
import org.iso200082.common.ecc.fields.towerextension.Fq12;
import org.iso200082.common.ecc.fields.towerextension.Fq2;
import org.iso200082.common.ecc.fields.towerextension.Fq6;
import org.iso200082.common.ecc.num.FqBigInteger;
import org.iso200082.common.ecc.num.FqMontgomeryBigInteger;
import org.iso200082.common.util.IntegerUtil;
import org.iso200082.tests.TestData;
import org.junit.Before;
import org.junit.Test;

public class TestECCBigInteger extends TestECC<BigInteger>
{

  @Before
  public void setUp()
  {
    Map<String, BigInteger> p = TestData.M4.getBeuchatCurveParameters();
    q     = p.get("q");
    r     = p.get("r");
    b     = p.get("b");
    t     = p.get("t");
    xi0   = p.get("xi0");
    xi1   = p.get("xi1");
    beta  = p.get("beta");
    cofac = IntegerUtil.TWO.multiply(q).subtract(r);
    
    Fq      = new FqBigInteger(  rnd, q);
    Fq2     = new Fq2<BigInteger>( rnd, Fq.getElementFromComponents(beta));
    FqMont  = new FqMontgomeryBigInteger(  rnd, q);
    Fq2Mont  = new Fq2<BigInteger>(  rnd, FqMont.getElementFromComponents(beta));
    
    Fq2Element<BigInteger> xi = Fq2.getElementFromComponents(xi0, xi1);
    
    Fq6     = new Fq6<BigInteger>( rnd, xi);
    Fq12    = new Fq12<BigInteger>(rnd, Fq6.getOneElement());
    
    cf  = new G1<BigInteger>(rnd, Fq, Fq.getElementFromComponents(b), r, IntegerUtil.ONE, true);
    cf2 = new G2<BigInteger>(rnd, Fq2, xi.invert().mulMutable(b), r.multiply(cofac), cofac, true);
    
    rnd.setSeed(System.currentTimeMillis());
  }
  
  @Test
  public void testAtePairingPrefixed()
  {
    super.testAtePairingPrefixed();
  }

  @Test
  public void testAtePairingRandom()
  {
    super.testAtePairingRandom();
  }
  
  @Override
  @Test
  public void testConversion()
  {
    super.testConversion();
  }
  
  @Override
  @Test
  public void testDoublePrecision()
  {
    super.testDoublePrecision();
  }
  
  @Override
  @Test
  public void testInversion()
  {
    super.testInversion();
  }
  
  @Override
  @Test
  public void testPointFromXComputation()
  {
    super.testPointFromXComputation();
  }
  
  @Override
  @Test
  public void testPointMulDoubleAdd()
  {
    super.testPointMulDoubleAdd();
  }
  
  @Override
  @Test
  public void testPairingEvaluation()
  {
    super.testPairingEvaluation();
  }
  
  @Override
  @Test
  public void testSqrtPow()
  {
    super.testSqrtPow();
  }
  
  @Override
  @Test
  public void testAddSub()
  {
    super.testAddSub();
  }
  
  @Override
  @Test
  public void testNegate()
  {
    super.testNegate();
  }
  
  @Override
  @Test
  public void testDivTwoFour()
  {
    super.testDivTwoFour();
  }
  
  @Override
  @Test
  public void testSquarePow()
  {
    super.testSquarePow();
  }
}
