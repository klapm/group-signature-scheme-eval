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
import java.util.Random;

import junit.framework.Assert;

import org.iso200082.common.ecc.api.AsymmetricPairing;
import org.iso200082.common.ecc.api.PairingResult;
import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.Fq12Element;
import org.iso200082.common.ecc.elements.Fq2Element;
import org.iso200082.common.ecc.elements.Fq6Element;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.G1;
import org.iso200082.common.ecc.fields.G2;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.common.ecc.fields.towerextension.Fq12;
import org.iso200082.common.ecc.fields.towerextension.Fq2;
import org.iso200082.common.ecc.fields.towerextension.Fq6;
import org.iso200082.common.ecc.pairings.Ate;
import org.iso200082.common.util.IntegerUtil;
import org.iso200082.tests.TestData;

/**
 * Tests the ECC/pairing mini-"library" which is used as a backend for the
 * mechanisms.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 */
public class TestECC<P>
{
  protected static Random rnd = new SecureRandom();
  
  protected Fq<P>   Fq;
  protected Fq2<P>  Fq2;
  protected Fq<P>   FqMont;
  protected Fq2<P>  Fq2Mont;
  protected Fq6<P>  Fq6;
  protected Fq12<P> Fq12;
  
  protected BigInteger q;
  protected BigInteger r;
  protected BigInteger b;
  protected BigInteger t;
  protected BigInteger xi0;
  protected BigInteger xi1;
  protected BigInteger beta;
  protected BigInteger cofac;
  
  protected G1<P> cf;
  protected G2<P> cf2;
  
  public void testConversion()
  {
    for(int i = 0; i < 100; i++) {
      Point<FqElement<P>, Fq<P>> pt = cf.getRandomElement();
      Point<FqElement<P>, Fq<P>> conv =
        cf.getElementFromByteArray(pt.toByteArray());
      
      Point<Fq2Element<P>, Fq2<P>> pt2 = cf2.getRandomElement();
      Point<Fq2Element<P>, Fq2<P>> conv2 =
        cf2.getElementFromByteArray(pt2.toByteArray());
  
      Fq12Element<P> fq12el1 = Fq12.getElementFromComponents("1", "2", "3", "4", 
                                    "5", "6", "7", "8", "9", "10", "11", "12");
      Fq12Element<P> fq12el2 = Fq12.getElementFromComponents(1, 2, 3, 4, 5, 6, 7, 8,
                                                          9, 10, 11, 12);
      Fq12Element<P> fq12el3 = Fq12.getRandomElement();
      
      Assert.assertEquals(fq12el1,fq12el2);
      Assert.assertEquals(Fq12.getElementFromByteArray(fq12el3.toByteArray()),
                          fq12el3);
      Assert.assertEquals(pt, conv);
      Assert.assertEquals(pt2, conv2);
  
      FqElement<P> monty = FqMont.getRandomElement();
      Assert.assertEquals(FqMont.getElementFromByteArray(monty.toByteArray()),
                          monty);
    }
  }
  
  public void testSqrtPow()
  {
    for(int i = 0; i < 1; i++){
      // non-montgomery
      FqElement<P>  t1 = Fq.getRandomElement().square();
      Fq2Element<P> t2 = Fq2.getRandomElement().square();

      FqElement<P>  t3 = Fq.getRandomElement().pow(BigInteger.valueOf(2));
      Fq2Element<P> t4 = Fq2.getRandomElement().pow(BigInteger.valueOf(2));

      Assert.assertEquals(t1.sqrt().square(), t1);
      Assert.assertEquals(t2.sqrt().square(), t2);
      Assert.assertEquals(t3.sqrt().square(), t3);
      Assert.assertEquals(t4.sqrt().square(), t4);
      
      // montgomery, Fq2 is not supported / wasn't needed.
      t1 =  FqMont.getRandomElement().square();
      Assert.assertEquals(t1.sqrt().square(), t1);
      Assert.assertEquals(t1.sqrt().pow(BigInteger.valueOf(2)), t1);
    }
  }
  
  public void testAddSub()
  {
    for(int i = 0; i < 100; i++){
      FqElement<P> a = Fq.getRandomElement();
      FqElement<P> b = Fq.getRandomElement();
      
      Assert.assertEquals(a, a.add(b).sub(b));
      Assert.assertEquals(a, a.twice().sub(a));
      Assert.assertEquals(a, a.sub(b).add(b));
      Assert.assertEquals(b, b.addNoReduction(a).subNoReduction(a));
      
      Fq2Element<P> c = Fq2.getRandomElement();
      Fq2Element<P> d = Fq2.getRandomElement();
      
      Assert.assertEquals(c, c.add(d).sub(d));
      Assert.assertEquals(c, c.twice().sub(c));
      Assert.assertEquals(c, c.sub(d).add(d));
      Assert.assertEquals(d, d.addNoReduction(c).subNoReduction(c));
      
      Fq6Element<P> e = Fq6.getRandomElement();
      Fq6Element<P> f = Fq6.getRandomElement();
      
      Assert.assertEquals(e, e.add(f).sub(f));
      Assert.assertEquals(e, e.twice().sub(e));
      Assert.assertEquals(e, e.sub(f).add(f));
      Assert.assertEquals(f, f.addNoReduction(e).subNoReduction(e));
      
      Fq12Element<P> g = Fq12.getRandomElement();
      Fq12Element<P> h = Fq12.getRandomElement();
      
      Assert.assertEquals(g, g.add(h).sub(h));
      Assert.assertEquals(g, g.twice().sub(g));
      Assert.assertEquals(g, g.sub(h).add(h));
      Assert.assertEquals(h, h.addNoReduction(g).subNoReduction(g));
    }
  }
  
  public void testNegate()
  {
    for(int i = 0; i < 100; i++){
      FqElement<P> a = Fq.getRandomElement();
      Assert.assertEquals(a, a.negate().negate());
    }
  }
  
  public void testDivTwoFour()
  {
    for(int i = 0; i < 100; i++){
      FqElement<P> a = Fq.getRandomElement();
      Assert.assertEquals(a, a.divByFour().mul(BigInteger.valueOf(4)));
      Assert.assertEquals(a, a.divByFour().twice().twice());
      Assert.assertEquals(a, a.divByTwo().mul(BigInteger.valueOf(2)));
      Assert.assertEquals(a, a.divByTwo().twice());
      
      Fq2Element<P> b = Fq2.getRandomElement();
      Assert.assertEquals(b, b.divByFour().mul(BigInteger.valueOf(4)));
      Assert.assertEquals(b, b.divByFour().twice().twice());
      Assert.assertEquals(b, b.divByTwo().mul(BigInteger.valueOf(2)));
      Assert.assertEquals(b, b.divByTwo().twice());
    }
  }
  
  public void testSquarePow()
  {
    FqElement<P>   t1 = Fq.getRandomElement();
    Fq2Element<P>  t2 = Fq2.getRandomElement();
    Fq6Element<P>  t3 = Fq6.getRandomElement();
    Fq12Element<P> t4 = Fq12.getRandomElement();
    
    FqElement<P>   t1m = FqMont.getRandomElement();
    Fq2Element<P>  t2m = Fq2Mont.getRandomElement();
    Assert.assertEquals(t1.square(), t1.pow(IntegerUtil.TWO));
    Assert.assertEquals(t1.square(), t1.mul(t1));
    Assert.assertEquals(t2.square(), t2.pow(IntegerUtil.TWO));
    Assert.assertEquals(t2.square(), t2.mul(t2));
    Assert.assertEquals(t3.square(), t3.pow(IntegerUtil.TWO));
    Assert.assertEquals(t3.square(), t3.mul(t3));
    Assert.assertEquals(t4.square(), t4.pow(IntegerUtil.TWO));
    Assert.assertEquals(t4.square(), t4.mul(t4));
    Assert.assertEquals(t1m.mul(t1m), t1m.pow(IntegerUtil.TWO));
    Assert.assertEquals(t1m.square(), t1m.pow(IntegerUtil.TWO));
    Assert.assertEquals(t1m.square(), t1m.mul(t1m));
    Assert.assertEquals(t2m.square(), t2m.pow(IntegerUtil.TWO));
    Assert.assertEquals(t2m.square(), t2m.mul(t2m));
  }
  
  public void testPointFromXComputation()
  {
    for(int i = 0; i < 150; i++)
    {
      Assert.assertTrue(cf.getRandomElement().isValid());
      Assert.assertTrue(cf2.getRandomElement().isValid());
    }
  }
  
  public void testInversion()
  {
    // all randoms invertible as long as q is prime
    FqElement<P>   t1  = Fq.getRandomElement();
    FqElement<P>   t1m = FqMont.getOneElement();
    Fq2Element<P>  t2  = Fq2.getRandomElement();
    Fq2Element<P>  t2m = Fq2Mont.getRandomElement();
    Fq6Element<P>  t3  = Fq6.getRandomElement();
    Fq12Element<P> t4  = Fq12.getRandomElement();
    
    Assert.assertEquals(t1.invert().mul(t1), Fq.getOneElement());
    Assert.assertEquals(t2.invert().mul(t2), Fq2.getOneElement());
    Assert.assertEquals(t3.invert().mul(t3), Fq6.getOneElement());
    Assert.assertEquals(t4.invert().mul(t4), Fq12.getOneElement());
    Assert.assertEquals(t1m.invert().mul(t1m), FqMont.getOneElement());
    Assert.assertEquals(t2m.invert().mul(t2m), Fq2Mont.getOneElement());
  }
  
  public void testDoublePrecision()
  {
    FqElement<P>   a1  = Fq.getRandomElement();
    FqElement<P>   a2  = Fq.getRandomElement();
    Fq2Element<P>  b1  = Fq2.getRandomElement();
    Fq2Element<P>  b2  = Fq2.getRandomElement();
    FqElement<P>   am1 = FqMont.getRandomElement();
    FqElement<P>   am2 = FqMont.getRandomElement();
    Fq2Element<P>  bm1 = Fq2Mont.getRandomElement();
    Fq2Element<P>  bm2 = Fq2Mont.getRandomElement();
    Fq6Element<P>  c1  = Fq6.getRandomElement();
    Fq6Element<P>  c2  = Fq6.getRandomElement();
    
    Assert.assertEquals(a1.squareDouble().mod(),  a1.square());
    Assert.assertEquals(a1.mulDouble(a2).mod(),   a1.mul(a2));
    Assert.assertEquals(a1.mulDouble(a2).add(a2.squareDouble()).mod(),
                        a1.mul(a2).add(a2.square()));
    Assert.assertEquals(b1.squareDouble().mod(),  b1.square());
    Assert.assertEquals(b1.mulDouble(b2).mod(),   b1.mul(b2));
    Assert.assertEquals(b1.mulDouble(b2).add(b2.squareDouble()).mod(),
                        b1.mul(b2).add(b2.square()));
    Assert.assertEquals(am1.squareDouble().mod(), am1.square());
    Assert.assertEquals(am1.mulDouble(am2).mod(),   am1.mul(am2));
    Assert.assertEquals(am1.mulDouble(am2).add(am2.squareDouble()).mod(),
                        am1.mul(am2).add(am2.square()));
    Assert.assertEquals(bm1.squareDouble().mod(), bm1.square());
    Assert.assertEquals(bm1.mulDouble(bm2).mod(),   bm1.mul(bm2));
    Assert.assertEquals(bm1.mulDouble(bm2).add(bm2.squareDouble()).mod(),
                        bm1.mul(bm2).add(bm2.square()));
    Assert.assertEquals(c1.squareDouble().mod(),  c1.square());
    Assert.assertEquals(c1.mulDouble(c2).mod(),   c1.mul(c2));
    Assert.assertEquals(c1.mulDouble(c2).add(c2.squareDouble()).mod(),
                        c1.mul(c2).add(c2.square()));
  }
  
  public void testPointMulDoubleAdd()
  {
    // G1
    Point<FqElement<P>, Fq<P>> pt  = TestData.M4.getBeuchatP1(cf);
    Point<FqElement<P>, Fq<P>> pt2 = pt.twice();
    Point<FqElement<P>, Fq<P>> pt3 = pt2.add(pt);
    Point<FqElement<P>, Fq<P>> pt4 = pt.mul(IntegerUtil.THREE);
    Point<FqElement<P>, Fq<P>> pt5 = pt2.sub(pt);
    Point<FqElement<P>, Fq<P>> gen = cf.getRandomGenerator();

    Assert.assertFalse(pt.isInfinite());
    Assert.assertFalse(pt2.isInfinite());
    Assert.assertFalse(pt3.isInfinite());
    Assert.assertFalse(pt4.isInfinite());
    Assert.assertFalse(pt5.isInfinite());
    Assert.assertFalse(gen.isInfinite());

    Assert.assertEquals(pt.add(pt).toAffine(), pt.toAffine().add(pt.toAffine()));
    Assert.assertEquals(pt.twice().toAffine(), pt.toAffine().twice());
    
    Point<FqElement<P>, Fq<P>> xpt = pt.add(pt).sub(pt);
    Assert.assertEquals(xpt, pt);
    Assert.assertEquals(pt3, pt4);
    Assert.assertEquals(pt3.sub(pt), pt2);
    Assert.assertEquals(pt5, pt);
    Point<FqElement<P>, Fq<P>> genorder = gen.mul(cf.getOrder());
    Assert.assertTrue(gen.mul(cf.getOrder()).isInfinite());
    Assert.assertTrue(genorder.infinite);
    
    // G2
    Point<Fq2Element<P>, Fq2<P>> ptc   = TestData.M4.getBeuchatQ1(cf2);
    Point<Fq2Element<P>, Fq2<P>> ptc2  = ptc.twice();
    Point<Fq2Element<P>, Fq2<P>> ptc3  = ptc2.add(ptc);
    Point<Fq2Element<P>, Fq2<P>> ptc4  = ptc.mul(IntegerUtil.THREE);
    Point<Fq2Element<P>, Fq2<P>> ptc5  = ptc2.sub(ptc);
    Point<Fq2Element<P>, Fq2<P>> genc  = cf2.getRandomGenerator();

    Assert.assertFalse(ptc.isInfinite());
    Assert.assertFalse(ptc2.isInfinite());
    Assert.assertFalse(ptc3.isInfinite());
    Assert.assertFalse(ptc4.isInfinite());
    Assert.assertFalse(ptc5.isInfinite());
    Assert.assertFalse(genc.isInfinite());
    
    Assert.assertEquals(ptc3, ptc4);
    Assert.assertEquals(ptc3.sub(ptc), ptc2);
    Assert.assertEquals(ptc5, ptc);
    Assert.assertTrue(genc.mul(cf2.getOrder()).isInfinite());
  }
    
  public void testAtePairingRandom()
  {
    // (the affine/mixed flag does not matter here)
    
    // montgomery domain
    AsymmetricPairing<P> ate = new Ate<P>(rnd, q, r, b, t, 
                                          beta, xi0, xi1, FqMont, true);
    testAtePairingImpl(ate);

    // non-montgomery domain
    ate = new Ate<P>(rnd, q, r, b, t, beta, xi0, xi1, Fq, true);
    testAtePairingImpl(ate);
  }
  
  public void testAtePairingPrefixed()
  {
    // non-montgomery domain
    AsymmetricPairing<P> ate              = TestData.M4.getBeuchatPairingData(rnd, Fq);
    Point<FqElement<P>, Fq<P>>   P1 = TestData.M4.getBeuchatP1(ate.getG1());
    Point<FqElement<P>, Fq<P>>   P2 = TestData.M4.getBeuchatP2(ate.getG1());
    Point<Fq2Element<P>, Fq2<P>> Q1 = TestData.M4.getBeuchatQ1(ate.getG2());
    Point<Fq2Element<P>, Fq2<P>> Q2 = TestData.M4.getBeuchatQ2(ate.getG2());

    Assert.assertFalse(P1.isInfinite());
    Assert.assertFalse(P2.isInfinite());
    Assert.assertFalse(Q1.isInfinite());
    Assert.assertFalse(Q2.isInfinite());
    
    PairingResult<P> p1 = ate.pairing(Q1, P1);
    PairingResult<P> p2 = ate.pairing(Q1, P2);
    PairingResult<P> p3 = ate.pairing(Q2, P1);
    
    Assert.assertEquals(p1.square(), p2);
    Assert.assertEquals(p1.square(), p3);
    Assert.assertEquals(p2, p3);
    
    // montgomery domain
    ate = TestData.M4.getBeuchatPairingData(rnd, FqMont);

    Assert.assertFalse(P1.isInfinite());
    Assert.assertFalse(P2.isInfinite());
    Assert.assertFalse(Q1.isInfinite());
    Assert.assertFalse(Q2.isInfinite());
    
    p1 = ate.pairing(Q1, P1);
    p2 = ate.pairing(Q1, P2);
    p3 = ate.pairing(Q2, P1);
    
    Assert.assertEquals(p1.square(), p2);
    Assert.assertEquals(p1.square(), p3);
    Assert.assertEquals(p2, p3);
  }
  
  private void testAtePairingImpl(AsymmetricPairing<P> ate)
  {
    Point<FqElement<P>, Fq<P>>   P1 = cf.getRandomElement();
    Point<FqElement<P>, Fq<P>>   P2 = P1.twice();
    
    Point<Fq2Element<P>, Fq2<P>> Q1 = cf2.getRandomGenerator();
    Point<Fq2Element<P>, Fq2<P>> Q2 = Q1.twice();
    
    PairingResult<P> p1 = ate.pairing(Q1, P1);
    PairingResult<P> p2 = ate.pairing(Q2, P1);
    PairingResult<P> p3 = ate.pairing(Q1, P2);
    
    Assert.assertEquals(p1.square(), p2);
    Assert.assertEquals(p1.square(), p3);
    Assert.assertEquals(p2, p3);
  }

  public void testPairingEvaluation()
  {
    // (the affine/mixed flag does not matter here)
    
    Ate<P> ate = new Ate<P>(rnd, q, r, b, t, beta, xi0, xi1, FqMont, true);
    Point<FqElement<P>, Fq<P>>   P1 = cf.getRandomElement();
    Point<Fq2Element<P>, Fq2<P>> Q1 = cf2.getRandomGenerator();
    for(int i = 0; i < 5; i++) // warmup loop
      ate.pairing(Q1, P1);
    
    long iter = 1000, duration = 0;
    System.out.println("Evaluating single ate pairing performance");
    System.out.println("-----------------------------------------"); 
    System.out.println("Iterations: " + iter); 
    System.out.println("Montgomery transformation: Enabled"); 
    for(int i = 0; i < iter; i++)
    {
      long begin = System.nanoTime();
      ate.pairing(Q1, P1);
      duration += (System.nanoTime() - begin);
    }
    System.out.println("Avg. Runtime: " + 
                       (duration/((double)(1000000*iter))) + "ms");
    System.out.println("-----------------------------------------"); 
    System.out.println("Montgomery transformation: Disabled");
    
    // non-montgomery domain should be slower, but it's not. my monty
    // implementation is probably bad. A mutable biginteger might help
    // for some cases..
    ate = new Ate<P>(rnd, q, r, b, t, beta, xi0, xi1, Fq, true);
    
    for(int i = 0; i < 5; i++) // warmup loop
      ate.pairing(Q1, P1);
    
    duration = 0;
    for(int i = 0; i < iter; i++)
    {
      long begin = System.nanoTime();
      ate.pairing(Q1, P1);
      duration += (System.nanoTime() - begin);
    }
    System.out.println("Avg. Runtime: " + 
                       (duration/((double)(1000000*iter))) + "ms");
    System.out.println("-----------------------------------------");
  }
}
