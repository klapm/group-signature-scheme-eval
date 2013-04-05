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

package org.iso200082.common.ecc.pairings;

import java.math.BigInteger;
import java.util.Random;

import org.iso200082.common.ecc.api.AsymmetricPairing;
import org.iso200082.common.ecc.api.FieldElement;
import org.iso200082.common.ecc.api.Pairing;
import org.iso200082.common.ecc.api.PairingResult;
import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.api.TowerFieldElement;
import org.iso200082.common.ecc.elements.Fq12Element;
import org.iso200082.common.ecc.elements.Fq2Element;
import org.iso200082.common.ecc.elements.Fq6Element;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.elements.ProjectivePoint;
import org.iso200082.common.ecc.elements.doubleprecision.Fq2DoubleElement;
import org.iso200082.common.ecc.fields.G1;
import org.iso200082.common.ecc.fields.G2;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.common.ecc.fields.towerextension.Fq12;
import org.iso200082.common.ecc.fields.towerextension.Fq2;
import org.iso200082.common.ecc.fields.towerextension.Fq6;
import org.iso200082.common.util.IntegerUtil;


/**
 * Implementation of the Ate Pairing, as proposed by Beuchat et al.
 * ("High-Speed Software Implementation of the Optimal Ate Pairing over
 * Barreto–Naehrig Curves") and enhanced using the insights of Aranha et al.
 * ("Faster Explicit Formulas for Computing Pairings over Ordinary Curves").
 * 
 * There is a 'reference implementation' available at
 * <a href="http://homepage1.nifty.com/herumi/crypt/ate-pairing.html">
 *   http://homepage1.nifty.com/herumi/crypt/ate-pairing.html
 * </a>
 * 
 * This implementation assumes a b
 * (as in E: y^2 = x^3 + b) of 2, beta of -1 and a xi of [1,1] (1 + i).
 * See Aranha et al. (pages 4, 12) for the reasoning behind this.
 * 
 * See {@link Pairing} for further notes and references on pairings
 * 
 * @see AsymmetricPairing
 * @see Pairing
 * @see PairingResult
 * @see TowerFieldElement
 * @see G1
 * @see G2
 * @see Fq12
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class Ate
<
  P
>
extends AsymmetricPairing<P>
{  
  /** The F(q^2) irreducible coefficient beta
   * @see Fq2#Fq2(Random, FqElement) */
  protected BigInteger beta;

  /** The F(q^6) irreducible coefficient beta
   * @see Fq6#Fq6(Random, Fq2Element) */
  protected Fq2Element<P> xi;
    
  /** {@link Fq2} */
  protected Fq2<P>  Fq2;
  
  /** {@link Fq6} */
  protected Fq6<P>  Fq6;
  
  /** {@link Fq12} */
  protected Fq12<P> Fq12;
  
  /* the 'public' (non-montgomery fields), used in G1, G2.
   * They are actually overhead if working in non-montgomery world.. */
  
  /** {@link Fq}, non-montgomery variant (=Fq if already) */
  protected Fq<P>  FqNM;

  /** {@link Fq2}, non-montgomery variant (=Fq2 if already) */
  protected Fq2<P> Fq2NM;
  
  /*
   * Gammas 1-3 as computed in algorithms 28, 29 and 30 of Beuchat et al.
   * respectively
   */
  
  /** Gamma1,0-Gamma1,4, see Beuchat et al., p. 6 and 30 */
  protected Fq2Element<P>[] gamma1;
  
  /** Gamma2,0-Gamma2,4, see Beuchat et al., p. 6 and 30 */
  protected Fq2Element<P>[] gamma2;
  
  /** Gamma3,0-Gamma3,4, see Beuchat et al., p. 6 and 31 */
  protected Fq2Element<P>[] gamma3;
  
  /*
   * (W^i)^p as computed in Beuchat et al., see 
   */
  
  /** (W^2)^p = gamma1,2 * W^2, see  Beuchat et al., p. 6 */
  protected Fq2Element<P> W2p;
  
  /** (W^3)^p = gamma1,3 * W^3 see  Beuchat et al., p. 6 */
  protected Fq2Element<P> W3p;
  
  /** Z = xi^((q^2 - 1)/6), required for the squared frobenius endomorphism
   * operator in line 11 of Beuchat et al. Algorithm 1 */
  protected FqElement<P> Z;

  /**
   * Ctor, initializes the pairing map (does some precomputation). The
   * factory parameter defines what underlying primitive implementation to use.
   * 
   * @see Pairing
   * @see Fq
   * 
   * @param rnd A {@link Random} instance
   * @param q The modulus
   * @param r The order
   * @param b 'b' as in y^2 = x^3 + b
   * @param t The frobenius trace
   * @param beta The irreducible's coefficient of the extension
   *             F(q^2) = F(q)[u](u^2 - beta)
   * @param xi0 The irreducible's coefficient x coordinate of the extension
   *            F(q^6) = F(q^2)[v](v^3 - xi)
   * @param xi1 The irreducible's coefficient y coordinate of the extension
   *            F(q^6) = F(q^2)[v](v^3 - xi)
   * @param factory Concrete field implementation to hand out field elements
   *                implemented using the desired primitive implementation
   * @param mixed_mode Whether or not to use a coordinate mix in
   *                   point multiplication
   */
  @SuppressWarnings({ "rawtypes", "unchecked" })
  public Ate(Random rnd,     BigInteger q,   BigInteger r, 
             BigInteger b,   BigInteger t,   BigInteger beta,
             BigInteger xi0, BigInteger xi1, Fq<P> factory, boolean mixed_mode)
  {
    super(rnd, q, r, b, t, factory);
    this.beta = beta;

    gamma1 = new Fq2Element[5];
    gamma2 = new Fq2Element[5];
    gamma3 = new Fq2Element[5];
    
    initializePairing(xi0, xi1, mixed_mode);
  }
  
  /**
   * Pairing "infrastructure" initialization. Creates the fields and
   * computes precomputable values.
   * 
   * @param xi0 The irreducible's coefficient x coordinate of the extension
   *            F(q^6) = F(q^2)[v](v^3 - xi)
   * @param xi1 The irreducible's coefficient y coordinate of the extension
   *            F(q^6) = F(q^2)[v](v^3 - xi)
   * @param mixed_mode Whether or not to use a coordinate mix in
   *                   point multiplication
   */
  protected void
  initializePairing(BigInteger xi0, BigInteger xi1, boolean mixed_mode)
  {
    Fq2  = new Fq2<P>(rnd, Fq.getElementFromComponents(beta));
    xi   = Fq2.getElementFromComponents(xi0, xi1);
    Fq6  = new Fq6<P>(rnd, xi);
    Fq12 = new Fq12<P>(rnd, Fq6.getOneElement());
    
    FqNM   = Fq.getNonMontgomeryField();
    Fq2NM  = new Fq2<P>(rnd, FqNM.getElementFromComponents(beta));
    
    FqElement<P> b_element = FqNM.getElementFromComponents(b);
    BigInteger cofac    = IntegerUtil.TWO.multiply(q).subtract(r);
    Fq2Element<P> xiNM     = Fq2NM.getElementFromComponents(xi0, xi1);
    
    G1 = new G1<P>(rnd, FqNM, b_element, r, BigInteger.ONE, mixed_mode);
    G2 = new G2<P>(rnd, Fq2NM, xiNM.invertMutable().mulMutable(b_element),
                r.multiply(cofac), cofac, mixed_mode);
    GT = Fq12;
    gamma1[0] = xi.pow(q.subtract(IntegerUtil.ONE).divide(IntegerUtil.SIX));
    
    for(int i = 1; i < gamma1.length; i++)
      gamma1[i] = gamma1[i-1].mul(gamma1[0]);
    for(int i = 0; i < gamma2.length; i++)
      gamma2[i] = new Fq2Element<P>(Fq2, gamma1[i].a, gamma1[i].b.negate())
                     .mulMutable(gamma1[i]);

    for(int i = 0; i < gamma3.length; i++)
      gamma3[i] = gamma1[i].mul(gamma2[i]);

    W2p = xi.pow(q.subtract(IntegerUtil.ONE).divide(IntegerUtil.THREE));
    W3p = xi.pow(q.multiply(IntegerUtil.THREE)
                  .subtract(IntegerUtil.ONE).divide(IntegerUtil.TWO)
                  .subtract(IntegerUtil.ONE).divide(IntegerUtil.THREE));

    Fq2Element<P> tmp = xi.pow(q.multiply(q)
                       .subtract(IntegerUtil.ONE).divide(IntegerUtil.SIX));

    if(!tmp.b.isZero())
      throw new IllegalStateException("initialization went wrong, " +
                                      "probably wrong curve data");
    
    Z = tmp.a.negateMutable().squareMutable();
  }
  
  @Override
  public PairingResult<P> pairing(Point<Fq2Element<P>, Fq2<P>> Q_in,
                                  Point<FqElement<P>,  Fq<P>>  P_in)
  {
    Point<Fq2Element<P>, Fq2<P>> Q = toProjectiveFq2(Q_in);
    Point<FqElement<P>, Fq<P>>   P = toProjectiveFq(P_in);
    P.z = P.y.negate();
    Point<Fq2Element<P>, Fq2<P>> T = Q.clone();
    
    BigInteger s = t.multiply(IntegerUtil.SIX).add(IntegerUtil.TWO);
    if(s.signum() < 0) // t can be negative (e.g. in Beuchat et al.)
      s = s.negate();

    Fq6Element<P>  d = Fq6.getZeroElement(), e = Fq6.getZeroElement();
    pointDoubleLineEval(d, T, P);
    pointAddLineEval(e, T, Q, P);
    Fq12Element<P> f = combineFq6ElementsToFq12(d, e);
    
    for (int i = s.bitLength() - 3; i >= 0; i--) // miller loop
    {
      pointDoubleLineEval(d, T, P);
      joinFq6ElementToFq12(f.squareMutable(), d);

      if(s.testBit(i)) {
        pointAddLineEval(e, T, Q, P);
        joinFq6ElementToFq12(f, e);
      }
    }

    Point<Fq2Element<P>, Fq2<P>> Q1 = endoTwist(Q);    
    Point<Fq2Element<P>, Fq2<P>> Q2 = endoTwist2(Q);

    Q.recycle();
    
    f.b = f.b.negateMutable();
    T.y = T.y.negateMutable();

    pointAddLineEval(d, T, Q1, P);
    pointAddLineEval(e, T, Q2, P);
    
    Q1.recycle(); Q2.recycle(); T.recycle(); P.recycle();

    Fq12Element<P> ft  = combineFq6ElementsToFq12(d, e);
    Fq12Element<P> out = finalExp(f.mulMutable(ft));

    f.recycle();
    ft.recycle();
    return out;
  }
  
  /**
   * Point addition in homogeneous/projective coordinates, Q gets Q + R.
   * Returns the tangent line l (F(q^12)) connecting the points. The zero
   * coefficients are skipped though and it's returned as a F(q^6) element.
   * 
   * See "Faster Explicit Formulas for Computing Pairings over Ordinary Curves"
   * (Aranha et al.), Algorithm 12.
   * 
   * @param Q The point to add R to
   * @param R The point to add to Q
   * @param P The initial pairing point of G1, as projective coordinates
   *          with z being -y
   *          
   * @see #pairing(Point, Point)
   */
  protected void pointAddLineEval(Fq6Element<P> out, 
                                  Point<Fq2Element<P>, Fq2<P>> Q,
                                  Point<Fq2Element<P>, Fq2<P>> R,
                                  Point<FqElement<P>, Fq<P>>   P)
  {
    // algorithm 12 [Aranha et al.]
        
    Fq2Element<P> t1 = Q.z.mul(R.x);
    Fq2Element<P> t2 = Q.z.mul(R.y);
    
    Fq2Element<P> t3, t4;
    Fq2DoubleElement<P> T1, T2;

    t1    = Q.x.sub(t1);
    t2    = Q.y.sub(t2);
    t3    = t1.square();
    Q.x   = Q.x.mulMutable(t3);
    t4    = t2.square();
    t3    = t3.mulMutable(t1);
    
    t4    = t4.mulMutable(Q.z).addMutable(t3).subMutable(Q.x).subMutable(Q.x);
    Q.x   = Q.x.subMutable(t4);
    T1    = t2.mulDouble(Q.x, false);
    T2    = t3.mulDouble(Q.y, false);
    T2.recycle(); 
    T2    = T1.subMutable(T2);
    Q.y.recycle();
    Q.y   = T2.mod();
    T2.recycle();
    Q.x.recycle();
    Q.x   = t1.mul(t4);
    Q.z   = Q.z.mulMutable(t3);

    out.c = t2.mul(P.x).negateMutable();
    T1    = t2.mulDouble(R.x, false);
    T2    = t1.mulDouble(R.y, false);
    T1    = T1.subMutable(T2);
    t2.recycle();
    t2    = T1.mod();
    out.a = t2.mulXiMutable();
    out.b = t1.mulMutable(P.y); // Z = -Y in this case 
    t3.recycle(); t4.recycle(); T1.recycle(); T2.recycle();
  }
  
  /**
   * Point doubling in homogeneous/projective coordinates, Q gets 2Q.
   * Returns the tangent line l (F(q^12)) connecting the points. The zero
   * coefficients are skipped though and it's returned as a F(q^6) element.
   * 
   * See "Faster Explicit Formulas for Computing Pairings over Ordinary Curves"
   * (Aranha et al.), Algorithm 11.
   * 
   * @param Q The point to double
   * @param P The initial pairing point of G1, as projective coordinates
   *          with z being -y
   *          
   * @see #pairing(Point, Point)
   */
  protected void pointDoubleLineEval(Fq6Element<P> out, 
                                     Point<Fq2Element<P>, Fq2<P>> Q,
                                     Point<FqElement<P>, Fq<P>>   P)
  {
    Fq2Element<P>       t0, t1, t2, t3, t4, t5;
    Fq2DoubleElement<P> T0, T1, T2;
        
    t0 = Q.z.square();
    t4 = Q.x.mul(Q.y);
    t1 = Q.y.square();

    t3 = t0.twice();
    t4 = t4.divByTwoMutable();
    t5 = t0.add(t1);
    t0 = t0.addMutable(t3);
    t2 = new Fq2Element<P>(Fq2, t0.a.add(t0.b), t0.b.sub(t0.a));
    t0.recycle();
    t0 = Q.x.squareMutable();
    t3 = t2.twice().addMutable(t2);
    
    out.c = t0.twiceNoReduction().addMutable(t0);
    Q.x = t1.sub(t3);
    Q.x = Q.x.mulMutable(t4);
    t3  = t3.addMutable(t1).divByTwoMutable();

    T0 = t3.squareDouble();
    T1 = t2.squareDouble();
    T2 = T1.twice();

    t3.recycle();
    t3 = Q.y.addMutable(Q.z);
    
    T2 = T2.addMutable(T1);
    t3 = t3.squareMutable().subMutable(t5);

    T0  = T0.subMutable(T2);
    Q.y = T0.mod();
    
    Q.z.recycle();
    Q.z = t1.mul(t3);
    t2  = t2.subMutable(t1);
    out.a = t2.mulXiMutable();
    
    out.c = out.c.mulMutable(P.x);
    out.b = t3.mulMutable(P.z);
    
    T0.recycle(); T1.recycle(); T2.recycle();
    t0.recycle(); t1.recycle(); t4.recycle(); t5.recycle();
  }
  
  /**
   * Computes out (F(q^12)) = a (F(q^6)) * b (F(q^6)), where
   * a, b are actually (F(q^12)) elements (with half of the coefficients zero,
   * so encoded as {@link Fq6Element}s.
   * 
   * An {@link Fq12Element} has coefficients x, y being Fq6. a, b encode
   * (x.a, y.b, x.c), where x.b, y.a, y.c are zero.
   * 
   * Destroys a,b.
   * 
   * @param a A "compressed" F(q^12) tangent, represented as F(q^6)
   * @param b A "compressed" F(q^12) tangent, represented as F(q^6)
   * @return A "combined" (multiplied) Fq12 Element
   */
  protected Fq12Element<P> combineFq6ElementsToFq12(Fq6Element<P> a, 
                                                    Fq6Element<P> b)
  {
    Fq2Element<P> faa, fab, fac, fba, fbb;
    Fq2DoubleElement<P> T00, T22, T44, T24, T40;
    
    T00 = a.a.mulDouble(b.a);
    T22 = a.c.mulDouble(b.c);
    T44 = a.b.mulDouble(b.b);
    
    faa = a.a.add(a.c);
    fab = b.a.add(b.c);
    fac = faa.mulDouble(fab).subMutable(T00).subMutable(T22).mod();
    
    faa = a.c.addMutable(a.b);
    fab = b.c.addMutable(b.b);
    
    T24 = faa.mulDouble(fab).subMutable(T22).subMutable(T44);
    fba = T24.mulXiMutable().mod();
    
    faa = a.b.addMutable(a.a);
    fab = b.b.addMutable(b.a);
    
    T40 = faa.mulDouble(fab).subMutable(T00).subMutable(T44);
    fbb = T40.mod();
    
    fab = T22.mulXiMutable().mod();
    
    faa = T44.mulXiMutable().addMutable(T00).mod();
    
    T00.recycle(); T22.recycle(); T44.recycle(); T24.recycle(); T40.recycle();
    
    // clears arg. elements (!)
    a.a.recycle(); a.b.recycle(); a.c.recycle();
    b.a.recycle(); b.b.recycle(); b.c.recycle();
    
    return new Fq12Element<P>(Fq12, new Fq6Element<P>(Fq6, faa, fab, fac),
                                    new Fq6Element<P>(Fq6, fba, fbb,
                                        Fq2.getZeroElement()));    
  }
  
  /**
   * returns f * l, where f is an {@link Fq12Element} and l is an Fq12Element,
   * compressed as {@link Fq6Element} of the form (x.a, y.b, x.c),
   * where x.b, y.a, y.c are zero (and thus spared).
   * 
   * Destroys l.
   * 
   * @param f The {@link Fq12Element} to multiply l to
   * @param l The {@link Fq6Element} to multiply to f
   * @return The product
   */
  protected Fq12Element<P> joinFq6ElementToFq12(Fq12Element<P> f, 
                                                Fq6Element<P>  l)
  {    
    Fq2Element<P> t0, t1, t2, s0, ac;
    Fq2DoubleElement<P> T3, T4, D0, D2, D4, S1, TX, TY;
    
    D0 = f.a.a.mulDouble(l.a);
    D2 = f.a.c.mulDouble(l.c);
    D4 = f.b.b.mulDouble(l.b);
    
    t2 = f.a.a.add(f.b.b);
    t1 = f.a.a.addMutable(f.a.c);
    s0 = f.a.b.add(f.b.a).addMutable(f.b.c);
    
    S1 = f.a.b.mulDouble(l.c);
    T3 = S1.add(D4).mulXiMutable().addMutable(D0);
    f.a.a = T3.mod();
    
    T3 = f.b.c.mulDouble(l.b);
    TX = f.b.a.mulDouble(l.b);
    TY = f.b.c.mulDouble(l.c);
    S1 = S1.addMutable(T3);
    T3 = T3.addMutable(D2);
    T4 = T3.mulXiMutable();
    T3 = f.a.b.mulDouble(l.a);
    f.a.b.recycle();
    S1 = S1.addMutable(T3);
    f.a.b = T4.addMutable(T3).mod();
    
    ac = l.a.add(l.c);
    T3 = t1.mulDouble(ac).subMutable(D0).subMutable(D2);
    t1.recycle();
    S1 = S1.addMutable(TX);
    T3 = T3.addMutable(TX);
    t0 = f.a.c.addMutable(f.b.b);
    f.a.c = T3.mod();
    T3.recycle(); T4.recycle();
    
    t1 = l.c.addMutable(l.b);
    T4 = t0.mulDouble(t1).subMutable(D2).subMutable(D4).mulXiMutable();
    T3 = f.b.a.mulDouble(l.a);
    S1 = S1.addMutable(T3);
    T4 = T4.addMutable(T3);
    t0.recycle(); f.b.a.recycle();
    f.b.a = T4.mod();
    
    S1 = S1.addMutable(TY);
    T4.recycle(); T3.recycle();
    T4 = TY.mulXiMutable();
    t0 = l.a.addMutable(l.b);
    T3 = t2.mulDouble(t0).subMutable(D0).subMutable(D4);
    T4 = T4.addMutable(T3);
    f.b.b.recycle();
    f.b.b = T4.mod();
    
    t0 = ac.addMutable(l.b);
    T3.recycle();
    T3 = s0.mulDouble(t0).subMutable(S1);
    f.b.c.recycle();
    f.b.c = T3.mod();

    T3.recycle(); T4.recycle(); D0.recycle(); D2.recycle(); D4.recycle();
    S1.recycle(); TX.recycle();
    t0.recycle(); t2.recycle(); s0.recycle();

    // clears arg. elements (!)
    l.a.recycle(); l.b.recycle(); l.c.recycle();
    
    return f;
  }
  
  /**
   * Frobenius operator, raises f (in) to the power p. See
   * "High-Speed Software Implementation of the Optimal Ate Pairing over
   * Barreto–Naehrig Curves" (Beuchat et al.), page 5+ and page 30 for
   * algorithm 28.
   * 
   * @param in The {@link Fq12Element} to raise
   * @return in^p
   */
  protected Fq12Element<P> frobenius(Fq12Element<P> in)
  {
    // algorithm 28 [Beuchat et al.]
        
    Fq2Element<P> faa = Fq2.getElement(in.a.a.a, in.a.a.b.negate());
    Fq2Element<P> fab = Fq2.getElement(in.a.b.a, in.a.b.b);
    Fq2Element<P> fac = Fq2.getElement(in.a.c.a, in.a.c.b.negate());
    fab = mulSwap(fab, gamma1[1].b);
    fac = fac.mul(gamma1[3].a);

    Fq2Element<P> fba = Fq2.getElement(in.b.a.a, in.b.a.b.negate());
    Fq2Element<P> fbb = Fq2.getElement(in.b.b.a, in.b.b.b.negate());
    Fq2Element<P> fbc = Fq2.getElement(in.b.c.a, in.b.c.b.negate());
    fba = fba.mulMutable(gamma1[0]);
    fbb = fbb.mulMutable(gamma1[2]);
    fbc = fbc.mulMutable(gamma1[4]);
    
    return Fq12.getElement(Fq6.getElement(faa, fab, fac),
                           Fq6.getElement(fba, fbb, fbc)); 
  }
  
  /**
   * Frobenius operator, raises f (in) to the power p^2. See
   * "High-Speed Software Implementation of the Optimal Ate Pairing over
   * Barreto–Naehrig Curves" (Beuchat et al.), page 5+ and page 30 for
   * algorithm 29.
   * 
   * @param in The {@link Fq12Element} to raise
   * @return in^(p^2)
   */
  protected Fq12Element<P> frobenius2(Fq12Element<P> in)
  {
    // algorithm 29 [Beuchat et al.]
    
    Fq2Element<P> faa = in.a.a;
    Fq2Element<P> fab = in.a.b.mul(gamma2[1].a);
    Fq2Element<P> fac = in.a.c.mul(gamma2[3].a);
    Fq2Element<P> fba = in.b.a.mul(gamma2[0].a);
    Fq2Element<P> fbb = in.b.b.mul(gamma2[2].a);
    Fq2Element<P> fbc = in.b.c.mul(gamma2[4].a);

    return Fq12.getElement(Fq6.getElement(faa, fab, fac),
                           Fq6.getElement(fba, fbb, fbc)); 
  }

  /**
   * Frobenius operator, raises f (in) to the power p^3. See
   * "High-Speed Software Implementation of the Optimal Ate Pairing over
   * Barreto–Naehrig Curves" (Beuchat et al.), page 5+ and page 31 for
   * algorithm 30.
   * 
   * @param in The {@link Fq12Element} to raise
   * @return in^(p^3)
   */
  protected Fq12Element<P> frobenius3(Fq12Element<P> in)
  {
    // algorithm 30 [Beuchat et al.]
    
    Fq2Element<P> faa = Fq2.getElement(in.a.a.a, in.a.a.b.negate());
    Fq2Element<P> fab = Fq2.getElement(in.a.b.b, in.a.b.a);
    Fq2Element<P> fac = Fq2.getElement(in.a.c.a, in.a.c.b.negate());
    fac = fac.mul(gamma3[3].a);

    Fq2Element<P> fba = Fq2.getElement(in.b.a.a, in.b.a.b.negate());
    fba = fba.mulMutable(gamma3[0]);

    Fq2Element<P> fbb = Fq2.getElement(in.b.b.a, in.b.b.b.negate());
    fbb = fbb.mulMutable(gamma3[2]);

    Fq2Element<P> fbc = Fq2.getElement(in.b.c.a, in.b.c.b.negate());
    fbc = fbc.mulMutable(gamma3[4]);

    return Fq12.getElement(Fq6.getElement(faa, fab, fac),
                           Fq6.getElement(fba, fbb, fbc));
  }
  
  /**
   * Final exponentiation, mixture of Algorithm 31 in
   * "High-Speed Software Implementation of the Optimal Ate Pairing over
   * Barreto–Naehrig Curves" (Beuchat et al.), page 32 and the proposal in
   * "Faster Explicit Formulas for Computing Pairings over Ordinary Curves"
   * (Aranha et al.) as used in their Beuchat et al.'s published 
   * implementation.
   * 
   * @param f the {@link Fq12Element} to raise to the power of (q^12 - 1)/r
   * @return The raised element
   */
  protected Fq12Element<P> finalExp(Fq12Element<P> f)
  {
    Fq12Element<P> out, ft1, ft2, ft3;
    Fq12Element<P> t0,  y0,  y2,  y4;

    Fq12Element<P> ff  = mapToCyclotomicPolynomial(f);

    ft1   = fixedPower(ff);
    ft1.b = ft1.b.negateMutable();
    ft2   = fixedPower(ft1);
    ft2.b = ft2.b.negateMutable();
    ft3   = fixedPower(ft2);
    ft3.b = ft3.b.negateMutable();
             
    y0    = frobenius(ff).mulMutable(frobenius2(ff)).mulMutable(frobenius3(ff));
    ff.b  = ff.b.negateMutable();
    y2    = frobenius2(ft2);
    y4    = frobenius(ft2).mulMutable(ft1);
    y4.b  = y4.b.negateMutable();
    ft2.b = ft2.b.negateMutable();
    out   = frobenius(ft3).mulMutable(ft3);
    out.b = out.b.negateMutable();
    out   = sqruMutable(out);
    t0    = out.mulMutable(y4).mulMutable(ft2);
    y4    = frobenius(ft1);
    y4.b  = y4.b.negateMutable();
    out   = y4.mulMutable(ft2).mulMutable(t0);
    t0    = t0.mulMutable(y2);
    out   = sqruMutable(sqruMutable(out).mulMutable(t0));
    ff    = sqruMutable(ff.mulMutable(out));
    
    out = out.mulMutable(y0).mulMutable(ff);

    ft1.recycle(); ft2.recycle(); ft3.recycle();
    y0.recycle(); ff.recycle(); t0.recycle(); y2.recycle();
    return out;
  }
  
  /**
   * Factoring f such that the power (q^12 -1)/r can be split into q^6 - 1,
   * q^2 + 1 and (q^4 - q^2 + 1)/r.
   * See section five of "Faster Explicit Formulas for Computing Pairings over
   * Ordinary Curves" (Aranha et al.), page 13.
   * 
   * "On the final exponentiation for calculating pairings on ordinary elliptic
   * curves" (Scott et al.) has some more details.
   * 
   * @param in The {@link Fq12Element} as before the final exponentiation
   * @return The mapped (factored) element
   */
  protected Fq12Element<P> mapToCyclotomicPolynomial(Fq12Element<P> in)
  {
    Fq12Element<P> out = Fq12.getElement(in.a, in.b.negate());
    Fq12Element<P> ininv = in.invert();
    out   = out.mulMutable(ininv);
    Fq12Element<P> xout = frobenius2(out);
    out   = out.mulMutable(xout);
    
    ininv.recycle(); xout.recycle();
    return out;
  }
  
  /**
   * Computes u-th powers in the cyclotomic field of F(q^2),
   * see section 5.2 "Faster Explicit Formulas for Computing Pairings over
   * Ordinary Curves" (Aranha et al.), page 14/15.
   * 
   * Note that there is some weird stuff going on with shared refs in
   * the inner {@link CompressedFq12Element} class, so beware
   * (so out is non-zero at the end of this function ..).
   * 
   * See the three-step guidance on page 15 on how to perform the powering.
   * 
   * @param in The {@link Fq12Element} to compute the power |u| of, being
   *           in^|u| = in^(2^62) * in^(2^55) * in
   * @return in^|u|
   */
  protected Fq12Element<P> fixedPower(Fq12Element<P> in)
  {
    Fq12Element<P> d62 = Fq12.getZeroElement();
    Fq12Element<P> out = Fq12.getZeroElement();
    
    Fq2Element<P>[] c55numdenom, c62numdenom;
    Fq2Element<P> acc;
    CompressedFq12Element c55, c62;
    c55 = new CompressedFq12Element(out, in);

    c55numdenom = c55.square(55).decompressBeforeInversion();

    c62 = new CompressedFq12Element(d62, c55);
    c62numdenom = c62.square(62-55).decompressBeforeInversion();

    acc = c55numdenom[1].mul(c62numdenom[1]).invertMutable();
    Fq2Element<P> tmp = acc.mul(c62numdenom[1]);
    c55.updateG1(c55numdenom[0].mulMutable(tmp));
    c55.decompressAfterInversion();
    tmp.recycle();

    c62.updateG1(c62numdenom[0].mulMutable(acc.mulMutable(c55numdenom[1])));
    c62.decompressAfterInversion();

    out = out.mulMutable(in).mulMutable(d62);
    d62.recycle();
    return out;
  }
  
  /**
   * Squaring F(q^4). There is no separate Fq4Element/Fq4 (yet), since
   * this is the only operation that was needed. This is admittedly sort of
   * a lazy workaround, taking (in1 + in2b) and returning an array of the two
   * Fq4 coefficients, representing (in1 + in2b)^2.
   * 
   * See "High-Speed Software Implementation of the Optimal Ate Pairing over
   * Barreto–Naehrig Curves" (Beuchat et al.), algorithm 9.
   * 
   * @param in1 coefficient 0
   * @param in2 coefficient 1
   * @return (c0 + c1b)^2 in F(q^4)
   */
  @SuppressWarnings({ "rawtypes", "unchecked" })
  protected Fq2Element<P>[] squareFq4(Fq2Element<P> in1, Fq2Element<P> in2)
  {
    // Algorithm 9 [Beuchat et al.]

    Fq2Element<P>[] out = new Fq2Element[2];
    
    Fq2Element<P> t0, t1;
    t0 = in1.square();
    t1 = in2.square();
    out[0] = t1.mulXi().addMutable(t0);
    out[1] = in1.add(in2).squareMutable().subMutable(t0).subMutable(t1);
    
    t0.recycle(); t1.recycle();
    return out;
  }
  
  /**
   * Fast squaring in Res_Fq^6/Fq^2G_phi_6(Fq) (mathematicians...), as done
   * in section 3.2 (F(q^6) as a cubic over a quadratic extension) of
   * "Faster Squaring in the Cyclotomic Subgroup of Sixth Degree Extensions"
   * (Granger, Scott), referenced in section 5.2 of
   * "Faster Explicit Formulas for Computing Pairings over
   * Ordinary Curves" (Aranha et al.), page 14.
   * 
   * @param in the element to square
   * @return in^2
   */
  protected Fq12Element<P> sqruMutable(Fq12Element<P> in)
  {
    Fq2Element<P>[] tmp, tmp2;
    
    tmp     = squareFq4(in.a.a, in.b.b);
    in.a.a = tmp[0].sub(in.a.a).twiceMutable().addMutable(tmp[0]);
    in.b.b = tmp[1].add(in.b.b).twiceMutable().addMutable(tmp[1]);
    tmp     = squareFq4(in.b.a, in.a.c);
    tmp2    = squareFq4(in.a.b, in.b.c);
    in.a.b = tmp[0].sub(in.a.b).twiceMutable().addMutable(tmp[0]);
    in.b.c = tmp[1].add(in.b.c).twiceMutable().addMutable(tmp[1]);
    tmp[0]  = tmp2[1].mulXiMutable();
    in.b.a = tmp[0].add(in.b.a).twiceMutable().addMutable(tmp[0]);
    in.a.c = tmp2[0].sub(in.a.c).twiceMutable().addMutable(tmp2[0]);
    
    tmp[0].recycle(); tmp[1].recycle();
    return in;
  }
  
  /**
   * Frobenius endomorphism (pi_p of algorithm 6 in Aranha et al. and/or
   * algorithm 1 in "High-Speed Software Implementation of the Optimal Ate
   * Pairing over Barreto–Naehrig Curves" by Beuchat et al., see for example
   * section 2 of "Faster Explicit Formulas for Computing Pairings over
   * Ordinary Curves" (Aranha et al.)
   * 
   * pi_p(x, y) = (x^p, y^p)
   * 
   * @param Q The point to map using pi_p
   * @return The mapped point
   */
  protected Point<Fq2Element<P>, Fq2<P>> endoTwist(
      Point<Fq2Element<P>, Fq2<P>> Q)
  {
    Point<Fq2Element<P>, Fq2<P>> Qt = Q.getField().getZeroElement();
    
    Qt.x.a = Q.x.b.mul(W2p.b);
    Qt.x.b = Q.x.a.mul(W2p.b);
    
    Qt.y.a = Q.y.a;
    Qt.y.b = Q.y.b.negate();
    Qt.y   = Qt.y.mulMutable(W3p);
    
    Qt.z = Q.z.getField().getOneElement(); // affine
    return Qt;
  }
  
  /**
   * Frobenius endomorphism (pi_(p^2) of algorithm 6 in Aranha et al. and/or
   * algorithm 1 in "High-Speed Software Implementation of the Optimal Ate
   * Pairing over Barreto–Naehrig Curves" by Beuchat et al., see for example
   * section 2 of "Faster Explicit Formulas for Computing Pairings over
   * Ordinary Curves" (Aranha et al.)
   * 
   * pi_(p^2)(x, y) = (x^(p^2), y^(p^2))
   * 
   * @param Q The point to map using pi_(p^2)
   * @return The mapped point
   */
  protected Point<Fq2Element<P>, Fq2<P>> endoTwist2(
      Point<Fq2Element<P>, Fq2<P>> Q)
  {
    Point<Fq2Element<P>, Fq2<P>> Qt = Q.clone();
    
    Qt.x = Qt.x.mulMutable(Z);
    return Qt;
  }
  
  /**
   * Simple helper that computes (in.y * b, in.x * b) from in (in.x, in.y)
   * 
   * @param x The element to swap and multiply b onto
   * @param b A factor to multiply onto x 
   * 
   * @return (in.y * b, in.x * b) from in (in.x, in.y)
   */
  private Fq2Element<P> mulSwap(Fq2Element<P> x, FqElement<P> b)
  {    
    return Fq2.getElement(x.b.mul(b), x.a.mul(b));
  }
  
  /**
   * Tiny helper to get a projective point from the given G2 affine point.
   * 
   * @param affine The initial affine point
   * 
   * @return The (transformed) projective point
   */
  private Point<Fq2Element<P>, Fq2<P>> toProjectiveFq2(
                                      Point<Fq2Element<P>, Fq2<P>> affine)
  {
    Fq2Element<P> outx = Fq2.getElementFromComponents(
                             affine.x.a.toBigInteger(), 
                             affine.x.b.toBigInteger());
    Fq2Element<P> outy = Fq2.getElementFromComponents(
                             affine.y.a.toBigInteger(),
                             affine.y.b.toBigInteger());
    
    Point<Fq2Element<P>, Fq2<P>> out = 
      new ProjectivePoint<Fq2Element<P>, Fq2<P>>(
          affine.getField(), outx, outy, Fq2.getOneElement());
    
    return out.toProjective();
  }

  /**
   * Tiny helper to get a projective point from the given G1 affine point.
   * 
   * @param affine The initial affine point
   * 
   * @return The (transformed) projective point
   */
  private Point<FqElement<P>, Fq<P>> toProjectiveFq(
                                    Point<FqElement<P>, Fq<P>> affine)
  {
    FqElement<P> outx = Fq.getElementFromComponents(affine.x.toBigInteger());
    FqElement<P> outy = Fq.getElementFromComponents(affine.y.toBigInteger());
    Point<FqElement<P>, Fq<P>> out = 
      new ProjectivePoint<FqElement<P>, Fq<P>>(
          affine.getField(), outx, outy, Fq.getOneElement());
        
    return out.toProjective();
  }
  
  @Override
  public G1<P> getG1()
  {
    return G1;
  }

  @Override
  public G2<P> getG2()
  {
    return G2;
  }

  @Override
  public Fq12<P> getGT()
  {
    return GT;
  }
  
  @Override
  public String toString()
  {
    return "Pairing configuration optimal ate pairing:\n"
         + "t:    " + t    + "\n"
         + "q:    " + q    + "\n"
         + "r:    " + r    + "\n"
         + "b:    " + b    + "\n"
         + "beta: " + beta + "\n"
         + "xi:   " + xi   + "\n"
         + "G1:   " + G1   + "\n"
         + "G2:   " + G2;
  }
  
  /**
   * Compressed Fq12 Element (actually, an element of G_(phi_6)(F(q^2)) but
   * encoded as Fq12.
   * The method was proposed in "Squaring in Cyclotomic Subgroups" (Karabina)
   * and is used in "Faster Explicit Formulas for Computing Pairings over
   * Ordinary Curves" (Aranha et al.), section 5.2, p. 14/15
   * 
   * Note that working with compressed elements <strong>modifies</strong>
   * outer structures. Their immutability accounts only for the provided
   * {@link FieldElement} operations, not for their (intentionally) public
   * members, which are modified in this class.
   * 
   * Furthermore, compressed elements are <strong>mutable</strong>.
   * 
   * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
   * @version 1.0
   */
  protected class CompressedFq12Element
  {
    /** the uncompressed element */
    private Fq12Element<P> z;
    
    /** g1 as in [Aranha et al.] */
    private Fq2Element<P>  g1;
    
    /** g2 as in [Aranha et al.] */
    private Fq2Element<P>  g2;
    
    /** g3 as in [Aranha et al.] */
    private Fq2Element<P>  g3;
    
    /** g4 as in [Aranha et al.] */
    private Fq2Element<P>  g4;
    
    /** g5 as in [Aranha et al.] */
    private Fq2Element<P>  g5;
    
    /**
     * Ctor. After this call, the g's, out and in all point to the same
     * reference. in is just read from and out is just written to.
     * 
     * @param out The element to modify the refs of so it points to in
     * @param in  The element to compress
     * 
     * @see Ate#fixedPower(Fq12Element)
     */
    public CompressedFq12Element(Fq12Element<P> out, Fq12Element<P> in)
    {
      z = out;
      
      g1 = out.b.b;
      g2 = out.b.a = in.b.a;
      g3 = out.a.c = in.a.c;
      g4 = out.a.b = in.a.b;
      g5 = out.b.c = in.b.c; 
    }
    
    /**
     * Ctor. After this call, the g's, out and in all point to the same
     * reference. in is just read from and out is just written to.
     * 
     * @param out The element to modify the refs of so it points to in
     * @param in  The compressed element to copy
     * 
     * @see Ate#fixedPower(Fq12Element)
     */
    public CompressedFq12Element(Fq12Element<P> out, CompressedFq12Element in)
    {   
      z = out;  
            
      g1 = out.b.b;
      g2 = out.b.a = in.g2;
      g3 = out.a.c = in.g3;
      g4 = out.a.b = in.g4;
      g5 = out.b.c = in.g5;
    }
    
    /**
     * squares a this a given amount of times
     * 
     * @param times how often to square
     * 
     * @return this, squared a given amount of times
     */
    public CompressedFq12Element square(int times)
    {
      for(int i = 0; i < times; i++)
        square();
      
      // update refs for z
      z.b.a = g2;
      z.a.c = g3;
      z.a.b = g4;
      z.b.c = g5;
      
      return this;
    }
    
    /**
     * Decompression as shown on page 14 of Aranha et al. Performs the
     * computations for g1, see {@link #decompressAfterInversion()} for
     * the computations for g0.
     * 
     * @return an array consisting of { numerator, denominator } of g1
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public Fq2Element<P>[] decompressBeforeInversion()
    {
      if(g2.isZero())
        return new Fq2Element[] { g4.twice().mulMutable(g5), g3 };
      
      Fq2Element<P> tmp, num, denom;
      
      num   = g5.square();
      denom = num.mulXiMutable();
      num   = g4.square();
      tmp   = num.sub(g3).twiceMutable().addMutable(num);
      num.recycle();
      num   = denom.addMutable(tmp).divByFourMutable();
      denom = g2;
      
      return new Fq2Element[] { num, denom };
    }
    
    /**
     * Decompression as shown on page 14 of Aranha et al. Performs the
     * computations for g0, see {@link #decompressBeforeInversion()} for
     * the computations for g1. Sets g0 (=z) accordingly.
     */
    public void decompressAfterInversion()
    {
      Fq2Element<P> t0 = g1.square();
      Fq2Element<P> t1 = g3.mul(g4);
      
      t0      = t0.subMutable(t1).twiceMutable().subMutable(t1);
      t1      = g2.mul(g5);
      t0      = t0.addMutable(t1);
      z.a.a   = t0.mulXiMutable();
      z.a.a.a = z.a.a.a.addMutable(Fq.getOneElement());
      t1.recycle();
    }
    
    /**
     * Compressed squaring as in Algorithm 8 in
     * "Faster Explicit Formulas for Computing Pairings over
     * Ordinary Curves" (Aranha et al.).
     */
    private void square()
    {
      // Algorithm 8 [Aranha et al.]
      
      Fq2Element<P> t0, t1, t2;
      Fq2DoubleElement<P> T0, T1, T2, T3;
      
      T0 = g4.squareDouble();
      T1 = g5.squareDouble();
      T2 = T1.mulXi();
      T2 = T2.addMutable(T0);
      t2 = T2.mod();
      T2.recycle();
      t0 = g4.add(g5);
      T2 = t0.squareDouble();
      T0 = T0.addMutable(T1);
      T2 = T2.subMutable(T0);
      t0 = T2.mod();
      T2.recycle();
      t1 = g2.add(g3);
      T3 = t1.squareDouble();
      T2 = g2.squareDouble();
      t1 = t0.mulXiMutable();
      g2 = g2.add(t1).twiceMutable().addMutable(t1);
      t1 = t2.sub(g3).twiceMutable();
      T1 = g3.squareDouble();
      g3 = t1.addMutable(t2);
      T0 = T1.mulXi();
      T0 = T0.addMutable(T2);
      t0 = T0.mod();
      g4 = t0.sub(g4).twiceMutable().addMutable(t0);
      T2 = T2.addMutable(T1);
      T3 = T3.subMutable(T2);
      t0 = T3.mod();
      g5 = g5.add(t0).twiceMutable().addMutable(t0);
      
      T0.recycle(); T1.recycle(); T2.recycle(); T3.recycle();
      t0.recycle(); t2.recycle();
    }
    
    /**
     * Updates G1 to a new outer value, updates the corresponding 
     * uncompressed polynomial as well.
     * 
     * @param new_value The new value to set
     */
    public void updateG1(Fq2Element<P> new_value)
    {
      z.b.b = g1 = new_value;
    }
    
    @Override
    public String toString()
    {
      return "Compressed[" + g2 + ", " + g3 + ", " + g4 + ", " + g5 + "]";             
    }
  }
}
