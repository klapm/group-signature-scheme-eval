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

package org.iso200082.common.ecc.api;

import java.math.BigInteger;
import java.util.Random;

import org.iso200082.common.ecc.elements.Fq12Element;
import org.iso200082.common.ecc.elements.Fq2Element;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.CurveField;
import org.iso200082.common.ecc.fields.G1;
import org.iso200082.common.ecc.fields.G2;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.common.ecc.fields.towerextension.Fq12;
import org.iso200082.common.ecc.fields.towerextension.Fq2;


/**
 * Abstract base class for asymmetric pairings. Currently, there is only one 
 * pairing implemented at the moment (opt. Ate).
 *
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public abstract class AsymmetricPairing
<
  P
>
implements Pairing
<
  P,
  Point<FqElement<P>, Fq<P>>, // might not be 'general' enough
  Point<Fq2Element<P>, Fq2<P>>,
  PairingResult<P>
>
{
  /** A {@link Random} instance */
  protected Random rnd;
 
  /** Group G1 of the pairing G2 x G1 -> GT */
  protected G1<P> G1;
  
  /** Group G2 of the pairing G2 x G1 -> GT */
  protected G2<P> G2;

  /** Group GT of the pairing G2 x G1 -> GT */
  protected Fq12<P> GT;
  
  /** The modulus, aka. 'p' in
   * "Pairing Friendly Curves of Prime Order (Barreto, Naehrig) */
  protected BigInteger q;
  
  /** The order, aka. 'n' in
   * "Pairing Friendly Curves of Prime Order (Barreto, Naehrig) */
  protected BigInteger r;
  
  /** Frobenius trace t of the curve, 't' in
   * "Pairing Friendly Curves of Prime Order (Barreto, Naehrig) */
  protected BigInteger t;
  
  /** 'b' as in y^2 = x^3 + b */
  protected BigInteger b;
  
  protected Fq<P> Fq;
  
  /**
   * Ctor, initializes modulus, order, b and the frobenius trace. Does *not*
   * initialize G1, G2, GT as the tower stack might be different.
   * 
   * (you might extend this with 'a')
   * 
   * @param rnd A {@link Random} instance
   * @param q The {@link Fq} modulus
   * @param r The group order
   * @param b 'b' as in y^2 = x^3 + b
   * @param t The frobenius trace
   * @param Fq The base field (used to supply the underlying primitive
   *           implementation)
   */
  public AsymmetricPairing(Random rnd, BigInteger q, BigInteger r, BigInteger b, 
                                       BigInteger t, Fq<P> Fq)
  {
    this.rnd  = rnd;
    this.q    = q;
    this.r    = r;
    this.b    = b;
    this.t    = t;
    this.Fq   = Fq;
  }

  @Override
  public CurveField<FqElement<P>, Fq<P>> getG1()
  {
    return G1;
  }

  @Override
  public CurveField<Fq2Element<P>, Fq2<P>> getG2()
  {
    return G2;
  }

  @Override
  public Field<Fq12Element<P>, Fq12<P>> getGT()
  {
    return GT;
  }

  @Override
  public Random getRandom()
  {
    return rnd;
  }
  
  /**
   * Getter for the base field to use
   * 
   * @return The base field
   */
  public Fq<P> getBaseField()
  {
    return Fq;
  }

}
