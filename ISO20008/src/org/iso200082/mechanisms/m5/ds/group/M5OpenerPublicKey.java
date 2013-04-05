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

package org.iso200082.mechanisms.m5.ds.group;


import java.math.BigInteger;

import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.mechanisms.m5.parties.M5Opener;


/**
 * Represents the opener public key.
 * 
 * @see M5Opener
 * @see M5OpenerProperties
 * @see M5MembershipOpeningKey
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M5OpenerPublicKey
<
  P
>
{
  /** q, named as in the standard */
  private BigInteger q;
  
  /** g, named as in the standard */
  private Point<FqElement<P>, Fq<P>> g;
  
  /** Y1, named as in the standard */
  private Point<FqElement<P>, Fq<P>> Y1;

  /** Y2, named as in the standard */
  private Point<FqElement<P>, Fq<P>> Y2;
  
  /**
   * Ctor, bundles q, g, Y1, Y2
   * @param q  Named as in the standard
   * @param g  Named as in the standard
   * @param Y1 Named as in the standard
   * @param Y2 Named as in the standard
   */
  public M5OpenerPublicKey(BigInteger q,
                           Point<FqElement<P>, Fq<P>> g,
                           Point<FqElement<P>, Fq<P>> Y1,
                           Point<FqElement<P>, Fq<P>> Y2)
  {
    this.q  = q;
    this.g  = g;
    this.Y1 = Y1;
    this.Y2 = Y2;
  }

  /**
   * Getter for q
   * @return q
   */
  public BigInteger getQ()
  {
    return this.q;
  }

  /**
   * Getter for g
   * @return g
   */
  public Point<FqElement<P>, Fq<P>> getG()
  {
    return this.g;
  }

  /**
   * Getter for Y1
   * @return Y1
   */
  public Point<FqElement<P>, Fq<P>> getY1()
  {
    return this.Y1;
  }

  /**
   * Getter for Y2
   * @return Y2
   */
  public Point<FqElement<P>, Fq<P>> getY2()
  {
    return this.Y2;
  }
}
