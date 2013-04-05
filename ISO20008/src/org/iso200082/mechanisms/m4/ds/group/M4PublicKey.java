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

package org.iso200082.mechanisms.m4.ds.group;

import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.Fq2Element;
import org.iso200082.common.ecc.fields.towerextension.Fq2;

/**
 * The group's public key.
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M4PublicKey
<
  P
>
{
  /** X, named as in the draft standard */
  private Point<Fq2Element<P>, Fq2<P>> X;
  
  /** Y, named as in the draft standard */
  private Point<Fq2Element<P>, Fq2<P>> Y;

  /**
   * Ctor, bundles X and Y.
   * 
   * @param X Named as in the draft standard
   * @param Y Named as in the draft standard
   */
  public M4PublicKey(Point<Fq2Element<P>, Fq2<P>> X,
                     Point<Fq2Element<P>, Fq2<P>> Y)
  {
    this.X = X;
    this.Y = Y;
  }

  /**
   * Getter for X
   * @return X
   */
  public Point<Fq2Element<P>, Fq2<P>> getX()
  {
    return this.X;
  }

  /**
   * Getter for Y
   * @return Y
   */
  public Point<Fq2Element<P>, Fq2<P>> getY()
  {
    return this.Y;
  }

}
