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

package org.iso200082.mechanisms.m4.ds;

import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.mechanisms.m4.parties.M4Issuer;
import org.iso200082.mechanisms.m4.parties.M4Signer;
import org.iso200082.mechanisms.m4.protocol.M4Protocol;

/**
 * Precomputation result to hold intermediate signature values if enabled.
 * 
 * @see M4Issuer
 * @see M4Signer
 * @see M4Protocol
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M4PrecomputationResult
<
  P
>
{

  /** R, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> R;

  /** S, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> S;
  
  /** T, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> T;
  
  /** W, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> W;

  /** R1, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> R1;
  
  /** R2, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> R2;

  /** K, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> K;

  /** J, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> J;
  
  private FqElement<P> r;  
  
  /**
   * Ctor, initializes the structure.
   * 
   * @param R Named as in the draft
   * @param S Named as in the draft
   * @param T Named as in the draft
   * @param W Named as in the draft
   */
  public M4PrecomputationResult(Point<FqElement<P>, Fq<P>> R,
                                Point<FqElement<P>, Fq<P>> S,
                                Point<FqElement<P>, Fq<P>> T,
                                Point<FqElement<P>, Fq<P>> W)
  {
    this.R = R;
    this.S = S;
    this.T = T;
    this.W = W;
  }

  /**
   * Getter for R
   * @return R
   */
  public Point<FqElement<P>, Fq<P>> getR()
  {
    return this.R;
  }

  /**
   * Getter for S
   * @return S
   */
  public Point<FqElement<P>, Fq<P>> getS()
  {
    return this.S;
  }

  /**
   * Getter for T
   * @return T
   */
  public Point<FqElement<P>, Fq<P>> getT()
  {
    return this.T;
  }

  /**
   * Getter for W
   * @return W
   */
  public Point<FqElement<P>, Fq<P>> getW()
  {
    return this.W;
  }
   
  /**
   * Setter for R1
   * 
   * @param r1 The new value for R1
   */
  public void setR1(Point<FqElement<P>, Fq<P>> r1)
  {
    this.R1 = r1;
  }

  /**
   * Setter for R2
   * 
   * @param r2 The new value for R2
   */
  public void setR2(Point<FqElement<P>, Fq<P>> r2)
  {
    this.R2 = r2;
  }

  /**
   * Setter for K
   * 
   * @param k The new value for K
   */
  public void setK(Point<FqElement<P>, Fq<P>> k)
  {
    this.K = k;
  }

  /**
   * Setter for J
   * 
   * @param j The new value for J
   */
  public void setJ(Point<FqElement<P>, Fq<P>> j)
  {
    this.J = j;
  }

  /**
   * Setter for r
   * 
   * @param r The new value for r
   */
  public void setRandomR(FqElement<P> r)
  {
    this.r = r;
  }

  /**
   * Getter for K
   * 
   * @return K
   */
  public Point<FqElement<P>, Fq<P>> getK()
  {
    return this.K;
  }

  /**
   * Getter for R1
   * 
   * @return R1
   */
  public Point<FqElement<P>, Fq<P>> getR1()
  {
    return this.R1;
  }

  /**
   * Getter for R2
   * 
   * @return R2
   */
  public Point<FqElement<P>, Fq<P>> getR2()
  {
    return this.R2;
  }

  /**
   * Getter for J
   * 
   * @return J
   */
  public Point<FqElement<P>, Fq<P>> getJ()
  {
    return this.J;
  }

  /**
   * Getter for r
   * 
   * @return r
   */
  public FqElement<P> getRandomR()
  {
    return r;
  }
  
}
