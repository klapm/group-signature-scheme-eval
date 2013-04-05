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

import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.mechanisms.m4.parties.M4Linker;
import org.iso200082.mechanisms.m4.parties.M4Signer;
import org.iso200082.mechanisms.m4.parties.M4Verifier;

/**
 * Represents a signature for mechanism 4.
 * 
 * @see M4Verifier
 * @see M4Signer
 * @see Signature
 * @see M4Linker
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M4Signature
<
  P
>
implements Signature
{
  /** R, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> R;

  /** S, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> S;

  /** T, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> T;

  /** W, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> W;

  /** J, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> J;

  /** K, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> K;

  /** h, named as in the draft standard */
  private FqElement<P> h;

  /** s, named as in the draft standard */
  private FqElement<P> s;

  /** nV, named as in the draft standard */
  private byte[] nV;

  /** nT, named as in the draft standard */
  private byte[] nT;
  
  /**
   * Ctor, compiles all signature's attributes to one signature instance
   * 
   * @param precomp the precomputed signature part
   * @param h  Named as in the draft standard
   * @param s  Named as in the draft standard
   * @param nV Named as in the draft standard
   * @param nT Named as in the draft standard
   */
  public M4Signature(M4PrecomputationResult<P> precomp,
                     FqElement<P> h, FqElement<P> s,
                     byte[] nV, byte[] nT)
  {
    this.R  = precomp.getR();
    this.S  = precomp.getS();
    this.T  = precomp.getT();
    this.W  = precomp.getW();
    this.J  = precomp.getJ();
    this.K  = precomp.getK();
    this.h  = h;
    this.s  = s;
    this.nV = nV;
    this.nT = nT;
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
   * Getter for J
   * @return J
   */
  public Point<FqElement<P>, Fq<P>> getJ()
  {
    return this.J;
  }

  /**
   * Getter for K
   * @return K
   */
  public Point<FqElement<P>, Fq<P>> getK()
  {
    return this.K;
  }

  /**
   * Getter for h
   * @return h
   */
  public FqElement<P> getH()
  {
    return this.h;
  }

  /**
   * Getter for s
   * @return s
   */
  public FqElement<P> getSElement()
  {
    return this.s;
  }

  /**
   * Getter for nV
   * @return nV
   */
  public byte[] getNv()
  {
    return this.nV;
  }

  /**
   * Getter for nT
   * @return nT
   */
  public byte[] getNt()
  {
    return this.nT;
  }

}
