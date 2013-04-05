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

package org.iso200082.mechanisms.m5.ds;


import java.math.BigInteger;

import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.mechanisms.m5.parties.M5Signer;
import org.iso200082.mechanisms.m5.parties.M5Verifier;


/**
 * Represents a mechanism five signature
 * 
 * @see M5Signer
 * @see M5Verifier
 * 
 * @param <P> The primitive Type to use
 *  
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M5Signature
<
  P
>
implements Signature
{
  /** E0, named as in the standard */
  private Point<FqElement<P>, Fq<P>> E0;

  /** E1, named as in the standard */
  private Point<FqElement<P>, Fq<P>> E1;

  /** E2, named as in the standard */
  private Point<FqElement<P>, Fq<P>> E2;

  /** A_COM, named as in the standard */
  private BigInteger A_COM;

  /** B_COM, named as in the standard */
  private BigInteger B_COM;

  /** c, named as in the standard */
  private BigInteger c;

  /** tau_x, named as in the standard */
  private BigInteger tau_x;
  
  /** tau_s, named as in the standard */  
  private BigInteger tau_s;

  /** tau_t, named as in the standard */
  private BigInteger tau_t;

  /** tau_e', named as in the standard */
  private BigInteger tau_eprime;

  /** tau_E, named as in the standard */
  private BigInteger tau_E;

  /**
   * Ctor, compiles a signature from all that attributes
   * @param E0 Named as in the standard
   * @param E1 Named as in the standard
   * @param E2 Named as in the standard
   * @param A_COM Named as in the standard
   * @param B_COM Named as in the standard
   * @param c Named as in the standard
   * @param tau_x Named as in the standard
   * @param tau_s Named as in the standard
   * @param tau_t Named as in the standard
   * @param tau_eprime Named as in the standard
   * @param tau_E Named as in the standard
   */
  public M5Signature(Point<FqElement<P>, Fq<P>> E0,
                     Point<FqElement<P>, Fq<P>> E1,
                     Point<FqElement<P>, Fq<P>> E2,
                     BigInteger A_COM, BigInteger B_COM,
                     BigInteger c,
                     BigInteger tau_x, BigInteger tau_s,
                     BigInteger tau_t, BigInteger tau_eprime,
                     BigInteger tau_E)
  {
    this.E0         = E0;
    this.E1         = E1;
    this.E2         = E2;
    this.A_COM      = A_COM;
    this.B_COM      = B_COM;
    this.c          = c;
    this.tau_x      = tau_x;
    this.tau_s      = tau_s;
    this.tau_t      = tau_t;
    this.tau_eprime = tau_eprime;
    this.tau_E      = tau_E;
  }

  /**
   * Getter for c
   * @return c
   */
  public BigInteger getC()
  {
    return this.c;
  }

  /**
   * Getter for E0
   * @return E0
   */
  public Point<FqElement<P>, Fq<P>> getE0()
  {
    return this.E0;
  }

  /**
   * Getter for E1
   * @return E1
   */
  public Point<FqElement<P>, Fq<P>> getE1()
  {
    return this.E1;
  }

  /**
   * Getter for E2
   * @return E2
   */
  public Point<FqElement<P>, Fq<P>> getE2()
  {
    return this.E2;
  }

  /**
   * Getter for A_COM
   * @return A_COM
   */
  public BigInteger getACOM()
  {
    return this.A_COM;
  }


  /**
   * Getter for B_COM
   * @return B_COM
   */
  public BigInteger getBCOM()
  {
    return this.B_COM;
  }


  /**
   * Getter for tau x
   * @return tau x
   */
  public BigInteger getTauX()
  {
    return this.tau_x;
  }

  /**
   * Getter for tau s
   * @return tau s
   */
  public BigInteger getTauS()
  {
    return this.tau_s;
  }

  /**
   * Getter for tau t
   * @return tau t
   */
  public BigInteger getTauT()
  {
    return this.tau_t;
  }

  /**
   * Getter for tau e'
   * @return tau e'
   */
  public BigInteger getTauEPrime()
  {
    return this.tau_eprime;
  }

  /**
   * Getter for tau E
   * @return tau E
   */
  public BigInteger getTauE()
  {
    return this.tau_E;
  }

}
