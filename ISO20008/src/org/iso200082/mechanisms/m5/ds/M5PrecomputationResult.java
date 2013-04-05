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

import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.mechanisms.m5.parties.M5Issuer;
import org.iso200082.mechanisms.m5.parties.M5Signer;
import org.iso200082.mechanisms.m5.protocol.M5Protocol;


/**
 * Precomputation result to hold intermediate signature values if enabled.
 * 
 * @see M5Issuer
 * @see M5Signer
 * @see M5Protocol
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M5PrecomputationResult
<
  P
>
{
  /** E0, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> E0          = null;

  /** E1, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> E1          = null;
  
  /** E2, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> E2          = null;
  
  /** VComCipher0, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> VComCipher0 = null;

  /** VComCipher1, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> VComCipher1 = null;

  /** VComCipher2, named as in the draft standard */
  private Point<FqElement<P>, Fq<P>> VComCipher2 = null;

  /** VComMPK, named as in the draft standard */
  private BigInteger                 VComMPK     = null;
  
  /** VComRev, named as in the draft standard */
  private BigInteger                 VComRev     = null;
  
  /** A_COM, named as in the draft standard */
  private BigInteger                 A_COM       = null;

  /** B_COM, named as in the draft standard */
  private BigInteger                 B_COM       = null;

  /** s, named as in the draft standard */
  private BigInteger                 s           = null;

  /** t, named as in the draft standard */
  private BigInteger                 t           = null;

  /** mu_x, named as in the draft standard */
  private BigInteger                 mu_x        = null;

  /** mu_s, named as in the draft standard */
  private BigInteger                 mu_s        = null;

  /** mu_e', named as in the draft standard */
  private BigInteger                 mu_eprime   = null;

  /** mu_E, named as in the draft standard */
  private BigInteger                 mu_E        = null;

  /** mu_t, named as in the draft standard */
  private BigInteger                 mu_t        = null;

  /** rho_E, named as in the draft standard */
  private BigInteger                 rho_E       = null;
  
  /**
   * Ctor, initializes the structure.
   * 
   * @param E0          Named as in the draft
   * @param E1          Named as in the draft
   * @param E2          Named as in the draft
   * @param VComCipher0 Named as in the draft
   * @param VComCipher1 Named as in the draft
   * @param VComCipher2 Named as in the draft
   * @param VComMPK     Named as in the draft
   * @param VComRev     Named as in the draft
   * @param A_COM       Named as in the draft
   * @param B_COM       Named as in the draft
   * @param s           Named as in the draft
   * @param t           Named as in the draft
   * @param mu_x        Named as in the draft
   * @param mu_s        Named as in the draft
   * @param mu_eprime   Named as in the draft
   * @param mu_E        Named as in the draft
   * @param mu_t        Named as in the draft
   * @param rho_E       Named as in the draft
   */
  public M5PrecomputationResult(Point<FqElement<P>, Fq<P>> E0,
                                Point<FqElement<P>, Fq<P>> E1,
                                Point<FqElement<P>, Fq<P>> E2,
                                Point<FqElement<P>, Fq<P>> VComCipher0,
                                Point<FqElement<P>, Fq<P>> VComCipher1,
                                Point<FqElement<P>, Fq<P>> VComCipher2,
                                BigInteger                 VComMPK,
                                BigInteger                 VComRev,
                                BigInteger                 A_COM,
                                BigInteger                 B_COM,
                                BigInteger                 s,
                                BigInteger                 t,
                                BigInteger                 mu_x,
                                BigInteger                 mu_s,
                                BigInteger                 mu_eprime,
                                BigInteger                 mu_E,
                                BigInteger                 mu_t,
                                BigInteger                 rho_E  )
  {
    // darn nice parameter list .. *ieeh*
    this.E0          = E0;
    this.E1          = E1;
    this.E2          = E2;
    this.VComCipher0 = VComCipher0;
    this.VComCipher1 = VComCipher1;
    this.VComCipher2 = VComCipher2;
    this.VComMPK     = VComMPK;
    this.VComRev     = VComRev;
    this.A_COM       = A_COM;
    this.B_COM       = B_COM;
    this.s           = s;
    this.t           = t;
    this.mu_x        = mu_x;
    this.mu_s        = mu_s;
    this.mu_eprime   = mu_eprime;
    this.mu_E        = mu_E;
    this.mu_t        = mu_t;
    this.rho_E       = rho_E;
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
   * Getter for VComCipher0
   * @return VComCipher0
   */
  public Point<FqElement<P>, Fq<P>> getVComCipher0()
  {
    return this.VComCipher0;
  }

  /**
   * Getter for VComCipher1
   * @return VComCipher1
   */
  public Point<FqElement<P>, Fq<P>> getVComCipher1()
  {
    return this.VComCipher1;
  }

  /**
   * Getter for VComCipher2
   * @return VComCipher2
   */
  public Point<FqElement<P>, Fq<P>> getVComCipher2()
  {
    return this.VComCipher2;
  }

  /**
   * Getter for VComMPK
   * @return VComMPK
   */
  public BigInteger getVComMPK()
  {
    return this.VComMPK;
  }

  /**
   * Getter for VComRev
   * @return VComRev
   */
  public BigInteger getVComRev()
  {
    return this.VComRev;
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
   * Getter for s
   * @return s
   */
  public BigInteger getS()
  {
    return this.s;
  }

  /**
   * Getter for t
   * @return t
   */
  public BigInteger getT()
  {
    return this.t;
  }

  /**
   * Getter for mu_x
   * @return mu_x
   */
  public BigInteger getMuX()
  {
    return this.mu_x;
  }

  /**
   * Getter for mu_s
   * @return mu_s
   */
  public BigInteger getMuS()
  {
    return this.mu_s;
  }

  /**
   * Getter for mu_e'
   * @return mu_e'
   */
  public BigInteger getMuEPrime()
  {
    return this.mu_eprime;
  }

  /**
   * Getter for mu_E
   * @return mu_E
   */
  public BigInteger getMuE()
  {
    return this.mu_E;
  }

  /**
   * Getter for mu_t
   * @return mu_t
   */
  public BigInteger getMuT()
  {
    return this.mu_t;
  }

  /**
   * Getter for rho_E
   * @return rho_E
   */
  public BigInteger getRhoE()
  {
    return this.rho_E;
  }
}
