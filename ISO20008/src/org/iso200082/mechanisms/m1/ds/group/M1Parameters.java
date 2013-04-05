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

package org.iso200082.mechanisms.m1.ds.group;

import java.security.MessageDigest;

/**
 * Container class for the group parameters.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * @see M1PrivateProperties
 * @see M1MembershipIssuingKey
 * @see M1Properties
 * @see M1PublicKey
 */
public class M1Parameters
{
  /** Default hash algorithm that's used if none is set */
  public static final String DEFAULT_HASH_ALGORITHM = "SHA-256";
  
  /** lp as denoted in the standard */
  private int    l_p = 0;

  /** k as denoted in the standard */
  private int    k   = 0;
  
  /** lx as denoted in the standard */
  private int    l_x = 0;
  
  /** le as denoted in the standard */
  private int    l_e = 0;
  
  /** lE as denoted in the standard */
  private int    l_E = 0;
  
  /** lX as denoted in the standard */
  private int    l_X = 0;
  
  /** epsilon as denoted in the standard */
  private double eps = 0;
  
  /** the chosen hash algorithm identifier */
  private String hash_algorithm = null;
  
  /**
   * Ctor which defaults to the recommended values as specified
   * in Annex C.2
   */
  public M1Parameters()
  {
    this(null);
  }
  
  /**
   * Ctor which defaults to the recommended parameters as specified
   * in Annex C.2 but leaves the choice for another hash algorithm
   * 
   * @param hash_algorithm Algorithm identifier as used in
   *        {@link MessageDigest#getInstance(String)}
   */
  public M1Parameters(String hash_algorithm)
  {
    this(1024, 160, 160, 170, 420, 410, (double) 5/4, hash_algorithm);
  }
  
  /**
   * Ctor that allows for custom parameters, but uses the default hash
   * algorithm as recommended in Annex C.2.
   * 
   * @param l_p lp as denoted in the standard
   * @param k   k as denoted in the standard
   * @param l_x lx as denoted in the standard
   * @param l_e le as denoted in the standard
   * @param l_E lE as denoted in the standard
   * @param l_X lX as denoted in the standard
   * @param eps epsilon as denoted in the standard
   */
  public M1Parameters(int l_p, int k,   int l_x,
                         int l_e, int l_E, int l_X, double eps)
  {
    this(l_p, k, l_x, l_e, l_E, l_X, eps, null);
  }
  
  /**
   * Ctor that allows for custom parameters.
   * 
   * @param hash_algorithm Algorithm identifier as used in
   *        {@link MessageDigest#getInstance(String)}
   * @param l_p lp as denoted in the standard
   * @param k   k as denoted in the standard
   * @param l_x lx as denoted in the standard
   * @param l_e le as denoted in the standard
   * @param l_E lE as denoted in the standard
   * @param l_X lX as denoted in the standard
   * @param eps epsilon as denoted in the standard
   */
  public M1Parameters(int l_p, int k,   int l_x,
                         int l_e, int l_E, int l_X, double eps,
                         String hash_algorithm)
  {
    this.l_p = l_p;
    this.k   = k;
    this.l_x = l_x;
    this.l_e = l_e;
    this.l_E = l_E;
    this.l_X = l_X;
    this.eps = eps;
    
    if(hash_algorithm == null)
      this.hash_algorithm = DEFAULT_HASH_ALGORITHM;
    else
      this.hash_algorithm = hash_algorithm;
  }

  /**
   * Getter for lp
   * 
   * @return lp
   */
  public int getLp()
  {
    return this.l_p;
  }

  /**
   * Getter for k
   * 
   * @return k
   */
  public int getK()
  {
    return this.k;
  }

  /**
   * Getter for lx
   * 
   * @return lx
   */
  public int getLx()
  {
    return this.l_x;
  }

  /**
   * Getter for le
   * 
   * @return le
   */
  public int getLe()
  {
    return this.l_e;
  }

  /**
   * Getter for lE
   * 
   * @return lE
   */
  public int getLE()
  {
    return this.l_E;
  }

  /**
   * Getter for lX
   * 
   * @return lX
   */
  public int getLX()
  {
    return this.l_X;
  }

  /**
   * Getter for epsilon
   * 
   * @return Epsilon
   */
  public double getEps()
  {
    return this.eps;
  }

  /**
   * Getter for the hash algorithm identifier
   * 
   * @return The hash algorithm identifier
   */
  public String getHashAlgorithm()
  {
    return this.hash_algorithm;
  }
  
  /**
   * Setter for lp
   * @param lp as denoted in the standard
   */
  public void setLp(int lp)
  {
    this.l_p = lp;
  }

  /**
   * Setter for k
   * @param k as denoted in the standard
   */
  public void setK(int k)
  {
    this.k = k;
  }

  /**
   * Setter for lx
   * @param lx as denoted in the standard
   */
  public void setLx(int lx)
  {
    this.l_x = lx;
  }

  /**
   * Setter for le
   * @param le as denoted in the standard
   */
  public void setLe(int le)
  {
    this.l_e = le;
  }

  /**
   * Setter for lE
   * @param lE as denoted in the standard
   */
  public void setLE(int lE)
  {
    this.l_E = lE;
  }

  /**
   * Setter for lX
   * @param lX as denoted in the standard
   */
  public void setLX(int lX)
  {
    this.l_X = lX;
  }

  /**
   * Setter for epsilon
   * @param eps as denoted in the standard
   */
  public void setEps(double eps)
  {
    this.eps = eps;
  }

  /**
   * Setter for the hash algorithm
   * @param hash_algorithm the hash algorithm to use
   */
  public void setHashAlgorithm(String hash_algorithm)
  {
    this.hash_algorithm = hash_algorithm;
  }
}
