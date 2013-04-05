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
import java.util.Random;

import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.CurveField;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.common.util.IntegerUtil;
import org.iso200082.mechanisms.m5.M5Scheme;


/**
 * Represents the group's public parameters. The parameters default
 * to the recommended settings as provided in the draft standard, but can
 * be parameterized using the setters.
 * See {@link M5Scheme#parameterize(String, BigInteger)}.
 * 
 * Note that the group G in which the DDH assumption is supposed to hold
 * is hardcoded in here for now, but can be altered using the parameterization.
 * 
 * @see M5Scheme
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M5Parameters<P>
{
  /** Kn, named as in the standard */
  protected int    Kn                   = 1024;

  /** K, named as in the standard */
  protected int    K                    = 160;

  /** Kc, named as in the standard */
  protected int    Kc                   = 160;
  
  /** Ks, named as in the standard */
  protected int    Ks                   = 60;

  /** Ke, named as in the standard */
  protected int    Ke                   = 504;

  /** Ke', named as in the standard */
  protected int    Keprime              = 60;

  /** m, named as in the standard */
  protected int    m                    = 10;

  /** The hash algorithm to use */
  protected String hash_algorithm       = "SHA-1";
  
  /** q, named as in the standard */
  protected BigInteger q                = getGroupGOrder();

  /** G, named as in the standard */
  protected CurveField<FqElement<P>, Fq<P>> G;

  /** Zq, named as in the standard */
  protected Fq<P> Zq;
   
  /**
   * Ctor, sets up the groups Zq and G
   * 
   * @param Fq  The field to use
   * @param rnd a {@link Random} instance
   * @param mixed_mode Whether or not to use a coordinate mix in point mult.
   */
  public M5Parameters(Random rnd, Fq<P> Fq, boolean mixed_mode)
  {
    Zq = Fq.getNonMontgomery(getGroupGOrder());
    G  = getGroupG(rnd, Zq, mixed_mode);
  }
  
  /**
   * Getter for the (hard-coded) group order
   * @return The order of G
   */
  public static BigInteger getGroupGOrder()
  {
    return IntegerUtil.fromHexString(
        "B32DF688 513664AE 1141034A E8E96559 1DA38F43"
        );
  }
  
  /**
   * Getter for the (hard-coded) group G
   * 
   * @param rnd a {@link Random} instance
   * @param field The internal Zq field
   * @param mixed_mode Whether or not to use a coordinate mix in point mult.
   * 
   * @return A representation of the group G
   */
  public static <P> CurveField<FqElement<P>, Fq<P>>
  getGroupG(Random rnd, Fq<P> field, boolean mixed_mode)
  {
    return new CurveField<FqElement<P>, Fq<P>>(rnd, 
        field,
        field.getElementFromComponents(16, "A559B0E0588FEDF752A8" +
                                           "E99066E6F28FA2A81926"),
        field.getElementFromComponents(16, "7C1EA8D284973DDF71E4" +
                                           "782CA06ABF7D8535B163"),
        getGroupGOrder(), BigInteger.ONE, mixed_mode
   );
  }
  
  /**
   * Getter for Kn
   * @return Kn
   */
  public int getKn()
  {
    return this.Kn;
  }

  /**
   * Setter for Kn
   * @param kn Named as in the draft standard
   */
  public void setKn(int kn)
  {
    this.Kn = kn;
  }

  /**
   * Getter for K
   * @return K
   */
  public int getK()
  {
    return this.K;
  }

  /**
   * Setter for K
   * @param k Named as in the draft standard
   */
  public void setK(int k)
  {
    this.K = k;
  }

  /**
   * Getter for Kc
   * @return Kc
   */
  public int getKc()
  {
    return this.Kc;
  }

  /**
   * Setter for Kc
   * @param kc Named as in the draft standard
   */
  public void setKc(int kc)
  {
    this.Kc = kc;
  }

  /**
   * Getter for Ks
   * @return Ks
   */
  public int getKs()
  {
    return this.Ks;
  }

  /**
   * Setter for Ks
   * @param ks Named as in the draft standard
   */
  public void setKs(int ks)
  {
    this.Ks = ks;
  }

  /**
   * Getter for Ke
   * @return Ke
   */
  public int getKe()
  {
    return this.Ke;
  }

  /**
   * Setter for Ke
   * @param ke Named as in the draft standard
   */
  public void setKe(int ke)
  {
    this.Ke = ke;
  }

  /**
   * Getter for Ke'
   * @return Ke'
   */
  public int getKeprime()
  {
    return this.Keprime;
  }

  /**
   * Setter for Ke'
   * @param keprime Named as in the draft standard
   */
  public void setKeprime(int keprime)
  {
    this.Keprime = keprime;
  }

  /**
   * Getter for the hash algorithm
   * @return The hash algorithm
   */
  public String getHashAlgorithm()
  {
    return this.hash_algorithm;
  }

  /**
   * Setter for the hash algorithm to use
   * @param hash_algorithm the hash algorithm to use (has to be a valid
   * identifier)
   */
  public void setHashAlgorithm(String hash_algorithm)
  {
    this.hash_algorithm = hash_algorithm;
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
   * Setter for Q
   * @param q Named as in the draft standard
   */
  public void setQ(BigInteger q)
  {
    this.q = q;
  }

  /**
   * Getter for G
   * @return G
   */
  public CurveField<FqElement<P>, Fq<P>> getG()
  {
    return this.G;
  }

  /**
   * Setter for G
   * @param g The group G
   */
  public void setG(CurveField<FqElement<P>, Fq<P>> g)
  {
    this.G = g;
  }

  /**
   * Getter for Zq
   * @return Zq
   */
  public Fq<P> getZq()
  {
    return this.Zq;
  }

  /**
   * Setter for Zq
   * @param zq Named as in the draft standard
   */
  public void setZq(Fq<P> zq)
  {
    this.Zq = zq;
  }

  /**
   * Getter for m
   * @return m
   */
  public int getM()
  {
    return this.m;
  }

  /**
   * Setter for m
   * @param m Named as in the draft standard
   */
  public void setM(int m)
  {
    this.m = m;
  }
  
}
