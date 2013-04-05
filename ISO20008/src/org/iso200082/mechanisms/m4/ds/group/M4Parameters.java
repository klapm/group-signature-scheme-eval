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


import java.math.BigInteger;
import java.util.Random;

import org.iso200082.common.ecc.api.AsymmetricPairing;
import org.iso200082.common.ecc.api.Field;
import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.Fq12Element;
import org.iso200082.common.ecc.elements.Fq2Element;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.G1;
import org.iso200082.common.ecc.fields.G2;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.common.ecc.fields.towerextension.Fq12;
import org.iso200082.common.ecc.fields.towerextension.Fq2;
import org.iso200082.mechanisms.m4.M4Scheme;


/**
 * The group's public parameters. Defaults to the recommended values as
 * shown in the draft, but can be altered using the setters.
 * See {@link M4Scheme#parameterize(String, BigInteger)}.
 * 
 * @see M4Scheme
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M4Parameters
<
  P
>
{
  /** Pairing function */
  protected AsymmetricPairing<P> ate;
  
  /** key length. with the current pairing implementation,
   *  only 256 bit are supported */
  protected int t = 256;
  
  /** hash algorithm to use */
  protected String hash_algorithm = "SHA-512";
  
  /** P1 as in the draft, to be set upon group generation */
  protected Point<FqElement<P>, Fq<P>>   P1;

  /** P2 as in the draft, to be set upon group generation */
  protected Point<Fq2Element<P>, Fq2<P>> P2;
  
  /** The field Fq */
  protected Fq<P> Fq;
  
  /**
   * Ctor, sets the pairing implementation
   * 
   * @param ate The (currently one and only) ate pairing implementation
   */
  public M4Parameters(AsymmetricPairing<P> ate)
  {
    this.ate = ate;
    this.Fq  = ate.getBaseField();
  }

  /**
   * Getter for r
   * @return p
   */
  public BigInteger getP()
  {
    return ate.getG1().getOrder();
  }
  
  /**
   * Getter for r
   * @return r
   */
  public BigInteger getR()
  {
    return ate.getG1().getOrder();
  }

  /**
   * Getter for t
   * @return t
   */
  public int getT()
  {
    return t;
  }

  /**
   * Getter for the hash algorithm
   * @return The hash algorithm
   */
  public String getHashAlgorithm()
  {
    return hash_algorithm;
  }

  /**
   * Getter for the pairing map
   * @return The pairing map
   */
  public AsymmetricPairing<P> getPairingMap()
  {
    return ate;
  }

  /**
   * Getter for P1
   * @return P1
   */
  public Point<FqElement<P>, Fq<P>> getP1()
  {
    return P1;
  }

  /**
   * Getter for P2
   * @return P2
   */
  public Point<Fq2Element<P>, Fq2<P>> getP2()
  {
    return P2;
  }

  /**
   * Setter for P1
   * @param pt P1
   */
  public void setP1(Point<FqElement<P>, Fq<P>> pt)
  {
    P1 = pt;
  }

  /**
   * Getter for Fq
   * @return Fq
   */
  public Fq<P> getFq()
  {
    return Fq;
  }

  /**
   * Setter for Fq
   * @param field Fq
   */
  public void setFq(Fq<P> field)
  {
    Fq = field;
  }

  /**
   * Setter for P2
   * @param pt P2
   */
  public void setP2(Point<Fq2Element<P>, Fq2<P>> pt)
  {
    P2 = pt;
  }

  /**
   * Setter for the hash algorithm
   * @param alg The hash algorithm (has to be a valid identifier)
   */
  public void setHashAlgorithm(String alg)
  {
    hash_algorithm = alg;
  }
  
  /**
   * Setter for t
   * @param value t
   */
  public void setT(int value)
  {
    t = value;
  }

  /**
   * Getter for G1, from the pairing map
   * @return G1
   */
  public G1<P> getG1()
  {
    return (G1<P>) ate.getG1();
  }

  /**
   * Getter for G2, from the pairing map
   * @return G2
   */
  public G2<P> getG2()
  {
    return (G2<P>) ate.getG2();
  }

  /**
   * Getter for GT, from the pairing map
   * @return GT
   */
  public Field<Fq12Element<P>, Fq12<P>> getGT()
  {
    return ate.getGT();
  }
  
  /**
   * Getter for the rng
   * 
   * @return The {@link Random} instance
   */
  public Random getRandom()
  {
    return ate.getRandom();
  }
}