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

package org.iso200082.mechanisms.m1.ds;


import java.math.BigInteger;

import org.iso200082.common.api.ds.SignatureKey;
import org.iso200082.common.api.parties.Signer;
import org.iso200082.mechanisms.m1.ds.messages.M1MembershipCredential;
import org.iso200082.mechanisms.m1.parties.M1Signer;


/**
 * Represents a SignatureKey, consisting of a membership credential and
 * a random x (= the private key).
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * @see Signer
 * @see M1Signer
 */
public class M1SignatureKey implements SignatureKey
{
  /** the membership credential of a group member */
  private M1MembershipCredential credential;
  
  /** the private key x */
  private BigInteger private_key;
  
  /**
   * Ctor, initializes the structure.
   * 
   * @param c The membership credential
   * @param x The private key
   */
  public M1SignatureKey(M1MembershipCredential c, BigInteger x)
  {
    private_key = x;
    credential  = c;
  }

  /**
   * Getter for the membership credential
   * 
   * @return The credential
   */
  public M1MembershipCredential getCredential()
  {
    return this.credential;
  }

  /**
   * Getter for the private key
   * 
   * @return The private key
   */
  public BigInteger getPrivateKey()
  {
    return this.private_key;
  }

  /**
   * Alias for {@link #getPrivateKey()}
   * 
   * @return The private key
   */
  public BigInteger getX()
  {
    return getPrivateKey();
  }  

}
