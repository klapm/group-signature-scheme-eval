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

package org.iso200082.mechanisms.m5.ds.messages;

import java.math.BigInteger;

import org.iso200082.mechanisms.m5.parties.M5Issuer;
import org.iso200082.mechanisms.m5.parties.M5Signer;

/**
 * Represents a join challenge that gets sent from the issuer in response
 * to the initial join request.
 * 
 * @see M5JoinRequest
 * @see M5JoinResponse
 * @see M5Issuer
 * @see M5Signer
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M5JoinChallenge
{
  /** x'', named as in the standard */
  private BigInteger x_dblprime;

  /**
   * Ctor, wraps x''
   * 
   * @param x_dblprime Named as in the standard
   */
  public M5JoinChallenge(BigInteger x_dblprime)
  {
    this.x_dblprime = x_dblprime;
  }

  /**
   * Getter for x''
   * @return x''
   */
  public BigInteger getX()
  {
    return this.x_dblprime;
  }

}
