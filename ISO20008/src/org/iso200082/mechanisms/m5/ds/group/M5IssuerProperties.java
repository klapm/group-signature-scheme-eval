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

import org.iso200082.mechanisms.m5.parties.M5Issuer;


/**
 * Issuer-relevant properties of the group (group membership issuing key and
 * group public key)
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * @see M5Issuer
 */
public class M5IssuerProperties
{  
  /** The group membership issuing key */
  private M5MembershipIssuingKey gmik;
  
  /** The group's public key */
  private M5PublicKey            gpub;

  /**
   * Ctor, sets the membership issuing key and the public key
   * 
   * @param gmik The membership issuing key
   * @param gpub The public key
   */
  public M5IssuerProperties(M5MembershipIssuingKey gmik, M5PublicKey gpub)
  {
    this.gmik = gmik;
    this.gpub = gpub;
  }

  /**
   * Getter for the membership issuing key
   * @return The membership issuing key
   */
  public M5MembershipIssuingKey getMembershipIssuingKey()
  {
    return this.gmik;
  }

  /**
   * Getter for the public key
   * @return The public key
   */
  public M5PublicKey getPublicKey()
  {
    return this.gpub;
  }

}
