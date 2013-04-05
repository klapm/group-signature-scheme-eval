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

/**
 * Container class for group-related properties. These are separated into
 * public and private properties as well as group parameters. * 
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * 
 * @see M1PrivateProperties
 * @see M1Parameters
 * @see M1MembershipIssuingKey
 * @see M1PublicKey
 */
public class M1Properties
{
  /**
   * The group's public key
   */
  protected M1PublicKey  gpub;
  
  /**
   * The group's public parameters
   */
  protected M1Parameters params;
  
  /**
   * The group private properties (membership issuing key, the primes p and q)
   */
  protected M1PrivateProperties gpriv;
  
  /**
   * Ctor, filling in the blanks.
   * 
   * @param params The group's parameters
   * @param gpub   The public key
   * @param gpriv  The private properties
   */
  public M1Properties(M1Parameters params, M1PublicKey gpub, M1PrivateProperties gpriv)
  {
    this.params = params;
    this.gpub   = gpub;
    this.gpriv  = gpriv;
  }
  
  /**
   * Getter for the public key
   * 
   * @return The public key
   */
  public M1PublicKey getPublicKey()
  {
    return gpub;
  }

  /**
   * Getter for the public group parameters
   * @return The public parameters
   */
  public M1Parameters getParameters()
  {
    return params;
  }

  /**
   * Getter for the private properties
   * @return The private properties
   */
  public M1PrivateProperties getPrivateProperties()
  {
    return gpriv;
  }

  /**
   * Getter for the membership issuing key
   * @return The group's membership issuing key
   */
  public M1MembershipIssuingKey getMembershipIssuingKey()
  {
    return gpriv.getGroupMembershipIssuingKey();
  }

}
