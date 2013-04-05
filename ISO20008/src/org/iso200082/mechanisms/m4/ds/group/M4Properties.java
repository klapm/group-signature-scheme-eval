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

/**
 * The group's overall properties (public and private). 
 *  
 * @see M4PublicKey
 * @see M4MembershipIssuingKey
 * @see M4Parameters
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M4Properties
<
  P
>
{
  /** The group's public key */
  M4PublicKey<P>            gpub;
  
  /** The group's membership issuing key */
  M4MembershipIssuingKey<P> gmik;
  
  /** The group's parameters */
  M4Parameters<P>           gparams;

  /**
   * Ctor, bundles params, public key and membership issuing key
   * 
   * @param gparams The group's public parameters
   * @param gpub    The group's public key
   * @param gmik    The membership issuing key
   */
  public M4Properties(M4Parameters<P>           gparams, M4PublicKey<P> gpub,
                      M4MembershipIssuingKey<P> gmik)
  {
    this.gparams = gparams;
    this.gpub    = gpub;
    this.gmik    = gmik;
  }

  /**
   * Getter for the public key
   * @return The public key
   */
  public M4PublicKey<P> getPublicKey()
  {
    return this.gpub;
  }

  /**
   * Getter for the membership issuing key
   * @return The membership issuing key
   */
  public M4MembershipIssuingKey<P> getMembershipIssuingKey()
  {
    return this.gmik;
  }

  /**
   * Getter for the public parameters
   * @return The public parameters
   */
  public M4Parameters<P> getParameters()
  {
    return this.gparams;
  }

  
}
