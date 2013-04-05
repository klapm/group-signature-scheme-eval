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

package org.iso200082.mechanisms.m1.revocation;

import org.iso200082.common.api.revocation.AbstractRevocationPolicy;
import org.iso200082.common.api.revocation.RevocationPolicy;
import org.iso200082.mechanisms.m1.parties.M1Verifier;

/**
 * Global private key revocation, hands requests to the issuer who stores
 * the global revocation state.
 * 
 * @see RevocationPolicy
 * @see AbstractRevocationPolicy
 * @see M1Verifier
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M1GlobalPrivateKeyPolicy extends M1LocalPrivateKeyPolicy
{
  @Override
  public RevocationPolicy anewIfLocal()
  {
    return this;
  }
}
