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

package org.iso200082.mechanisms.m4.revocation;

import org.iso200082.common.api.revocation.AbstractRevocationPolicy;
import org.iso200082.common.api.revocation.RevocationPolicy;
import org.iso200082.mechanisms.m4.parties.M4Verifier;

/**
 * Global signature revocation policy, simply derives from the local one
 * and does not copy state (but uses the same instance) when a duplicate
 * attempt is made.
 * 
 * @see M4Verifier
 * @see RevocationPolicy
 * @see AbstractRevocationPolicy
 * @see M4LocalSignaturePolicy
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M4GlobalSignaturePolicy
<
  P
>
extends M4LocalSignaturePolicy<P>
{  
  @Override
  public RevocationPolicy anewIfLocal()
  {
    return this;
  }
}
