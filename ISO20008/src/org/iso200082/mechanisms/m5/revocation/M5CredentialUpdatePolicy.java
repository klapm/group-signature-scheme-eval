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

package org.iso200082.mechanisms.m5.revocation;

import org.iso200082.common.api.parties.Signer;
import org.iso200082.common.api.revocation.AbstractRevocationPolicy;
import org.iso200082.common.api.revocation.RevocationPolicy;
import org.iso200082.mechanisms.m5.parties.M5Issuer;

/**
 * Sort of a hack as the credential update policy grips on issuer side.
 * It is more like an empty class that just states its a credential update
 * policy so that the issuer can take action. No more logic in here, but
 * in {@link M5Issuer#doCredentialUpdate(Signer...)}.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * @see M5Issuer
 * @see RevocationPolicy
 * @see AbstractRevocationPolicy
 */
public class M5CredentialUpdatePolicy extends AbstractRevocationPolicy
{
  @Override
  public RevocationType getRevocationType()
  {
    return RevocationType.GLOBAL_CREDENTIAL_UPDATE_REVOCATION; 
  }

  @Override
  public RevocationPolicy anewIfLocal()
  {
    return this;
  }

}
