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

package org.iso200082.common.api.revocation;


import java.math.BigInteger;

import org.iso200082.common.api.GroupSignatureScheme;
import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.api.ds.SignatureKey;
import org.iso200082.common.api.exceptions.NotSupportedByRevocationPolicyException;
import org.iso200082.common.api.parties.Signer;

/**
 * Abstract Revocation Policy superclass. Acts as some sort of adapter class
 * that denies all operations if not otherwise overridden by the policy (saves
 * some typing...).
 * See {@link RevocationPolicy} for further documentation of the methods.
 * 
 * @see RevocationPolicy
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public abstract class AbstractRevocationPolicy
implements RevocationPolicy
{
  @Override
  public void setScheme(GroupSignatureScheme scheme)
  {
    // override this if you need the scheme..
  }

  @Override
  public boolean requestBlacklistRevocation(BigInteger bsn, Signature sig)
      throws NotSupportedByRevocationPolicyException
  {
    throw new NotSupportedByRevocationPolicyException("Not supported");
  }

  @Override
  public boolean requestPrivateKeyRevocation(SignatureKey key)
      throws NotSupportedByRevocationPolicyException
  {
    throw new NotSupportedByRevocationPolicyException("Not supported");
  }

  @Override
  public boolean requestSignatureRevocation(Signature sig)
  throws NotSupportedByRevocationPolicyException
  {
    throw new NotSupportedByRevocationPolicyException("Not supported");
  }
  
  @Override
  public boolean isSignatureRevoked(String msg, Signature sig, Signer prover)
  {
    return false;
  }

  @Override
  public boolean isAuthorRevoked(BigInteger bsn, Signature sig)
  {
    return false;
  }

}
