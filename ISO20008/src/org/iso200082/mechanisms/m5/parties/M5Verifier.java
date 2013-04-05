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

package org.iso200082.mechanisms.m5.parties;


import java.math.BigInteger;

import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.api.ds.SignatureKey;
import org.iso200082.common.api.exceptions.NotSupportedByRevocationPolicyException;
import org.iso200082.common.api.parties.Signer;
import org.iso200082.common.api.parties.Verifier;
import org.iso200082.common.api.revocation.RevocationPolicy;
import org.iso200082.common.util.Util;
import org.iso200082.mechanisms.m5.M5Scheme;
import org.iso200082.mechanisms.m5.ds.M5Signature;
import org.iso200082.mechanisms.m5.protocol.M5Protocol;


/**
 * Mechanism 5 Verifier.
 *  
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * 
 * @param <P> The primitive Type to use
 * 
 * @see M5Issuer
 * @see M5Signer
 * @see RevocationPolicy
 * @see M5Signature
 */
public class M5Verifier
<
  P
>
implements Verifier
{
  /** The corresponding {@link M5Scheme} instance */
  protected M5Scheme<P>      scheme;
  
  /** The revocation policy to enforce (more of a placeholder as there is only 
   * credential update and this is done on issuer side)*/
  protected RevocationPolicy policy;

  /**
   * Ctor, creates a new verifier
   * 
   * @param scheme The corresponding {@link M5Scheme} instance
   * @param policy The {@link RevocationPolicy} to enforce
   */
  public M5Verifier(M5Scheme<P> scheme, RevocationPolicy policy)
  {
    this.scheme = scheme;
    this.policy = policy;
  }

  @Override
  public boolean isSignatureValid(String message, BigInteger linking_base,
      Signature signature)
  {
    return isSignatureValid(message, signature);
  }
  
  @Override
  @SuppressWarnings("unchecked")
  public boolean isSignatureValid(String message, Signature signature)
  {
    if(Util.isAnyNull(message, signature))
      return false;
    
    if(!(signature instanceof M5Signature))
      return false;
            
    return M5Protocol.verifySignature(message, (M5Signature<P>) signature,
           scheme.getParameters(), scheme.getPublicKey(),
           scheme.getOpenerPublicKey());
  }

  @Override
  public boolean isSignatureValid(String message, BigInteger linking_base,
                                  Signature signature, Signer signer)
  {
    // that body is for signature-based revocation, see Mechanism 4
    return isSignatureValid(message, signature);
  }

  @Override
  public boolean blacklist(BigInteger bsn, Signature sig)
  throws NotSupportedByRevocationPolicyException
  {
    return policy.requestBlacklistRevocation(bsn, sig);
  }

  @Override
  public boolean revokeKey(SignatureKey key)
  throws NotSupportedByRevocationPolicyException
  {
    return policy.requestPrivateKeyRevocation(key);
  }

  @Override
  public boolean revokeSignature(Signature sig)
  throws NotSupportedByRevocationPolicyException
  {
    return policy.requestSignatureRevocation(sig);
  }

}
