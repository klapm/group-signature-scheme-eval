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

package org.iso200082.mechanisms.m4.parties;


import java.math.BigInteger;

import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.api.ds.SignatureKey;
import org.iso200082.common.api.exceptions.NotSupportedByMechanismException;
import org.iso200082.common.api.exceptions.NotSupportedByRevocationPolicyException;
import org.iso200082.common.api.parties.Signer;
import org.iso200082.common.api.parties.Verifier;
import org.iso200082.common.api.revocation.RevocationPolicy;
import org.iso200082.common.api.revocation.RevocationPolicy.RevocationType;
import org.iso200082.mechanisms.m4.M4Scheme;
import org.iso200082.mechanisms.m4.ds.M4Signature;
import org.iso200082.mechanisms.m4.protocol.M4Protocol;


/**
 * Mechanism four verifier
 * 
 * @see M4Signer
 * @see M4Scheme
 * @see RevocationPolicy
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M4Verifier
<
  P
>
implements Verifier
{
  /** The corresponding scheme */
  protected M4Scheme<P> scheme;
  
  /** The revocation policy to use */
  protected RevocationPolicy policy;
  
  /**
   * Ctor, creates a new verifier using the public values from scheme and
   * the given revocation policy
   * 
   * @param scheme The corresponding group signature scheme
   * @param policy The revocation policy to use
   */
  public M4Verifier(M4Scheme<P> scheme, RevocationPolicy policy)
  {
    this.scheme = scheme;
    this.policy = policy;
  }

  @Override
  public boolean isSignatureValid(String message, BigInteger linking_base, Signature signature)
  {
    if(policy.getRevocationType() == RevocationType.LOCAL_SIGNATURE_REVOCATION ||
       policy.getRevocationType() == RevocationType.GLOBAL_SIGNATURE_REVOCATION)
      return false; // needs the other call.

    if(policy.isAuthorRevoked(linking_base, signature))
      return false;
    
    return verifySignature(message, linking_base, signature);
  }

  @Override
  public boolean isSignatureValid(String message, BigInteger linking_base, Signature signature, Signer prover)
  {
    if(policy.isSignatureRevoked(message, signature, prover))
      return false;

    return verifySignature(message, linking_base, signature);
  }
  
  @Override
  public boolean isSignatureValid(String message, Signature signature)
  throws NotSupportedByMechanismException
  {
    throw new NotSupportedByMechanismException(
        "Provision of linking base is required for this mechanism");
  }
  
  protected boolean verifySignature(String message, BigInteger linking_base, Signature signature)
  {
    if(!(signature instanceof M4Signature))
      return false;
    
    @SuppressWarnings("unchecked")
    M4Signature<P> sig = (M4Signature<P>) signature;
    
    return M4Protocol.verifySignature(message.getBytes(), linking_base, sig,
                                      scheme.getParameters(),
                                      scheme.getPublicKey());
  }

  @Override
  public boolean blacklist(BigInteger bsn, Signature sig) throws NotSupportedByRevocationPolicyException
  {
    return policy.requestBlacklistRevocation(bsn, sig);
  }
  
  @Override
  public boolean revokeKey(SignatureKey key) throws NotSupportedByRevocationPolicyException
  {
    return policy.requestPrivateKeyRevocation(key);
  }

  @Override
  public boolean revokeSignature(Signature sig) throws NotSupportedByRevocationPolicyException
  {
    return policy.requestSignatureRevocation(sig);
  }

}
