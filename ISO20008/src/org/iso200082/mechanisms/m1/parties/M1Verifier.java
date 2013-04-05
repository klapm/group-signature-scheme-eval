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

package org.iso200082.mechanisms.m1.parties;


import java.math.BigInteger;

import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.api.ds.SignatureKey;
import org.iso200082.common.api.exceptions.NotSupportedByMechanismException;
import org.iso200082.common.api.exceptions.NotSupportedByRevocationPolicyException;
import org.iso200082.common.api.parties.Signer;
import org.iso200082.common.api.parties.Verifier;
import org.iso200082.common.api.revocation.RevocationPolicy;
import org.iso200082.common.util.Util;
import org.iso200082.mechanisms.m1.M1Scheme;
import org.iso200082.mechanisms.m1.ds.M1Signature;
import org.iso200082.mechanisms.m1.protocol.M1Protocol;


/**
 * Verifying party implementation. Instantiated using a revocation policy
 * ({@link RevocationPolicy}). 
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * @see M1Signer
 * @see RevocationPolicy
 */
public class M1Verifier implements Verifier
{
  protected M1Scheme scheme;
  
  /** revocation policy */
  protected RevocationPolicy policy = null;
  
  /**
   * Ctor, sets scheme and revocation policy.
   * 
   * @param scheme The corresponding scheme
   * @param policy The {@link RevocationPolicy} to use
   */
  public M1Verifier(M1Scheme scheme, RevocationPolicy policy)
  {
    this.scheme = scheme;
    this.policy = policy;
  }

  @Override
  public boolean isSignatureValid(String message, BigInteger linking_base,
      Signature signature)
  {
    if(Util.isAnyNull(message, linking_base, signature))
      return false;
    
    if(!(signature instanceof M1Signature))
      return false;
    
    // revocation check
    if(policy.isAuthorRevoked(linking_base, signature))
      return false;

    return M1Protocol.verifySignature(message,
                      linking_base, (M1Signature) signature,
                      scheme.getPublicKey(), scheme.getParameters());
  }

  @Override
  public boolean isSignatureValid(String message, BigInteger linking_base,
      Signature signature, Signer signer)
  {
    // that body is for signature-based revocation, see Mechanism 4
    return isSignatureValid(message, linking_base, signature);
  }

  @Override
  public boolean isSignatureValid(String message, Signature signature)
  throws NotSupportedByMechanismException
  {
    throw new NotSupportedByMechanismException(
        "Provision of linking base is required for this mechanism");
  }

  @Override
  public boolean blacklist(BigInteger bsn, Signature sig)
  throws NotSupportedByRevocationPolicyException
  {
    if(Util.isAnyNull(bsn, sig))
      return false;
    
    return policy.requestBlacklistRevocation(bsn, sig);
  }

  @Override
  public boolean revokeKey(SignatureKey key)
  throws NotSupportedByRevocationPolicyException
  {
    if(Util.isAnyNull(key))
      return false;
    
    return policy.requestPrivateKeyRevocation(key);
  }

  @Override
  public boolean revokeSignature(Signature sig)
  throws NotSupportedByRevocationPolicyException
  {
    throw new NotSupportedByRevocationPolicyException("Not supported in M1");
  }

}
