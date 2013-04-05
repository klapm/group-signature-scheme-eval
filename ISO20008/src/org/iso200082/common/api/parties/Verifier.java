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

package org.iso200082.common.api.parties;


import java.math.BigInteger;

import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.api.ds.SignatureKey;
import org.iso200082.common.api.exceptions.NotSupportedByMechanismException;
import org.iso200082.common.api.exceptions.NotSupportedByRevocationPolicyException;


/**
 * Verification party, verifies signatures (d'oh).
 * 
 * Note that the method signatures might seem somewhat weird. This is a result
 * of the mechanism differences, where some require a linking base whereas
 * others don't. A generic way is to use
 * {@link #isSignatureValid(String, BigInteger, Signature)} with
 * {@link Signer#getLinkingBase()} for the linking base. It might return null
 * if none is required by the mechanism but this should be fine for the
 * verifier. See TestLib in the tests that came with this implementation for
 * some examples.
 * 
 * Also note the {@link Signer} parameter in
 * {@link #isSignatureValid(String, BigInteger, Signature, Signer)}.
 * This is even more awkward as the draft standard is categorized in
 * 'Anonymous Digital Signatures', right? However, this method is to be used
 * in signature revocation scenarios, where some callback is needed such that
 * the {@link Signer} can generate a non-revocation proof. One has to trust
 * that no bad games are played here O_o. This should maybe be refactored
 * to some anonymous broker between the two parties but was considered out of
 * scope for this project.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public interface Verifier
{
  /**
   * Verifies a signature.
   * 
   * @param message The message that was signed
   * @param bsn     The member's linking base (or null if not required
   * by the mechanism)
   * @param signature The message's signature
   * 
   * @return True if the signature is valid (and not revoked in some way),
   * false otherwise
   */
  public boolean
  isSignatureValid(String message, BigInteger bsn, Signature signature);
  
  /**
   * Verifies a signature.
   * 
   * @param message The message that was signed
   * @param signature The message's signature
   * 
   * @return True if the signature is valid (and not revoked in some way),
   * false otherwise
   * 
   * @throws NotSupportedByMechanismException if a linking base is required
   */
  public boolean isSignatureValid(String message, Signature signature)
  throws NotSupportedByMechanismException;
  
  /**
   * Verifies a signature. See class documentation if you're suspicious
   * regarding the {@link Signer} parameter. To be used in signature
   * revocation scenarios.
   * 
   * Note that another way might be to publicly disclose the revocation list
   * and provide a package containing all relevant proofs along this
   * verification call. That way, the verifier would not have to directly
   * interact with the signer..
   * 
   * @param message The message that was signed
   * @param bsn     The member's linking base (or null if not required
   * by the mechanism)
   * @param signature The message's signature
   * @param signer Callback instance of the signer to get some non-revocation
   * proof
   * 
   * @return True if the signature is valid (and not revoked in some way),
   * false otherwise
   */
  public boolean isSignatureValid(String    message,   BigInteger bsn,
                                  Signature signature, Signer     signer);
  
  /**
   * Blacklists a signature (if the policy supports this). Local revocation.
   * 
   * @param bsn The member's linking base
   * @param sig The signature to blacklist
   * 
   * @return True if it got blacklisted (or was already blacklisted),
   * false otherwise
   * 
   * @throws NotSupportedByRevocationPolicyException If the policy does not
   * support blacklisting
   */
  public boolean blacklist(BigInteger bsn, Signature sig)
  throws NotSupportedByRevocationPolicyException;
  
  /**
   * Revokes a signature key. Either locally or globally, depending on the
   * actual policy.
   *  
   * @param key The signature key to revoke
   * 
   * @return True if it got revoked (or was already revoked), false otherwise
   * 
   * @throws NotSupportedByRevocationPolicyException If the policy does not
   * support blacklisting
   */
  public boolean revokeKey(SignatureKey key)
  throws NotSupportedByRevocationPolicyException;
  
  /**
   * Revokes a signature.
   *  
   * @param sig The signature to revoke
   * 
   * @return True if it got revoked (or was already revoked), false otherwise
   * 
   * @throws NotSupportedByRevocationPolicyException If the policy does not
   * support blacklisting
   */
  public boolean revokeSignature(Signature sig)
  throws NotSupportedByRevocationPolicyException;
}
