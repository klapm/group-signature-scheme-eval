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
 * Interface for revocation policies. The idea is to provide the verifier
 * with a RevocationPolicy object and thus inject the revocation behaviour
 * in a strategy-like manner. However, this approach has limitations,
 * especially since some revocation mechanisms are actually performed on
 * issuer side (credential update), so expect some dirty workarounds. 
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public interface RevocationPolicy
{
  /**
   * Revocation types as defined in the standard
   * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
   */
  public enum RevocationType {                
    /** No revocation checks are performed */
    NO_REVOCATION,
    /** Blacklisting revocation is enforced */
    LOCAL_BLACKLIST_REVOCATION,
    /** Private key revocation is enforced separately by each verifier */
    LOCAL_PRIVATEKEY_REVOCATION,
    /** Private key revocation is enforced globally */
    GLOBAL_PRIVATEKEY_REVOCATION,
    /** Signature revocation is enforced, locally */
    LOCAL_SIGNATURE_REVOCATION,
    /** Signature revocation is enforced, globally */
    GLOBAL_SIGNATURE_REVOCATION,
    /** Credential update revocation is enforced*/
    GLOBAL_CREDENTIAL_UPDATE_REVOCATION };
                       
  /**
   * Returns whether an author is revoked. Behaves differently, depending on 
   * the actual revocation policy implementation. Might be doing nothing or 
   * check whether it's globally or locally revoked using private key or 
   * blacklist revocation.
   * 
   * @param bsn The linking base (if required)
   * @param sig The signature to check for
   * 
   * @return true if revoked, false otherwise
   */
  public boolean isAuthorRevoked(BigInteger bsn, Signature sig);

  /**
   * Requests blacklist revocation, verifier-local.
   * 
   * @param bsn The member's basename (linking base)
   * @param sig The signature to use for blacklisting
   * 
   * @return true if the blacklisting request was accepted, false otherwise
   * 
   * @throws NotSupportedByRevocationPolicyException
   * If the verifier does not support blacklisting
   */
  public boolean requestBlacklistRevocation(BigInteger bsn, Signature sig)
  throws NotSupportedByRevocationPolicyException;

  /**
   * Requests private key revocation, either verifier-local or global,
   * depending on the actual implementation.
   * 
   * @param key The signature key to revoke
   * 
   * @return true if the revocation request was accepted, false otherwise
   * 
   * @throws NotSupportedByRevocationPolicyException If the verifier does not
   * support private key revocation
   */
  public boolean requestPrivateKeyRevocation(SignatureKey key)
  throws NotSupportedByRevocationPolicyException;
  
  /**
   * Getter for the type of underlying revocation implementation.
   * 
   * @return The revocation policy type
   */
  public RevocationType getRevocationType();
  
  /**
   * Simple method that returns a fresh instance on local revocation policies
   * and 'this' on global ones, thus preserving state.
   * 
   * @return this on global policies, a new instance on local ones
   */
  public RevocationPolicy anewIfLocal();
  
  /**
   * Requests signature revocation (either local or global, depending on the
   * actual implementation).
   * 
   * @param sig The signature to revoke
   * 
   * @return True if it got revoked (or was already revoked), false otherwise
   * @throws NotSupportedByRevocationPolicyException if the policy (or
   * mechanism in general) is not supporting this type of revocation
   */
  public boolean requestSignatureRevocation(Signature sig)
  throws NotSupportedByRevocationPolicyException;
  
  /**
   * Returns whether a signature is revoked. Always returns false if the
   * policy/mechanism does not allow signature revocation.
   * 
   * @param msg The message that was signed
   * @param sig The signature
   * @param prover The one who signed it, required for the non-revocation proof
   * listed in 6.4.6 of the draft standard.
   * 
   * @return true if revoked, false otherwise
   */
  public boolean isSignatureRevoked(String msg, Signature sig, Signer prover);

  /**
   * Allows setting the general scheme, in case the policy needs some public
   * group information.
   * 
   * @param scheme The group signature scheme (mechanism) that is used
   */
  public void setScheme(GroupSignatureScheme scheme);
  
}
