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

import org.iso200082.common.api.exceptions.NotSupportedByRevocationPolicyException;
import org.iso200082.common.api.exceptions.SchemeException;

/**
 * Issuer, creates a group (static method, see one of the implementations),
 * allows adding a member and performing credential updates as revocation
 * mechanism (in case the policy supports it).
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public interface Issuer
{
  /**
   * Performs the join phase and returns a readily joined {@link Signer}, ready
   * for signing messages.
   * 
   * @param identifier The {@link Signer}'s ID
   * 
   * @return A valid {@link Signer}
   * 
   * @throws SchemeException in case something went wrong during the join phase
   */
  public Signer addMember(String identifier) throws SchemeException;
  
  /**
   * Performs a credential update and notifies all registered Signers who are
   * also listed in to_include. With the consequence that all other registered
   * {@link Signer}s are operating on outdated credentials and are thus no
   * longer able to participate successfully. 
   * 
   * @param to_include members to be kept up2date
   * @throws NotSupportedByRevocationPolicyException if the policy
   * (or mechanism) does not support credential updates
   */
  public void doCredentialUpdate(Signer... to_include)
  throws NotSupportedByRevocationPolicyException;
  
  /**
   * Same as {@link #doCredentialUpdate(Signer...)}, except that one can
   * set the invert flag. If set, all registered signers will be notified
   * about the credential update *except* those listed in to_include.
   * 
   * @param invert whether to invert the inclusion or not
   * @param to_include members to be kept up2date or to be excluded, depending
   * on invert
   * 
   * @throws NotSupportedByRevocationPolicyException if the policy
   * (or mechanism) does not support credential updates
   */
  public void doCredentialUpdate(boolean invert, Signer... to_include)
  throws NotSupportedByRevocationPolicyException;
}
