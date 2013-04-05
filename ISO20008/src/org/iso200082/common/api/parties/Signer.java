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
import org.iso200082.common.api.revocation.NonRevocationChallenge;
import org.iso200082.common.api.revocation.NonRevocationProof;

/**
 * Represents a joined member. Signers are always readily joined, the join
 * process itself is though intended to be encapsulated in
 * {@link Issuer#addMember(String)}.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public interface Signer
{
  /**
   * Instructs the signer to precompute a partial signature. Allows better
   * on-line performance. Has no effect if there is no possibility to 
   * precompute values in a meaningful way. Depends on the underlying scheme.
   * 
   * @param full Level of precomputation. To be simply ignored if there is only
   *             one (or none)
   * 
   * @return true if precomputation was successful (or none was performed),
   *         false otherwise
   */
  public boolean precomputeSignature(boolean full);
  
  /**
   * Signs a message. Further requirements, such as the linking base, are to be
   * obtained from within this method.
   * 
   * @param message The message to sign
   * 
   * @return A signature, or null on error
   */
  public Signature signMessage(String message);
  
  /**
   * Getter for the ID
   * @return the name (ID) of the signer
   */
  public String getName();
  
  /**
   * Getter for the linking base (basename, bsn)
   * 
   * @return The signer's basename/linking base
   */
  public BigInteger getLinkingBase();
  
  /**
   * Computes a non-revocation proof as described in 6.4.6 in the draft
   * standard. Used in conjunction with signature revocation. 
   * 
   * @param message The message that was signed
   * @param sig     The signature
   * @param challenge The verifier's challenge
   * @return A proof that this signer is not revoked
   */
  public NonRevocationProof
  getNonRevocationProof(String message, Signature sig,
                        NonRevocationChallenge challenge);   
}
