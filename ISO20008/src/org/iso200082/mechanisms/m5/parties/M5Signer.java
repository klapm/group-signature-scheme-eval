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

import org.iso200082.common.Debug;
import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.api.ds.SignatureKey;
import org.iso200082.common.api.parties.CarelessSigner;
import org.iso200082.common.api.parties.Signer;
import org.iso200082.common.api.revocation.NonRevocationChallenge;
import org.iso200082.common.api.revocation.NonRevocationProof;
import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.mechanisms.m5.M5Scheme;
import org.iso200082.mechanisms.m5.ds.M5PrecomputationResult;
import org.iso200082.mechanisms.m5.ds.M5Signature;
import org.iso200082.mechanisms.m5.ds.M5SignatureKey;
import org.iso200082.mechanisms.m5.ds.group.M5OpenerPublicKey;
import org.iso200082.mechanisms.m5.ds.group.M5Parameters;
import org.iso200082.mechanisms.m5.ds.group.M5PublicKey;
import org.iso200082.mechanisms.m5.ds.messages.M5JoinChallenge;
import org.iso200082.mechanisms.m5.ds.messages.M5JoinRequest;
import org.iso200082.mechanisms.m5.ds.messages.M5JoinResponse;
import org.iso200082.mechanisms.m5.ds.messages.M5MembershipCredential;
import org.iso200082.mechanisms.m5.protocol.M5Protocol;


/**
 * Represents a mechanism five signer. Provides means to join a group 
 * (though not exposed as a non-joined member is not much of a 'Signer')
 * and sign messages.
 *  
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 *
 * @param <P> The primitive Type to use
 * 
 * @see M5Issuer
 * @see M5Verifier
 * @see M5Signature
 */
public class M5Signer
<
  P
>
implements Signer, CarelessSigner
{
  /** opener public key */
  protected M5OpenerPublicKey<P> gopk;
  
  /** group's public parameters */
  protected M5Parameters<P>      gparams;
  
  /** the corresponding {@link M5Scheme} instance */
  protected M5Scheme<P>          scheme;
  
  /** The signer ID (name) */
  protected String            identifier;
  
  /* join state */
  protected BigInteger                 xi;
  protected BigInteger                 xi_prime;
  protected Point<FqElement<P>, Fq<P>> hi;

  /** The signer's private key */
  private M5SignatureKey<P> key;

  /** Precomputation result (remains null if 
   * {@link #precomputeSignature(boolean)} is not used) */
  private M5PrecomputationResult<P> precomp_result;
  
  /** 
   * Ctor, creates a new, not-yet joined signer instance.
   * 
   * @param scheme The corresponding {@link M5Scheme}
   * @param identifier The signer's ID
   */
  public M5Signer(M5Scheme<P> scheme, String identifier)
  {
    this.scheme     = scheme;
    this.gopk       = scheme.getOpenerPublicKey();
    this.gparams    = scheme.getParameters();
    this.identifier = identifier;
  }
  
  /**
   * Creates an initial join request to indicate the intention to join
   * a certain group.
   * 
   * @return a new {@link M5JoinRequest}
   */
  public M5JoinRequest createJoinRequest()
  {
    // (step 1)
    int Kn = gparams.getKn(), K = gparams.getK(), Ks = gparams.getKs();
    xi_prime = new BigInteger(Kn + K + Ks, scheme.getRandom());
    
    return M5Protocol.createJoinRequest(gparams, scheme.getPublicKey(),
                                        xi_prime);
  }
  
  /**
   * Answers a join challenge, as given by the {@link M5Issuer}.
   * See {@link M5Protocol#createJoinResponse(M5Parameters, M5PublicKey, 
   * M5OpenerPublicKey, M5JoinChallenge, BigInteger)} for the associated
   * protocol steps
   * 
   * @param challenge The challenge to answer.
   * 
   * @return A new {@link M5JoinResponse}, or null on error
   */
  public M5JoinResponse<P> answerJoinChallenge(M5JoinChallenge challenge)
  {
    if(xi_prime == null)
      return null;
    
    M5JoinResponse<P> resp = 
      M5Protocol.createJoinResponse(gparams, scheme.getPublicKey(), gopk, 
                                    challenge, xi_prime);
    hi = resp.getHi();
    xi = resp.getXi();
    return resp;
  }
  
  /**
   * Verifies the {@link M5MembershipCredential} as given by the
   * {@link M5Issuer}. Sets the resulting {@link M5SignatureKey}.
   * 
   * @param c The credential to verify
   * 
   * @return true if successful (the signer can now sign messages),
   *         false otherwise
   */
  public boolean setMembershipCredential(M5MembershipCredential<P> c)
  {
    key = M5Protocol.verifyMembershipCredential(hi, xi, gparams, 
                                                scheme.getPublicKey(), c);
    
    hi       = null;
    xi       = null;
    xi_prime = null;
    
    return key != null;
  }

  @Override
  public boolean precomputeSignature(boolean ignored_flag)
  {
    if(key == null)
    {
      Debug.out(Debug.SIGN, "Join first.");
      return false;
    }
    
    precomp_result = M5Protocol.precomputeSignature(key, scheme.getPublicKey(), 
                                                   gopk, gparams);
    return precomp_result != null;
  }

  @Override
  public Signature signMessage(String message)
  {
    if(key == null)
    {
      Debug.out(Debug.SIGN, "Join first.");
      return null;
    }
    
    M5Signature<P> out = M5Protocol.signMessage(message, key, 
                                                scheme.getPublicKey(),
                                                gopk, gparams, precomp_result);
    precomp_result = null;
    return out;
  }

  @Override
  public String getName()
  {
    return identifier;
  }

  @Override
  public BigInteger getLinkingBase()
  {
    return null; // linking not supported in M5
  }

  @Override
  public NonRevocationProof getNonRevocationProof(String message,
  Signature sig, NonRevocationChallenge challenge)
  {
    return null;  // not supported in M5
  }

  @Override
  public SignatureKey getDrunkAndTellSecrets()
  {
    return key;
  }
  
  /**
   * Updates the membership credential (actually, the signature key) 
   * as a consequence of credential update revocation.
   * 
   * @param mc The new membership credential values to update the key with
   */
  public void updateMembershipCredential(M5MembershipCredential<P> mc)
  {
    key = new M5SignatureKey<P>(key.getXi(), mc.getAi(), mc.getEiPrime(),
                                          mc.getBi(), mc.getHi());
  }

}
