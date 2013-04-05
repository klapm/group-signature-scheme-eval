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

import org.iso200082.common.Debug;
import org.iso200082.common.Hash;
import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.api.ds.SignatureKey;
import org.iso200082.common.api.parties.CarelessSigner;
import org.iso200082.common.api.parties.Signer;
import org.iso200082.common.api.revocation.NonRevocationChallenge;
import org.iso200082.common.api.revocation.NonRevocationProof;
import org.iso200082.common.ecc.api.Point;
import org.iso200082.common.ecc.elements.FqElement;
import org.iso200082.common.ecc.fields.towerextension.Fq;
import org.iso200082.mechanisms.m4.M4Scheme;
import org.iso200082.mechanisms.m4.ds.M4PrecomputationResult;
import org.iso200082.mechanisms.m4.ds.M4Signature;
import org.iso200082.mechanisms.m4.ds.M4SignatureKey;
import org.iso200082.mechanisms.m4.ds.group.M4Parameters;
import org.iso200082.mechanisms.m4.ds.group.M4PublicKey;
import org.iso200082.mechanisms.m4.ds.messages.M4JoinRequest;
import org.iso200082.mechanisms.m4.ds.messages.M4MembershipCredential;
import org.iso200082.mechanisms.m4.ds.messages.M4NonRevokedChallenge;
import org.iso200082.mechanisms.m4.protocol.M4Protocol;


/**
 * Signer, provides means to join a group (though not exposed as a non-joined
 * member is not much of a 'Signer') and sign messages.
 * 
 * Note that in this framework, there is no separation between actual signer
 * (e.g. TPM) and 'assistant signer' (host platform).
 * 
 * @see M4Verifier
 * @see M4Issuer
 * @see M4Signature
 * @see M4SignatureKey
 * @see M4Scheme
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M4Signer
<
  P
>
implements Signer, CarelessSigner
{
  /** The group's public key */
  protected M4PublicKey<P>  gpub;
  
  /** The group's public parameters */
  protected M4Parameters<P> gparams;
  
  /** The signers name (ID) */
  protected String       identifier;
  
  /** The linking base to use */
  protected BigInteger   bsn;
  
  /** private signature key */
  private M4SignatureKey<P> key;
  
  /** temporary 'f' (named as in the draft), used during join phase */
  private FqElement<P> f;
  
  /** Precomputation result (remains null if 
   * {@link #precomputeSignature(boolean)} is not used) */
  private M4PrecomputationResult<P> precomp_result;
  
  /**
   * Ctor, creates a new (not-yet joined) signer, also creates
   * the linking base (simple sha1 hash over the name -> room for improvement
   * as it's easy to test all known names against a hash..)
   * 
   * @param gpub The group's public key
   * @param gparams The group's public parameters
   * @param identifier The signer's ID
   */
  public M4Signer(M4PublicKey<P> gpub,       M4Parameters<P> gparams,
                  String      identifier)
  {
    this.gpub       = gpub;
    this.gparams    = gparams;
    this.identifier = identifier;
    
    // a more sophisticated (salted!) method would be better.
    this.bsn = Hash.H("SHA-1", identifier.getBytes(), 160);
  }
  
  /**
   * Creates a join request indicating that the non-member wants to join
   * 
   * @param nonce A nonce (nI), initially chosen by the issuer. The nonce
   * could be separated into another messages.
   * 
   * @return A new {@link M4JoinRequest}
   */
  public M4JoinRequest<P> createJoinRequest(byte[] nonce)
  {
    f = gparams.getFq().getRandomElement();
    return M4Protocol.createJoinRequest(nonce, f, gparams, gpub);
  }
  
  /**
   * Completes a join request, creates the {@link M4SignatureKey} by combining
   * the retrieved {@link M4MembershipCredential} with the private key f.
   * 
   * @param mc The {@link M4MembershipCredential} sent by the {@link M4Issuer}
   * 
   * @return true if the credential could be verified
   */
  public boolean completeJoin(M4MembershipCredential<P> mc)
  {
    key = M4Protocol.createKeyFromCredential(gparams, f, mc, gpub);
    f = null;
    
    return key != null;
  }

  @Override
  public boolean precomputeSignature(boolean full)
  {
    if(key == null)
    {
      Debug.out(Debug.SIGN, "Join first.");
      return false;
    }
    
    precomp_result = M4Protocol.precomputeInitialSignature(key, gparams);
    if(full)
      M4Protocol.precomputeUnlinkableSignature(precomp_result, getLinkingBase(), key, gparams);
    
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
    
    // if precomp_result != null, fine. If not, it will be computed
    M4Signature<P> out = M4Protocol.signMessage(message.getBytes(), 
                                    bsn, key, gparams, precomp_result);
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
    return bsn;
  }

  /**
   * Updates the group public key, thus affecting the signer's private key.
   * Used in Credential Update revocation scenarios.
   * 
   * @param C The updated C
   */
  public void updateGroupPublicKey(Point<FqElement<P>, Fq<P>> C)
  {
    key = new M4SignatureKey<P>(key.getA(), key.getB(), C, key.getD(), key.getF());
  }

  @SuppressWarnings("unchecked")
  @Override
  public boolean equals(Object obj)
  {
    if(this == obj) return true;
    
    if(!(obj instanceof M4Signer))
      return false;
    
    return identifier.equals(((M4Signer<P>) obj).getName());
  }

  @Override
  public SignatureKey getDrunkAndTellSecrets()
  {
    return key;
  }

  @Override
  @SuppressWarnings("unchecked")
  public NonRevocationProof
  getNonRevocationProof(String message, Signature sig, 
                        NonRevocationChallenge challenge)
  {
    if(!(challenge instanceof M4NonRevokedChallenge))
      return null;
    
    if(!(sig instanceof M4Signature))
      return null;
    
    M4NonRevokedChallenge<P> c = (M4NonRevokedChallenge<P>) challenge;
    M4Signature<P>           s = (M4Signature<P>)           sig;
    
    return M4Protocol.getNonRevokedProof(message.getBytes(), key, s, c.getJ(),
                                         c.getK(), gparams);
  }
  
}
