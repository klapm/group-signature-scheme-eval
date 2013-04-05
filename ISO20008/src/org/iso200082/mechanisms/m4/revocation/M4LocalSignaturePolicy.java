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

package org.iso200082.mechanisms.m4.revocation;


import java.util.ArrayList;
import java.util.List;

import org.iso200082.common.api.GroupSignatureScheme;
import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.api.parties.Signer;
import org.iso200082.common.api.revocation.AbstractRevocationPolicy;
import org.iso200082.common.api.revocation.NonRevocationProof;
import org.iso200082.common.api.revocation.RevocationPolicy;
import org.iso200082.mechanisms.m4.M4Scheme;
import org.iso200082.mechanisms.m4.ds.M4Signature;
import org.iso200082.mechanisms.m4.ds.messages.M4NonRevokedChallenge;
import org.iso200082.mechanisms.m4.ds.messages.M4NonRevokedProof;
import org.iso200082.mechanisms.m4.parties.M4Signer;
import org.iso200082.mechanisms.m4.parties.M4Verifier;
import org.iso200082.mechanisms.m4.protocol.M4Protocol;


/**
 * Local signature revocation policy. Keeps a list of revoked signatures
 * (encoded as {@link M4NonRevokedChallenge}, containing J and K) and lets the
 * {@link M4Signer} generate proofs that he/she is not on that list upon
 * verification.
 * 
 * @see M4Verifier
 * @see RevocationPolicy
 * @see AbstractRevocationPolicy
 * @see M4GlobalSignaturePolicy
 * 
 * @param <P> The primitive Type to use
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 */
public class M4LocalSignaturePolicy
<
  P
>
extends AbstractRevocationPolicy
{  
  /** The list of revoked signatures */
  protected List<M4NonRevokedChallenge<P>> revoked_signatures;
  
  /** The correspondig scheme */
  protected M4Scheme<P> scheme;
  
  /**
   * Ctor, initializes the list
   */
  public M4LocalSignaturePolicy()
  {
    this.revoked_signatures = new ArrayList<M4NonRevokedChallenge<P>>();
  }
  
  /**
   * Ctor, initializes the list and sets the scheme. Used on duplication
   * @param scheme
   */
  private M4LocalSignaturePolicy(M4Scheme<P> scheme)
  {
    this.revoked_signatures = new ArrayList<M4NonRevokedChallenge<P>>();
    this.scheme = scheme;
  }

  @Override
  @SuppressWarnings("unchecked")
  public void setScheme(GroupSignatureScheme scheme)
  {
    if(scheme instanceof M4Scheme)
      this.scheme = (M4Scheme<P>) scheme;
  }

  @Override
  public RevocationType getRevocationType()
  {
    return RevocationType.LOCAL_SIGNATURE_REVOCATION;
  }

  @Override
  public RevocationPolicy anewIfLocal()
  {
    return new M4LocalSignaturePolicy<P>(scheme);
  }
  
  @Override
  @SuppressWarnings("unchecked")
  public boolean requestSignatureRevocation(Signature sig)
  {
    // always accepted
    
    if(!(sig instanceof M4Signature))
      return false;
    
    M4Signature<P> s = (M4Signature<P>) sig;
    revoked_signatures.add(new M4NonRevokedChallenge<P>(s.getJ(), s.getK()));
    return true;
  }
  
  @Override
  @SuppressWarnings("unchecked")
  public boolean isSignatureRevoked(String msg, Signature sig, Signer prover)
  {
    if(!(sig instanceof M4Signature))
      return true;
    
    M4Signature<P> s = (M4Signature<P>) sig;
    
    for(M4NonRevokedChallenge<P> jk : revoked_signatures)
    {
      NonRevocationProof proof = prover.getNonRevocationProof(msg, sig, jk);
      if(proof == null || !(proof instanceof M4NonRevokedProof))
        return true; // nope, chuck testa.

      if(M4Protocol.isSignatureRevoked(msg.getBytes(), s,
         (M4NonRevokedProof<P>) proof, scheme.getParameters(),
         jk.getJ(), jk.getK()))
        return true;
    }
    return false;
  }

}
