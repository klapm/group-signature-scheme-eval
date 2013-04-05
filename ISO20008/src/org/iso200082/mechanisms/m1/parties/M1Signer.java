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

import org.iso200082.common.Debug;
import org.iso200082.common.Hash;
import org.iso200082.common.api.ds.Signature;
import org.iso200082.common.api.ds.SignatureKey;
import org.iso200082.common.api.parties.CarelessSigner;
import org.iso200082.common.api.parties.Signer;
import org.iso200082.common.api.parties.Verifier;
import org.iso200082.common.api.revocation.NonRevocationChallenge;
import org.iso200082.common.api.revocation.NonRevocationProof;
import org.iso200082.common.util.Util;
import org.iso200082.mechanisms.m1.ds.M1PrecomputationResult;
import org.iso200082.mechanisms.m1.ds.M1Signature;
import org.iso200082.mechanisms.m1.ds.M1SignatureKey;
import org.iso200082.mechanisms.m1.ds.group.M1Parameters;
import org.iso200082.mechanisms.m1.ds.group.M1PublicKey;
import org.iso200082.mechanisms.m1.ds.messages.M1JoinChallenge;
import org.iso200082.mechanisms.m1.ds.messages.M1JoinRequest;
import org.iso200082.mechanisms.m1.ds.messages.M1JoinResponse;
import org.iso200082.mechanisms.m1.ds.messages.M1MembershipCredential;
import org.iso200082.mechanisms.m1.ds.proofs.M1U;
import org.iso200082.mechanisms.m1.ds.proofs.M1V;
import org.iso200082.mechanisms.m1.ds.proofs.M1W;
import org.iso200082.mechanisms.m1.protocol.M1Protocol;


/**
 * Signing party implementation. Created by successfully completing a join
 * request. Leaks its private key, so probably not the best implementation 
 * for real-world usage scenarios.
 * 
 * @author Klaus Potzmader <klaus-dot-potzmader-at-student-dot-tugraz-dot-at>
 * @version 1.0
 * @see Signer
 * @see M1Signer
 * @see CarelessSigner
 * @see Verifier
 * @see M1Verifier
 */
public class M1Signer implements Signer, CarelessSigner
{
  /** the signer's 'name' */
  protected String identifier = null;
  
  /** group public key */
  protected M1PublicKey   gpub = null;
  
  /** group parameters */
  protected M1Parameters  params = null;
  
  /** the signer's private key */
  protected M1SignatureKey key = null;
  
  /** basename, or linking base */
  protected BigInteger bsn = null;
  
  /* join state */
  protected BigInteger x_prime = null;
  protected BigInteger r_check = null;
  protected BigInteger C1      = null;
  protected BigInteger x       = null;
  protected BigInteger C2      = null;
  

  /** precomputation result, set if {@link #precomputeSignature(boolean)} 
   * is used */
  private M1PrecomputationResult precomp_result = null;
 
  /**
   * Ctor, assigns identifier and public properties, also creates
   * the linking base (simple sha1 hash over the name -> room for improvement
   * as it's easy to test all known names against a hash..)
   * 
   * @param gpub The group's public key
   * @param params The group's public parameters
   * @param identifier The signer's identifier
   */
  public M1Signer(M1PublicKey gpub, M1Parameters params, String identifier)
  {
    this.identifier  = identifier;
    this.gpub        = gpub;
    this.params      = params;
    
    // a more sophisticated (salted!) method would be better.
    this.bsn = Hash.H("SHA-1", identifier.getBytes(), 160);
  }
  
  /**
   * Creates an initial join request. See
   * {@link M1Protocol#initiateJoin(M1Parameters, M1PublicKey)} and
   * {@link M1Protocol#createProofU(BigInteger[], M1Parameters, M1PublicKey)}
   * for the associated protocol steps.
   * 
   * @return a {@link M1JoinRequest} instance on success, null on error
   */
  public M1JoinRequest createJoinRequest()
  {
    if(gpub == null || params == null)
    {
      Debug.out(Debug.JOIN, "Invalid group");
      return null;
    }
    
    BigInteger[] join_data = M1Protocol.initiateJoin(params, gpub);
    M1U u = M1Protocol.createProofU(join_data, params, gpub);
    
    this.C1     = join_data[0];
    this.x_prime = join_data[1];
    this.r_check = join_data[2];
    
    return new M1JoinRequest(identifier, join_data[0], u);
  }
  
  /**
   * Answers the challenge given by the issuer in order to complete a join,
   * resulting in a {@link M1JoinResponse}.
   * 
   * @param challenge The {@link M1JoinChallenge} as given by the
   * {@link M1Issuer}
   * 
   * @return a {@link M1JoinResponse} on success, null on error
   */
  public M1JoinResponse answerJoinChallenge(M1JoinChallenge challenge)
  {
    if(Util.isAnyNull(C1, r_check, x_prime))
    {
      Debug.out(Debug.JOIN, "No existing join session");
      return null;
    }
    
    if(challenge == null)
    {
      Debug.out(Debug.JOIN, "Invalid challenge");
      clear_session();
      return null;
    }
    
    BigInteger[] data = 
      M1Protocol.onJoinChallengeReceive(challenge, x_prime, gpub, params); 
    if(data == null)
    {
      Debug.out(Debug.JOIN,
                "Something went wrong at interpreting the challenge..");
      clear_session();
      return null;
    }
    
    M1V v = M1Protocol.createProofV(data[0], data[1], gpub, params);
    M1W w = M1Protocol.createProofW(C1, r_check, data[0], data[1], data[2],
                                    challenge.getAlpha(), gpub, params);
    
    if(v == null || w == null)
    {
      Debug.out(Debug.JOIN,
                "Proof V or W could not be created");
      clear_session();
      return null;
    }

    x  = data[0];
    C2 = data[1];
     
    return new M1JoinResponse(identifier, data[1], v, w);
  }

  /**
   * Join completion, resulting in a valid {@link M1SignatureKey} if successful.
   * 
   * @param c The {@link M1MembershipCredential} as received by the
   * {@link M1Issuer}.
   * 
   * @return true on success (credential was valid), false otherwise
   */
  public boolean completeJoin(M1MembershipCredential c)
  {
    if(Util.isAnyNull(x_prime, x, r_check, C1, C2))
    {
      Debug.out(Debug.JOIN, "Protocol error, invalid state.");
      return false;
    }
    
    try
    {
      if(c == null)
      {
        Debug.out(Debug.JOIN, "Received invalid credential");
        return false;
      }
      
      if(M1Protocol.verifyMembershipCredential(x, c, gpub))
      {
        key = new M1SignatureKey(c, x);
        return true;
      }
    }
    finally
    {
      clear_session();
    }
    
    return false;
  }
  
  @Override
  public boolean precomputeSignature(boolean full)
  {
    if(key == null || gpub == null)
    {
      Debug.out(Debug.SIGN, "Join first.");
      return false;
    }
    
    precomp_result = M1Protocol.precomputeSignature(full, bsn, gpub, key, params);
    return precomp_result != null;
  }

  @Override
  public M1Signature signMessage(String message)
  {
    if(key == null || gpub == null)
    {
      Debug.out(Debug.SIGN, "Join first.");
      return null;
    }
    
    M1Signature out = M1Protocol.signMessage(bsn, message, gpub,
                                  key, params, precomp_result);
    precomp_result = null;
    return out;
  }

  @Override
  public SignatureKey getDrunkAndTellSecrets()
  {
    return key;
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

  @Override
  public NonRevocationProof getNonRevocationProof(String message,
      Signature sig, NonRevocationChallenge challenge)
  {
    // not supported in M1
    return null;
  }
  
  /**
   * Clears an existing session, resets the join process
   */
  private void clear_session()
  {
    this.x_prime = null;
    this.x       = null;
    this.r_check = null;
    this.C1      = null;
    this.C2      = null;
  }
  
}
